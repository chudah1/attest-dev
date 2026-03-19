# @warrant/mcp

Warrant credential enforcement middleware for [Model Context Protocol](https://modelcontextprotocol.io/) servers.

Drop it in front of your existing MCP server in ~5 lines of code, and every tool call is checked against a Warrant credential before it reaches your handler.

## Install

```bash
npm install @warrant/mcp @warrant/sdk @modelcontextprotocol/sdk jose
```

## 5-line integration

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createWarrantMcpServer } from '@warrant/mcp';

const server = new McpServer({ name: 'my-server', version: '1.0.0' });
// Register your tools normally:
server.tool('send_email', { to: z.string(), body: z.string() }, sendEmailHandler);

const secured = createWarrantMcpServer(server, {
  warrantBaseUrl: 'http://localhost:8080',
  extractToken: (req) => req.params._meta?.warrant_token ?? null,
});
```

That's it. Every call to `send_email` now requires a valid Warrant credential with scope `tool:send_email`.

## How it works

When a tool call arrives the middleware:

1. **Extracts the token** using your `extractToken` function (or the built-in default that checks `_meta.warrant_token` and then `arguments.warrant_token`).
2. **Verifies the JWT offline** — RS256 signature + expiry check using the server's JWKS (fetched once at startup, cached; re-fetched on key rotation).
3. **Checks scope** — does `wrt_scope` contain `tool:<toolName>`, `tool:*`, or `*:*`?
4. **Checks revocation** — calls `GET /v1/revoked/{jti}` on the Warrant server (fail-closed: if the server is unreachable, the call is denied).
5. **Passes through** to your original handler on success, or returns an MCP error on failure.

## What an agent sees when denied

```json
{
  "error": "warrant_denied",
  "code": "scope_violation",
  "tool": "send_email",
  "required_scope": "tool:send_email",
  "granted_scope": ["gmail:read"],
  "jti": "abc123..."
}
```

The `code` field is one of:

| Code | Meaning |
|---|---|
| `missing_token` | No token was found in the request |
| `invalid_token` | JWT signature verification failed |
| `expired` | JWT has expired |
| `revoked` | Credential has been revoked |
| `scope_violation` | Token doesn't grant the required tool scope |

## Scope mapping

Tool names map to scope entries using the `scopePrefix` option (default `"tool"`):

| Tool name | Required scope |
|---|---|
| `send_email` | `tool:send_email` |
| `read_file` | `tool:read_file` |
| `*` (any tool) | `tool:*` or `*:*` |

When issuing credentials for an agent, set `wrt_scope` accordingly:

```json
{ "scope": ["tool:send_email", "tool:read_file"] }
```

## Options

```typescript
interface WarrantMcpOptions {
  /** Warrant server base URL. Required. */
  warrantBaseUrl: string;

  /** Full JWKS URL. Defaults to warrantBaseUrl + "/.well-known/jwks.json". */
  jwksUrl?: string;

  /**
   * Pre-loaded JWKS for offline/test mode.
   * When provided the JWKS endpoint is never contacted.
   */
  staticJwks?: JWKSResponse;

  /**
   * How to extract the Warrant token from a tool call request.
   * Default: checks _meta.warrant_token then arguments.warrant_token.
   */
  extractToken?: (request: CallToolRequest) => string | null;

  /**
   * Whether to check the revocation list on every call.
   * Default: true. Set false for offline or latency-sensitive mode.
   */
  checkRevocation?: boolean;

  /**
   * Revocation check timeout in milliseconds.
   * If the Warrant server doesn't respond in time the call is DENIED.
   * Default: 500.
   */
  revocationTimeoutMs?: number;

  /**
   * Scope prefix for tool name mapping.
   * Default: "tool"  →  tool "send_email" maps to scope "tool:send_email".
   */
  scopePrefix?: string;

  /**
   * Audit hook called whenever a tool call is denied.
   * Use this to log or alert on denied attempts.
   */
  onDenied?: (reason: DeniedReason, request: CallToolRequest) => void;
}
```

## Token extraction strategies

### From MCP `_meta` (recommended)

MCP clients can attach metadata to any tool call via `_meta`:

```typescript
extractToken: (req) => {
  const meta = req.params._meta as Record<string, unknown> | undefined;
  return typeof meta?.warrant_token === 'string' ? meta.warrant_token : null;
}
```

### From HTTP Authorization header

If your transport captures HTTP headers separately, pass the header through:

```typescript
import { extractTokenFromHeader } from '@warrant/mcp';

// In your HTTP handler:
const token = extractTokenFromHeader(req.headers.authorization ?? '');

// Then thread it into MCP meta when calling the tool, or:
extractToken: () => token   // captured via closure
```

### From tool arguments

The default extractor also checks `arguments.warrant_token`. Agents can include their token as a regular tool argument:

```json
{
  "tool": "send_email",
  "arguments": {
    "to": "alice@example.com",
    "body": "Hello",
    "warrant_token": "eyJ..."
  }
}
```

## Offline / test mode

Pass a `staticJwks` to run fully offline — no network calls to the Warrant server:

```typescript
import { createWarrantMcpServer } from '@warrant/mcp';
import type { JWKSResponse } from '@warrant/sdk';

const testJwks: JWKSResponse = { keys: [/* your public key */] };

const secured = createWarrantMcpServer(server, {
  warrantBaseUrl: 'http://localhost:8080',
  staticJwks: testJwks,
  checkRevocation: false,   // no network calls
  extractToken: (req) => req.params._meta?.warrant_token ?? null,
});
```

## Lower-level: wrapping individual tools

Use `WarrantToolMiddleware` to protect specific tools rather than the whole server:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WarrantToolMiddleware } from '@warrant/mcp';
import { z } from 'zod';

const server = new McpServer({ name: 'my-server', version: '1.0.0' });

const middleware = new WarrantToolMiddleware({
  warrantBaseUrl: 'http://localhost:8080',
});

// Only send_email is protected; other tools are not.
server.tool(
  'send_email',
  { to: z.string(), body: z.string() },
  middleware.wrap('send_email', async (args, claims) => {
    // args is typed as { to: string; body: string }
    // claims contains the verified WarrantClaims (wrt_scope, wrt_uid, etc.)
    await sendEmail(args.to, args.body);
    return { content: [{ type: 'text', text: 'Email sent.' }] };
  }),
);
```

## Audit logging

```typescript
const secured = createWarrantMcpServer(server, {
  warrantBaseUrl: 'http://localhost:8080',
  extractToken: (req) => req.params._meta?.warrant_token ?? null,
  onDenied: (reason, request) => {
    console.warn('Tool call denied', {
      code: reason.code,
      tool: reason.tool,
      jti: reason.jti,
      message: reason.message,
    });
  },
});
```

## Full example

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createWarrantMcpServer } from '@warrant/mcp';
import { z } from 'zod';

// 1. Create and configure your server normally.
const server = new McpServer({ name: 'email-server', version: '1.0.0' });

server.tool(
  'send_email',
  { to: z.string().email(), subject: z.string(), body: z.string() },
  async ({ to, subject, body }) => {
    // Your implementation here.
    return { content: [{ type: 'text', text: `Sent to ${to}` }] };
  },
);

// 2. Wrap with Warrant enforcement.
const secured = createWarrantMcpServer(server, {
  warrantBaseUrl: process.env.WARRANT_URL ?? 'http://localhost:8080',
  extractToken: (req) => {
    const meta = req.params._meta as Record<string, unknown> | undefined;
    return typeof meta?.warrant_token === 'string' ? meta.warrant_token : null;
  },
  onDenied: (reason) => console.warn('Denied:', reason),
});

// 3. Connect transport — same as without Warrant.
const transport = new StdioServerTransport();
await secured.connect(transport);
```

## License

Apache-2.0
