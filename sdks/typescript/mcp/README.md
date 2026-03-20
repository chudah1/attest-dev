# @attest-dev/sdk/mcp

Attest credential enforcement middleware for [Model Context Protocol](https://modelcontextprotocol.io/) servers.

Two lines to protect every tool call on an existing MCP server.

## Install

```bash
npm install @attest-dev/sdk
```

`@attest-dev/sdk` ships both the core client and the MCP middleware as a single package with two entry points.

## Two-line integration

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { withAttest } from "@attest-dev/sdk/mcp";

const server = new McpServer({ name: "my-tools", version: "1.0.0" });
const protectedServer = withAttest(server, {
  issuerUri: "https://api.attest.dev",
});

// Register tools exactly as before — every call is now credential-gated.
protectedServer.tool("send_email", schema, handler);
```

`withAttest` patches `server.tool()` in place and returns the same server object typed as the original. Everything else — `connect()`, `close()`, transports — works unchanged.

## How it works

On every tool call, before the handler executes:

1. **Extract credential** from `extra.authInfo.token` (MCP auth middleware path), `extra.meta.attest_token`, or `extra.meta.authorization`
2. **Verify RS256 signature + expiry** offline against the issuer's JWKS (fetched once, cached for 1 hour by default)
3. **Map tool name → scope** using `scopeForTool()` and check the credential's `att_scope` covers it
4. **Check revocation** via `GET /v1/revoked/{jti}` (10-second in-process cache)
5. **Pass through** to the original handler on success
6. **Return a structured error** on any failure — agent frameworks receive `isError: true` with a typed JSON payload
7. **Fire audit event** to `POST /v1/audit` — async, never blocks the tool call

## Scope mapping

Tool names are automatically mapped to `resource:action` scope strings. The first word (before the first `_`) becomes the action; the remainder becomes the resource.

| Tool name | Required scope | Notes |
|---|---|---|
| `send_email` | `email:send` | |
| `read_file` | `file:read` | |
| `list_documents` | `documents:list` → `documents:read` | `list` aliases to `read` |
| `create_user` | `user:create` → `user:write` | `create` aliases to `write` |
| `delete_record` | `record:delete` | |
| `get_weather_forecast` | `weather_forecast:read` | multi-word resources keep underscores |
| `run_query` | `query:run` → `query:execute` | `run` aliases to `execute` |

**Action aliases** — these raw prefixes map to canonical actions:

| Raw prefix | Canonical action |
|---|---|
| `create`, `update`, `put`, `patch`, `set`, `upsert` | `write` |
| `get`, `fetch`, `list`, `search`, `query`, `find`, `lookup` | `read` |
| `remove`, `destroy` | `delete` |
| `run`, `invoke`, `call` | `execute` |

**Multi-word resources** keep their underscores in the scope string. `get_weather_forecast` → `weather_forecast:read`. This is intentional — the full noun phrase is preserved as the resource. When issuing credentials, use the same string: `scope: ["weather_forecast:read"]`.

**Override at registration** — pass a `AttestToolOptions` object as the final argument to `server.tool()`. This is the preferred way to set scope for non-standard tool names because the scope lives next to the tool definition:

```typescript
import { withAttest } from "@attest-dev/sdk/mcp";
import type { AttestToolOptions } from "@attest-dev/sdk/mcp";

protectedServer.tool("gh_create_issue", schema, handler, {
  requiredScope: "github:write",
} satisfies AttestToolOptions);

protectedServer.tool("stripe_charge", schema, handler, {
  requiredScope: "stripe:write",
} satisfies AttestToolOptions);

// Auto-mapping still applies when requiredScope is omitted.
protectedServer.tool("send_email", schema, handler);
// → "email:send"
```

The options object is consumed by `withAttest` and stripped before the MCP SDK sees the arguments — the SDK is unaware of it.

**Override globally** using `toolScopeMap` in options (applies to all tools that don't declare `requiredScope` explicitly):

```typescript
const protectedServer = withAttest(server, {
  issuerUri: "https://api.attest.dev",
  toolScopeMap: {
    "send_message": "slack:send",
    "query_db":     "postgres:read",
  },
});
```

## Scope discovery endpoint

`getAttestScopes()` returns the live scope registry — every tool name mapped to its resolved scope string. Wire it to an HTTP endpoint so credential issuers can query what scopes a server requires without out-of-band coordination.

```typescript
import { withAttest, getAttestScopes } from "@attest-dev/sdk/mcp";

const protectedServer = withAttest(server, { issuerUri: "https://api.attest.dev" });

protectedServer.tool("send_email", schema, handler);
protectedServer.tool("gh_create_issue", schema, handler, { requiredScope: "github:write" });

// Express / Hono / any HTTP framework:
app.get("/.well-known/attest-scopes", (_req, res) => {
  res.json({ tools: getAttestScopes(protectedServer) });
});
```

Response:

```json
{
  "tools": {
    "send_email":      "email:send",
    "gh_create_issue": "github:write"
  }
}
```

An orchestrator agent issues credentials by fetching this endpoint first:

```typescript
// Before starting a task, discover what the MCP server needs:
const { tools } = await fetch("https://my-mcp-server/.well-known/attest-scopes")
  .then(r => r.json());

// Issue a credential with exactly those scopes:
const { token } = await attestClient.issue({
  agent_id: "my-agent",
  user_id:  "usr_alice",
  scope:    Object.values(tools),   // ["email:send", "github:write"]
  instruction: "...",
});
```

No spreadsheet of scope strings. No manual sync between server and client. The server is the source of truth.

## What an agent receives when blocked

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\n  \"error\": \"attest_violation\",\n  \"reason\": \"scope_violation\",\n  \"detail\": \"Credential (jti: abc-123) grants [research:read] but tool \\\"send_email\\\" requires \\\"email:send\\\".\",\n  \"jti\": \"abc-123\",\n  \"taskId\": \"tid-xyz\"\n}"
    }
  ],
  "isError": true
}
```

`isError: true` signals the MCP framework that this is an error response. The `reason` field is machine-readable:

| `reason` | Meaning |
|---|---|
| `no_credential` | No Attest JWT found in the request |
| `invalid_credential` | JWT signature verification failed or malformed |
| `credential_expired` | JWT `exp` has passed |
| `credential_revoked` | JTI is in the revocation list |
| `scope_violation` | Credential does not grant the required scope |

## Options

```typescript
withAttest(server, {
  // Required: URI of your Attest server
  issuerUri: "https://api.attest.dev",

  // How long to cache JWKS before re-fetching (seconds). Default: 3600
  jwksCacheTTL: 3600,

  // How long to cache revocation status per JTI (seconds).
  // Set 0 to disable caching (every call hits the server). Default: 10
  revocationCacheTTL: 10,

  // false = log violations via onViolation but don't block the call.
  // Useful for gradual rollout. Default: true
  requireCredential: true,

  // Per-tool scope overrides. Keys are exact tool names.
  toolScopeMap: {
    "send_message": "slack:send",
  },

  // Called on every scope violation (synchronous).
  // Use for metrics, alerting, structured logging.
  onViolation: (event) => {
    console.warn("Attest violation", {
      tool:     event.toolName,
      reason:   event.reason,
      required: event.requiredScope,
      granted:  event.grantedScope,
      jti:      event.jti,
    });
  },
});
```

## Reading credential claims inside a tool handler

After `withAttest` has already verified the credential, use `getAttestContext` to read the claims without re-verifying:

```typescript
import { withAttest, getAttestContext } from "@attest-dev/sdk/mcp";

protectedServer.tool("send_email", schema, async (args, extra) => {
  const ctx = getAttestContext(extra);
  // ctx.att_uid   — the human who initiated the task
  // ctx.att_tid   — task tree ID (use for audit correlation)
  // ctx.att_scope — granted scopes
  // ctx.att_depth — delegation depth (0 = root)
  // ctx.jti       — this credential's unique ID

  await sendEmail(args.to, args.body, { actingAs: ctx?.att_uid });
  return { content: [{ type: "text", text: "sent" }] };
});
```

## Gradual rollout

Add Attest to an existing server without blocking traffic until you're confident the mapping is correct:

```typescript
const protectedServer = withAttest(server, {
  issuerUri: "https://api.attest.dev",
  requireCredential: false,   // observe, don't block
  onViolation: (event) => metrics.increment("attest.violation", {
    tool:   event.toolName,
    reason: event.reason,
  }),
});
```

Flip `requireCredential` to `true` once violation rates drop to zero in your monitoring.

## Audit logging

Every tool call — pass or fail — fires a `POST /v1/audit` to your Attest server. Delivery is async and never blocks tool execution.

**Audit delivery is best-effort with structured error surfacing. For guaranteed delivery, configure `onAuditError` and implement your own retry queue.**

Failures surface in priority order — nothing is ever silently dropped:

1. **`onAuditError(error, event)`** — you handle it (retry queue, fallback log, pager)
2. **`onViolation({ reason: "audit_failure", ... })`** — surfaces to your existing monitoring if `onAuditError` is not set
3. **`console.warn`** — last resort if neither callback is configured

```typescript
const protectedServer = withAttest(server, {
  issuerUri: "https://api.attest.dev",

  // Tier 1: implement a retry queue for guaranteed delivery
  onAuditError: (err, event) => {
    retryQueue.push({ event, attempts: 0, nextRetry: Date.now() + 5000 });
    logger.error("attest audit delivery failed", {
      jti:      event.jti,
      agent_id: event.agent_id,
      error:    err.message,
    });
  },

  // Tier 2: violations (including audit_failure) go to your monitoring
  onViolation: (e) => metrics.increment("attest.event", { reason: e.reason }),
});
```

Non-2xx responses from the audit endpoint are treated as delivery failures, not silent successes.

The audit event carries: `event_type`, `jti`, `att_tid`, `att_uid`, `agent_id` (`mcp:<toolName>`), `scope`, and an `outcome` meta field (`allowed`, `scope_violation`, `blocked_revoked`).

Query the audit chain for a task tree:

```typescript
import { AttestClient } from "@attest-dev/sdk";

const client = new AttestClient({ baseUrl: "https://api.attest.dev", apiKey: "..." });
const chain = await client.audit(taskId);
chain.events.forEach(e => console.log(e.event_type, e.jti, e.created_at));
```

## Full example

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { withAttest } from "@attest-dev/sdk/mcp";
import { z } from "zod";

const server = new McpServer({ name: "email-server", version: "1.0.0" });

server.tool(
  "send_email",
  { to: z.string().email(), subject: z.string(), body: z.string() },
  async ({ to, subject, body }) => {
    await sendEmail(to, subject, body);
    return { content: [{ type: "text", text: `Sent to ${to}` }] };
  },
);

// Wrap — every tool now requires a valid credential with "email:send" scope.
const protectedServer = withAttest(server, {
  issuerUri: process.env.ATTEST_URI ?? "http://localhost:8080",
  onViolation: (e) => console.warn("blocked:", e.reason, e.toolName),
});

const transport = new StdioServerTransport();
await protectedServer.connect(transport);
```

## License

Apache-2.0
