# @attest-dev/sdk

TypeScript SDK for [Attest](https://github.com/attest-dev/attest) — cryptographic credentials for AI agent pipelines.

Attest issues RS256-signed JWTs to agents carrying scope, delegation lineage, and task provenance. Every handoff narrows scope, every action is auditable, and the entire task tree can be revoked in one call.

> **Beta** — self-host the [Attest server](https://github.com/attest-dev/attest) or point at your own instance. Hosted service coming soon.

## Install

```bash
npm install @attest-dev/sdk@beta
```

## Quickstart

```ts
import { AttestClient } from "@attest-dev/sdk";

const client = new AttestClient({
  baseUrl: "http://localhost:8080",
  apiKey:  "your-api-key",
});

// Issue a root credential for an orchestrator agent
const { token, claims } = await client.issue({
  agent_id:    "orchestrator-v1",
  user_id:     "usr_alice",
  scope:       ["research:read", "gmail:send"],
  instruction: "Research competitors and email the board",
});

// Delegate a narrowed credential to a sub-agent
const { token: childToken } = await client.delegate({
  parent_token: token,
  child_agent:  "email-agent-v1",
  child_scope:  ["gmail:send"],   // must be a subset of parent — enforced server-side
});

// Verify offline (no network call after JWKS is fetched once)
const jwks   = await client.fetchJWKS();
const result = await client.verify(childToken, jwks);
console.log(result.valid, result.warnings);

// Revoke the entire task tree in one call
await client.revoke(claims.jti);

// Retrieve the tamper-evident audit chain
const chain = await client.audit(claims.att_tid);
chain.events.forEach(e => console.log(e.event_type, e.jti, e.created_at));
```

## MCP middleware

Enforce Attest credentials on every tool call in an MCP server — two lines:

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { withAttest } from "@attest-dev/sdk/mcp";

const server = new McpServer({ name: "my-tools", version: "1.0.0" });
const protectedServer = withAttest(server, {
  issuerUri: "http://localhost:8080",
});

// Register tools exactly as before — every call is now credential-gated
protectedServer.tool("send_email", schema, handler);
```

Tool names map to scope strings automatically (`send_email` → `email:send`, `read_file` → `file:read`). Override per tool:

```ts
protectedServer.tool("gh_create_issue", schema, handler, {
  requiredScope: "github:write",
});
```

Expose a discovery endpoint so orchestrators know what scopes to request:

```ts
import { getAttestScopes } from "@attest-dev/sdk/mcp";

app.get("/.well-known/attest-scopes", (_req, res) => {
  res.json({ tools: getAttestScopes(protectedServer) });
});
```

See [`mcp/README.md`](./mcp/README.md) for the full MCP middleware reference.

## Scope syntax

Scopes follow `resource:action`. Either field may be `*` as a wildcard.

| Expression | Meaning |
|---|---|
| `gmail:send` | Send via Gmail only |
| `gmail:*` | All Gmail actions |
| `*:read` | Read access to any resource |
| `*:*` | Full access (root credentials only) |

Delegation enforces that child scope is a strict subset of parent scope — server-side, cryptographically.

## Self-hosting

```bash
# Clone and start (Docker required)
git clone https://github.com/attest-dev/attest
cd attest
docker compose up

# Or run without Docker (ephemeral key, in-memory storage)
cd server && go run ./cmd/attest
```

Server starts on `http://localhost:8080`.

## License

Apache-2.0
