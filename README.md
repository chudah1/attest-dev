# Attest

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Attest is the control plane for delegated agent actions. It gives orchestrators and sub-agents signed, scope-limited credentials tied to the original human instruction, so every handoff stays narrow, every tool call can be checked, the whole task tree can be revoked in one operation, and the resulting evidence can be verified later.

This repository also includes a standalone MCP server:

- [TypeScript MCP server](./sdks/typescript/mcp-server/README.md) — a real stdio Model Context Protocol server that exposes Attest tools like `issue_credential`, `delegate_credential`, `list_tasks`, `get_audit_trail`, `get_evidence`, and approval actions.
- [TypeScript MCP middleware](./sdks/typescript/mcp/README.md) — middleware for protecting your own MCP server with Attest.

---

## Quickstart (TypeScript)

```ts
import { AttestClient, isScopeSubset } from '@attest-dev/sdk';

const client = new AttestClient({ baseUrl: 'http://localhost:8080', apiKey: 'dev' });

// 1. Issue a root credential for your orchestrator
const { token: rootToken, claims: root } = await client.issue({
  agent_id:    'orchestrator-v1',
  user_id:     'usr_alice',
  scope:       ['research:read', 'gmail:send'],
  instruction: 'Research our top 3 competitors and email a summary to the board',
});

// 2. Delegate a narrowed credential to a sub-agent
const { token: childToken, claims: child } = await client.delegate({
  parent_token: rootToken,
  child_agent:  'email-agent-v1',
  child_scope:  ['gmail:send'],        // subset of parent — enforced server-side
});

// 3. Verify offline (no network call after fetching JWKS once)
const jwks   = await client.fetchJWKS('org_abc123');
const result = await client.verify(childToken, jwks);
console.log(result.valid, result.warnings);

// 4. Revoke the entire task tree in one call
await client.revoke(root.jti);

// 5. Retrieve the tamper-evident audit chain
const chain = await client.audit(root.att_tid);
chain.events.forEach(e => console.log(e.event_type, e.jti, e.created_at));
```

---

## Scope syntax

Scopes follow the pattern `resource:action`. Either field may be `*` as a wildcard.

| Expression | Meaning |
|---|---|
| `gmail:send` | Send via Gmail only |
| `gmail:*` | All Gmail actions |
| `*:read` | Read access to any resource |
| `*:*` | Full access (root grants only) |

Delegation enforces that the child scope is a **strict subset** of the parent scope.
The utility `isScopeSubset(parentScope, childScope)` replicates this check client-side.

---

## Getting started

**Prerequisites:** Docker and Docker Compose.

```bash
# Clone and start everything
git clone https://github.com/chudah1/attest-dev
cd attest-dev
docker compose up --build

# The server is now running at http://localhost:8080
# PostgreSQL at localhost:5432

# Issue your first credential (replace YOUR_API_KEY with the key from POST /v1/orgs)
curl -s -X POST http://localhost:8080/v1/credentials \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{
    "agent_id":    "orchestrator-v1",
    "user_id":     "usr_alice",
    "scope":       ["research:read", "gmail:send"],
    "instruction": "Research competitors and email the board"
  }' | jq .

# Open the interactive demo
open demo/index.html
```

If you want to run the Go server outside Docker, point it at the Compose database:

```bash
docker compose up -d postgres
cd server
DATABASE_URL=postgres://attest:attest@localhost:5432/attest go run ./cmd/attest
```

---

## API reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/orgs` | Create an organization and get an API key |
| `POST` | `/v1/credentials` | Issue a root credential |
| `POST` | `/v1/credentials/delegate` | Delegate to a child agent |
| `DELETE` | `/v1/credentials/{jti}` | Revoke credential and all descendants |
| `GET` | `/v1/revoked/{jti}` | Check revocation status (public, no auth) |
| `GET` | `/v1/tasks/{tid}/audit` | Retrieve the audit chain for a task |
| `POST` | `/v1/audit/report` | Report an agent action to the audit log |
| `POST` | `/v1/audit/status` | Report agent lifecycle event (started/completed/failed) |
| `POST` | `/v1/approvals` | Request human-in-the-loop approval |
| `POST` | `/v1/approvals/{id}/grant` | Grant a pending HITL approval |
| `GET` | `/orgs/{orgId}/jwks.json` | Public key set for offline verification |
| `GET` | `/health` | Health check |

---

## Specification

The credential format is defined in [spec/WCS-01.md](spec/WCS-01.md) (Attest Credential Standard, revision 01).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
