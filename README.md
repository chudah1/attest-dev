# Warrant

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Warrant is a cryptographic credentialing standard for AI agent pipelines. When an orchestrator spawns sub-agents to complete a task, Warrant issues each agent a short-lived, scope-limited JWT that is cryptographically bound to the original human instruction via a SHA-256 intent hash. Every delegation narrows scope, cannot outlive the parent, and is recorded in an append-only, hash-chained audit log — so the full chain of authority from a human principal down to any tool call is provable, revocable in a single operation, and independently verifiable by any party with access to the public key.

---

## Quickstart (TypeScript)

```ts
import { WarrantClient, isScopeSubset } from '@warrant/sdk';

const client = new WarrantClient({ baseUrl: 'http://localhost:8080', apiKey: 'dev' });

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
const jwks   = await client.fetchJWKS();
const result = await client.verify(childToken, jwks);
console.log(result.valid, result.warnings);

// 4. Revoke the entire task tree in one call
await client.revoke(root.jti);

// 5. Retrieve the tamper-evident audit chain
const chain = await client.audit(root.wrt_tid);
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
git clone https://github.com/warrant-dev/warrant
cd warrant
docker compose up

# The server is now running at http://localhost:8080
# PostgreSQL at localhost:5432, Redis at localhost:6379

# Issue your first credential
curl -s -X POST http://localhost:8080/v1/credentials \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id":    "orchestrator-v1",
    "user_id":     "usr_alice",
    "scope":       ["research:read", "gmail:send"],
    "instruction": "Research competitors and email the board"
  }' | jq .

# Open the interactive demo
open demo/index.html
```

**Without Docker** (dev mode — ephemeral key, no database):

```bash
cd server
go run ./cmd/warrant          # starts on :8080, warns about missing DB
```

---

## API reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/credentials` | Issue a root credential |
| `POST` | `/v1/credentials/delegate` | Delegate to a child agent |
| `DELETE` | `/v1/credentials/{jti}` | Revoke credential and all descendants |
| `GET` | `/v1/revoked/{jti}` | Check revocation status |
| `GET` | `/v1/tasks/{tid}/audit` | Retrieve the audit chain for a task |
| `GET` | `/.well-known/jwks.json` | Public key set for offline verification |
| `GET` | `/health` | Health check |

---

## Specification

The credential format is defined in [spec/WCS-01.md](spec/WCS-01.md) (Warrant Credential Standard, revision 01).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
