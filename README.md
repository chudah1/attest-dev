# Attest

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Attest controls and proves risky AI actions before they hit production systems. It gives agents signed, scope-limited credentials, routes high-risk mutations through policy and optional approval, issues short-lived execution grants, and leaves signed receipts that can be verified later.

This repository also includes a standalone MCP server:

- [TypeScript MCP server](./sdks/typescript/mcp-server/README.md) — a real stdio Model Context Protocol server that exposes Attest tools like `issue_credential`, `delegate_credential`, `list_tasks`, `get_audit_trail`, `get_evidence`, and approval actions.
- [TypeScript MCP middleware](./sdks/typescript/mcp/README.md) — middleware for protecting your own MCP server with Attest.

---

## Quickstart (TypeScript)

```ts
import { AttestClient } from '@attest-dev/sdk';

const client = new AttestClient({ baseUrl: 'http://localhost:8080', apiKey: 'dev' });

// 1. Issue a root credential for your agent workflow
const root = await client.issue({
  agent_id: 'support-bot',
  user_id: 'alice@acme.com',
  scope: ['refund:execute', 'credit:execute'],
  instruction: 'Review support incidents and safely process eligible refunds.',
});

// 2. Request a risky action before touching the target system
const action = await client.requestAction({
  action_type: 'refund',
  target_system: 'stripe',
  target_object: 'order_ORD-4821',
  action_payload: {
    amount_cents: 4799,
    currency: 'USD',
    reason: 'damaged_item',
  },
  agent_id: 'support-bot',
  sponsor_user_id: 'alice@acme.com',
  att_tid: root.claims.att_tid,
});

if (action.status !== 'approved' || !action.grant?.token) {
  throw new Error(`refund needs approval: ${action.status}`);
}

// 3. Execute with the short-lived grant, then record the receipt
const receipt = await client.executeAction(action.id, {
  outcome: 'success',
  provider_ref: 're_abc123',
  response_payload: { stripe_status: 'succeeded' },
});
console.log(receipt.signed_packet_hash);

// 4. Fetch the immutable receipt later
const confirmed = await client.getReceipt(action.id);
console.log(confirmed.outcome, confirmed.provider_ref);
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

Delegation still enforces that child scope is a **strict subset** of the parent scope.
The Action API builds on top of that delegation substrate to gate risky writes.

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
| `GET` | `/v1/actions` | List action requests |
| `POST` | `/v1/actions/request` | Create an action request and run policy |
| `GET` | `/v1/actions/{id}` | Fetch an action request |
| `POST` | `/v1/actions/{id}/approve` | Approve a pending action |
| `POST` | `/v1/actions/{id}/deny` | Deny a pending action |
| `POST` | `/v1/actions/{id}/execute` | Record execution and mint a receipt |
| `GET` | `/v1/actions/{id}/receipt` | Fetch the signed execution receipt |
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
