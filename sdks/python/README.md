# attest-sdk

Python SDK for the [Attest](https://github.com/attest-dev/attest) cryptographic agent credential service.

Attest issues RS256-signed JWTs to AI agents. Each token carries:
- `att_scope` — list of `"resource:action"` permission strings
- `att_chain` — ordered delegation lineage (list of JTIs)
- `att_depth` — delegation depth (0 = root)
- `att_intent` — SHA-256 hex of the original instruction
- `att_tid` — task tree UUID shared across the chain
- `att_uid` — originating human user ID

## Install

```bash
pip install attest-sdk

# With LangGraph integration
pip install "attest-sdk[langgraph]"
```

## Basic usage

```python
from attest import AttestClient, IssueParams, DelegateParams

client = AttestClient(
    base_url="http://localhost:8080",
    api_key="your-api-key",
)

# Issue a root credential
token = client.issue(IssueParams(
    agent_id="orchestrator-v1",
    user_id="user-42",
    scope=["research:read", "gmail:send"],
    instruction="Draft and send the quarterly report",
    ttl_seconds=3600,
))
print(token.claims.att_tid)    # task tree UUID
print(token.claims.att_scope)  # ["research:read", "gmail:send"]

# Delegate to a child agent (scope must be a subset)
child = client.delegate(DelegateParams(
    parent_token=token.token,
    child_agent="email-agent-v1",
    child_scope=["gmail:send"],
))

# Offline verify — fetch JWKS once, reuse it
jwks = client.fetch_jwks()
result = client.verify(token.token, jwks=jwks)  # no server call needed
if result.valid:
    print("Issuer:", result.claims.iss)
else:
    print("Invalid:", result.warnings)

# Check revocation
is_revoked = client.check_revoked(token.claims.jti)

# Revoke (cascades to all descendants)
client.revoke(token.claims.jti, revoked_by="orchestrator")

# Audit trail for the whole task tree
chain = client.audit(token.claims.att_tid)
for event in chain.events:
    print(event.event_type, event.agent_id, event.created_at)
```

## Async client

```python
import asyncio
from attest import AsyncAttestClient, IssueParams

async def main():
    async with AsyncAttestClient(api_key="your-api-key") as client:
        token = await client.issue(IssueParams(
            agent_id="async-agent",
            user_id="user-1",
            scope=["files:read"],
            instruction="Read the file",
        ))
        jwks = await client.fetch_jwks()
        result = await client.verify(token.token, jwks=jwks)
        print(result.valid)

asyncio.run(main())
```

## LangGraph integration

```python
from typing import TypedDict
from attest import AttestClient
from attest.integrations.langgraph import AttestState, attest_tool, AttestNodes

client = AttestClient(api_key="your-api-key")

# 1. Extend AttestState with your own fields
class MyState(AttestState):
    messages: list
    instruction: str
    user_id: str

# 2. Issue at graph entry — stores JWT in state["attest_tokens"]["orchestrator-v1"]
graph.add_node("issue", AttestNodes.issue(
    client=client,
    agent_id="orchestrator-v1",
    scope=["research:read", "gmail:send"],
    instruction_key="instruction",
    user_id_key="user_id",
))

# 3. Enforce scope at tool call — raises AttestScopeError if not covered
@attest_tool(scope="gmail:send", agent_id="email-agent-v1")
def send_email(state: MyState, to: str, body: str) -> str:
    ...

# 4. Delegate when spawning a sub-agent
graph.add_node("spawn_email_agent", AttestNodes.delegate(
    client=client,
    parent_agent_id="orchestrator-v1",
    child_agent_id="email-agent-v1",
    child_scope=["gmail:send"],
))

# 5. Revoke at graph teardown
graph.add_node("cleanup", AttestNodes.revoke(
    client=client,
    agent_id="orchestrator-v1",
))
```

## Offline verification note

Once you have fetched the JWKS with `client.fetch_jwks()`, you can verify
any token from the same server without making additional network calls:

```python
jwks = client.fetch_jwks()   # one network call

for token_str in incoming_tokens:
    result = client.verify(token_str, jwks=jwks)  # pure local crypto
```

The public key is stable for the lifetime of the server instance; cache it
as long as your process runs.
