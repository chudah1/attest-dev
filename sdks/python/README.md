# warrant-sdk

Python SDK for the [Warrant](https://github.com/warrant-dev/warrant) cryptographic agent credential service.

Warrant issues RS256-signed JWTs to AI agents. Each token carries:
- `wrt_scope` — list of `"resource:action"` permission strings
- `wrt_chain` — ordered delegation lineage (list of JTIs)
- `wrt_depth` — delegation depth (0 = root)
- `wrt_intent` — SHA-256 hex of the original instruction
- `wrt_tid` — task tree UUID shared across the chain
- `wrt_uid` — originating human user ID

## Install

```bash
pip install warrant-sdk

# With LangGraph integration
pip install "warrant-sdk[langgraph]"
```

## Basic usage

```python
from warrant import WarrantClient, IssueParams, DelegateParams

client = WarrantClient(
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
print(token.claims.wrt_tid)    # task tree UUID
print(token.claims.wrt_scope)  # ["research:read", "gmail:send"]

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
chain = client.audit(token.claims.wrt_tid)
for event in chain.events:
    print(event.event_type, event.agent_id, event.created_at)
```

## Async client

```python
import asyncio
from warrant import AsyncWarrantClient, IssueParams

async def main():
    async with AsyncWarrantClient(api_key="your-api-key") as client:
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
from warrant import WarrantClient
from warrant.integrations.langgraph import WarrantState, warrant_tool, WarrantNodes

client = WarrantClient(api_key="your-api-key")

# 1. Extend WarrantState with your own fields
class MyState(WarrantState):
    messages: list
    instruction: str
    user_id: str

# 2. Issue at graph entry — stores JWT in state["warrant_tokens"]["orchestrator-v1"]
graph.add_node("issue", WarrantNodes.issue(
    client=client,
    agent_id="orchestrator-v1",
    scope=["research:read", "gmail:send"],
    instruction_key="instruction",
    user_id_key="user_id",
))

# 3. Enforce scope at tool call — raises WarrantScopeError if not covered
@warrant_tool(scope="gmail:send", agent_id="email-agent-v1")
def send_email(state: MyState, to: str, body: str) -> str:
    ...

# 4. Delegate when spawning a sub-agent
graph.add_node("spawn_email_agent", WarrantNodes.delegate(
    client=client,
    parent_agent_id="orchestrator-v1",
    child_agent_id="email-agent-v1",
    child_scope=["gmail:send"],
))

# 5. Revoke at graph teardown
graph.add_node("cleanup", WarrantNodes.revoke(
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
