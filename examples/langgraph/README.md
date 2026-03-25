# LangGraph + Attest

Research-and-email pipeline where each graph node gets a delegated credential with narrowed scope.

```
orchestrator (depth:0) → [research:read, gmail:send]
  ├── researcher (depth:1) → [research:read]
  └── emailer    (depth:1) → [gmail:send]
```

## Setup

```bash
pip install attest-sdk[langgraph] langgraph langchain-core
export ATTEST_API_KEY=att_live_...
```

## Run

```bash
python main.py
```

## What it demonstrates

- **`AttestStateGraph`** — drop-in `StateGraph` replacement that auto-delegates credentials to each node
- **`AttestNodes.issue()`** — issues root credential at graph entry
- **`AttestNodes.revoke()`** — cascade-revokes the entire tree at cleanup
- **`@attest_tool`** — scope enforcement decorator on individual tool functions
