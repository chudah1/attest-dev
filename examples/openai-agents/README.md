# OpenAI Agents SDK + Attest

Multi-agent triage system where handoffs automatically issue delegated credentials.

```
triage-agent (depth:0) → [billing:read, gmail:send]
  ├── billing-agent (depth:1) → [billing:read]
  └── email-agent   (depth:1) → [gmail:send]
```

## Setup

```bash
pip install attest-sdk openai-agents
export ATTEST_API_KEY=att_live_...
export OPENAI_API_KEY=sk-...
```

## Run

```bash
python main.py
```

## What it demonstrates

- **`AttestRunHooks`** — intercepts `on_handoff` to auto-delegate credentials when agents hand off
- **`AttestContext`** — dataclass mixin that carries credentials through the run
- **`@attest_tool_openai`** — scope enforcement on individual tool functions
- **`scope_map`** — explicit scope assignment per agent
