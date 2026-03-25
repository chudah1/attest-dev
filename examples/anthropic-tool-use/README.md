# Anthropic Claude + Attest

Claude tool-use loop with scope-enforced credentials and automatic cleanup.

## Setup

```bash
pip install attest-sdk[anthropic] anthropic
export ATTEST_API_KEY=att_live_...
export ANTHROPIC_API_KEY=sk-ant-...
```

## Run

```bash
python main.py
```

## What it demonstrates

- **`AttestSession`** — context manager that issues a root credential on entry, revokes on exit
- **`@attest_tool_anthropic`** — scope enforcement decorator (uses ambient ContextVar)
- **`system_prompt` checksumming** — computes `att_ack` from the prompt + tools config for prompt integrity detection
- **`report_action()`** — logs each tool call to the tamper-evident audit trail
- **Manual delegation** — `session.delegate()` for spawning sub-agents
