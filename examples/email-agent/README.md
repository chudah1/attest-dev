# Email Agent Examples

This folder contains a few email-oriented Attest examples, from simple to more realistic.

## Recommended first example

`run_delegated.py` is the best Attest-focused example in this folder.

It shows:

- root credential issuance for the orchestrator
- delegation to narrower child agents
- scope checks before tool execution
- audit events for allowed and blocked actions
- cascade revocation from the root
- evidence export and verification

### Run with built-in fixtures

This mode does not call Anthropic. It still talks to the Attest API and exercises the full credential, audit, revoke, and evidence flow.

```bash
export ATTEST_API_KEY=att_live_...
python examples/email-agent/run_delegated.py --dry-run
```

### Run with real Claude calls

```bash
export ATTEST_API_KEY=att_live_...
export ANTHROPIC_API_KEY=sk-ant-...
python examples/email-agent/run_delegated.py
```

### Dependencies

Install the Python SDK first, then optionally Anthropic if you want live model calls:

```bash
cd sdks/python
python3 -m pip install -e .
python3 -m pip install anthropic PyJWT
```

## Other scripts

- `main.py` shows a simpler single-agent email flow
- `main_delegated.py` shows a lighter delegated version
- `run_demo.py` is a shorter demo-oriented script
