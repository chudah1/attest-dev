# Attest Integration Examples

Working examples showing how to wire Attest credentials into popular agent frameworks.

| Example | Framework | Language | Key Feature |
|---------|-----------|----------|-------------|
| [langgraph/](langgraph/) | LangGraph | Python | Auto-delegation per graph node |
| [openai-agents/](openai-agents/) | OpenAI Agents SDK | Python | Credential delegation on handoffs |
| [anthropic-tool-use/](anthropic-tool-use/) | Anthropic Claude | Python | Session context manager + scope-gated tools |
| [mcp-server/](mcp-server/) | MCP (Model Context Protocol) | TypeScript | Two-line server protection |

## Prerequisites

All examples need an Attest API key:

```bash
export ATTEST_API_KEY=att_live_...
```

Get one at [attestdev.com](https://www.attestdev.com) or run the server locally:

```bash
cd server && go run ./cmd/attest --memory
```

## What each example shows

Every example follows the same pattern:

1. **Issue** a root credential with broad scope
2. **Delegate** narrower credentials to child agents/nodes
3. **Enforce** scope on every tool call
4. **Revoke** the entire tree when done

The credential chain, intent hash, and audit trail are handled automatically by the SDK.
