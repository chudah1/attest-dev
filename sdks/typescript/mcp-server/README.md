# @attest-dev/mcp-server

Operate Attest from any MCP client.

This server exposes Attest control-plane and evidence tools over MCP so an
agent host like Claude Desktop, Cursor, or Windsurf can:

- issue scoped credentials for a task
- delegate narrower credentials to sub-agents
- request, approve, or deny human approvals
- revoke a credential chain
- inspect recent tasks, audit trails, and evidence packets

## Install

Run it from npm:

```bash
npx -y @attest-dev/mcp-server
```

Required environment variables:

- `ATTEST_API_KEY`: Attest org API key
- `ATTEST_BASE_URL`: optional, defaults to `https://api.attestdev.com`

Example MCP config:

```json
{
  "mcpServers": {
    "attest": {
      "command": "npx",
      "args": ["-y", "@attest-dev/mcp-server"],
      "env": {
        "ATTEST_API_KEY": "attest_live_xxx",
        "ATTEST_BASE_URL": "https://api.attestdev.com"
      }
    }
  }
}
```

## What this is for

Use this server when your agents do more than answer questions.

Once an agent can send email, touch CRM, update tickets, call internal APIs, or
hand work to other agents, you usually need more than an API key and a log
line. You need to know:

- who authorized the task
- what each agent was allowed to do
- whether a child agent was narrowed properly
- what happened when something was blocked
- how to revoke the whole chain if something goes wrong

Attest gives you that control and evidence layer. This MCP server makes those
operations available inside MCP-native workflows.

## Practical use case

Imagine a support operations assistant handling a refund request.

The top-level orchestrator receives a request like:

> Refund the customer, update the billing system, and send a confirmation email.

Without Attest, the orchestrator often runs with broad access and child agents
inherit too much of it. If the orchestrator is compromised, every downstream
agent can keep acting with no clean chain of authority.

With Attest, the workflow looks like this:

1. The orchestrator calls `issue_credential` for the root task with scopes like
   `billing:write` and `email:send`.
2. It delegates a narrower credential to a billing sub-agent using
   `delegate_credential` with only `billing:write`.
3. It delegates a separate credential to a notification agent with only
   `email:send`.
4. If the billing step is high-risk, it can call `request_approval` and wait for
   a human to `grant_approval` before the refund goes through.
5. Each agent reports what it did using `report_action` or `report_status`.
6. Later, an operator can use `list_tasks`, `get_audit_trail`, and
   `get_evidence` to reconstruct exactly what happened.
7. If the parent task needs to be shut down, `revoke_credential` cascades the
   revoke through the whole task tree.

That is the practical shape of Attest:

- scoped authority at every step
- narrower delegation across handoffs
- explicit approval for risky actions
- recoverable audit history
- evidence you can verify later

## Core tools

Credentials:

- `issue_credential`
- `delegate_credential`
- `revoke_credential`
- `verify_credential`
- `check_revocation`

Tasks and evidence:

- `list_tasks`
- `get_audit_trail`
- `get_evidence`

Audit reporting:

- `report_action`
- `report_status`

Approvals:

- `request_approval`
- `get_approval`
- `grant_approval`
- `deny_approval`

## Example flow

Issue a root credential:

```json
{
  "agent_id": "support-orchestrator",
  "user_id": "usr_123",
  "scope": ["billing:write", "email:send"],
  "instruction": "Refund the customer, update billing, and send confirmation."
}
```

Delegate to a billing sub-agent:

```json
{
  "parent_token": "<root jwt>",
  "child_agent": "billing-agent",
  "child_scope": ["billing:write"]
}
```

List recent active tasks for a user:

```json
{
  "user_id": "usr_123",
  "status": "active",
  "limit": 10
}
```

Fetch evidence for a finished task:

```json
{
  "task_id": "tid_abc123"
}
```

## Development

From this package directory:

```bash
npm install
npm run typecheck
npm run build
```

Run locally:

```bash
ATTEST_API_KEY=attest_live_xxx npm exec -- attest-mcp-server
```

## Related packages

- [TypeScript SDK](/Users/cyakung/Projects/warrant/sdks/typescript/README.md)
- [MCP middleware for protecting your own MCP server](/Users/cyakung/Projects/warrant/sdks/typescript/mcp/README.md)
