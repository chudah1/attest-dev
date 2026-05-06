# Refund Workflow Example

This example shows the new Attest Action API in a real support workflow:

- a support agent gets a root credential for a refund task
- the agent requests a **risky action** instead of directly mutating a system
- low-value refunds are auto-approved and receive a short-lived execution grant
- high-value refunds pause in `pending_approval` until a human approves them
- every execution produces an immutable signed receipt

## Why this example matters

It demonstrates the new product surface:

- **Action request** before mutation
- **policy decision** and risk tagging
- **optional human approval**
- **short-lived execution grant**
- **signed execution receipt**

The refund handler is only the first supported action family. The core workflow
is generic and is meant to expand to other risky writes over time.

## Prerequisites

```bash
export ATTEST_API_KEY=att_live_...
```

Optional:

```bash
export ATTEST_BASE_URL=https://api.attestdev.com
```

## Run

```bash
node examples/refund-workflow/main.cjs
```

## What it does

1. Issues a root credential for `support-bot`
2. Requests a low-value refund action and receives an auto-approved grant
3. Executes the low-value refund and records a signed receipt
4. Requests a high-value refund action that waits for dashboard approval
5. Polls the action until it is approved or times out
6. Lists recent action requests for the org

## What to look for

The important part is the decision boundary:

- the agent proposes the mutation first
- Attest decides whether it can run immediately
- approval is attached to the action, not just a chat message
- the receipt proves what happened later

Open the dashboard **Actions** tab while the script is running if you want to
approve the high-value refund manually.
