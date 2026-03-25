"""OpenAI Agents SDK + Attest: Multi-agent triage with automatic delegation.

When the triage agent hands off to the billing or email agent, AttestRunHooks
automatically issues a delegated credential with narrowed scope. Tools on each
agent are scope-gated — the billing agent can't send email and the email agent
can't read invoices.

Requirements:
    pip install attest-sdk openai-agents

Run:
    export ATTEST_API_KEY=att_live_...
    export OPENAI_API_KEY=sk-...
    python main.py
"""

import asyncio
import os
from dataclasses import dataclass

from agents import Agent, Runner, RunContextWrapper, function_tool

from attest import AttestClient
from attest.integrations.openai_agents import (
    AttestContext,
    AttestRunHooks,
    attest_tool_openai,
)
from attest.types import IssueParams


# -- Context -----------------------------------------------------------------

@dataclass
class AppContext(AttestContext):
    user_id: str = ""


# -- Tools (scope-enforced) --------------------------------------------------

@function_tool
@attest_tool_openai(scope="billing:read", agent_name="billing-agent")
async def lookup_invoice(ctx: RunContextWrapper[AppContext], invoice_id: str) -> str:
    """Look up an invoice by ID."""
    return f"Invoice {invoice_id}: $149.99, paid 2026-03-01"


@function_tool
@attest_tool_openai(scope="gmail:send", agent_name="email-agent")
async def send_receipt(ctx: RunContextWrapper[AppContext], to: str, invoice_id: str) -> str:
    """Email a receipt to the customer."""
    return f"Receipt for {invoice_id} sent to {to}"


# -- Agents ------------------------------------------------------------------

billing_agent = Agent(
    name="billing-agent",
    instructions="You help with billing questions. Use lookup_invoice to find invoice details.",
    tools=[lookup_invoice],
)

email_agent = Agent(
    name="email-agent",
    instructions="You send emails. Use send_receipt to email receipts.",
    tools=[send_receipt],
)

triage_agent = Agent(
    name="triage-agent",
    instructions=(
        "You triage customer requests. "
        "Hand off billing questions to billing-agent. "
        "Hand off email requests to email-agent."
    ),
    handoffs=[billing_agent, email_agent],
)


# -- Run ---------------------------------------------------------------------

async def main():
    client = AttestClient(
        base_url=os.getenv("ATTEST_BASE_URL", "https://api.attestdev.com"),
        api_key=os.getenv("ATTEST_API_KEY", ""),
    )

    # Issue root credential for the triage agent
    root = client.issue(IssueParams(
        agent_id="triage-agent",
        user_id="usr_alice",
        scope=["billing:read", "gmail:send"],
        instruction="Help customer with billing question and send receipt",
    ))

    ctx = AppContext(
        user_id="usr_alice",
        attest_root_token=root.token,
        attest_tokens={"triage-agent": root.token},
        attest_task_id=root.claims.att_tid,
    )

    hooks = AttestRunHooks(
        client=client,
        scope_map={
            "billing-agent": ["billing:read"],
            "email-agent": ["gmail:send"],
        },
    )

    print(f"Task ID: {root.claims.att_tid}")
    print(f"Root scope: {root.claims.att_scope}")
    print()

    result = await Runner.run(
        triage_agent,
        input="Can you look up invoice INV-42 and email the receipt to alice@example.com?",
        context=ctx,
        hooks=hooks,
    )

    print(f"Final output: {result.final_output}")

    # Revoke the entire credential tree
    client.revoke(root.claims.jti)
    print("Credential tree revoked.")


if __name__ == "__main__":
    asyncio.run(main())
