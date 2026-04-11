"""Email agent with delegation: orchestrator + drafting agent + sending agent.

Same email task, but now the orchestrator delegates to specialized sub-agents.
This is where Attest becomes essential: the drafting agent should only read
context, the sending agent should only send email. If either gets compromised,
it can't exceed its scope, and revoking the root kills both.

Requirements:
    pip install attest-sdk[anthropic] anthropic

Run:
    export ATTEST_API_KEY=att_live_...
    export ANTHROPIC_API_KEY=sk-ant-...
    python main_delegated.py
"""

import json
import os

import anthropic

from attest import AttestClient
from attest.types import DelegateParams, IssueParams


def draft_email(
    claude: anthropic.Anthropic,
    instruction: str,
    sender_name: str,
    attest: AttestClient,
    token: str,
) -> dict:
    """Drafting agent: can read context, cannot send email."""
    response = claude.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        temperature=0.1,
        messages=[{"role": "user", "content": instruction}],
        system=(
            "You are an email drafting assistant. Given an instruction, "
            "return a JSON object with: to, subject, body. "
            f"Sign emails as {sender_name}. Return only valid JSON."
        ),
    )
    text = response.content[0].text
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]

    email = json.loads(text)

    attest.report_action(
        token=token,
        tool="claude:draft_email",
        outcome="success",
        meta={"to": email["to"], "subject": email["subject"]},
    )
    return email


def send_email(
    to: str,
    subject: str,
    body: str,
    attest: AttestClient,
    token: str,
) -> bool:
    """Sending agent: can send email, cannot read CRM or files."""
    # In production: call Gmail API or Microsoft Graph here
    print(f"\n  Sending email...")
    print(f"  To:      {to}")
    print(f"  Subject: {subject}")
    print(f"  Body:    {body[:120]}...")

    sent = True
    attest.report_action(
        token=token,
        tool="email:send",
        outcome="success" if sent else "failed",
        meta={"to": to, "subject": subject},
    )
    print(f"  Status:  sent")
    return sent


def main():
    attest = AttestClient(
        base_url=os.getenv("ATTEST_BASE_URL", "https://api.attestdev.com"),
        api_key=os.getenv("ATTEST_API_KEY", ""),
    )
    claude = anthropic.Anthropic()

    user_id = "usr_alice"
    instruction = "Send an email to john@acme.com thanking him for the meeting yesterday and confirming we'll send the proposal by Friday."

    print(f"User: {instruction}\n")

    # -- Root credential for the orchestrator --
    # Has both read and send scope because it coordinates the full task.
    root = attest.issue(IssueParams(
        agent_id="orchestrator",
        user_id=user_id,
        scope=["context:read", "email:send"],
        instruction=instruction,
    ))
    print(f"Root credential issued to orchestrator")
    print(f"  Scope: {root.claims.att_scope}")

    # -- Delegate to the drafting agent --
    # Gets context:read only. Even if this agent is compromised, it
    # cannot send email. The scope is enforced by Attest, not by trust.
    drafter = attest.delegate(DelegateParams(
        parent_token=root.token,
        child_agent="drafter",
        child_scope=["context:read"],
    ))
    print(f"\nDelegated to drafter")
    print(f"  Scope: {drafter.claims.att_scope}")
    print(f"  Depth: {drafter.claims.att_depth}")

    # Drafter does its job
    email = draft_email(claude, instruction, "Alice", attest, drafter.token)
    print(f"\nDraft ready: {email['subject']}")

    # -- User confirms --
    print(f"\nConfirm send? [yes/no]", end=" ")
    if input().strip().lower() != "yes":
        print("Cancelled. Revoking all credentials.")
        attest.revoke(root.claims.jti, revoked_by="user")
        return

    # -- Delegate to the sending agent --
    # Gets email:send only. Cannot read files, CRM, or anything else.
    sender = attest.delegate(DelegateParams(
        parent_token=root.token,
        child_agent="sender",
        child_scope=["email:send"],
    ))
    print(f"\nDelegated to sender")
    print(f"  Scope: {sender.claims.att_scope}")
    print(f"  Depth: {sender.claims.att_depth}")

    # Sender does its job
    send_email(email["to"], email["subject"], email["body"], attest, sender.token)

    # -- Revoke the root (kills drafter + sender credentials too) --
    attest.revoke(root.claims.jti, revoked_by="orchestrator")
    print(f"\nRoot revoked. Drafter and sender credentials are now invalid.")

    # -- Verify the drafter's credential is actually dead --
    drafter_check = attest.verify(drafter.token)
    sender_check = attest.verify(sender.token)
    print(f"  Drafter valid: {drafter_check.valid}")
    print(f"  Sender valid:  {sender_check.valid}")

    # -- Full audit trail --
    audit = attest.audit_log(root.claims.att_tid)
    print(f"\nAudit trail ({len(audit.events)} events):")
    for event in audit.events:
        meta_str = f" {event.meta}" if event.meta else ""
        print(f"  [{event.event_type}] {event.agent_id}{meta_str}")

    # -- Evidence packet --
    evidence = attest.fetch_evidence(root.claims.att_tid)
    result = attest.verify_evidence_packet(evidence)
    print(f"\nEvidence packet: {len(evidence.events)} events, valid={result.valid}")


if __name__ == "__main__":
    main()
