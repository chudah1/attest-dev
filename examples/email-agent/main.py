"""Email agent with Attest audit trail.

A single-agent email flow: user gives an instruction, Claude drafts the
email, user confirms, agent sends it. Attest records the full chain of
authority so you can prove later exactly what was authorized.

This mirrors a real pattern: apps like SideQuest where an AI agent sends
email on behalf of a user through Gmail or Outlook. Without Attest, your
only record is a row in Postgres. With Attest, you get a signed credential
tying the action to the human instruction, plus a tamper-evident audit log.

Requirements:
    pip install attest-sdk[anthropic] anthropic

Run:
    export ATTEST_API_KEY=att_live_...
    export ANTHROPIC_API_KEY=sk-ant-...
    python main.py
"""

import json
import os

import anthropic

from attest import AttestClient
from attest.types import IssueParams


def draft_email(claude: anthropic.Anthropic, instruction: str, sender_name: str) -> dict:
    """Use Claude to turn a natural language instruction into an email."""
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
    # Strip markdown fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    return json.loads(text)


def send_email(to: str, subject: str, body: str) -> bool:
    """Send email via Gmail/Outlook API.

    In a real app this calls the Gmail or Microsoft Graph API using the
    user's OAuth token. Here we just print it.
    """
    print(f"\n  Sending email...")
    print(f"  To:      {to}")
    print(f"  Subject: {subject}")
    print(f"  Body:    {body[:120]}...")
    print(f"  Status:  sent")
    return True


def main():
    attest = AttestClient(
        base_url=os.getenv("ATTEST_BASE_URL", "https://api.attestdev.com"),
        api_key=os.getenv("ATTEST_API_KEY", ""),
    )
    claude = anthropic.Anthropic()

    # -- Simulate user request --
    user_id = "usr_alice"
    instruction = "Send an email to john@acme.com thanking him for the meeting yesterday and confirming we'll send the proposal by Friday."

    print(f"User: {instruction}\n")

    # -- Step 1: Issue a credential --
    # This binds the user's instruction to a signed token. The instruction
    # is hashed into the credential (att_intent), so months later you can
    # recompute the hash and prove this action traces back to this request.
    root = attest.issue(IssueParams(
        agent_id="email-agent",
        user_id=user_id,
        scope=["email:send"],
        instruction=instruction,
    ))

    print(f"Credential issued")
    print(f"  Task ID:  {root.claims.att_tid}")
    print(f"  Token ID: {root.claims.jti}")
    print(f"  Scope:    {root.claims.att_scope}")
    print(f"  Intent:   {root.claims.att_intent[:80]}...")

    # -- Step 2: Draft the email with Claude --
    email = draft_email(claude, instruction, sender_name="Alice")
    print(f"\nDraft ready:")
    print(f"  To:      {email['to']}")
    print(f"  Subject: {email['subject']}")
    print(f"  Body:    {email['body'][:120]}...")

    # Report the draft action to the audit log
    attest.report_action(
        token=root.token,
        tool="claude:draft_email",
        outcome="success",
        meta={"to": email["to"], "subject": email["subject"]},
    )

    # -- Step 3: User confirms --
    print(f"\nConfirm send? [yes/no]", end=" ")
    confirmation = input().strip().lower()

    if confirmation != "yes":
        print("Cancelled.")
        attest.report_action(
            token=root.token,
            tool="email:send",
            outcome="cancelled_by_user",
        )
        attest.revoke(root.claims.jti, revoked_by="user")
        return

    # -- Step 4: Send the email --
    sent = send_email(email["to"], email["subject"], email["body"])

    # Report the send to the audit log
    attest.report_action(
        token=root.token,
        tool="email:send",
        outcome="success" if sent else "failed",
        meta={"to": email["to"], "subject": email["subject"]},
    )

    # -- Step 5: Revoke the credential (task is done) --
    attest.revoke(root.claims.jti, revoked_by="email-agent")
    print(f"\nCredential revoked. Task complete.")

    # -- Step 6: Fetch the audit trail --
    # This is the evidence you'd hand to an auditor. Every event is
    # hash-chained, so tampering with one entry breaks the chain.
    audit = attest.audit_log(root.claims.att_tid)
    print(f"\nAudit trail ({len(audit.events)} events):")
    for event in audit.events:
        print(f"  [{event.event_type}] agent={event.agent_id} scope={event.scope}")
        if event.meta:
            print(f"    meta: {event.meta}")

    # -- Step 7: Export evidence packet --
    # A self-contained, verifiable record of everything that happened.
    # Any third party can verify this without access to your backend.
    evidence = attest.fetch_evidence(root.claims.att_tid)
    print(f"\nEvidence packet exported")
    print(f"  Task ID:   {evidence.task_id}")
    print(f"  Events:    {len(evidence.events)}")
    print(f"  Integrity: hash-chained, independently verifiable")

    # Verify the evidence packet
    result = attest.verify_evidence_packet(evidence)
    print(f"  Verified:  {result.valid}")


if __name__ == "__main__":
    main()
