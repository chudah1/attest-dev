"""Email agent demo: runs end to end against live Attest API + Claude.

A user tells an agent to send an email. The agent:
  1. Gets a credential scoped to email:send
  2. Calls Claude to draft the email
  3. Sends it (simulated Gmail API call)
  4. Everything is recorded in a tamper-evident audit log
  5. Credential is revoked when the task is done
  6. Evidence packet can be verified by any third party
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdks", "python"))

import anthropic

from attest import AttestClient
from attest.types import IssueParams


ATTEST_API_KEY = os.getenv("ATTEST_API_KEY", "")
ATTEST_BASE_URL = os.getenv("ATTEST_BASE_URL", "https://api.attestdev.com")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ORG_ID = os.getenv("ATTEST_ORG_ID", "")


def draft_email(claude: anthropic.Anthropic, instruction: str) -> dict:
    """Call Claude to turn a natural language instruction into an email."""
    response = claude.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        temperature=0.1,
        messages=[{"role": "user", "content": instruction}],
        system=(
            "You are an email drafting assistant. Given an instruction, "
            "return ONLY a JSON object with these fields: to, subject, body. "
            "Sign the email as Alice. No markdown, no explanation, just JSON."
        ),
    )
    text = response.content[0].text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return json.loads(text)


def send_via_gmail(to: str, subject: str, body: str) -> bool:
    """In production: Gmail API or Microsoft Graph with the user's OAuth token."""
    print(f"   To:      {to}")
    print(f"   Subject: {subject}")
    print(f"   Body:")
    for line in body.split("\n"):
        print(f"            {line}")
    return True


def main():
    attest = AttestClient(base_url=ATTEST_BASE_URL, api_key=ATTEST_API_KEY)
    claude = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    instruction = (
        "Send an email to john@acme.com thanking him for the meeting "
        "yesterday and confirming we'll send the proposal by Friday."
    )
    print(f"User: {instruction}\n")

    # ── 1. Issue credential ───────────────────────────────────────────────
    # Ties this agent's actions to the human instruction.
    cred = attest.issue(IssueParams(
        agent_id="email-agent",
        user_id="usr_alice",
        scope=["email:send"],
        instruction=instruction,
    ))
    print(f"1. Credential issued")
    print(f"   Task:  {cred.claims.att_tid}")
    print(f"   JTI:   {cred.claims.jti}")
    print(f"   Scope: {cred.claims.att_scope}")

    # ── 2. Claude drafts the email ────────────────────────────────────────
    print(f"\n2. Calling Claude...")
    email = draft_email(claude, instruction)
    print(f"   Draft: \"{email['subject']}\"")

    attest.report_action(
        token=cred.token,
        tool="claude:draft",
        outcome="success",
        meta={"to": email["to"], "subject": email["subject"]},
    )

    # ── 3. Send the email ─────────────────────────────────────────────────
    print(f"\n3. Sending email")
    sent = send_via_gmail(email["to"], email["subject"], email["body"])

    attest.report_action(
        token=cred.token,
        tool="gmail:send",
        outcome="success" if sent else "failed",
        meta={"to": email["to"], "subject": email["subject"]},
    )

    # ── 4. Revoke credential (task done) ──────────────────────────────────
    attest.revoke(cred.claims.jti, revoked_by="email-agent")
    print(f"\n4. Credential revoked")
    print(f"   Revoked: {attest.is_revoked(cred.claims.jti)}")

    # ── 5. Audit trail ───────────────────────────────────────────────────
    audit = attest.audit_log(cred.claims.att_tid)
    print(f"\n5. Audit trail ({len(audit.events)} events):")
    for i, event in enumerate(audit.events):
        meta_str = ""
        if event.meta:
            meta_str = f"  {event.meta}"
        print(f"   {i+1}. [{event.event_type}] agent={event.agent_id}{meta_str}")

    # ── 6. Evidence packet ───────────────────────────────────────────────
    evidence = attest.fetch_evidence(cred.claims.att_tid)
    result = attest.verify_evidence_packet(evidence, org_id=ORG_ID)
    print(f"\n6. Evidence packet")
    print(f"   Events: {len(evidence.events)}")
    print(f"   Valid:  {result.valid}")
    print(f"   Hash:   {result.hash_valid}")
    print(f"   Sig:    {result.signature_valid}")
    print(f"   Chain:  {result.audit_chain_valid}")


if __name__ == "__main__":
    main()
