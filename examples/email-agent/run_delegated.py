"""Delegated email workflow with Attest.

A small multi-agent pipeline:

  Orchestrator [crm:read, email:draft, email:send]
    |
    +-- Researcher [crm:read]
    +-- Drafter    [email:draft]
    +-- Sender     [email:send]

Each child gets a narrower credential than the parent. We also show the
failure mode: a child agent trying to use a tool outside its granted scope
is blocked before the action runs.

Run with real Claude calls:

    export ATTEST_API_KEY=att_live_...
    export ANTHROPIC_API_KEY=sk-ant-...
    python examples/email-agent/run_delegated.py

Run without Anthropic:

    export ATTEST_API_KEY=att_live_...
    python examples/email-agent/run_delegated.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import jwt

from attest import AttestClient
from attest.client import AttestScopeError
from attest.types import DelegateParams, IssueParams

try:
    import anthropic
except ImportError:  # pragma: no cover - optional dependency in dry-run mode
    anthropic = None


ATTEST_BASE_URL = os.getenv("ATTEST_BASE_URL", "https://api.attestdev.com")


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(
            f"Missing {name}. Set it in your environment before running this example."
        )
    return value


def require_scope(token: str, scope: str, tool: str) -> None:
    """Check the JWT has the required scope before executing the tool."""
    claims = jwt.decode(token, options={"verify_signature": False})
    granted = claims.get("att_scope", [])
    if scope not in granted:
        raise AttestScopeError(
            tool=tool,
            required_scope=scope,
            granted_scope=granted,
            jti=claims.get("jti", ""),
        )


def _extract_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return json.loads(cleaned)


def make_claude_client(dry_run: bool):
    if dry_run:
        return None
    if anthropic is None:
        raise SystemExit(
            "The anthropic package is not installed. Install it or rerun with --dry-run."
        )
    return anthropic.Anthropic(api_key=require_env("ANTHROPIC_API_KEY"))


def research_contact(
    claude, token: str, recipient: str, *, dry_run: bool
) -> dict[str, Any]:
    """Researcher agent. Scope required: crm:read."""
    require_scope(token, "crm:read", "crm:lookup")

    if dry_run:
        return {
            "name": "John Carter",
            "company": "Acme Corp",
            "role": "VP Partnerships",
            "last_meeting_topic": "Proposal rollout timeline",
            "relationship_notes": "Warm relationship after last week's meeting.",
        }

    response = claude.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=500,
        temperature=0.2,
        messages=[{"role": "user", "content": (
            f"You are a CRM system. Return a JSON object with context about "
            f"the contact {recipient}. Include: name, company, role, "
            f"last_meeting_topic, relationship_notes. "
            f"Make it realistic. Return only JSON."
        )}],
    )
    return _extract_json(response.content[0].text)


def draft_email(
    claude,
    token: str,
    instruction: str,
    context: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, str]:
    """Drafter agent. Scope required: email:draft."""
    require_scope(token, "email:draft", "claude:draft")

    if dry_run:
        return {
            "to": "john@acme.com",
            "subject": "Great meeting yesterday",
            "body": (
                "Hi John,\n\n"
                "Thanks again for the meeting yesterday. It was great to talk "
                "through the proposal rollout timeline.\n\n"
                "As discussed, we'll send the proposal by Friday.\n\n"
                "Best,\nAlice"
            ),
        }

    response = claude.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        temperature=0.1,
        messages=[{"role": "user", "content": (
            f"Write an email based on this instruction:\n{instruction}\n\n"
            f"Use this CRM context to personalize it:\n{json.dumps(context, indent=2)}\n\n"
            f"Return ONLY a JSON object with: to, subject, body. "
            f"Sign as Alice. No markdown, just JSON."
        )}],
    )
    return _extract_json(response.content[0].text)


def send_via_gmail(token: str, to: str, subject: str, body: str) -> bool:
    """Sender agent. Scope required: email:send."""
    require_scope(token, "email:send", "gmail:send")

    print(f"   To:      {to}")
    print(f"   Subject: {subject}")
    print("   Body:")
    for line in body.split("\n"):
        print(f"            {line}")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a delegated Attest email workflow example."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use built-in CRM/email fixtures instead of making Anthropic calls.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    attest = AttestClient(
        base_url=ATTEST_BASE_URL,
        api_key=require_env("ATTEST_API_KEY"),
    )
    claude = make_claude_client(args.dry_run)

    instruction = (
        "Send an email to john@acme.com thanking him for the meeting "
        "yesterday and confirming we'll send the proposal by Friday."
    )
    print(f"User: {instruction}\n")
    if args.dry_run:
        print("Dry run: using built-in CRM/email fixtures instead of Anthropic.\n")

    root = attest.issue(IssueParams(
        agent_id="orchestrator",
        user_id="usr_alice",
        scope=["crm:read", "email:draft", "email:send"],
        instruction=instruction,
    ))
    print("1. Orchestrator credential")
    print(f"   Task:  {root.claims.att_tid}")
    print(f"   Scope: {root.claims.att_scope}")

    researcher_cred = attest.delegate(DelegateParams(
        parent_token=root.token,
        child_agent="researcher",
        child_scope=["crm:read"],
    ))
    print("\n2. Researcher delegated [crm:read]")
    print("   Looking up john@acme.com in CRM...")
    contact = research_contact(
        claude,
        researcher_cred.token,
        "john@acme.com",
        dry_run=args.dry_run,
    )
    print(f"   Found: {contact.get('name', 'unknown')} at {contact.get('company', 'unknown')}")
    print(f"   Role:  {contact.get('role', 'unknown')}")

    attest.report_action(
        token=researcher_cred.token,
        tool="crm:lookup",
        outcome="success",
        meta={"contact": "john@acme.com"},
    )

    drafter_cred = attest.delegate(DelegateParams(
        parent_token=root.token,
        child_agent="drafter",
        child_scope=["email:draft"],
    ))
    print("\n3. Drafter delegated [email:draft]")
    print("   Drafting with CRM context...")
    email = draft_email(
        claude,
        drafter_cred.token,
        instruction,
        contact,
        dry_run=args.dry_run,
    )
    print(f"   Subject: \"{email['subject']}\"")

    attest.report_action(
        token=drafter_cred.token,
        tool="claude:draft",
        outcome="success",
        meta={"to": email["to"], "subject": email["subject"]},
    )

    sender_cred = attest.delegate(DelegateParams(
        parent_token=root.token,
        child_agent="sender",
        child_scope=["email:send"],
    ))
    print("\n4. Sender delegated [email:send]")
    print("   Sending...")
    sent = send_via_gmail(
        sender_cred.token,
        email["to"],
        email["subject"],
        email["body"],
    )

    attest.report_action(
        token=sender_cred.token,
        tool="gmail:send",
        outcome="success" if sent else "failed",
        meta={"to": email["to"], "subject": email["subject"]},
    )

    print("\n5. What happens when the researcher tries to send email?")
    try:
        send_via_gmail(researcher_cred.token, "attacker@evil.com", "pwned", "haha")
        print("   BAD: email sent (should not happen)")
    except AttestScopeError as error:
        print(f"   BLOCKED: {error.tool} requires [{error.required_scope}]")
        print(f"   Researcher only has {error.granted_scope}")
        attest.report_action(
            token=researcher_cred.token,
            tool="gmail:send",
            outcome="skipped",
            meta={"reason": f"missing scope: {error.required_scope}"},
        )

    print("\n6. What happens when the drafter tries to read CRM?")
    try:
        research_contact(
            claude,
            drafter_cred.token,
            "secret@competitor.com",
            dry_run=args.dry_run,
        )
        print("   BAD: CRM read succeeded (should not happen)")
    except AttestScopeError as error:
        print(f"   BLOCKED: {error.tool} requires [{error.required_scope}]")
        print(f"   Drafter only has {error.granted_scope}")
        attest.report_action(
            token=drafter_cred.token,
            tool="crm:lookup",
            outcome="skipped",
            meta={"reason": f"missing scope: {error.required_scope}"},
        )

    print("\n7. Revoking orchestrator...")
    attest.revoke(root.claims.jti, revoked_by="orchestrator")

    for name, cred_obj in [
        ("orchestrator", root),
        ("researcher", researcher_cred),
        ("drafter", drafter_cred),
        ("sender", sender_cred),
    ]:
        revoked = attest.is_revoked(cred_obj.claims.jti)
        print(f"   {name:14s} {'REVOKED' if revoked else 'still live?!'}")

    audit = attest.audit_log(root.claims.att_tid)
    print(f"\n8. Audit trail ({len(audit.events)} events):")
    for index, event in enumerate(audit.events, start=1):
        meta_str = ""
        if event.meta:
            parts = []
            if "contact" in event.meta:
                parts.append(event.meta["contact"])
            if "to" in event.meta:
                parts.append(f"to={event.meta['to']}")
            if "reason" in event.meta:
                parts.append(event.meta["reason"])
            if "revoked_by" in event.meta:
                parts.append(f"by={event.meta['revoked_by']}")
            meta_str = f"  ({', '.join(parts)})" if parts else ""
        print(f"   {index}. [{event.event_type:10s}] {event.agent_id}{meta_str}")

    evidence = attest.fetch_evidence(root.claims.att_tid)
    result = attest.verify_evidence_packet(evidence)
    print(
        f"\n9. Evidence packet: {len(evidence.events)} events, "
        f"{len(evidence.credentials)} credentials, valid={result.valid}"
    )


if __name__ == "__main__":
    main()
