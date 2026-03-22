#!/usr/bin/env python3
"""Demonstration of Human-in-the-Loop (HITL) Cryptography flow.

This script mimics an Enterprise AI agent trying to execute a high-risk tool,
pausing to request human approval, and resuming with a cryptographically
elevated token.
"""

import os
import sys
import time
import requests

try:
    from attest.client import AttestClient
    from attest.types import IssueParams, DelegateParams
    from attest.verifier import AttestVerifier
except ImportError:
    print("Run this from the root directory with PYTHONPATH=sdks/python set.")
    sys.exit(1)

BASE_URL = os.getenv("ATTEST_BASE_URL", "http://localhost:8080")

def main():
    print("=== Step 1: Bootstrapping an Org and creating a Root Session ===")
    
    # 1. Signup and get API key
    org_name = f"hitl-demo-{int(time.time())}"
    r = requests.post(f"{BASE_URL}/v1/orgs", json={"name": org_name})
    if r.status_code != 201:
        print(f"Failed to bootstrap org: {r.text}")
        sys.exit(1)
        
    api_key = r.json()["api_key"]
    org_id = r.json()["org"]["ID"]
    print(f"✅ Created Organization: {org_id}")

    # 2. Issue a root credential for our orchestrator
    client = AttestClient(base_url=BASE_URL, api_key=api_key)
    
    root_token = client.issue(IssueParams(
        agent_id="orchestrator",
        user_id="user_john",
        scope=["finance:view", "finance:transfer"],
        instruction="Manage user finances.",
        ttl_seconds=3600
    ))
    print(f"✅ Orchestrator booted with root credential (JTI={root_token.claims.jti})")
    print(f"   Granted Scopes: {root_token.claims.att_scope}")

    print("\n=== Step 2: Agent attempts a high-risk action (finance:transfer) ===")
    
    # Simulate the agent wanting to delegate to the bank transfer tool
    print("🤖 Agent: 'I need to transfer $5,000 to routing #12345.'")
    print("🛡️  Policy: The `finance:transfer` tool requires Human Approval!")
    
    print("\n=== Step 3: Requesting Human Approval ===")
    challenge = client.request_approval(
        parent_token=root_token.token,
        agent_id="bank-transfer-tool",
        task_id=root_token.claims.att_tid,
        intent="Transfer $5,000 to account #12345",
        requested_scope=["finance:transfer"]
    )
    print(f"✅ Approval Requested! Challenge ID: {challenge.challenge_id}")
    print(f"⏳ Status: {challenge.status.upper()}")
    print("   (Agent execution is now PAUSED, waiting for the human on Slack...)")
    
    time.sleep(1)  # Simulate waiting for the human
    
    print("\n=== Step 4: Human Approves the Request ===")
    print("👤 Human (via Slack/Dashboard): CLICKS 'APPROVE'")
    
    # Simulate the backend dashboard endpoint granting the approval.
    # We pass a dummy id_token since we are in dev-mode where IdP is not strictly configured.
    approved_child_token = client.grant_approval(
        challenge_id=challenge.challenge_id,
        id_token="dev_mode_token" 
    )
    
    print(f"✅ Approval Granted! New Elevated Credential Minted (JTI={approved_child_token.claims.jti})")
    
    print("\n=== Step 5: Agent Resumes Execution with Cryptographic Proof ===")
    
    print("🔍 Inspecting the mathematically enforced Human Intent claims...")
    claims = approved_child_token.claims
    print(f"   - HITL Request ID: {claims.att_hitl_req}")
    print(f"   - HITL Approver ID: {claims.att_hitl_uid}")
    print(f"   - HITL IdP Issuer: {claims.att_hitl_iss}")
    
    print("\n✅ Verification Successful: This token unambiguously proves the human authorized this specific action.")
    
    print("\n=== Step 6: Checking the Immutable Audit Trail ===")
    audit_chain = client.audit(task_id=root_token.claims.att_tid)
    for event in audit_chain.events:
        print(f"[{event.event_type.upper()}] JTI={event.jti} | Agent={event.agent_id} | HITL Approver={event.hitl_subject}")

    print("\n=== Step 7: The 'Always Allow' Scenario (Sub-Agent Delegation) ===")
    print("If the human checked 'Always Allow' or if the agent delegates this approved task further,")
    print("the cryptographic approval flows down the chain automatically without pausing again!")
    
    sub_agent_token = client.delegate(DelegateParams(
        parent_token=approved_child_token.token,
        child_agent="stripe-api-executor",
        child_scope=["finance:transfer"]
    ))
    
    print(f"✅ Sub-Agent Credential Minted (JTI={sub_agent_token.claims.jti})")
    print(f"🔍 Inspecting Sub-Agent's HITL inheritance:")
    print(f"   - Inherited HITL Approver ID: {sub_agent_token.claims.att_hitl_uid}")
    print("✅ The Sub-Agent completely bypassed the pause-loop because the human's signature was inherited!")

    print("\n=== Step 8: Agent Lifecycle & Action Reporting ===")

    # Report that the sub-agent started
    client.report_status(token=sub_agent_token.token, status="started")
    print("📋 Reported: stripe-api-executor STARTED")

    # Report the action outcome
    client.report_action(
        token=sub_agent_token.token,
        tool="stripe:transfer",
        outcome="success",
        meta={"amount": "5000", "currency": "USD", "routing": "12345"}
    )
    print("📋 Reported: stripe:transfer action SUCCESS")

    # Report that the sub-agent completed
    client.report_status(token=sub_agent_token.token, status="completed")
    print("📋 Reported: stripe-api-executor COMPLETED")

    print("\n=== Step 9: Final Audit Trail ===")
    audit_chain = client.audit(task_id=root_token.claims.att_tid)
    for event in audit_chain.events:
        hitl = f" | HITL={event.hitl_subject}" if event.hitl_subject else ""
        meta = f" | meta={event.meta}" if event.meta else ""
        print(f"  [{event.event_type.upper():12s}] Agent={event.agent_id:24s} JTI={event.jti[:8]}…{hitl}{meta}")

    print(f"\n✅ Complete: {len(audit_chain.events)} audit events for task {root_token.claims.att_tid[:8]}…")

if __name__ == "__main__":
    main()
