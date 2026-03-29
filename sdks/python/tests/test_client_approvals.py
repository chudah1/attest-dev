from __future__ import annotations

import httpx
import pytest
import respx

from attest import AsyncAttestClient, AttestClient
from attest.client import AttestApprovalDenied, AttestApprovalTimeout

BASE_URL = "http://localhost:8080"


def _sync_client() -> AttestClient:
    return AttestClient(base_url=BASE_URL, api_key="test-key")


def _async_client() -> AsyncAttestClient:
    return AsyncAttestClient(base_url=BASE_URL, api_key="test-key")


@respx.mock
def test_get_approval_returns_full_status() -> None:
    respx.get(f"{BASE_URL}/v1/approvals/hitl_123").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "hitl_123",
                "agent_id": "deploy-agent",
                "att_tid": "task-1",
                "intent": "Deploy to production",
                "requested_scope": ["deploy:prod"],
                "status": "pending",
                "approved_by": None,
                "created_at": "2026-03-29T12:00:00Z",
                "resolved_at": None,
            },
        )
    )

    status = _sync_client().get_approval("hitl_123")

    assert status.id == "hitl_123"
    assert status.agent_id == "deploy-agent"
    assert status.requested_scope == ["deploy:prod"]
    assert status.status == "pending"


@respx.mock
def test_deny_approval_returns_resolved_status() -> None:
    respx.post(f"{BASE_URL}/v1/approvals/hitl_123/deny").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "hitl_123",
                "status": "rejected",
            },
        )
    )

    status = _sync_client().deny_approval("hitl_123")

    assert status.id == "hitl_123"
    assert status.status == "rejected"


@respx.mock
def test_wait_for_approval_returns_on_approved() -> None:
    poll_count = 0

    def response(_: httpx.Request) -> httpx.Response:
        nonlocal poll_count
        poll_count += 1
        status = "approved" if poll_count >= 2 else "pending"
        return httpx.Response(200, json={"id": "hitl_123", "status": status})

    respx.get(f"{BASE_URL}/v1/approvals/hitl_123").mock(side_effect=response)

    status = _sync_client().wait_for_approval("hitl_123", poll_interval=0.01, timeout=0.1)

    assert status.status == "approved"
    assert poll_count >= 2


@respx.mock
def test_wait_for_approval_raises_on_denial() -> None:
    respx.get(f"{BASE_URL}/v1/approvals/hitl_123").mock(
        return_value=httpx.Response(200, json={"id": "hitl_123", "status": "rejected"})
    )

    with pytest.raises(AttestApprovalDenied):
        _sync_client().wait_for_approval("hitl_123", poll_interval=0.01, timeout=0.1)


@respx.mock
def test_wait_for_approval_raises_on_timeout() -> None:
    respx.get(f"{BASE_URL}/v1/approvals/hitl_123").mock(
        return_value=httpx.Response(200, json={"id": "hitl_123", "status": "pending"})
    )

    with pytest.raises(AttestApprovalTimeout):
        _sync_client().wait_for_approval("hitl_123", poll_interval=0.01, timeout=0.03)


@pytest.mark.asyncio
@respx.mock
async def test_async_get_approval_returns_full_status() -> None:
    respx.get(f"{BASE_URL}/v1/approvals/hitl_456").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "hitl_456",
                "agent_id": "review-agent",
                "att_tid": "task-2",
                "intent": "Review financial changes",
                "requested_scope": ["finance:approve"],
                "status": "approved",
                "approved_by": "usr_approver",
                "created_at": "2026-03-29T12:00:00Z",
                "resolved_at": "2026-03-29T12:01:00Z",
            },
        )
    )

    async with _async_client() as client:
        status = await client.get_approval("hitl_456")

    assert status.id == "hitl_456"
    assert status.status == "approved"
    assert status.approved_by == "usr_approver"


@pytest.mark.asyncio
@respx.mock
async def test_async_wait_for_approval_raises_on_timeout() -> None:
    respx.get(f"{BASE_URL}/v1/approvals/hitl_456").mock(
        return_value=httpx.Response(200, json={"id": "hitl_456", "status": "pending"})
    )

    async with _async_client() as client:
        with pytest.raises(AttestApprovalTimeout):
            await client.wait_for_approval("hitl_456", poll_interval=0.01, timeout=0.03)
