"""Tests for attest/integrations/anthropic_sdk.py.

Uses respx to mock the httpx transport so no live server is needed.
The 'anthropic' package itself is NOT required — the integration never
imports it at the top level.
"""

from __future__ import annotations

import json
import time
import warnings

import httpx
import jwt as _jwt
import pytest
import respx

from attest import AsyncAttestClient, AttestClient
from attest.client import AttestScopeError
from attest.integrations.anthropic_sdk import (
    AsyncAttestSession,
    AttestSession,
    attest_tool_anthropic,
    current_attest_session,
)

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:8080"


def _fake_token(
    scope: list[str],
    jti: str = "jti-root-1",
    tid: str = "tid-task-1",
    agent_id: str = "test-agent",
) -> str:
    """Return a valid HS256 JWT with the given Attest claims.

    PyJWT skips algorithm validation when verify_signature=False, so HS256
    tokens decode cleanly even though the integration specifies algorithms=["RS256"].
    """
    now = int(time.time())
    payload = {
        "iss": "attest",
        "sub": f"agent:{agent_id}",
        "iat": now,
        "exp": now + 3600,
        "jti": jti,
        "att_tid": tid,
        "att_depth": 0,
        "att_scope": scope,
        "att_intent": "do a thing",
        "att_chain": [jti],
        "att_uid": "usr_alice",
    }
    return _jwt.encode(payload, "test-secret-key-at-least-32-bytes!!", algorithm="HS256")


def _issue_body(
    scope: list[str],
    jti: str = "jti-root-1",
    tid: str = "tid-task-1",
    agent_id: str = "test-agent",
) -> dict:
    """Fake response body for POST /v1/credentials."""
    now = int(time.time())
    return {
        "token": _fake_token(scope, jti=jti, tid=tid, agent_id=agent_id),
        "claims": {
            "iss": "attest",
            "sub": f"agent:{agent_id}",
            "iat": now,
            "exp": now + 3600,
            "jti": jti,
            "att_tid": tid,
            "att_depth": 0,
            "att_scope": scope,
            "att_intent": "do a thing",
            "att_chain": [jti],
            "att_uid": "usr_alice",
        },
    }


def _delegate_body(
    scope: list[str],
    jti: str = "jti-child-1",
    tid: str = "tid-task-1",
    agent_id: str = "child-agent",
    parent_jti: str = "jti-root-1",
) -> dict:
    """Fake response body for POST /v1/credentials/delegate."""
    now = int(time.time())
    return {
        "token": _fake_token(scope, jti=jti, tid=tid, agent_id=agent_id),
        "claims": {
            "iss": "attest",
            "sub": f"agent:{agent_id}",
            "iat": now,
            "exp": now + 3600,
            "jti": jti,
            "att_tid": tid,
            "att_depth": 1,
            "att_scope": scope,
            "att_intent": "do a thing",
            "att_chain": [parent_jti, jti],
            "att_uid": "usr_alice",
            "att_pid": parent_jti,
        },
    }


def _sync_client() -> AttestClient:
    return AttestClient(base_url=BASE_URL, api_key="test-key")


def _async_client() -> AsyncAttestClient:
    return AsyncAttestClient(base_url=BASE_URL, api_key="test-key")


# ---------------------------------------------------------------------------
# Sync AttestSession — lifecycle
# ---------------------------------------------------------------------------


@respx.mock
def test_session_enter_calls_issue():
    """POST /v1/credentials is called on __enter__; token/task_id/claims populated."""
    route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )
    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ) as session:
        assert route.called
        assert session.token  # non-empty JWT string
        assert session.task_id == "tid-task-1"
        assert session.claims.att_scope == ["web:read"]


@respx.mock
def test_session_exit_calls_revoke():
    """DELETE /v1/credentials/{jti} is called on __exit__ when revoke_on_exit=True."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    revoke_route = respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ):
        pass

    assert revoke_route.called


@respx.mock
def test_session_exit_no_revoke_when_disabled():
    """No DELETE is issued when revoke_on_exit=False."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    revoke_route = respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
        revoke_on_exit=False,
    ):
        pass

    assert not revoke_route.called


@respx.mock
def test_session_revokes_on_exception():
    """Revocation still fires even when the body raises an exception."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    revoke_route = respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with pytest.raises(ValueError):
        with AttestSession(
            client=_sync_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            raise ValueError("boom")

    assert revoke_route.called


@respx.mock
def test_session_revoke_failure_warns_not_raises():
    """A revocation failure emits RuntimeWarning and does not propagate."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(500, json={"error": "server error"})
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with AttestSession(
            client=_sync_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            pass

    assert any(issubclass(w.category, RuntimeWarning) for w in caught)


# ---------------------------------------------------------------------------
# Sync AttestSession — delegation
# ---------------------------------------------------------------------------


@respx.mock
def test_session_delegate():
    """delegate() calls POST /v1/credentials/delegate with correct body."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read", "files:write"]))
    )
    delegate_route = respx.post(f"{BASE_URL}/v1/credentials/delegate").mock(
        return_value=httpx.Response(201, json=_delegate_body(["files:write"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read", "files:write"],
        instruction="do a thing",
    ) as session:
        child = session.delegate("child-agent", ["files:write"])

    assert delegate_route.called
    sent_body = json.loads(delegate_route.calls[0].request.content)
    assert sent_body["child_agent"] == "child-agent"
    assert sent_body["child_scope"] == ["files:write"]
    assert child.claims.att_scope == ["files:write"]


def test_session_delegate_outside_context_raises():
    """delegate() raises RuntimeError when called outside the 'with' block."""
    session = AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    )
    with pytest.raises(RuntimeError, match="outside of 'with' block"):
        session.delegate("child", ["web:read"])


# ---------------------------------------------------------------------------
# Sync AttestSession — ContextVar behaviour
# ---------------------------------------------------------------------------


@respx.mock
def test_contextvar_set_on_enter_reset_on_exit():
    """current_attest_session is set inside the block and None after."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    assert current_attest_session.get() is None

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ) as session:
        assert current_attest_session.get() is session

    assert current_attest_session.get() is None


@respx.mock
def test_contextvar_reset_on_exception():
    """current_attest_session is reset even when an exception escapes the block."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with pytest.raises(RuntimeError):
        with AttestSession(
            client=_sync_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            raise RuntimeError("test error")

    assert current_attest_session.get() is None


# ---------------------------------------------------------------------------
# Sync AttestSession — property guard
# ---------------------------------------------------------------------------


def test_properties_outside_context_raise():
    """token, task_id, and claims raise RuntimeError when accessed outside 'with'."""
    session = AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    )
    with pytest.raises(RuntimeError):
        _ = session.token
    with pytest.raises(RuntimeError):
        _ = session.task_id
    with pytest.raises(RuntimeError):
        _ = session.claims


# ---------------------------------------------------------------------------
# Sync AttestSession — agent_checksum
# ---------------------------------------------------------------------------


@respx.mock
def test_system_prompt_includes_checksum():
    """When system_prompt is provided, agent_checksum appears in the issue request."""
    issue_route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
        system_prompt="You are a helpful assistant.",
    ):
        pass

    body = json.loads(issue_route.calls[0].request.content)
    assert "agent_checksum" in body
    assert body["agent_checksum"]  # non-empty hex string


@respx.mock
def test_no_system_prompt_no_checksum():
    """When system_prompt is None, agent_checksum is absent from the issue request."""
    issue_route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ):
        pass

    body = json.loads(issue_route.calls[0].request.content)
    assert "agent_checksum" not in body


# ---------------------------------------------------------------------------
# @attest_tool_anthropic — sync
# ---------------------------------------------------------------------------


@respx.mock
def test_attest_tool_passes_with_valid_scope():
    """@attest_tool_anthropic allows the call when scope is covered."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read", "files:write"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    @attest_tool_anthropic(scope="web:read")
    def my_tool() -> str:
        return "ok"

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read", "files:write"],
        instruction="do a thing",
    ):
        assert my_tool() == "ok"


@respx.mock
def test_attest_tool_raises_scope_error_insufficient_scope():
    """@attest_tool_anthropic raises AttestScopeError when scope is not covered."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    @attest_tool_anthropic(scope="files:write")
    def my_tool() -> str:
        return "ok"

    with pytest.raises(AttestScopeError):
        with AttestSession(
            client=_sync_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            my_tool()


def test_attest_tool_raises_runtime_error_no_session():
    """@attest_tool_anthropic raises RuntimeError when no session is active."""

    @attest_tool_anthropic(scope="web:read")
    def my_tool() -> str:
        return "ok"

    with pytest.raises(RuntimeError, match="no active AttestSession"):
        my_tool()


# ---------------------------------------------------------------------------
# Async AttestSession — lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_session_enter_calls_issue():
    """POST /v1/credentials is called on __aenter__; token/task_id/claims populated."""
    route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )
    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ) as session:
        assert route.called
        assert session.token
        assert session.task_id == "tid-task-1"
        assert session.claims.att_scope == ["web:read"]


@pytest.mark.asyncio
@respx.mock
async def test_async_session_exit_calls_revoke():
    """DELETE /v1/credentials/{jti} is called on __aexit__."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    revoke_route = respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ):
        pass

    assert revoke_route.called


@pytest.mark.asyncio
@respx.mock
async def test_async_session_no_revoke_when_disabled():
    """No DELETE when revoke_on_exit=False (async)."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    revoke_route = respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
        revoke_on_exit=False,
    ):
        pass

    assert not revoke_route.called


@pytest.mark.asyncio
@respx.mock
async def test_async_session_revokes_on_exception():
    """Revocation still fires when the body raises an exception (async)."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    revoke_route = respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with pytest.raises(ValueError):
        async with AsyncAttestSession(
            client=_async_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            raise ValueError("boom")

    assert revoke_route.called


@pytest.mark.asyncio
@respx.mock
async def test_async_session_revoke_failure_warns():
    """Revocation failure emits RuntimeWarning and does not propagate (async)."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(500, json={"error": "server error"})
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        async with AsyncAttestSession(
            client=_async_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            pass

    assert any(issubclass(w.category, RuntimeWarning) for w in caught)


# ---------------------------------------------------------------------------
# Async AttestSession — delegation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_delegate():
    """async_delegate() calls POST /v1/credentials/delegate with correct body."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read", "files:write"]))
    )
    delegate_route = respx.post(f"{BASE_URL}/v1/credentials/delegate").mock(
        return_value=httpx.Response(201, json=_delegate_body(["files:write"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read", "files:write"],
        instruction="do a thing",
    ) as session:
        child = await session.async_delegate("child-agent", ["files:write"])

    assert delegate_route.called
    sent_body = json.loads(delegate_route.calls[0].request.content)
    assert sent_body["child_agent"] == "child-agent"
    assert sent_body["child_scope"] == ["files:write"]
    assert child.claims.att_scope == ["files:write"]


@pytest.mark.asyncio
async def test_async_delegate_outside_context_raises():
    """async_delegate() raises RuntimeError when called outside 'async with'."""
    session = AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    )
    with pytest.raises(RuntimeError, match="outside of 'async with' block"):
        await session.async_delegate("child", ["web:read"])


# ---------------------------------------------------------------------------
# Async AttestSession — ContextVar behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_contextvar_set_and_reset():
    """current_attest_session is set inside the async block and None after."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    assert current_attest_session.get() is None

    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ) as session:
        assert current_attest_session.get() is session

    assert current_attest_session.get() is None


@pytest.mark.asyncio
@respx.mock
async def test_async_contextvar_reset_on_exception():
    """current_attest_session is reset even when an exception escapes (async)."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    with pytest.raises(RuntimeError):
        async with AsyncAttestSession(
            client=_async_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            raise RuntimeError("test error")

    assert current_attest_session.get() is None


# ---------------------------------------------------------------------------
# Async AttestSession — agent_checksum
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_system_prompt_includes_checksum():
    """agent_checksum appears in the async issue request when system_prompt provided."""
    issue_route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
        system_prompt="You are a helpful assistant.",
    ):
        pass

    body = json.loads(issue_route.calls[0].request.content)
    assert "agent_checksum" in body
    assert body["agent_checksum"]


@pytest.mark.asyncio
@respx.mock
async def test_async_no_system_prompt_no_checksum():
    """agent_checksum is absent from the async issue request when system_prompt is None."""
    issue_route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ):
        pass

    body = json.loads(issue_route.calls[0].request.content)
    assert "agent_checksum" not in body


# ---------------------------------------------------------------------------
# @attest_tool_anthropic — async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_attest_tool_passes_with_valid_scope():
    """@attest_tool_anthropic allows the async call when scope is covered."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    @attest_tool_anthropic(scope="web:read")
    async def my_async_tool() -> str:
        return "ok"

    async with AsyncAttestSession(
        client=_async_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read"],
        instruction="do a thing",
    ):
        assert await my_async_tool() == "ok"


@pytest.mark.asyncio
@respx.mock
async def test_async_attest_tool_raises_scope_error():
    """@attest_tool_anthropic raises AttestScopeError for async tool with bad scope."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    @attest_tool_anthropic(scope="files:write")
    async def my_async_tool() -> str:
        return "ok"

    with pytest.raises(AttestScopeError):
        async with AsyncAttestSession(
            client=_async_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["web:read"],
            instruction="do a thing",
        ):
            await my_async_tool()


# ---------------------------------------------------------------------------
# Sync AttestSession — HITL approval delegation
# ---------------------------------------------------------------------------


@respx.mock
def test_delegate_with_approval_handler_grants_hitl_token():
    """delegate(require_approval=True) can use approval_handler to obtain HITL token."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["deploy:prod"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    approval_route = respx.post(f"{BASE_URL}/v1/approvals").mock(
        return_value=httpx.Response(200, json={
            "challenge_id": "hitl_handler_1",
            "status": "pending",
        })
    )

    grant_route = respx.post(f"{BASE_URL}/v1/approvals/hitl_handler_1/grant").mock(
        return_value=httpx.Response(200, json={
            **_delegate_body(["deploy:prod"], jti="jti-hitl-granted", agent_id="deploy-agent"),
            "claims": {
                **_delegate_body(["deploy:prod"], jti="jti-hitl-granted", agent_id="deploy-agent")["claims"],
                "att_hitl_req": "hitl_handler_1",
                "att_hitl_uid": "usr_approver",
                "att_hitl_iss": "https://idp.example.com",
            },
        })
    )

    seen_challenge_ids: list[str] = []

    def approval_handler(challenge):
        seen_challenge_ids.append(challenge.challenge_id)
        return "oidc-id-token"

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["deploy:prod"],
        instruction="do a thing",
    ) as session:
        child = session.delegate(
            "deploy-agent",
            ["deploy:prod"],
            require_approval=True,
            approval_handler=approval_handler,
        )

    assert approval_route.called
    assert grant_route.called
    assert seen_challenge_ids == ["hitl_handler_1"]
    assert child.claims.att_hitl_req == "hitl_handler_1"
    assert child.claims.att_hitl_uid == "usr_approver"


@respx.mock
def test_delegate_with_approval_polls_until_approved():
    """delegate(require_approval=True) polls get_approval and delegates on approval."""

    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read", "deploy:prod"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    # Mock the approval request endpoint.
    approval_route = respx.post(f"{BASE_URL}/v1/approvals").mock(
        return_value=httpx.Response(200, json={
            "challenge_id": "hitl_anthro_1",
            "status": "pending",
        })
    )

    # Mock get_approval — first call returns pending, second returns approved.
    poll_count = 0

    def get_approval_response(request):
        nonlocal poll_count
        poll_count += 1
        if poll_count >= 2:
            return httpx.Response(200, json={
                "challenge_id": "hitl_anthro_1",
                "status": "approved",
            })
        return httpx.Response(200, json={
            "challenge_id": "hitl_anthro_1",
            "status": "pending",
        })

    respx.get(f"{BASE_URL}/v1/approvals/hitl_anthro_1").mock(
        side_effect=get_approval_response,
    )

    # Mock delegate — called after approval confirmed.
    delegate_route = respx.post(f"{BASE_URL}/v1/credentials/delegate").mock(
        return_value=httpx.Response(201, json=_delegate_body(["deploy:prod"]))
    )

    with AttestSession(
        client=_sync_client(),
        agent_id="test-agent",
        user_id="usr_alice",
        scope=["web:read", "deploy:prod"],
        instruction="do a thing",
    ) as session, warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        child = session.delegate(
            "deploy-agent",
            ["deploy:prod"],
            require_approval=True,
            intent="Deploy to production",
            poll_interval=0.01,  # fast for tests
        )

    assert approval_route.called
    assert delegate_route.called
    assert poll_count >= 2
    assert child.claims.att_scope == ["deploy:prod"]
    assert any("approval_handler" in str(w.message) for w in caught)


@respx.mock
def test_delegate_with_approval_raises_on_denial():
    """delegate(require_approval=True) raises AttestApprovalDenied when rejected."""
    from attest.client import AttestApprovalDenied

    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["deploy:prod"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    respx.post(f"{BASE_URL}/v1/approvals").mock(
        return_value=httpx.Response(200, json={
            "challenge_id": "hitl_denied_2",
            "status": "pending",
        })
    )

    respx.get(f"{BASE_URL}/v1/approvals/hitl_denied_2").mock(
        return_value=httpx.Response(200, json={
            "challenge_id": "hitl_denied_2",
            "status": "rejected",
        })
    )

    with pytest.raises(AttestApprovalDenied):
        with AttestSession(
            client=_sync_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["deploy:prod"],
            instruction="do a thing",
        ) as session:
            session.delegate(
                "deploy-agent",
                ["deploy:prod"],
                require_approval=True,
                poll_interval=0.01,
            )


@respx.mock
def test_delegate_with_approval_raises_on_timeout():
    """delegate(require_approval=True) raises AttestApprovalTimeout on timeout."""
    from attest.client import AttestApprovalTimeout

    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["deploy:prod"]))
    )
    respx.delete(f"{BASE_URL}/v1/credentials/jti-root-1").mock(
        return_value=httpx.Response(200, json={})
    )

    respx.post(f"{BASE_URL}/v1/approvals").mock(
        return_value=httpx.Response(200, json={
            "challenge_id": "hitl_timeout_1",
            "status": "pending",
        })
    )

    # Always return pending — never approve.
    respx.get(f"{BASE_URL}/v1/approvals/hitl_timeout_1").mock(
        return_value=httpx.Response(200, json={
            "challenge_id": "hitl_timeout_1",
            "status": "pending",
        })
    )

    with pytest.raises(AttestApprovalTimeout):
        with AttestSession(
            client=_sync_client(),
            agent_id="test-agent",
            user_id="usr_alice",
            scope=["deploy:prod"],
            instruction="do a thing",
        ) as session:
            session.delegate(
                "deploy-agent",
                ["deploy:prod"],
                require_approval=True,
                poll_interval=0.01,
                poll_timeout=0.05,  # very short for test
            )
