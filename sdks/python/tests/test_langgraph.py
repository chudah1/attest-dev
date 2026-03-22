"""Tests for attest/integrations/langgraph.py.

Uses respx to mock the httpx transport so no live server is needed.
LangGraph is NOT required — the integration uses lazy imports, so we
only test the parts that work without langgraph installed:
AttestNodes, @attest_tool, current_attest_token, and AttestState.
"""

from __future__ import annotations

import json
import time

import httpx
import jwt as _jwt
import pytest
import respx

from attest.client import AttestClient, AttestScopeError
from attest.integrations.langgraph import (
    AttestNodes,
    AttestState,
    attest_tool,
    current_attest_token,
)

# ---------------------------------------------------------------------------
# Shared test fixtures (same pattern as test_anthropic_sdk.py)
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


# ---------------------------------------------------------------------------
# AttestNodes.issue()
# ---------------------------------------------------------------------------


@respx.mock
def test_issue_node_posts_to_credentials():
    """issue() returns a node callable that POSTs to /v1/credentials."""
    route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )

    node = AttestNodes.issue(
        client=_sync_client(),
        agent_id="test-agent",
        scope=["web:read"],
    )

    state = {"instruction": "do a thing", "user_id": "usr_alice"}
    result = node(state)

    assert route.called
    assert "attest_tokens" in result
    assert "test-agent" in result["attest_tokens"]
    assert result["attest_task_id"] == "tid-task-1"
    assert result["attest_user_id"] == "usr_alice"


@respx.mock
def test_issue_node_populates_state_fields():
    """issue() populates attest_tokens, attest_task_id, attest_user_id."""
    respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(
            201,
            json=_issue_body(["research:read", "gmail:send"], agent_id="orchestrator-v1"),
        )
    )

    node = AttestNodes.issue(
        client=_sync_client(),
        agent_id="orchestrator-v1",
        scope=["research:read", "gmail:send"],
    )

    state = {"instruction": "summarize my emails", "user_id": "usr_bob"}
    result = node(state)

    assert result["attest_tokens"]["orchestrator-v1"]  # non-empty JWT
    assert result["attest_task_id"] == "tid-task-1"
    assert result["attest_user_id"] == "usr_alice"  # from the mock body


@respx.mock
def test_issue_node_uses_custom_instruction_and_user_id_keys():
    """issue() uses instruction_key and user_id_key to read from state."""
    issue_route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )

    node = AttestNodes.issue(
        client=_sync_client(),
        agent_id="test-agent",
        scope=["web:read"],
        instruction_key="task_description",
        user_id_key="requesting_user",
    )

    state = {
        "task_description": "custom instruction text",
        "requesting_user": "usr_custom",
    }
    node(state)

    assert issue_route.called
    sent_body = json.loads(issue_route.calls[0].request.content)
    assert sent_body["instruction"] == "custom instruction text"
    assert sent_body["user_id"] == "usr_custom"


@respx.mock
def test_issue_node_passes_ttl_seconds():
    """issue() passes ttl_seconds when provided."""
    issue_route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )

    node = AttestNodes.issue(
        client=_sync_client(),
        agent_id="test-agent",
        scope=["web:read"],
        ttl_seconds=600,
    )

    state = {"instruction": "do a thing", "user_id": "usr_alice"}
    node(state)

    sent_body = json.loads(issue_route.calls[0].request.content)
    assert sent_body["ttl_seconds"] == 600


@respx.mock
def test_issue_node_no_ttl_when_not_specified():
    """issue() does not include ttl_seconds when not provided."""
    issue_route = respx.post(f"{BASE_URL}/v1/credentials").mock(
        return_value=httpx.Response(201, json=_issue_body(["web:read"]))
    )

    node = AttestNodes.issue(
        client=_sync_client(),
        agent_id="test-agent",
        scope=["web:read"],
    )

    state = {"instruction": "do a thing", "user_id": "usr_alice"}
    node(state)

    sent_body = json.loads(issue_route.calls[0].request.content)
    assert "ttl_seconds" not in sent_body


# ---------------------------------------------------------------------------
# AttestNodes.delegate()
# ---------------------------------------------------------------------------


@respx.mock
def test_delegate_node_posts_to_delegate_endpoint():
    """delegate() returns a node callable that POSTs to /v1/credentials/delegate."""
    parent_token = _fake_token(["web:read", "files:write"], agent_id="parent-agent")

    delegate_route = respx.post(f"{BASE_URL}/v1/credentials/delegate").mock(
        return_value=httpx.Response(201, json=_delegate_body(["files:write"]))
    )

    node = AttestNodes.delegate(
        client=_sync_client(),
        parent_agent_id="parent-agent",
        child_agent_id="child-agent",
        child_scope=["files:write"],
    )

    state = {"attest_tokens": {"parent-agent": parent_token}}
    result = node(state)

    assert delegate_route.called
    sent_body = json.loads(delegate_route.calls[0].request.content)
    assert sent_body["parent_token"] == parent_token
    assert sent_body["child_agent"] == "child-agent"
    assert sent_body["child_scope"] == ["files:write"]


@respx.mock
def test_delegate_node_reads_parent_token_from_state():
    """delegate() reads parent token from state['attest_tokens'][parent_agent_id]."""
    parent_token = _fake_token(["web:read"], agent_id="orchestrator")

    respx.post(f"{BASE_URL}/v1/credentials/delegate").mock(
        return_value=httpx.Response(201, json=_delegate_body(["web:read"]))
    )

    node = AttestNodes.delegate(
        client=_sync_client(),
        parent_agent_id="orchestrator",
        child_agent_id="researcher",
        child_scope=["web:read"],
    )

    state = {"attest_tokens": {"orchestrator": parent_token}}
    node(state)

    # Implicitly tested by not raising — the code successfully read the parent token.


@respx.mock
def test_delegate_node_stores_child_token_in_state():
    """delegate() stores child token in state['attest_tokens'][child_agent_id]."""
    parent_token = _fake_token(["web:read", "files:write"], agent_id="parent")

    respx.post(f"{BASE_URL}/v1/credentials/delegate").mock(
        return_value=httpx.Response(201, json=_delegate_body(["files:write"]))
    )

    node = AttestNodes.delegate(
        client=_sync_client(),
        parent_agent_id="parent",
        child_agent_id="child-agent",
        child_scope=["files:write"],
    )

    state = {"attest_tokens": {"parent": parent_token}}
    result = node(state)

    assert "child-agent" in result["attest_tokens"]
    assert result["attest_tokens"]["child-agent"]  # non-empty JWT
    # Parent token should also be preserved.
    assert result["attest_tokens"]["parent"] == parent_token


def test_delegate_node_raises_when_parent_token_missing():
    """delegate() raises RuntimeError if parent token is missing from state."""
    node = AttestNodes.delegate(
        client=_sync_client(),
        parent_agent_id="missing-parent",
        child_agent_id="child-agent",
        child_scope=["web:read"],
    )

    state: dict = {"attest_tokens": {}}
    with pytest.raises(RuntimeError, match="no credential found for parent agent"):
        node(state)


def test_delegate_node_raises_when_attest_tokens_empty():
    """delegate() raises RuntimeError when attest_tokens is not in state."""
    node = AttestNodes.delegate(
        client=_sync_client(),
        parent_agent_id="parent",
        child_agent_id="child",
        child_scope=["web:read"],
    )

    state: dict = {}
    with pytest.raises(RuntimeError, match="no credential found for parent agent"):
        node(state)


# ---------------------------------------------------------------------------
# AttestNodes.revoke()
# ---------------------------------------------------------------------------


@respx.mock
def test_revoke_node_deletes_credential():
    """revoke() returns a node callable that DELETEs /v1/credentials/{jti}."""
    token = _fake_token(["web:read"], jti="jti-to-revoke", agent_id="my-agent")

    revoke_route = respx.delete(f"{BASE_URL}/v1/credentials/jti-to-revoke").mock(
        return_value=httpx.Response(200, json={})
    )

    node = AttestNodes.revoke(
        client=_sync_client(),
        agent_id="my-agent",
    )

    state = {"attest_tokens": {"my-agent": token}}
    result = node(state)

    assert revoke_route.called
    assert "my-agent" not in result["attest_tokens"]


@respx.mock
def test_revoke_node_removes_agent_from_tokens():
    """revoke() removes the agent from attest_tokens in returned state."""
    token_a = _fake_token(["web:read"], jti="jti-a", agent_id="agent-a")
    token_b = _fake_token(["files:write"], jti="jti-b", agent_id="agent-b")

    respx.delete(f"{BASE_URL}/v1/credentials/jti-a").mock(
        return_value=httpx.Response(200, json={})
    )

    node = AttestNodes.revoke(
        client=_sync_client(),
        agent_id="agent-a",
    )

    state = {"attest_tokens": {"agent-a": token_a, "agent-b": token_b}}
    result = node(state)

    assert "agent-a" not in result["attest_tokens"]
    assert result["attest_tokens"]["agent-b"] == token_b


def test_revoke_node_noop_when_agent_has_no_token():
    """revoke() returns empty dict if agent has no token (no-op)."""
    node = AttestNodes.revoke(
        client=_sync_client(),
        agent_id="nonexistent-agent",
    )

    state: dict = {"attest_tokens": {}}
    result = node(state)

    assert result == {}


def test_revoke_node_noop_when_no_attest_tokens_key():
    """revoke() returns empty dict if attest_tokens is absent from state."""
    node = AttestNodes.revoke(
        client=_sync_client(),
        agent_id="some-agent",
    )

    state: dict = {}
    result = node(state)

    assert result == {}


# ---------------------------------------------------------------------------
# @attest_tool — scope enforcement via state["attest_tokens"]
# ---------------------------------------------------------------------------


def test_attest_tool_passes_with_valid_scope():
    """@attest_tool allows the call when scope is covered."""
    token = _fake_token(["web:read", "files:write"], agent_id="my-agent")

    @attest_tool(scope="web:read", agent_id="my-agent")
    def my_tool(state: dict) -> str:
        return "ok"

    state = {"attest_tokens": {"my-agent": token}}
    assert my_tool(state) == "ok"


def test_attest_tool_raises_scope_error_insufficient_scope():
    """@attest_tool raises AttestScopeError when scope is insufficient."""
    token = _fake_token(["web:read"], agent_id="my-agent")

    @attest_tool(scope="files:write", agent_id="my-agent")
    def my_tool(state: dict) -> str:
        return "ok"

    state = {"attest_tokens": {"my-agent": token}}
    with pytest.raises(AttestScopeError):
        my_tool(state)


def test_attest_tool_raises_runtime_error_no_credential():
    """@attest_tool raises RuntimeError when no credential found for agent."""
    @attest_tool(scope="web:read", agent_id="missing-agent")
    def my_tool(state: dict) -> str:
        return "ok"

    state: dict = {"attest_tokens": {}}
    with pytest.raises(RuntimeError, match="no credential found for agent"):
        my_tool(state)


def test_attest_tool_works_with_ambient_context_var():
    """@attest_tool works with ambient ContextVar (current_attest_token)."""
    token = _fake_token(["web:read", "files:write"], agent_id="ambient-agent")

    @attest_tool(scope="web:read")
    def my_tool(state: dict) -> str:
        return "ok"

    # Set the ambient token via ContextVar.
    reset_tok = current_attest_token.set(token)
    try:
        # State has no attest_tokens, but the ambient ContextVar is set.
        state: dict = {}
        assert my_tool(state) == "ok"
    finally:
        current_attest_token.reset(reset_tok)


def test_attest_tool_ambient_scope_error():
    """@attest_tool raises AttestScopeError even through ambient ContextVar."""
    token = _fake_token(["web:read"], agent_id="ambient-agent")

    @attest_tool(scope="files:write")
    def my_tool(state: dict) -> str:
        return "ok"

    reset_tok = current_attest_token.set(token)
    try:
        state: dict = {}
        with pytest.raises(AttestScopeError):
            my_tool(state)
    finally:
        current_attest_token.reset(reset_tok)


def test_attest_tool_with_explicit_agent_id():
    """@attest_tool works with explicit agent_id parameter."""
    token_a = _fake_token(["web:read"], agent_id="agent-a")
    token_b = _fake_token(["files:write"], agent_id="agent-b")

    @attest_tool(scope="files:write", agent_id="agent-b")
    def my_tool(state: dict) -> str:
        return "ok"

    state = {"attest_tokens": {"agent-a": token_a, "agent-b": token_b}}
    assert my_tool(state) == "ok"


def test_attest_tool_falls_back_to_first_token_when_only_one():
    """@attest_tool falls back to first token when only one exists and no agent_id."""
    token = _fake_token(["web:read"], agent_id="only-agent")

    @attest_tool(scope="web:read")
    def my_tool(state: dict) -> str:
        return "ok"

    state = {"attest_tokens": {"only-agent": token}}
    assert my_tool(state) == "ok"


@pytest.mark.asyncio
async def test_attest_tool_supports_async_functions():
    """@attest_tool supports async functions."""
    token = _fake_token(["web:read"], agent_id="async-agent")

    @attest_tool(scope="web:read", agent_id="async-agent")
    async def my_async_tool(state: dict) -> str:
        return "async-ok"

    state = {"attest_tokens": {"async-agent": token}}
    result = await my_async_tool(state)
    assert result == "async-ok"


@pytest.mark.asyncio
async def test_attest_tool_async_raises_scope_error():
    """@attest_tool raises AttestScopeError for async function with bad scope."""
    token = _fake_token(["web:read"], agent_id="async-agent")

    @attest_tool(scope="files:write", agent_id="async-agent")
    async def my_async_tool(state: dict) -> str:
        return "ok"

    state = {"attest_tokens": {"async-agent": token}}
    with pytest.raises(AttestScopeError):
        await my_async_tool(state)


@pytest.mark.asyncio
async def test_attest_tool_async_with_ambient_context_var():
    """@attest_tool async works with ambient ContextVar."""
    token = _fake_token(["web:read"], agent_id="ambient-async")

    @attest_tool(scope="web:read")
    async def my_async_tool(state: dict) -> str:
        return "async-ok"

    reset_tok = current_attest_token.set(token)
    try:
        state: dict = {}
        result = await my_async_tool(state)
        assert result == "async-ok"
    finally:
        current_attest_token.reset(reset_tok)


def test_attest_tool_state_as_keyword_arg():
    """@attest_tool extracts state from keyword arguments."""
    token = _fake_token(["web:read"], agent_id="kw-agent")

    @attest_tool(scope="web:read", agent_id="kw-agent")
    def my_tool(state: dict) -> str:
        return "ok"

    state = {"attest_tokens": {"kw-agent": token}}
    assert my_tool(state=state) == "ok"


def test_attest_tool_raises_when_no_state_found():
    """@attest_tool raises RuntimeError when no state dict is found."""
    @attest_tool(scope="web:read")
    def my_tool(x: int) -> str:
        return "ok"

    with pytest.raises(RuntimeError, match="could not find a 'state' dict"):
        my_tool(42)


def test_attest_tool_raises_with_multiple_tokens_and_no_agent_id():
    """@attest_tool raises RuntimeError with multiple tokens and no agent_id."""
    token_a = _fake_token(["web:read"], agent_id="agent-a")
    token_b = _fake_token(["files:write"], agent_id="agent-b")

    @attest_tool(scope="web:read")
    def my_tool(state: dict) -> str:
        return "ok"

    state = {"attest_tokens": {"agent-a": token_a, "agent-b": token_b}}
    with pytest.raises(RuntimeError, match="multiple agent credentials"):
        my_tool(state)


# ---------------------------------------------------------------------------
# current_attest_token ContextVar
# ---------------------------------------------------------------------------


def test_context_var_default_is_none():
    """current_attest_token default is None."""
    assert current_attest_token.get() is None


def test_context_var_can_be_set_and_reset():
    """current_attest_token can be set and reset."""
    assert current_attest_token.get() is None

    reset_tok = current_attest_token.set("my-jwt-token")
    assert current_attest_token.get() == "my-jwt-token"

    current_attest_token.reset(reset_tok)
    assert current_attest_token.get() is None


# ---------------------------------------------------------------------------
# AttestState TypedDict
# ---------------------------------------------------------------------------


def test_attest_state_is_typeddict():
    """AttestState is a TypedDict with the expected keys."""
    # AttestState is total=False, so we can create it empty.
    state: AttestState = {}  # type: ignore[typeddict-item]
    assert isinstance(state, dict)

    # Verify the expected keys are defined in annotations.
    annotations = AttestState.__annotations__
    assert "attest_tokens" in annotations
    assert "attest_task_id" in annotations
    assert "attest_user_id" in annotations
