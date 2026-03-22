"""Tests for attest/integrations/openai_agents.py.

Does NOT import the ``agents`` package — the integration uses TYPE_CHECKING
guards, so we test what works without it installed.
"""

from __future__ import annotations

import time

import jwt as _jwt
import pytest

from attest.client import AttestScopeError
from attest.integrations.openai_agents import (
    AttestContext,
    AttestRunHooks,
    _tool_name,
    attest_tool_openai,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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


class MockContext:
    """Minimal stand-in for ``RunContextWrapper`` from the agents SDK."""

    def __init__(self, attest_ctx: AttestContext) -> None:
        self.context = attest_ctx


# ---------------------------------------------------------------------------
# AttestContext dataclass — defaults
# ---------------------------------------------------------------------------


class TestAttestContextDefaults:
    def test_default_tokens_is_empty_dict(self):
        ctx = AttestContext()
        assert ctx.attest_tokens == {}

    def test_default_root_token_is_empty_string(self):
        ctx = AttestContext()
        assert ctx.attest_root_token == ""

    def test_default_task_id_is_none(self):
        ctx = AttestContext()
        assert ctx.attest_task_id is None

    def test_custom_values(self):
        ctx = AttestContext(
            attest_tokens={"agent-a": "tok-a"},
            attest_root_token="root-jwt",
            attest_task_id="tid-123",
        )
        assert ctx.attest_tokens == {"agent-a": "tok-a"}
        assert ctx.attest_root_token == "root-jwt"
        assert ctx.attest_task_id == "tid-123"

    def test_instances_have_independent_token_dicts(self):
        """Each instance gets its own dict (field default_factory)."""
        a = AttestContext()
        b = AttestContext()
        a.attest_tokens["x"] = "y"
        assert "x" not in b.attest_tokens


# ---------------------------------------------------------------------------
# AttestRunHooks — _resolve_scope helper
# ---------------------------------------------------------------------------


class TestResolveScope:
    """Test AttestRunHooks._resolve_scope via mock agent objects."""

    def _make_hooks(self, scope_map: dict[str, list[str]] | None = None) -> AttestRunHooks:
        # client is never called in _resolve_scope, so pass a sentinel.
        return AttestRunHooks(client=None, scope_map=scope_map)  # type: ignore[arg-type]

    def test_explicit_scope_map_takes_priority(self):
        hooks = self._make_hooks(scope_map={"billing": ["billing:read"]})

        class FakeAgent:
            name = "billing"
            tools = []

        assert hooks._resolve_scope(FakeAgent()) == ["billing:read"]  # type: ignore[arg-type]

    def test_agent_attest_scope_attribute(self):
        hooks = self._make_hooks()

        class FakeAgent:
            name = "research"
            attest_scope = ["research:read", "research:write"]

        assert hooks._resolve_scope(FakeAgent()) == ["research:read", "research:write"]  # type: ignore[arg-type]

    def test_auto_derive_from_tool_names(self):
        hooks = self._make_hooks()

        class FakeTool:
            name = "send_email"

        class FakeAgent:
            name = "email-agent"
            tools = [FakeTool()]

        assert hooks._resolve_scope(FakeAgent()) == ["tool:send_email"]  # type: ignore[arg-type]

    def test_empty_scope_when_no_tools(self):
        hooks = self._make_hooks()

        class FakeAgent:
            name = "empty-agent"
            tools = []

        assert hooks._resolve_scope(FakeAgent()) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _tool_name() helper
# ---------------------------------------------------------------------------


class TestToolName:
    def test_extracts_name_attribute(self):
        class T:
            name = "my_tool"

        assert _tool_name(T()) == "my_tool"

    def test_extracts_function_attribute_string(self):
        class T:
            function = "do_stuff"

        assert _tool_name(T()) == "do_stuff"

    def test_extracts_function_attribute_callable(self):
        """When .function is a callable, uses its __name__."""

        def helper_fn():
            pass

        class T:
            function = helper_fn

        assert _tool_name(T()) == "helper_fn"

    def test_extracts_dunder_name(self):
        def some_func():
            pass

        assert _tool_name(some_func) == "some_func"

    def test_falls_back_to_str(self):
        assert _tool_name(42) == "42"


# ---------------------------------------------------------------------------
# @attest_tool_openai — sync decorator
# ---------------------------------------------------------------------------


class TestAttestToolOpenaiSync:
    def test_passes_when_scope_is_covered(self):
        token = _fake_token(["web:read", "files:write"])
        ctx = MockContext(AttestContext(attest_tokens={"my-agent": token}))

        @attest_tool_openai(scope="web:read", agent_name="my-agent")
        def my_tool(ctx_arg):
            return "ok"

        assert my_tool(ctx) == "ok"

    def test_raises_scope_error_when_insufficient(self):
        token = _fake_token(["web:read"])
        ctx = MockContext(AttestContext(attest_tokens={"my-agent": token}))

        @attest_tool_openai(scope="files:write", agent_name="my-agent")
        def my_tool(ctx_arg):
            return "ok"

        with pytest.raises(AttestScopeError):
            my_tool(ctx)

    def test_raises_runtime_error_when_no_credential(self):
        ctx = MockContext(AttestContext(attest_tokens={"my-agent": ""}))

        @attest_tool_openai(scope="web:read", agent_name="my-agent")
        def my_tool(ctx_arg):
            return "ok"

        with pytest.raises(RuntimeError, match="no credential for agent"):
            my_tool(ctx)

    def test_raises_runtime_error_multiple_credentials_no_agent_name(self):
        tok_a = _fake_token(["web:read"], agent_id="agent-a")
        tok_b = _fake_token(["files:write"], agent_id="agent-b")
        ctx = MockContext(
            AttestContext(attest_tokens={"agent-a": tok_a, "agent-b": tok_b})
        )

        @attest_tool_openai(scope="web:read")
        def my_tool(ctx_arg):
            return "ok"

        with pytest.raises(RuntimeError, match="multiple agent credentials"):
            my_tool(ctx)

    def test_works_with_explicit_agent_name(self):
        tok = _fake_token(["billing:read"], agent_id="billing-agent")
        ctx = MockContext(
            AttestContext(
                attest_tokens={
                    "billing-agent": tok,
                    "other-agent": _fake_token(["other:read"], agent_id="other"),
                }
            )
        )

        @attest_tool_openai(scope="billing:read", agent_name="billing-agent")
        def lookup_invoice(ctx_arg):
            return "found"

        assert lookup_invoice(ctx) == "found"

    def test_falls_back_to_single_credential(self):
        tok = _fake_token(["web:read"])
        ctx = MockContext(AttestContext(attest_tokens={"only-agent": tok}))

        @attest_tool_openai(scope="web:read")
        def my_tool(ctx_arg):
            return "ok"

        assert my_tool(ctx) == "ok"

    def test_preserves_function_name(self):
        @attest_tool_openai(scope="web:read")
        def my_special_tool(ctx_arg):
            return "ok"

        assert my_special_tool.__name__ == "my_special_tool"


# ---------------------------------------------------------------------------
# @attest_tool_openai — async decorator
# ---------------------------------------------------------------------------


class TestAttestToolOpenaiAsync:
    @pytest.mark.asyncio
    async def test_async_passes_when_scope_is_covered(self):
        token = _fake_token(["web:read", "files:write"])
        ctx = MockContext(AttestContext(attest_tokens={"my-agent": token}))

        @attest_tool_openai(scope="web:read", agent_name="my-agent")
        async def my_tool(ctx_arg):
            return "ok"

        assert await my_tool(ctx) == "ok"

    @pytest.mark.asyncio
    async def test_async_raises_scope_error_when_insufficient(self):
        token = _fake_token(["web:read"])
        ctx = MockContext(AttestContext(attest_tokens={"my-agent": token}))

        @attest_tool_openai(scope="files:write", agent_name="my-agent")
        async def my_tool(ctx_arg):
            return "ok"

        with pytest.raises(AttestScopeError):
            await my_tool(ctx)

    @pytest.mark.asyncio
    async def test_async_raises_runtime_error_no_credential(self):
        ctx = MockContext(AttestContext(attest_tokens={"my-agent": ""}))

        @attest_tool_openai(scope="web:read", agent_name="my-agent")
        async def my_tool(ctx_arg):
            return "ok"

        with pytest.raises(RuntimeError, match="no credential for agent"):
            await my_tool(ctx)

    @pytest.mark.asyncio
    async def test_async_falls_back_to_single_credential(self):
        tok = _fake_token(["web:read"])
        ctx = MockContext(AttestContext(attest_tokens={"only-agent": tok}))

        @attest_tool_openai(scope="web:read")
        async def my_tool(ctx_arg):
            return "ok"

        assert await my_tool(ctx) == "ok"

    @pytest.mark.asyncio
    async def test_async_preserves_function_name(self):
        @attest_tool_openai(scope="web:read")
        async def my_async_tool(ctx_arg):
            return "ok"

        assert my_async_tool.__name__ == "my_async_tool"

    @pytest.mark.asyncio
    async def test_async_passes_extra_args_and_kwargs(self):
        token = _fake_token(["web:read"])
        ctx = MockContext(AttestContext(attest_tokens={"agent": token}))

        @attest_tool_openai(scope="web:read", agent_name="agent")
        async def my_tool(ctx_arg, recipient: str, body: str = "hello"):
            return f"{recipient}:{body}"

        result = await my_tool(ctx, "alice", body="hi")
        assert result == "alice:hi"
