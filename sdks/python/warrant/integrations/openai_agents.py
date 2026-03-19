"""OpenAI Agents SDK integration for Warrant.

Intercepts every agent handoff via the official ``RunHooks.on_handoff`` API,
automatically issues a delegated Warrant credential for the receiving agent,
and stores it in the run context so tools can enforce scope.

Usage::

    from dataclasses import dataclass, field
    from agents import Agent, Runner
    from warrant import WarrantClient, IssueParams
    from warrant.integrations.openai_agents import WarrantContext, WarrantRunHooks

    @dataclass
    class AppContext(WarrantContext):
        user_id: str = ""

    client = WarrantClient(base_url="http://localhost:8080", api_key="dev")

    # Issue a root credential for the orchestrator before the run
    root = client.issue(IssueParams(
        agent_id="triage-agent",
        user_id="usr_alice",
        scope=["research:read", "billing:read", "gmail:send"],
        instruction="Help the user with their billing question",
    ))

    ctx = AppContext(
        user_id="usr_alice",
        warrant_root_token=root.token,
        warrant_tokens={"triage-agent": root.token},
        warrant_task_id=root.claims.wrt_tid,
    )

    hooks = WarrantRunHooks(
        client=client,
        # Explicit scope per agent. If omitted, auto-derived from agent tools.
        scope_map={
            "billing-agent": ["billing:read"],
            "email-agent":   ["gmail:send"],
        },
    )

    result = await Runner.run(
        triage_agent,
        input="I have a billing question",
        context=ctx,
        hooks=hooks,
    )

    # Inside any tool on billing-agent:
    # async def lookup_invoice(ctx: RunContextWrapper[AppContext], invoice_id: str) -> str:
    #     token = ctx.context.warrant_tokens.get("billing-agent")
    #     ...  or use @warrant_tool_openai decorator below
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from warrant.client import WarrantClient, WarrantScopeError
from warrant.scope import is_subset
from warrant.types import DelegateParams, WarrantClaims

if TYPE_CHECKING:
    # Imported only for type checking; not required at runtime.
    from agents import Agent, RunContextWrapper  # type: ignore[import]


# ---------------------------------------------------------------------------
# WarrantContext — mixin dataclass for OpenAI Agents SDK contexts
# ---------------------------------------------------------------------------


@dataclass
class WarrantContext:
    """Mixin for OpenAI Agents SDK context objects.

    Extend this in your own context dataclass::

        @dataclass
        class AppContext(WarrantContext):
            user_id: str = ""
    """

    # JWT string for each agent that has received a credential.
    # Maps agent_name → raw JWT string.
    warrant_tokens: dict[str, str] = field(default_factory=dict)

    # The root JWT issued before the run starts.
    # WarrantRunHooks reads this as the parent when the first handoff fires.
    warrant_root_token: str = ""

    # wrt_tid shared across the entire delegation tree.
    warrant_task_id: str | None = None


# ---------------------------------------------------------------------------
# WarrantRunHooks — the interceptor
# ---------------------------------------------------------------------------


class WarrantRunHooks:
    """RunHooks subclass that issues delegated Warrant credentials on every handoff.

    Pass an instance to ``Runner.run(hooks=...)``::

        result = await Runner.run(agent, input="...", context=ctx, hooks=WarrantRunHooks(client))

    On each handoff from agent A → agent B, this hook:

    1. Determines B's scope from ``scope_map`` or auto-derives from ``to_agent.tools``.
    2. Finds A's current credential (or ``warrant_root_token`` as fallback).
    3. Issues a delegated credential for B, bounded by A's scope.
    4. Stores the child JWT in ``context.context.warrant_tokens[to_agent.name]``.

    Parameters
    ----------
    client:
        A sync ``WarrantClient``. Called from async context via ``asyncio.to_thread``.
    scope_map:
        Optional explicit mapping of agent name → scope list.
        Agents not in the map get scope auto-derived from their tool names:
        tool ``"send_email"`` → scope ``"tool:send_email"``.
    on_delegation_failed:
        Optional callback invoked if delegation fails (e.g. scope violation).
        Receives ``(from_agent_name, to_agent_name, error)``.
        If not provided, the error is re-raised and the handoff is aborted.
    """

    def __init__(
        self,
        client: WarrantClient,
        scope_map: dict[str, list[str]] | None = None,
        on_delegation_failed: Any | None = None,
    ) -> None:
        self._client = client
        self._scope_map = scope_map or {}
        self._on_failed = on_delegation_failed

    # ------------------------------------------------------------------
    # The one hook that matters
    # ------------------------------------------------------------------

    async def on_handoff(
        self,
        context: RunContextWrapper[WarrantContext],  # type: ignore[type-arg]
        from_agent: Agent,  # type: ignore[type-arg]
        to_agent: Agent,  # type: ignore[type-arg]
    ) -> None:
        """Issue a delegated credential for ``to_agent`` before it runs."""
        ctx: WarrantContext = context.context  # type: ignore[attr-defined]

        # Find the parent credential: from_agent's token or root token.
        parent_token = ctx.warrant_tokens.get(from_agent.name) or ctx.warrant_root_token
        if not parent_token:
            raise RuntimeError(
                f"WarrantRunHooks: no credential found for '{from_agent.name}' "
                "and warrant_root_token is not set on the context. "
                "Issue a root credential before starting the run."
            )

        child_scope = self._resolve_scope(to_agent)

        try:
            dt = await asyncio.to_thread(
                self._client.delegate,
                DelegateParams(
                    parent_token=parent_token,
                    child_agent=to_agent.name,
                    child_scope=child_scope,
                ),
            )
        except Exception as exc:
            if self._on_failed is not None:
                if asyncio.iscoroutinefunction(self._on_failed):
                    await self._on_failed(from_agent.name, to_agent.name, exc)
                else:
                    self._on_failed(from_agent.name, to_agent.name, exc)
                return
            raise

        ctx.warrant_tokens[to_agent.name] = dt.token
        if ctx.warrant_task_id is None:
            ctx.warrant_task_id = dt.claims.wrt_tid

    # ------------------------------------------------------------------
    # Scope resolution
    # ------------------------------------------------------------------

    def _resolve_scope(self, agent: Agent) -> list[str]:  # type: ignore[type-arg]
        """Return the scope list for *agent*.

        Priority:
        1. Explicit entry in ``scope_map``.
        2. ``agent.warrant_scope`` attribute (set by developer on the Agent object).
        3. Auto-derive from tool names: ``tool:{tool.name}``.
        """
        if agent.name in self._scope_map:
            return self._scope_map[agent.name]

        if hasattr(agent, "warrant_scope") and isinstance(agent.warrant_scope, list):
            return agent.warrant_scope  # type: ignore[return-value]

        # Auto-derive: each tool becomes "tool:{tool_name}"
        tools = getattr(agent, "tools", None) or []
        if tools:
            return [f"tool:{_tool_name(t)}" for t in tools]

        # No tools — grant empty scope (agent can't call anything).
        return []


def _tool_name(tool: Any) -> str:
    """Extract a consistent name string from a tool object."""
    for attr in ("name", "function", "__name__"):
        val = getattr(tool, attr, None)
        if val is not None:
            if callable(val):
                return val.__name__
            if isinstance(val, str):
                return val
    return str(tool)


# ---------------------------------------------------------------------------
# warrant_tool_openai — scope enforcement decorator for OpenAI Agents tools
# ---------------------------------------------------------------------------


def warrant_tool_openai(scope: str, agent_name: str | None = None) -> Any:
    """Decorator that enforces Warrant scope on an OpenAI Agents SDK tool function.

    The decorated function must accept a ``RunContextWrapper`` as its first
    argument (the standard pattern for OpenAI Agents tools).

    Parameters
    ----------
    scope:
        Required scope string, e.g. ``"tool:send_email"`` or ``"gmail:send"``.
    agent_name:
        Optional explicit agent name to look up in ``context.context.warrant_tokens``.
        If omitted, the decorator looks for the single credential in the context.

    Example::

        @function_tool
        @warrant_tool_openai(scope="tool:send_email", agent_name="email-agent")
        async def send_email(ctx: RunContextWrapper[AppContext], to: str, body: str) -> str:
            ...
    """

    def decorator(fn: Any) -> Any:
        @functools.wraps(fn)
        async def async_wrapper(ctx: Any, *args: Any, **kwargs: Any) -> Any:
            _check_openai_scope(fn.__name__, ctx, scope, agent_name)
            return await fn(ctx, *args, **kwargs)

        @functools.wraps(fn)
        def sync_wrapper(ctx: Any, *args: Any, **kwargs: Any) -> Any:
            _check_openai_scope(fn.__name__, ctx, scope, agent_name)
            return fn(ctx, *args, **kwargs)

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator


def _check_openai_scope(
    tool_name: str,
    ctx: Any,
    required_scope: str,
    explicit_agent_name: str | None,
) -> None:
    """Raise WarrantScopeError if the credential in ctx does not cover required_scope."""
    import jwt as _jwt  # lazy import

    warrant_ctx: WarrantContext = ctx.context
    tokens = warrant_ctx.warrant_tokens

    if explicit_agent_name:
        token_str = tokens.get(explicit_agent_name)
        resolved_name = explicit_agent_name
    elif len(tokens) == 1:
        resolved_name, token_str = next(iter(tokens.items()))
    else:
        raise RuntimeError(
            f"warrant_tool_openai on '{tool_name}': multiple agent credentials present. "
            "Pass agent_name= to @warrant_tool_openai."
        )

    if not token_str:
        raise RuntimeError(
            f"warrant_tool_openai on '{tool_name}': no credential for agent '{resolved_name}'"
        )

    try:
        payload: dict = _jwt.decode(
            token_str,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=["RS256"],
        )
        claims = WarrantClaims.from_dict(payload)
    except Exception as exc:
        raise RuntimeError(
            f"warrant_tool_openai: failed to decode credential for '{resolved_name}': {exc}"
        ) from exc

    if not is_subset(claims.wrt_scope, [required_scope]):
        raise WarrantScopeError(
            tool=tool_name,
            required_scope=required_scope,
            granted_scope=claims.wrt_scope,
            jti=claims.jti,
        )
