"""LangGraph integration for Attest.

This module wires Attest credential issuance, delegation, and scope
enforcement into LangGraph state graphs.  LangGraph (and langchain-core) are
**not** required at import time — they are imported lazily so the base SDK
works without those packages installed.

Usage example (static graph with explicit delegation nodes)::

    from typing import TypedDict
    from attest.client import AttestClient
    from attest.integrations.langgraph import AttestState, attest_tool, AttestNodes

    client = AttestClient(api_key="...")

    class MyState(AttestState):
        messages: list
        instruction: str
        user_id: str

    # Issue a root credential at graph entry
    graph.add_node("issue", AttestNodes.issue(
        client=client,
        agent_id="orchestrator-v1",
        scope=["research:read", "gmail:send"],
        instruction_key="instruction",
        user_id_key="user_id",
    ))

    # Enforce scope at a specific tool call
    @attest_tool(scope="gmail:send", agent_id="email-agent-v1")
    def send_email(state: MyState, to: str, body: str) -> str:
        ...

    # Delegate when handing off to a sub-agent
    graph.add_node("spawn_email_agent", AttestNodes.delegate(
        client=client,
        parent_agent_id="orchestrator-v1",
        child_agent_id="email-agent-v1",
        child_scope=["gmail:send"],
    ))

    # Revoke a credential at graph teardown
    graph.add_node("cleanup", AttestNodes.revoke(
        client=client,
        agent_id="orchestrator-v1",
    ))

Usage example (dynamic graph — automatic delegation on every node)::

    from attest.integrations.langgraph import AttestStateGraph

    # Drop-in replacement for StateGraph.
    # Every node receives an auto-delegated credential scoped to its
    # registered scope_map entry (or auto-derived from tool names).
    graph = AttestStateGraph(
        MyState,
        client=client,
        scope_map={
            "research_node": ["research:read"],
            "email_node":    ["gmail:send"],
        },
    )

    graph.add_node("orchestrator", orchestrator_fn)
    graph.add_node("research_node", research_fn)
    graph.add_node("email_node", email_fn)

    # Inside any node function, retrieve the injected credential:
    # from attest.integrations.langgraph import current_attest_token
    # token = current_attest_token.get()
"""

from __future__ import annotations

import contextvars
import functools
import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from attest.client import AttestClient, AttestScopeError
from attest.scope import is_subset
from attest.types import DelegateParams, IssueParams, AttestClaims

if TYPE_CHECKING:
    # These imports are only used for type annotations and are never executed
    # at runtime unless langgraph is installed.
    pass

# ---------------------------------------------------------------------------
# ContextVar — ambient credential for the currently executing node.
# Set automatically by AttestStateGraph; readable from any tool function
# without needing to thread state through every call.
# ---------------------------------------------------------------------------

#: Holds the raw JWT string for the currently executing node's credential.
#: ``None`` when no Attest-managed node is on the call stack.
current_attest_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "attest_current_token", default=None
)


# ---------------------------------------------------------------------------
# AttestState — the TypedDict mixin
# ---------------------------------------------------------------------------


# We use a plain TypedDict without requiring langgraph to be installed.
# Callers extend this mixin in their own state class.
try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict  # type: ignore[no-redef]


class AttestState(TypedDict, total=False):
    """TypedDict mixin that adds Attest fields to a LangGraph state.

    Extend this in your own state class::

        class MyState(AttestState):
            messages: list
            instruction: str
    """

    # Maps agent_id → raw JWT string for that agent's current credential.
    attest_tokens: dict[str, str]

    # The att_tid shared across the entire delegation tree for this task.
    attest_task_id: str | None

    # The originating human user ID (att_uid).
    attest_user_id: str | None


# ---------------------------------------------------------------------------
# attest_tool decorator
# ---------------------------------------------------------------------------


def attest_tool(
    scope: str,
    agent_id: str | None = None,
) -> Callable:
    """Decorator that enforces Attest scope before executing a tool function.

    The decorated function must accept ``state`` as its first positional
    argument (or as a keyword argument).  The decorator reads
    ``state["attest_tokens"]`` to find the credential for *agent_id* (or the
    agent derived from the state), decodes it without signature verification
    (the credential was already verified on issue/delegate), and checks that
    *scope* is covered.

    Parameters
    ----------
    scope:
        Required scope string, e.g. ``"gmail:send"``.
    agent_id:
        Optional explicit agent ID to look up in ``attest_tokens``.  If
        omitted the decorator tries ``state.get("attest_agent_id")`` and
        finally falls back to the first key in ``attest_tokens``.

    Raises
    ------
    AttestScopeError
        If the credential does not cover *scope*.
    RuntimeError
        If no credential can be found for the resolved agent.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            state = _extract_state(fn, args, kwargs)
            _enforce_scope(fn.__name__, state, scope, agent_id)
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args: object, **kwargs: object) -> object:
            state = _extract_state(fn, args, kwargs)
            _enforce_scope(fn.__name__, state, scope, agent_id)
            return await fn(*args, **kwargs)

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return wrapper

    return decorator


def _extract_state(fn: Callable, args: tuple, kwargs: dict) -> dict:
    """Pull the ``state`` argument out of positional or keyword args."""
    sig = inspect.signature(fn)
    params = list(sig.parameters.keys())

    # Check keyword args first.
    if "state" in kwargs:
        state = kwargs["state"]
        if isinstance(state, dict):
            return state

    # Then check positional.
    if params and args:
        first_param = params[0]
        if first_param == "state" and isinstance(args[0], dict):
            return args[0]
        # Sometimes state is the second arg when `self` is first.
        if first_param == "self" and len(params) > 1 and len(args) > 1:
            if isinstance(args[1], dict):
                return args[1]

    raise RuntimeError(
        f"attest_tool: could not find a 'state' dict argument in call to '{fn.__name__}'. "
        "Ensure the decorated function accepts 'state' as its first argument."
    )


def _check_token_scope(
    tool_name: str,
    token_str: str,
    required_scope: str,
    agent_label: str,
) -> None:
    """Decode *token_str* and raise AttestScopeError if *required_scope* is not covered."""
    import jwt as _jwt  # lazy import

    try:
        payload: dict = _jwt.decode(
            token_str,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=["RS256"],
        )
        claims = AttestClaims.from_dict(payload)
    except Exception as exc:
        raise RuntimeError(
            f"attest_tool: failed to decode credential for '{agent_label}': {exc}"
        ) from exc

    if not is_subset(claims.att_scope, [required_scope]):
        raise AttestScopeError(
            tool=tool_name,
            required_scope=required_scope,
            granted_scope=claims.att_scope,
            jti=claims.jti,
        )


def _enforce_scope(
    tool_name: str,
    state: dict,
    required_scope: str,
    explicit_agent_id: str | None,
) -> None:
    """Check that *required_scope* is covered by the credential in *state*.

    Checks the ambient ContextVar first (set by AttestStateGraph), then falls
    back to ``state["attest_tokens"]``.  Raises AttestScopeError if not covered.
    """
    # Fast path: AttestStateGraph injects the token via ContextVar.
    ambient = current_attest_token.get()
    if ambient is not None:
        _check_token_scope(tool_name, ambient, required_scope, agent_label="<ambient>")
        return

    tokens: dict[str, str] = state.get("attest_tokens") or {}

    resolved_agent_id = _resolve_agent_id(state, tokens, explicit_agent_id)

    token_str = tokens.get(resolved_agent_id)
    if not token_str:
        raise RuntimeError(
            f"attest_tool: no credential found for agent '{resolved_agent_id}' "
            f"in state['attest_tokens']"
        )

    _check_token_scope(tool_name, token_str, required_scope, agent_label=resolved_agent_id)


def _resolve_agent_id(
    state: dict,
    tokens: dict[str, str],
    explicit_agent_id: str | None,
) -> str:
    """Return the agent ID to use for scope enforcement."""
    if explicit_agent_id:
        return explicit_agent_id

    # Allow state to carry a hint.
    hint = state.get("attest_agent_id")
    if isinstance(hint, str) and hint:
        return hint

    # Fall back to the only available token.
    if len(tokens) == 1:
        return next(iter(tokens))

    raise RuntimeError(
        "attest_tool: multiple agent credentials are present in state['attest_tokens'] "
        "but no agent_id was specified. Pass agent_id= to @attest_tool."
    )


# ---------------------------------------------------------------------------
# AttestNodes — factory for LangGraph node callables
# ---------------------------------------------------------------------------


class AttestNodes:
    """Factory class that produces LangGraph node callables.

    Each static method returns a ``Callable[[dict], dict]`` suitable for use
    as a LangGraph node function.  The returned callable merges Attest
    credential data into the graph state.
    """

    @staticmethod
    def issue(
        client: AttestClient,
        agent_id: str,
        scope: list[str],
        instruction_key: str = "instruction",
        user_id_key: str = "user_id",
        ttl_seconds: int | None = None,
    ) -> Callable[[dict], dict]:
        """Return a node that issues a root credential and stores it in state.

        The node reads ``state[instruction_key]`` and ``state[user_id_key]``
        to obtain the instruction and user ID, then stores the resulting JWT
        in ``state["attest_tokens"][agent_id]`` and sets
        ``state["attest_task_id"]`` and ``state["attest_user_id"]``.

        Parameters
        ----------
        client:
            A ``AttestClient`` instance.
        agent_id:
            The issuing agent's ID.
        scope:
            List of ``"resource:action"`` scope strings for the root credential.
        instruction_key:
            Key in the state dict that holds the task instruction string.
        user_id_key:
            Key in the state dict that holds the human user ID.
        ttl_seconds:
            Optional TTL for the credential.
        """

        def node(state: dict) -> dict:
            instruction: str = state.get(instruction_key) or ""
            user_id: str = state.get(user_id_key) or ""

            params = IssueParams(
                agent_id=agent_id,
                user_id=user_id,
                scope=scope,
                instruction=instruction,
                ttl_seconds=ttl_seconds,
            )
            wt = client.issue(params)

            existing_tokens: dict[str, str] = dict(state.get("attest_tokens") or {})
            existing_tokens[agent_id] = wt.token

            return {
                "attest_tokens": existing_tokens,
                "attest_task_id": wt.claims.att_tid,
                "attest_user_id": wt.claims.att_uid,
            }

        return node

    @staticmethod
    def delegate(
        client: AttestClient,
        parent_agent_id: str,
        child_agent_id: str,
        child_scope: list[str],
        ttl_seconds: int | None = None,
    ) -> Callable[[dict], dict]:
        """Return a node that delegates from a parent agent to a child agent.

        Reads ``state["attest_tokens"][parent_agent_id]`` to obtain the
        parent JWT, issues a delegated child credential, and stores it in
        ``state["attest_tokens"][child_agent_id]``.

        Parameters
        ----------
        client:
            A ``AttestClient`` instance.
        parent_agent_id:
            The delegating (parent) agent's ID.
        child_agent_id:
            The receiving (child) agent's ID.
        child_scope:
            Narrowed scope for the child credential.
        ttl_seconds:
            Optional TTL cap for the child credential.
        """

        def node(state: dict) -> dict:
            tokens: dict[str, str] = state.get("attest_tokens") or {}
            parent_token = tokens.get(parent_agent_id)
            if not parent_token:
                raise RuntimeError(
                    f"AttestNodes.delegate: no credential found for parent agent "
                    f"'{parent_agent_id}' in state['attest_tokens']"
                )

            params = DelegateParams(
                parent_token=parent_token,
                child_agent=child_agent_id,
                child_scope=child_scope,
                ttl_seconds=ttl_seconds,
            )
            dt = client.delegate(params)

            updated_tokens = dict(tokens)
            updated_tokens[child_agent_id] = dt.token

            return {"attest_tokens": updated_tokens}

        return node

    @staticmethod
    def revoke(
        client: AttestClient,
        agent_id: str,
        revoked_by: str = "langgraph",
    ) -> Callable[[dict], dict]:
        """Return a node that revokes the given agent's credential.

        Reads ``state["attest_tokens"][agent_id]``, decodes the JTI, calls
        the server revocation endpoint, and removes the token from state.

        Parameters
        ----------
        client:
            A ``AttestClient`` instance.
        agent_id:
            The agent whose credential should be revoked.
        revoked_by:
            Attribution string recorded in the audit log.
        """

        def node(state: dict) -> dict:
            tokens: dict[str, str] = dict(state.get("attest_tokens") or {})
            token_str = tokens.get(agent_id)
            if not token_str:
                # Nothing to revoke — return state unchanged.
                return {}

            import jwt as _jwt  # lazy import

            try:
                payload: dict = _jwt.decode(
                    token_str,
                    options={"verify_signature": False, "verify_exp": False},
                    algorithms=["RS256"],
                )
                jti: str = payload["jti"]
            except Exception as exc:
                raise RuntimeError(
                    f"AttestNodes.revoke: failed to decode token for agent '{agent_id}': {exc}"
                ) from exc

            client.revoke(jti, revoked_by=revoked_by)

            tokens.pop(agent_id, None)
            return {"attest_tokens": tokens}

        return node


# ---------------------------------------------------------------------------
# AttestStateGraph — drop-in StateGraph replacement with automatic delegation
# ---------------------------------------------------------------------------


class AttestStateGraph:
    """Drop-in replacement for ``langgraph.graph.StateGraph`` that automatically
    issues a delegated Attest credential before every node executes.

    This is the recommended integration for **dynamic** agent systems where the
    LLM decides at runtime which node/agent to invoke.  You do not need to add
    explicit ``AttestNodes.delegate`` nodes — delegation happens transparently
    as the graph routes between nodes.

    How it works
    ------------
    ``add_node`` is overridden.  Each registered node function is wrapped with a
    closure that:

    1. Reads the root/parent credential from ``state["attest_tokens"]`` (uses
       the first available token, or the ``attest_root_agent_id`` hint in state).
    2. Calls ``client.delegate()`` with the scope resolved for *node_name* from
       ``scope_map`` (or auto-derived as ``["tool:<node_name>"]``).
    3. Sets ``current_attest_token`` ContextVar so ``@attest_tool`` decorators
       pick it up without needing ``agent_id=`` specified.
    4. Stores the child JWT in ``state["attest_tokens"][node_name]`` for
       downstream nodes and audit queries.
    5. Resets the ContextVar after the node returns.

    Parameters
    ----------
    state_schema:
        The state TypedDict class — forwarded to the underlying ``StateGraph``.
    client:
        A sync ``AttestClient`` used to call ``delegate()``.
    scope_map:
        Optional explicit mapping of node name → scope list.
        Nodes not in the map get ``["tool:<node_name>"]`` as their scope.
    parent_agent_id:
        Optional explicit key to use when looking up the parent token in
        ``state["attest_tokens"]``.  If omitted, the first token found is used.
    skip_nodes:
        Set of node names that should NOT receive automatic delegation (e.g. the
        root issuer node itself).  Defaults to ``{"__start__", "issue"}``.
    **kwargs:
        Any additional keyword arguments are forwarded to ``StateGraph.__init__``.

    Example::

        from attest.integrations.langgraph import AttestStateGraph

        graph = AttestStateGraph(
            MyState,
            client=client,
            scope_map={
                "researcher": ["research:read"],
                "emailer":    ["gmail:send"],
            },
        )
        graph.add_node("orchestrator", orchestrator_fn)
        graph.add_node("researcher", researcher_fn)
        graph.add_node("emailer", emailer_fn)
        # ... add_edge, compile, etc. — identical to StateGraph
    """

    def __init__(
        self,
        state_schema: Any,
        client: AttestClient,
        scope_map: dict[str, list[str]] | None = None,
        parent_agent_id: str | None = None,
        skip_nodes: set[str] | None = None,
        **kwargs: Any,
    ) -> None:
        # Lazy import — langgraph not required for the base SDK.
        try:
            from langgraph.graph import StateGraph as _StateGraph  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "AttestStateGraph requires langgraph. "
                "Install it with: pip install langgraph"
            ) from exc

        self._graph = _StateGraph(state_schema, **kwargs)
        self._client = client
        self._scope_map = scope_map or {}
        self._parent_agent_id = parent_agent_id
        self._skip_nodes: set[str] = skip_nodes if skip_nodes is not None else {"__start__", "issue"}

    # ------------------------------------------------------------------
    # The one override that matters
    # ------------------------------------------------------------------

    def add_node(self, node_name: str, fn: Callable, **kwargs: Any) -> "AttestStateGraph":
        """Register *fn* as node *node_name*, wrapping it with Attest delegation."""
        if node_name in self._skip_nodes:
            self._graph.add_node(node_name, fn, **kwargs)
            return self

        wrapped = self._wrap_node(node_name, fn)
        self._graph.add_node(node_name, wrapped, **kwargs)
        return self

    # ------------------------------------------------------------------
    # Delegation wrapper factory
    # ------------------------------------------------------------------

    def _wrap_node(self, node_name: str, fn: Callable) -> Callable:
        client = self._client
        scope = self._scope_map.get(node_name) or [f"tool:{node_name}"]
        parent_agent_id = self._parent_agent_id

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapped(state: dict, *args: Any, **kwargs: Any) -> Any:
                token_str = _pick_parent_token(state, parent_agent_id)
                if token_str:
                    import asyncio as _asyncio
                    dt = await _asyncio.to_thread(
                        client.delegate,
                        DelegateParams(
                            parent_token=token_str,
                            child_agent=node_name,
                            child_scope=scope,
                        ),
                    )
                    child_token = dt.token
                    # Merge into state so downstream nodes can see it.
                    updated_tokens = dict(state.get("attest_tokens") or {})
                    updated_tokens[node_name] = child_token
                    state = {**state, "attest_tokens": updated_tokens}
                    tok_var = current_attest_token.set(child_token)
                    try:
                        result = await fn(state, *args, **kwargs)
                    finally:
                        current_attest_token.reset(tok_var)
                    # Propagate updated tokens into the result dict if possible.
                    if isinstance(result, dict):
                        result.setdefault("attest_tokens", updated_tokens)
                    return result
                return await fn(state, *args, **kwargs)

            return async_wrapped

        @functools.wraps(fn)
        def sync_wrapped(state: dict, *args: Any, **kwargs: Any) -> Any:
            token_str = _pick_parent_token(state, parent_agent_id)
            if token_str:
                dt = client.delegate(
                    DelegateParams(
                        parent_token=token_str,
                        child_agent=node_name,
                        child_scope=scope,
                    )
                )
                child_token = dt.token
                updated_tokens = dict(state.get("attest_tokens") or {})
                updated_tokens[node_name] = child_token
                state = {**state, "attest_tokens": updated_tokens}
                tok_var = current_attest_token.set(child_token)
                try:
                    result = fn(state, *args, **kwargs)
                finally:
                    current_attest_token.reset(tok_var)
                if isinstance(result, dict):
                    result.setdefault("attest_tokens", updated_tokens)
                return result
            return fn(state, *args, **kwargs)

        return sync_wrapped

    # ------------------------------------------------------------------
    # Proxy everything else to the underlying StateGraph
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        # Delegate attribute access to the wrapped StateGraph so callers
        # can use add_edge, compile, set_entry_point, etc. without change.
        return getattr(self._graph, name)


def _pick_parent_token(state: dict, explicit_agent_id: str | None) -> str | None:
    """Return the best available parent token from *state*, or ``None``."""
    tokens: dict[str, str] = state.get("attest_tokens") or {}
    if not tokens:
        return None
    if explicit_agent_id:
        return tokens.get(explicit_agent_id)
    # Prefer hint from state.
    hint = state.get("attest_root_agent_id")
    if isinstance(hint, str) and hint and hint in tokens:
        return tokens[hint]
    # Fall back to first token.
    return next(iter(tokens.values()))
