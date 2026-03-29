"""Anthropic SDK integration for Attest.

Provides session context managers that issue a root Attest credential on entry
and revoke it on exit.  Because the Anthropic Python SDK has no native handoff
hook, delegation is manual — callers use ``session.delegate()`` to produce child
credentials for sub-agents spawned via tool calls.

Usage::

    import anthropic
    from attest import AttestClient
    from attest.integrations.anthropic_sdk import AttestSession, attest_tool_anthropic

    attest = AttestClient(base_url="...", api_key="...")

    with AttestSession(
        client=attest,
        agent_id="claude-orchestrator",
        user_id="usr_alice",
        scope=["files:*", "web:read", "shell:exec"],
        instruction="refactor the auth module",
        system_prompt=SYSTEM_PROMPT,   # auto-computes att_ack checksum
    ) as session:

        @attest_tool_anthropic(scope="web:read")
        def search_web(query: str) -> str: ...

        def spawn_coder(task: str) -> str:
            child = session.delegate("coder-agent", ["files:write", "shell:exec"])
            return run_coder_agent(child.token, task)

        anthropic.Anthropic().messages.create(
            model="claude-opus-4-6",
            tools=[search_web, spawn_coder],
            messages=[{"role": "user", "content": "refactor the auth module"}],
        )
    # root + all delegated children revoked here
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import time
import warnings
from typing import Any

from attest.checksum import compute_agent_checksum
from attest.client import (
    AsyncAttestClient,
    AttestApprovalDenied,
    AttestApprovalTimeout,
    AttestClient,
    AttestScopeError,
)
from attest.scope import is_subset
from attest.types import AttestClaims, AttestToken, DelegateParams, DelegatedToken, IssueParams

# ---------------------------------------------------------------------------
# ContextVar — ambient session for the currently executing Attest context.
# Set by AttestSession.__enter__ / AsyncAttestSession.__aenter__.
# Readable from tool functions without threading arguments.
# ---------------------------------------------------------------------------

#: Holds the active ``AttestSession | AsyncAttestSession`` for the current
#: execution context.  ``None`` when no session is on the call stack.
current_attest_session: contextvars.ContextVar[
    "AttestSession | AsyncAttestSession | None"
] = contextvars.ContextVar("attest_current_session", default=None)


# ---------------------------------------------------------------------------
# AttestSession — sync context manager
# ---------------------------------------------------------------------------


class AttestSession:
    """Sync context manager that issues a root Attest credential on entry.

    On exit the credential (and all its delegated descendants) is revoked,
    unless ``revoke_on_exit=False``.

    The session's token is accessible via ``session.token``, the task ID via
    ``session.task_id``, and the decoded claims via ``session.claims`` — all
    of which raise ``RuntimeError`` if accessed outside the ``with`` block.

    The active session is also stored in the ambient ``current_attest_session``
    ContextVar so ``@attest_tool_anthropic`` decorators can reach it from
    anywhere on the call stack without threading arguments.

    Parameters
    ----------
    client:
        A sync ``AttestClient``.
    agent_id:
        ID of the orchestrating agent that will hold the root credential.
    user_id:
        ID of the human user initiating the task.
    scope:
        List of ``"resource:action"`` scope strings for the root credential.
    instruction:
        Human-readable task instruction recorded in the credential.
    system_prompt:
        Optional system prompt.  If provided, ``agent_checksum`` is computed
        via ``compute_agent_checksum(system_prompt, tools)`` and included in
        the issue request (enables server-side prompt injection detection).
    tools:
        Optional list of tool objects included alongside ``system_prompt`` in
        the checksum.  Ignored when ``system_prompt`` is ``None``.
    ttl_seconds:
        Optional TTL cap for the root credential.
    revoke_on_exit:
        If ``True`` (default), call ``client.revoke()`` in ``__exit__``.
    revoked_by:
        Attribution string recorded in the audit log on revocation.
    """

    def __init__(
        self,
        *,
        client: AttestClient,
        agent_id: str,
        user_id: str,
        scope: list[str],
        instruction: str,
        system_prompt: str | None = None,
        tools: list[Any] | None = None,
        ttl_seconds: int | None = None,
        revoke_on_exit: bool = True,
        revoked_by: str = "anthropic-sdk",
    ) -> None:
        self._client = client
        self._agent_id = agent_id
        self._user_id = user_id
        self._scope = scope
        self._instruction = instruction
        self._system_prompt = system_prompt
        self._tools = tools
        self._ttl_seconds = ttl_seconds
        self._revoke_on_exit = revoke_on_exit
        self._revoked_by = revoked_by
        self._token_obj: AttestToken | None = None
        self._active: bool = False
        self._ctx_token: contextvars.Token | None = None  # type: ignore[type-arg]

    # ------------------------------------------------------------------
    # Context manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "AttestSession":
        agent_checksum: str | None = None
        if self._system_prompt is not None:
            agent_checksum = compute_agent_checksum(
                system_prompt=self._system_prompt,
                tools=self._tools or [],
            )

        params = IssueParams(
            agent_id=self._agent_id,
            user_id=self._user_id,
            scope=self._scope,
            instruction=self._instruction,
            ttl_seconds=self._ttl_seconds,
            agent_checksum=agent_checksum,
        )
        self._token_obj = self._client.issue(params)
        self._active = True
        self._ctx_token = current_attest_session.set(self)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Always reset the ContextVar first, then mark inactive.
        if self._ctx_token is not None:
            current_attest_session.reset(self._ctx_token)
            self._ctx_token = None

        if self._revoke_on_exit and self._token_obj is not None:
            try:
                self._client.revoke(
                    self._token_obj.claims.jti,
                    revoked_by=self._revoked_by,
                )
            except Exception as exc:
                warnings.warn(
                    f"AttestSession: revocation of {self._token_obj.claims.jti!r} "
                    f"failed: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

        self._active = False

    # ------------------------------------------------------------------
    # Public properties — only accessible inside the context
    # ------------------------------------------------------------------

    @property
    def token(self) -> str:
        """Raw JWT string for the root credential."""
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AttestSession.token accessed outside of 'with' block"
            )
        return self._token_obj.token

    @property
    def task_id(self) -> str:
        """att_tid shared across the entire delegation tree."""
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AttestSession.task_id accessed outside of 'with' block"
            )
        return self._token_obj.claims.att_tid

    @property
    def claims(self) -> AttestClaims:
        """Decoded JWT claims for the root credential."""
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AttestSession.claims accessed outside of 'with' block"
            )
        return self._token_obj.claims

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------

    def delegate(
        self,
        child_agent: str,
        child_scope: list[str],
        ttl_seconds: int | None = None,
        require_approval: bool = False,
        intent: str = "",
        poll_interval: float = 2.0,
        poll_timeout: float = 300.0,
    ) -> DelegatedToken:
        """Issue a delegated credential for a child agent.

        Parameters
        ----------
        child_agent:
            ID of the child agent that will receive the credential.
        child_scope:
            Narrowed scope for the child — must be a subset of this
            session's scope.
        ttl_seconds:
            Optional TTL cap for the delegated credential.
        require_approval:
            If ``True``, create a HITL approval challenge and poll until
            a human approves or denies it.  The resulting credential will
            carry ``att_hitl_req/uid/iss`` claims.
        intent:
            Human-readable description of what the child will do.  Shown
            in the approval UI when ``require_approval=True``.
        poll_interval:
            Seconds between polls when waiting for approval (default 2s).
        poll_timeout:
            Maximum seconds to wait for approval before raising
            ``AttestApprovalTimeout`` (default 300s / 5 min).

        Returns
        -------
        DelegatedToken

        Raises
        ------
        RuntimeError
            If called outside of the ``with`` block.
        AttestApprovalDenied
            If the human denies the approval.
        AttestApprovalTimeout
            If polling exceeds *poll_timeout*.
        """
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AttestSession.delegate() called outside of 'with' block"
            )

        if not require_approval:
            return self._client.delegate(
                DelegateParams(
                    parent_token=self._token_obj.token,
                    child_agent=child_agent,
                    child_scope=child_scope,
                    ttl_seconds=ttl_seconds,
                )
            )

        # --- HITL approval path ---
        challenge = self._client.request_approval(
            parent_token=self._token_obj.token,
            agent_id=child_agent,
            task_id=self._token_obj.claims.att_tid,
            intent=intent or f"Delegate to {child_agent}",
            requested_scope=child_scope,
        )

        # Today the external approval surface confirms the gate, then the
        # session issues a narrowed child credential to continue execution.
        # This keeps the orchestration flow simple even when the human approves
        # outside the current process.
        self._client.wait_for_approval(
            challenge.challenge_id,
            poll_interval=poll_interval,
            timeout=poll_timeout,
        )
        return self._client.delegate(
            DelegateParams(
                parent_token=self._token_obj.token,
                child_agent=child_agent,
                child_scope=child_scope,
                ttl_seconds=ttl_seconds,
            )
        )


# ---------------------------------------------------------------------------
# AsyncAttestSession — async context manager
# ---------------------------------------------------------------------------


class AsyncAttestSession:
    """Async context manager that issues a root Attest credential on entry.

    Mirrors ``AttestSession`` exactly, using ``AsyncAttestClient`` and ``await``.

    Parameters
    ----------
    client:
        An ``AsyncAttestClient``.
    agent_id, user_id, scope, instruction, system_prompt, tools,
    ttl_seconds, revoke_on_exit, revoked_by:
        See ``AttestSession``.
    """

    def __init__(
        self,
        *,
        client: AsyncAttestClient,
        agent_id: str,
        user_id: str,
        scope: list[str],
        instruction: str,
        system_prompt: str | None = None,
        tools: list[Any] | None = None,
        ttl_seconds: int | None = None,
        revoke_on_exit: bool = True,
        revoked_by: str = "anthropic-sdk",
    ) -> None:
        self._client = client
        self._agent_id = agent_id
        self._user_id = user_id
        self._scope = scope
        self._instruction = instruction
        self._system_prompt = system_prompt
        self._tools = tools
        self._ttl_seconds = ttl_seconds
        self._revoke_on_exit = revoke_on_exit
        self._revoked_by = revoked_by
        self._token_obj: AttestToken | None = None
        self._active: bool = False
        self._ctx_token: contextvars.Token | None = None  # type: ignore[type-arg]

    # ------------------------------------------------------------------
    # Async context manager protocol
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncAttestSession":
        agent_checksum: str | None = None
        if self._system_prompt is not None:
            agent_checksum = compute_agent_checksum(
                system_prompt=self._system_prompt,
                tools=self._tools or [],
            )

        params = IssueParams(
            agent_id=self._agent_id,
            user_id=self._user_id,
            scope=self._scope,
            instruction=self._instruction,
            ttl_seconds=self._ttl_seconds,
            agent_checksum=agent_checksum,
        )
        self._token_obj = await self._client.issue(params)
        self._active = True
        self._ctx_token = current_attest_session.set(self)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Always reset the ContextVar first, then mark inactive.
        if self._ctx_token is not None:
            current_attest_session.reset(self._ctx_token)
            self._ctx_token = None

        if self._revoke_on_exit and self._token_obj is not None:
            try:
                await self._client.revoke(
                    self._token_obj.claims.jti,
                    revoked_by=self._revoked_by,
                )
            except Exception as exc:
                warnings.warn(
                    f"AsyncAttestSession: revocation of {self._token_obj.claims.jti!r} "
                    f"failed: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

        self._active = False

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def token(self) -> str:
        """Raw JWT string for the root credential."""
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AsyncAttestSession.token accessed outside of 'async with' block"
            )
        return self._token_obj.token

    @property
    def task_id(self) -> str:
        """att_tid shared across the entire delegation tree."""
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AsyncAttestSession.task_id accessed outside of 'async with' block"
            )
        return self._token_obj.claims.att_tid

    @property
    def claims(self) -> AttestClaims:
        """Decoded JWT claims for the root credential."""
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AsyncAttestSession.claims accessed outside of 'async with' block"
            )
        return self._token_obj.claims

    # ------------------------------------------------------------------
    # Async delegation
    # ------------------------------------------------------------------

    async def async_delegate(
        self,
        child_agent: str,
        child_scope: list[str],
        ttl_seconds: int | None = None,
        require_approval: bool = False,
        intent: str = "",
        poll_interval: float = 2.0,
        poll_timeout: float = 300.0,
    ) -> DelegatedToken:
        """Issue a delegated credential for a child agent (async).

        Parameters
        ----------
        child_agent:
            ID of the child agent.
        child_scope:
            Narrowed scope for the child.
        ttl_seconds:
            Optional TTL cap.
        require_approval:
            If ``True``, create a HITL approval challenge and poll until
            a human approves or denies.
        intent:
            Description of the child's task (shown in approval UI).
        poll_interval:
            Seconds between polls (default 2s).
        poll_timeout:
            Max seconds to wait (default 300s).

        Returns
        -------
        DelegatedToken

        Raises
        ------
        RuntimeError
            If called outside of the ``async with`` block.
        AttestApprovalDenied
            If the approval is denied.
        AttestApprovalTimeout
            If polling exceeds *poll_timeout*.
        """
        if not self._active or self._token_obj is None:
            raise RuntimeError(
                "AsyncAttestSession.async_delegate() called outside of 'async with' block"
            )

        if not require_approval:
            return await self._client.delegate(
                DelegateParams(
                    parent_token=self._token_obj.token,
                    child_agent=child_agent,
                    child_scope=child_scope,
                    ttl_seconds=ttl_seconds,
                )
            )

        # --- HITL approval path ---
        import asyncio as _asyncio

        challenge = await self._client.request_approval(
            parent_token=self._token_obj.token,
            agent_id=child_agent,
            task_id=self._token_obj.claims.att_tid,
            intent=intent or f"Delegate to {child_agent}",
            requested_scope=child_scope,
        )

        await self._client.wait_for_approval(
            challenge.challenge_id,
            poll_interval=poll_interval,
            timeout=poll_timeout,
        )
        return await self._client.delegate(
            DelegateParams(
                parent_token=self._token_obj.token,
                child_agent=child_agent,
                child_scope=child_scope,
                ttl_seconds=ttl_seconds,
            )
        )


# ---------------------------------------------------------------------------
# attest_tool_anthropic — scope enforcement decorator
# ---------------------------------------------------------------------------


def attest_tool_anthropic(scope: str) -> Any:
    """Decorator that enforces Attest scope on an Anthropic SDK tool function.

    Reads the ambient ``current_attest_session`` ContextVar set by
    ``AttestSession.__enter__`` (or ``AsyncAttestSession.__aenter__``).
    Supports both sync and async tool functions.

    Parameters
    ----------
    scope:
        Required scope string, e.g. ``"web:read"`` or ``"files:write"``.

    Raises
    ------
    RuntimeError
        If no active ``AttestSession`` is found in the ContextVar.
    AttestScopeError
        If the session's credential does not cover *scope*.

    Example::

        @attest_tool_anthropic(scope="web:read")
        def search_web(query: str) -> str:
            ...

        @attest_tool_anthropic(scope="files:write")
        async def write_file(path: str, content: str) -> str:
            ...
    """

    def decorator(fn: Any) -> Any:
        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            _check_anthropic_scope(fn.__name__, scope)
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            _check_anthropic_scope(fn.__name__, scope)
            return await fn(*args, **kwargs)

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator


def _check_anthropic_scope(tool_name: str, required_scope: str) -> None:
    """Raise AttestScopeError if the current session's credential lacks required_scope."""
    session = current_attest_session.get()
    if session is None:
        raise RuntimeError(
            f"attest_tool_anthropic on '{tool_name}': no active AttestSession. "
            "Ensure the function is called inside a 'with AttestSession(...)' block."
        )

    import jwt as _jwt  # lazy import

    # session is guaranteed active when present in the ContextVar
    token_str: str = session._token_obj.token  # type: ignore[union-attr]

    # verify_signature=False is correct: the credential was already verified by
    # the server at issuance time; this is only a local scope-subset check.
    try:
        payload: dict = _jwt.decode(
            token_str,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=["RS256"],
        )
        claims = AttestClaims.from_dict(payload)
    except Exception as exc:
        raise RuntimeError(
            f"attest_tool_anthropic: failed to decode session credential: {exc}"
        ) from exc

    if not is_subset(claims.att_scope, [required_scope]):
        raise AttestScopeError(
            tool=tool_name,
            required_scope=required_scope,
            granted_scope=claims.att_scope,
            jti=claims.jti,
        )
