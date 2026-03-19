"""Synchronous and asynchronous Warrant API clients."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import jwt
import jwt.algorithms

from warrant.types import (
    AuditChain,
    AuditEvent,
    DelegateParams,
    DelegatedToken,
    IssueParams,
    VerifyResult,
    WarrantClaims,
    WarrantToken,
)

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WarrantError(Exception):
    """Base class for all Warrant SDK errors."""


class WarrantAPIError(WarrantError):
    """Raised when the Warrant server returns a non-2xx response."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class WarrantVerifyError(WarrantError):
    """Raised when offline JWT verification fails fatally."""


class WarrantScopeError(WarrantError):
    """Raised when a tool is invoked without sufficient scope."""

    def __init__(
        self,
        *,
        tool: str,
        required_scope: str,
        granted_scope: list[str],
        jti: str,
    ) -> None:
        self.tool = tool
        self.required_scope = required_scope
        self.granted_scope = granted_scope
        self.jti = jti
        super().__init__(
            f"Tool '{tool}' requires scope '{required_scope}'; "
            f"credential {jti} only grants {granted_scope}"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL = "http://localhost:8080"


def _raise_for_status(response: httpx.Response) -> None:
    """Raise WarrantAPIError if the response indicates failure."""
    if response.is_success:
        return
    try:
        body = response.json()
        message = body.get("error") or response.text
    except Exception:
        message = response.text or f"HTTP {response.status_code}"
    raise WarrantAPIError(response.status_code, message)


def _parse_token_response(data: dict, delegated: bool = False) -> WarrantToken | DelegatedToken:
    """Parse an issue or delegate response into the appropriate token type."""
    raw_claims = data.get("claims", {})

    # The server returns the registered claims nested under standard JWT names.
    # Map Go struct field names → claim keys.
    claims_dict = {
        "iss": raw_claims.get("iss", ""),
        "sub": raw_claims.get("sub", ""),
        "iat": _extract_numeric_date(raw_claims.get("iat")),
        "exp": _extract_numeric_date(raw_claims.get("exp")),
        "jti": raw_claims.get("jti", ""),
        "wrt_tid": raw_claims.get("wrt_tid", ""),
        "wrt_depth": raw_claims.get("wrt_depth", 0),
        "wrt_scope": raw_claims.get("wrt_scope") or [],
        "wrt_intent": raw_claims.get("wrt_intent", ""),
        "wrt_chain": raw_claims.get("wrt_chain") or [],
        "wrt_uid": raw_claims.get("wrt_uid", ""),
        "wrt_pid": raw_claims.get("wrt_pid"),
    }

    claims = WarrantClaims.from_dict(claims_dict)
    token_str: str = data["token"]

    if delegated:
        return DelegatedToken(token=token_str, claims=claims)
    return WarrantToken(token=token_str, claims=claims)


def _extract_numeric_date(v: object) -> int:
    """Extract a Unix timestamp from a JWT NumericDate value.

    The Go jwt library serialises NumericDate as ``{"time": "..."}`` in some
    contexts; in JSON responses it may also appear as a plain integer.
    """
    match v:
        case int() | float():
            return int(v)
        case {"time": str(t)}:
            # Fallback: parse RFC3339 if needed — but timestamps are simpler.
            import datetime
            dt = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
            return int(dt.timestamp())
        case _:
            return 0


def _build_public_key(jwks: dict):  # type: ignore[return]
    """Return the first RSA public key from a JWKS dict.

    Uses ``jwt.algorithms.RSAAlgorithm.from_jwk`` which is backed by the
    ``cryptography`` package (pulled in via ``pyjwt[crypto]``).
    """
    keys = jwks.get("keys", [])
    for key in keys:
        if key.get("kty") == "RSA":
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    raise WarrantVerifyError("No RSA key found in JWKS")


def _verify_token(token: str, jwks: dict) -> VerifyResult:
    """Perform offline RS256 verification, returning a VerifyResult.

    Checks performed:
    1. RS256 signature validity.
    2. Token expiry (PyJWT handles this via ``verify_exp``).
    3. ``len(wrt_chain) == wrt_depth + 1``.
    4. ``wrt_chain[-1] == jti``.
    """
    try:
        public_key = _build_public_key(jwks)
    except WarrantVerifyError as exc:
        return VerifyResult(valid=False, claims=None, warnings=[str(exc)])

    try:
        payload: dict = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        return VerifyResult(valid=False, claims=None, warnings=["token has expired"])
    except jwt.InvalidSignatureError:
        return VerifyResult(valid=False, claims=None, warnings=["invalid RS256 signature"])
    except jwt.DecodeError as exc:
        return VerifyResult(valid=False, claims=None, warnings=[f"decode error: {exc}"])
    except jwt.PyJWTError as exc:
        return VerifyResult(valid=False, claims=None, warnings=[f"jwt error: {exc}"])

    try:
        claims = WarrantClaims.from_dict(payload)
    except (KeyError, TypeError, ValueError) as exc:
        return VerifyResult(valid=False, claims=None, warnings=[f"claims parse error: {exc}"])

    warnings: list[str] = []

    expected_chain_len = claims.wrt_depth + 1
    if len(claims.wrt_chain) != expected_chain_len:
        warnings.append(
            f"chain length {len(claims.wrt_chain)} does not match "
            f"depth {claims.wrt_depth} (expected {expected_chain_len})"
        )

    if claims.wrt_chain and claims.wrt_chain[-1] != claims.jti:
        warnings.append("chain tail does not match jti")

    if warnings:
        return VerifyResult(valid=False, claims=claims, warnings=warnings)

    return VerifyResult(valid=True, claims=claims, warnings=[])


def _parse_audit_response(task_id: str, data: list[dict]) -> AuditChain:
    events = [AuditEvent.from_dict(e) for e in data]
    return AuditChain(task_id=task_id, events=events)


# ---------------------------------------------------------------------------
# Synchronous client
# ---------------------------------------------------------------------------


class WarrantClient:
    """Synchronous Warrant client backed by ``httpx``."""

    def __init__(
        self,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        api_key: str,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._http = httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0,
        )

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> "WarrantClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Credential operations
    # ------------------------------------------------------------------

    def issue(self, params: IssueParams) -> WarrantToken:
        """Issue a root credential for *agent_id*."""
        body: dict = {
            "agent_id": params.agent_id,
            "user_id": params.user_id,
            "scope": params.scope,
            "instruction": params.instruction,
        }
        if params.ttl_seconds is not None:
            body["ttl_seconds"] = params.ttl_seconds

        resp = self._http.post("/v1/credentials", json=body)
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=False)
        assert isinstance(result, WarrantToken)
        return result

    def delegate(self, params: DelegateParams) -> DelegatedToken:
        """Delegate a child credential from *params.parent_token*."""
        body: dict = {
            "parent_token": params.parent_token,
            "child_agent": params.child_agent,
            "child_scope": params.child_scope,
        }
        if params.ttl_seconds is not None:
            body["ttl_seconds"] = params.ttl_seconds

        resp = self._http.post("/v1/credentials/delegate", json=body)
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=True)
        assert isinstance(result, DelegatedToken)
        return result

    def revoke(self, jti: str, revoked_by: str = "sdk") -> None:
        """Revoke credential *jti* and all its descendants."""
        resp = self._http.request(
            "DELETE",
            f"/v1/credentials/{jti}",
            json={"revoked_by": revoked_by},
        )
        _raise_for_status(resp)

    def check_revoked(self, jti: str) -> bool:
        """Return ``True`` if credential *jti* has been revoked."""
        resp = self._http.get(f"/v1/revoked/{jti}")
        _raise_for_status(resp)
        return bool(resp.json().get("revoked", False))

    def audit(self, task_id: str) -> AuditChain:
        """Fetch the full audit chain for task tree *task_id*."""
        resp = self._http.get(f"/v1/tasks/{task_id}/audit")
        _raise_for_status(resp)
        return _parse_audit_response(task_id, resp.json())

    def fetch_jwks(self) -> dict:
        """Fetch the server's JWKS (public key set) for offline verification."""
        resp = self._http.get("/.well-known/jwks.json")
        _raise_for_status(resp)
        return resp.json()

    def verify(self, token: str, jwks: dict | None = None) -> VerifyResult:
        """Verify *token* offline using RS256.

        If *jwks* is ``None``, the JWKS is fetched from the server first.
        Checks RS256 signature, expiry, chain length, and chain tail.
        """
        resolved_jwks = jwks if jwks is not None else self.fetch_jwks()
        return _verify_token(token, resolved_jwks)


# ---------------------------------------------------------------------------
# Asynchronous client
# ---------------------------------------------------------------------------


class AsyncWarrantClient:
    """Async Warrant client backed by ``httpx.AsyncClient``."""

    def __init__(
        self,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        api_key: str,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0,
        )

    async def aclose(self) -> None:
        """Close the underlying async HTTP connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncWarrantClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Credential operations
    # ------------------------------------------------------------------

    async def issue(self, params: IssueParams) -> WarrantToken:
        """Issue a root credential for *agent_id*."""
        body: dict = {
            "agent_id": params.agent_id,
            "user_id": params.user_id,
            "scope": params.scope,
            "instruction": params.instruction,
        }
        if params.ttl_seconds is not None:
            body["ttl_seconds"] = params.ttl_seconds

        resp = await self._http.post("/v1/credentials", json=body)
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=False)
        assert isinstance(result, WarrantToken)
        return result

    async def delegate(self, params: DelegateParams) -> DelegatedToken:
        """Delegate a child credential from *params.parent_token*."""
        body: dict = {
            "parent_token": params.parent_token,
            "child_agent": params.child_agent,
            "child_scope": params.child_scope,
        }
        if params.ttl_seconds is not None:
            body["ttl_seconds"] = params.ttl_seconds

        resp = await self._http.post("/v1/credentials/delegate", json=body)
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=True)
        assert isinstance(result, DelegatedToken)
        return result

    async def revoke(self, jti: str, revoked_by: str = "sdk") -> None:
        """Revoke credential *jti* and all its descendants."""
        resp = await self._http.request(
            "DELETE",
            f"/v1/credentials/{jti}",
            json={"revoked_by": revoked_by},
        )
        _raise_for_status(resp)

    async def check_revoked(self, jti: str) -> bool:
        """Return ``True`` if credential *jti* has been revoked."""
        resp = await self._http.get(f"/v1/revoked/{jti}")
        _raise_for_status(resp)
        return bool(resp.json().get("revoked", False))

    async def audit(self, task_id: str) -> AuditChain:
        """Fetch the full audit chain for task tree *task_id*."""
        resp = await self._http.get(f"/v1/tasks/{task_id}/audit")
        _raise_for_status(resp)
        return _parse_audit_response(task_id, resp.json())

    async def fetch_jwks(self) -> dict:
        """Fetch the server's JWKS (public key set) for offline verification."""
        resp = await self._http.get("/.well-known/jwks.json")
        _raise_for_status(resp)
        return resp.json()

    async def verify(self, token: str, jwks: dict | None = None) -> VerifyResult:
        """Verify *token* offline using RS256.

        If *jwks* is ``None``, the JWKS is fetched from the server first.
        Checks RS256 signature, expiry, chain length, and chain tail.
        """
        resolved_jwks = jwks if jwks is not None else await self.fetch_jwks()
        return _verify_token(token, resolved_jwks)
