"""Synchronous and asynchronous Attest API clients."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import urllib.parse
import httpx
import jwt
import jwt.algorithms

from attest.types import (
    ApprovalChallenge,
    ApprovalStatus,
    AuditChain,
    AuditEvent,
    DelegateParams,
    DelegatedToken,
    IssueParams,
    VerifyResult,
    AttestClaims,
    AttestToken,
    EvidencePacket,
    EvidencePacketVerifyResult,
)
from attest.verifier import AttestVerifier

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AttestError(Exception):
    """Base class for all Attest SDK errors."""


class AttestAPIError(AttestError):
    """Raised when the Attest server returns a non-2xx response."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class AttestVerifyError(AttestError):
    """Raised when offline JWT verification fails fatally."""


class AttestScopeError(AttestError):
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


class AttestApprovalDenied(AttestError):
    """Raised when a HITL approval challenge is denied."""

    def __init__(self, challenge_id: str) -> None:
        self.challenge_id = challenge_id
        super().__init__(f"Approval {challenge_id} was denied")


class AttestApprovalTimeout(AttestError):
    """Raised when polling for HITL approval exceeds the timeout."""

    def __init__(self, challenge_id: str, timeout: float) -> None:
        self.challenge_id = challenge_id
        self.timeout = timeout
        super().__init__(f"Approval {challenge_id} timed out after {timeout}s")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL = "http://localhost:8080"


def _raise_for_status(response: httpx.Response) -> None:
    """Raise AttestAPIError if the response indicates failure."""
    if response.is_success:
        return
    try:
        body = response.json()
        message = body.get("error") or response.text
    except Exception:
        message = response.text or f"HTTP {response.status_code}"
    raise AttestAPIError(response.status_code, message)


def _parse_token_response(data: dict, delegated: bool = False) -> AttestToken | DelegatedToken:
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
        "att_tid": raw_claims.get("att_tid", ""),
        "att_depth": raw_claims.get("att_depth", 0),
        "att_scope": raw_claims.get("att_scope") or [],
        "att_intent": raw_claims.get("att_intent", ""),
        "att_chain": raw_claims.get("att_chain") or [],
        "att_uid": raw_claims.get("att_uid", ""),
        "att_pid": raw_claims.get("att_pid"),
        "att_ack": raw_claims.get("att_ack"),
        "att_idp_iss": raw_claims.get("att_idp_iss"),
        "att_idp_sub": raw_claims.get("att_idp_sub"),
        "att_hitl_req": raw_claims.get("att_hitl_req"),
        "att_hitl_uid": raw_claims.get("att_hitl_uid"),
        "att_hitl_iss": raw_claims.get("att_hitl_iss"),
    }

    claims = AttestClaims.from_dict(claims_dict)
    token_str: str = data["token"]

    if delegated:
        return DelegatedToken(token=token_str, claims=claims)
    return AttestToken(token=token_str, claims=claims)


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
    raise AttestVerifyError("No RSA key found in JWKS")


def _verify_token(token: str, jwks: dict) -> VerifyResult:
    """Perform offline RS256 verification, returning a VerifyResult.

    Checks performed:
    1. RS256 signature validity.
    2. Token expiry (PyJWT handles this via ``verify_exp``).
    3. ``len(att_chain) == att_depth + 1``.
    4. ``att_chain[-1] == jti``.
    """
    try:
        public_key = _build_public_key(jwks)
    except AttestVerifyError as exc:
        return VerifyResult(valid=False, claims=None, warnings=[str(exc)])

    try:
        payload: dict = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"require": ["exp", "jti"]},
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
        claims = AttestClaims.from_dict(payload)
    except (KeyError, TypeError, ValueError) as exc:
        return VerifyResult(valid=False, claims=None, warnings=[f"claims parse error: {exc}"])

    warnings: list[str] = []

    expected_chain_len = claims.att_depth + 1
    if len(claims.att_chain) != expected_chain_len:
        warnings.append(
            f"chain length {len(claims.att_chain)} does not match "
            f"depth {claims.att_depth} (expected {expected_chain_len})"
        )

    if claims.att_chain and claims.att_chain[-1] != claims.jti:
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


class AttestClient:
    """Synchronous Attest client backed by ``httpx``."""

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

    def __enter__(self) -> "AttestClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Credential operations
    # ------------------------------------------------------------------

    def issue(self, params: IssueParams) -> AttestToken:
        """Issue a root credential for *agent_id*."""
        body: dict = {
            "agent_id": params.agent_id,
            "user_id": params.user_id,
            "scope": params.scope,
            "instruction": params.instruction,
        }
        if params.ttl_seconds is not None:
            body["ttl_seconds"] = params.ttl_seconds
        if params.agent_checksum is not None:
            body["agent_checksum"] = params.agent_checksum
        if params.id_token is not None:
            body["id_token"] = params.id_token

        resp = self._http.post("/v1/credentials", json=body)
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=False)
        assert isinstance(result, AttestToken)
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

    def request_approval(
        self,
        parent_token: str,
        agent_id: str,
        task_id: str,
        intent: str,
        requested_scope: list[str],
    ) -> ApprovalChallenge:
        """Request human approval for a high-risk delegation."""
        body = {
            "parent_token": parent_token,
            "agent_id": agent_id,
            "att_tid": task_id,
            "intent": intent,
            "requested_scope": requested_scope,
        }
        resp = self._http.post("/v1/approvals", json=body)
        _raise_for_status(resp)
        data = resp.json()
        return ApprovalChallenge(
            challenge_id=data["challenge_id"],
            status=data["status"],
        )

    def grant_approval(self, challenge_id: str, id_token: str) -> DelegatedToken:
        """Grant a pending approval challenge using an OIDC identity token.

        Returns the delegated credential issued by the server with HITL claims
        (``att_hitl_req``, ``att_hitl_uid``, ``att_hitl_iss``) baked in.
        """
        cid = urllib.parse.quote(challenge_id)
        resp = self._http.post(f"/v1/approvals/{cid}/grant", json={"id_token": id_token})
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=True)
        assert isinstance(result, DelegatedToken)
        return result

    def get_approval(self, challenge_id: str) -> ApprovalStatus:
        """Get the full status of an approval challenge."""
        cid = urllib.parse.quote(challenge_id)
        resp = self._http.get(f"/v1/approvals/{cid}")
        _raise_for_status(resp)
        return ApprovalStatus.from_dict(resp.json())

    def deny_approval(self, challenge_id: str) -> ApprovalStatus:
        """Deny an approval challenge and return the resolved status."""
        cid = urllib.parse.quote(challenge_id)
        resp = self._http.post(f"/v1/approvals/{cid}/deny", json={})
        _raise_for_status(resp)
        return ApprovalStatus.from_dict(resp.json())

    def wait_for_approval(
        self,
        challenge_id: str,
        *,
        poll_interval: float = 2.0,
        timeout: float = 300.0,
    ) -> ApprovalStatus:
        """Poll an approval challenge until it resolves or times out."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.get_approval(challenge_id)
            if status.status == "approved":
                return status
            if status.status in ("rejected", "expired"):
                raise AttestApprovalDenied(challenge_id)
            time.sleep(poll_interval)

        raise AttestApprovalTimeout(challenge_id, timeout)

    def revoke(self, jti: str, revoked_by: str | None = None) -> None:
        """Revoke a credential by its JTI."""
        qjti = urllib.parse.quote(jti)
        resp = self._http.request(
            "DELETE",
            f"/v1/credentials/{qjti}",
            json={"revoked_by": revoked_by},
        )
        _raise_for_status(resp)

    def is_revoked(self, jti: str) -> bool:
        """Check if a credential has been revoked."""
        qjti = urllib.parse.quote(jti)
        resp = self._http.get(f"/v1/revoked/{qjti}")
        _raise_for_status(resp)
        return bool(resp.json().get("revoked", False))

    def report_action(
        self,
        token: str,
        tool: str,
        outcome: str,
        meta: dict[str, str] | None = None,
    ) -> None:
        """Report an action outcome against a credential for the audit trail."""
        body: dict = {"token": token, "tool": tool, "outcome": outcome}
        if meta:
            body["meta"] = meta
        resp = self._http.post("/v1/audit/report", json=body)
        _raise_for_status(resp)

    def report_status(
        self,
        token: str,
        status: str,
        meta: dict[str, str] | None = None,
    ) -> None:
        """Report an agent lifecycle event (started, completed, failed)."""
        body: dict = {"token": token, "status": status}
        if meta:
            body["meta"] = meta
        resp = self._http.post("/v1/audit/status", json=body)
        _raise_for_status(resp)

    def audit_log(self, task_id: str) -> AuditChain:
        """Retrieve the cryptographic audit chain for a given task ID."""
        tid = urllib.parse.quote(task_id)
        resp = self._http.get(f"/v1/tasks/{tid}/audit")
        _raise_for_status(resp)
        return _parse_audit_response(task_id, resp.json())

    def fetch_jwks(self, org_id: str) -> dict:
        """Fetch the server's JWKS (public key set) for offline verification."""
        qorg_id = urllib.parse.quote(org_id)
        resp = self._http.get(f"/orgs/{qorg_id}/jwks.json")
        _raise_for_status(resp)
        return resp.json()

    def fetch_evidence(self, task_id: str) -> EvidencePacket:
        """Fetch the canonical evidence packet for a task tree."""
        tid = urllib.parse.quote(task_id)
        resp = self._http.get(f"/v1/tasks/{tid}/evidence")
        _raise_for_status(resp)
        return EvidencePacket.from_dict(resp.json())

    def verify(self, token: str, org_id: str | None = None, jwks: dict | None = None) -> VerifyResult:
        """Verify *token* offline using RS256.

        If *jwks* is ``None``, the JWKS is fetched from the server first
        (requires *org_id*).
        Checks RS256 signature, expiry, chain length, and chain tail.
        """
        if jwks is None:
            if org_id is None:
                raise AttestError("org_id is required when jwks is not provided")
            jwks = self.fetch_jwks(org_id)
        return _verify_token(token, jwks)

    def verify_evidence_packet(
        self,
        packet: EvidencePacket | dict,
        *,
        org_id: str | None = None,
        jwks: dict | None = None,
    ) -> EvidencePacketVerifyResult:
        """Verify a signed evidence packet offline using the org JWKS."""
        if jwks is None:
            if org_id is None:
                if isinstance(packet, EvidencePacket):
                    org_id = packet.org.id
                elif isinstance(packet, dict):
                    org_id = str(packet.get("org", {}).get("id", "") or "")
            if not org_id:
                raise AttestError("org_id is required when jwks is not provided")
            jwks = self.fetch_jwks(org_id)

        verifier = AttestVerifier(org_id=org_id or "", base_url=self._base_url)
        return verifier.verify_evidence_packet(packet, jwks=jwks)


# ---------------------------------------------------------------------------
# Asynchronous client
# ---------------------------------------------------------------------------


class AsyncAttestClient:
    """Async Attest client backed by ``httpx.AsyncClient``."""

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

    async def __aenter__(self) -> "AsyncAttestClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Credential operations
    # ------------------------------------------------------------------

    async def issue(self, params: IssueParams) -> AttestToken:
        """Issue a root credential for *agent_id*."""
        body: dict = {
            "agent_id": params.agent_id,
            "user_id": params.user_id,
            "scope": params.scope,
            "instruction": params.instruction,
        }
        if params.ttl_seconds is not None:
            body["ttl_seconds"] = params.ttl_seconds
        if params.agent_checksum is not None:
            body["agent_checksum"] = params.agent_checksum
        if params.id_token is not None:
            body["id_token"] = params.id_token

        resp = await self._http.post("/v1/credentials", json=body)
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=False)
        assert isinstance(result, AttestToken)
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

    async def request_approval(
        self,
        parent_token: str,
        agent_id: str,
        task_id: str,
        intent: str,
        requested_scope: list[str],
    ) -> ApprovalChallenge:
        """Request human approval for a high-risk delegation."""
        body = {
            "parent_token": parent_token,
            "agent_id": agent_id,
            "att_tid": task_id,
            "intent": intent,
            "requested_scope": requested_scope,
        }
        resp = await self._http.post("/v1/approvals", json=body)
        _raise_for_status(resp)
        data = resp.json()
        return ApprovalChallenge(
            challenge_id=data["challenge_id"],
            status=data["status"],
        )

    async def grant_approval(self, challenge_id: str, id_token: str) -> DelegatedToken:
        """Grant a pending approval challenge using an OIDC identity token.

        Returns the delegated credential issued by the server with HITL claims
        (``att_hitl_req``, ``att_hitl_uid``, ``att_hitl_iss``) baked in.
        """
        cid = urllib.parse.quote(challenge_id)
        resp = await self._http.post(f"/v1/approvals/{cid}/grant", json={"id_token": id_token})
        _raise_for_status(resp)
        result = _parse_token_response(resp.json(), delegated=True)
        assert isinstance(result, DelegatedToken)
        return result

    async def get_approval(self, challenge_id: str) -> ApprovalStatus:
        """Get the full status of an approval challenge."""
        cid = urllib.parse.quote(challenge_id)
        resp = await self._http.get(f"/v1/approvals/{cid}")
        _raise_for_status(resp)
        return ApprovalStatus.from_dict(resp.json())

    async def deny_approval(self, challenge_id: str) -> ApprovalStatus:
        """Deny an approval challenge and return the resolved status."""
        cid = urllib.parse.quote(challenge_id)
        resp = await self._http.post(f"/v1/approvals/{cid}/deny", json={})
        _raise_for_status(resp)
        return ApprovalStatus.from_dict(resp.json())

    async def wait_for_approval(
        self,
        challenge_id: str,
        *,
        poll_interval: float = 2.0,
        timeout: float = 300.0,
    ) -> ApprovalStatus:
        """Poll an approval challenge until it resolves or times out."""
        import asyncio as _asyncio

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = await self.get_approval(challenge_id)
            if status.status == "approved":
                return status
            if status.status in ("rejected", "expired"):
                raise AttestApprovalDenied(challenge_id)
            await _asyncio.sleep(poll_interval)

        raise AttestApprovalTimeout(challenge_id, timeout)

    async def revoke(self, jti: str, revoked_by: str | None = None) -> None:
        """Revoke a credential by its JTI."""
        qjti = urllib.parse.quote(jti)
        resp = await self._http.request(
            "DELETE",
            f"/v1/credentials/{qjti}",
            json={"revoked_by": revoked_by},
        )
        _raise_for_status(resp)

    async def is_revoked(self, jti: str) -> bool:
        """Check if a credential has been revoked."""
        qjti = urllib.parse.quote(jti)
        resp = await self._http.get(f"/v1/revoked/{qjti}")
        _raise_for_status(resp)
        return bool(resp.json().get("revoked", False))

    async def report_action(
        self,
        token: str,
        tool: str,
        outcome: str,
        meta: dict[str, str] | None = None,
    ) -> None:
        """Report an action outcome against a credential for the audit trail."""
        body: dict = {"token": token, "tool": tool, "outcome": outcome}
        if meta:
            body["meta"] = meta
        resp = await self._http.post("/v1/audit/report", json=body)
        _raise_for_status(resp)

    async def report_status(
        self,
        token: str,
        status: str,
        meta: dict[str, str] | None = None,
    ) -> None:
        """Report an agent lifecycle event (started, completed, failed)."""
        body: dict = {"token": token, "status": status}
        if meta:
            body["meta"] = meta
        resp = await self._http.post("/v1/audit/status", json=body)
        _raise_for_status(resp)

    async def audit_log(self, task_id: str) -> AuditChain:
        """Retrieve the cryptographic audit chain for a given task ID."""
        tid = urllib.parse.quote(task_id)
        resp = await self._http.get(f"/v1/tasks/{tid}/audit")
        _raise_for_status(resp)
        return _parse_audit_response(task_id, resp.json())

    async def fetch_jwks(self, org_id: str) -> dict:
        """Fetch the server's JWKS (public key set) for offline verification."""
        qorg_id = urllib.parse.quote(org_id)
        resp = await self._http.get(f"/orgs/{qorg_id}/jwks.json")
        _raise_for_status(resp)
        return resp.json()

    async def fetch_evidence(self, task_id: str) -> EvidencePacket:
        """Fetch the canonical evidence packet for a task tree."""
        tid = urllib.parse.quote(task_id)
        resp = await self._http.get(f"/v1/tasks/{tid}/evidence")
        _raise_for_status(resp)
        return EvidencePacket.from_dict(resp.json())

    async def verify(self, token: str, org_id: str | None = None, jwks: dict | None = None) -> VerifyResult:
        """Verify *token* offline using RS256.

        If *jwks* is ``None``, the JWKS is fetched from the server first
        (requires *org_id*).
        Checks RS256 signature, expiry, chain length, and chain tail.
        """
        if jwks is None:
            if org_id is None:
                raise AttestError("org_id is required when jwks is not provided")
            jwks = await self.fetch_jwks(org_id)
        return _verify_token(token, jwks)

    async def verify_evidence_packet(
        self,
        packet: EvidencePacket | dict,
        *,
        org_id: str | None = None,
        jwks: dict | None = None,
    ) -> EvidencePacketVerifyResult:
        """Verify a signed evidence packet offline using the org JWKS."""
        if jwks is None:
            if org_id is None:
                if isinstance(packet, EvidencePacket):
                    org_id = packet.org.id
                elif isinstance(packet, dict):
                    org_id = str(packet.get("org", {}).get("id", "") or "")
            if not org_id:
                raise AttestError("org_id is required when jwks is not provided")
            jwks = await self.fetch_jwks(org_id)

        verifier = AttestVerifier(org_id=org_id or "", base_url=self._base_url)
        return verifier.verify_evidence_packet(packet, jwks=jwks)
