"""Standalone verifier for Attest credentials.

AttestVerifier verifies RS256 JWTs without needing an API key.  It fetches
and caches the org's public JWKS and checks token expiry, chain integrity,
and live revocation status.

Example::

    from attest.verifier import AttestVerifier

    verifier = AttestVerifier(org_id="my-org-id")
    result = verifier.verify(token)
    if result.valid:
        print(result.claims.att_scope)
"""

from __future__ import annotations

import threading
import urllib.parse
import json
import hashlib
import base64
from typing import Optional

import httpx
import jwt
import jwt.algorithms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from attest.types import AttestClaims, VerifyResult, EvidencePacket, EvidencePacketVerifyResult, AuditEvent


_DEFAULT_BASE_URL = "https://api.attestdev.com"
_GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def _build_public_key(jwks: dict, kid: str):  # type: ignore[return]
    """Return an RSAPublicKey for the given kid from a JWKS dict."""
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
    # Fall back to first key if kid not found.
    keys = jwks.get("keys", [])
    if keys:
        return jwt.algorithms.RSAAlgorithm.from_jwk(keys[0])
    raise ValueError("No RSA key found in JWKS")


def _canonical_packet_json(packet: EvidencePacket | dict) -> str:
    if isinstance(packet, EvidencePacket):
        raw = _packet_to_raw(packet)
    else:
        raw = _drop_none(json.loads(json.dumps(packet)))

    integrity = raw.get("integrity") or {}
    integrity["packet_hash"] = ""
    integrity.pop("signature_algorithm", None)
    integrity.pop("signature_kid", None)
    integrity.pop("packet_signature", None)
    raw["integrity"] = integrity
    return json.dumps(raw, separators=(",", ":"), ensure_ascii=False)


def _validate_audit_chain(events: list[AuditEvent]) -> list[str]:
    warnings: list[str] = []
    if not events:
        return warnings
    if events[0].prev_hash != _GENESIS_HASH:
        warnings.append("first audit event does not use the genesis previous hash")
    for prev, current in zip(events, events[1:]):
        if current.prev_hash != prev.entry_hash:
            warnings.append(
                f"audit chain break between event {prev.id or '?'} and {current.id or '?'}"
            )
    return warnings


def _drop_none(value):  # type: ignore[no-untyped-def]
    if isinstance(value, dict):
        return {
            key: _drop_none(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_drop_none(item) for item in value]
    return value


def _packet_to_raw(packet: EvidencePacket) -> dict:
    raw: dict = {
        "packet_type": packet.packet_type,
        "schema_version": packet.schema_version,
        "generated_at": packet.generated_at,
        "org": {
            "id": packet.org.id,
            "name": packet.org.name,
        },
        "task": {
            "att_tid": packet.task.att_tid,
            "root_jti": packet.task.root_jti,
            "root_agent_id": packet.task.root_agent_id,
            "att_uid": packet.task.att_uid,
        },
        "identity": {
            "user_id": packet.identity.user_id,
        },
        "credentials": [_credential_to_raw(item) for item in packet.credentials],
        "events": [_event_to_raw(item) for item in packet.events],
        "integrity": {
            "audit_chain_valid": packet.integrity.audit_chain_valid,
            "hash_algorithm": packet.integrity.hash_algorithm,
            "packet_hash": packet.integrity.packet_hash,
            "notes": list(packet.integrity.notes),
        },
        "summary": {
            "result": packet.summary.result,
            "scope_violations": packet.summary.scope_violations,
            "approvals": packet.summary.approvals,
            "revocations": packet.summary.revocations,
        },
    }

    if packet.task.instruction_hash is not None:
        raw["task"]["instruction_hash"] = packet.task.instruction_hash
    raw["task"]["depth_max"] = packet.task.depth_max
    raw["task"]["credential_count"] = packet.task.credential_count
    raw["task"]["event_count"] = packet.task.event_count
    raw["task"]["revoked"] = packet.task.revoked

    if packet.identity.idp_issuer is not None:
        raw["identity"]["idp_issuer"] = packet.identity.idp_issuer
    if packet.identity.idp_subject is not None:
        raw["identity"]["idp_subject"] = packet.identity.idp_subject
    if packet.identity.approval is not None:
        approval = {"present": packet.identity.approval.present}
        if packet.identity.approval.request_id is not None:
            approval["request_id"] = packet.identity.approval.request_id
        if packet.identity.approval.issuer is not None:
            approval["issuer"] = packet.identity.approval.issuer
        if packet.identity.approval.subject is not None:
            approval["subject"] = packet.identity.approval.subject
        raw["identity"]["approval"] = approval

    if packet.integrity.signature_algorithm is not None:
        raw["integrity"]["signature_algorithm"] = packet.integrity.signature_algorithm
    if packet.integrity.signature_kid is not None:
        raw["integrity"]["signature_kid"] = packet.integrity.signature_kid
    if packet.integrity.packet_signature is not None:
        raw["integrity"]["packet_signature"] = packet.integrity.packet_signature

    return raw


def _credential_to_raw(credential):  # type: ignore[no-untyped-def]
    raw = {
        "jti": credential.jti,
    }
    if credential.parent_jti is not None:
        raw["parent_jti"] = credential.parent_jti
    raw["agent_id"] = credential.agent_id
    raw["scope"] = list(credential.scope)
    raw["depth"] = credential.depth
    raw["issued_at"] = credential.issued_at
    raw["expires_at"] = credential.expires_at
    raw["chain"] = list(credential.chain)
    if credential.intent_hash is not None:
        raw["intent_hash"] = credential.intent_hash
    if credential.agent_checksum is not None:
        raw["agent_checksum"] = credential.agent_checksum
    if credential.idp_issuer is not None:
        raw["idp_issuer"] = credential.idp_issuer
    if credential.idp_subject is not None:
        raw["idp_subject"] = credential.idp_subject
    if credential.hitl_request_id is not None:
        raw["hitl_request_id"] = credential.hitl_request_id
    if credential.hitl_subject is not None:
        raw["hitl_subject"] = credential.hitl_subject
    if credential.hitl_issuer is not None:
        raw["hitl_issuer"] = credential.hitl_issuer
    return raw


def _event_to_raw(event: AuditEvent) -> dict:
    raw = {
        "id": event.id,
        "prev_hash": event.prev_hash,
        "entry_hash": event.entry_hash,
        "event_type": event.event_type,
        "jti": event.jti,
        "org_id": event.org_id,
        "att_tid": event.att_tid,
        "att_uid": event.att_uid,
        "agent_id": event.agent_id,
        "scope": list(event.scope),
    }
    if event.meta is not None:
        raw["meta"] = dict(event.meta)
    if event.idp_issuer is not None:
        raw["idp_issuer"] = event.idp_issuer
    if event.idp_subject is not None:
        raw["idp_subject"] = event.idp_subject
    if event.hitl_req is not None:
        raw["hitl_req"] = event.hitl_req
    if event.hitl_subject is not None:
        raw["hitl_subject"] = event.hitl_subject
    if event.hitl_issuer is not None:
        raw["hitl_issuer"] = event.hitl_issuer
    raw["created_at"] = event.created_at
    return raw


class AttestVerifier:
    """Verifies Attest credentials for a specific organisation.

    This class is safe to share across threads.  JWKS are cached in memory
    until :meth:`clear_jwks_cache` is called.

    Args:
        org_id:   The organisation ID whose credentials you want to verify.
        base_url: Base URL of the Attest API (default: https://api.attestdev.com).
    """

    def __init__(
        self,
        org_id: str,
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        self._org_id = org_id
        self._base_url = base_url.rstrip("/")
        self._lock = threading.Lock()
        self._jwks_cache: Optional[dict] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(self, token: str, *, expected_checksum: str | None = None) -> VerifyResult:
        """Verify an Attest JWT.

        Fetches the JWKS on first call (then caches), verifies the RS256
        signature, checks expiry, chain integrity, and live revocation.

        If *expected_checksum* is provided, also verifies that ``att_ack``
        in the token matches it — detecting prompt injection or tool tampering.

        Returns:
            A :class:`~attest.types.VerifyResult` with ``valid``, ``claims``,
            and ``warnings``.
        """
        warnings: list[str] = []

        # Decode header to find kid.
        try:
            header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError as exc:
            return VerifyResult(valid=False, claims=None, warnings=[str(exc)])

        kid = header.get("kid", "")

        # Fetch / use cached JWKS.
        jwks = self._get_jwks()
        try:
            public_key = _build_public_key(jwks, kid)
        except (ValueError, Exception) as exc:
            return VerifyResult(valid=False, claims=None, warnings=[f"JWKS error: {exc}"])

        # Verify signature and standard claims (exp, iss, etc.).
        try:
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"require": ["exp", "jti"]},
            )
        except jwt.exceptions.ExpiredSignatureError:
            return VerifyResult(valid=False, claims=None, warnings=["token has expired"])
        except jwt.exceptions.InvalidTokenError as exc:
            return VerifyResult(valid=False, claims=None, warnings=[str(exc)])

        # Build AttestClaims.
        try:
            claims = AttestClaims.from_dict(payload)
        except Exception as exc:
            return VerifyResult(valid=False, claims=None, warnings=[f"claims parse error: {exc}"])

        # Chain integrity: att_chain length must equal att_depth + 1,
        # and the last element must equal jti.
        chain = claims.att_chain
        depth = claims.att_depth
        if len(chain) != depth + 1:
            warnings.append(
                f"chain integrity: expected {depth + 1} elements, got {len(chain)}"
            )
        if chain and chain[-1] != claims.jti:
            warnings.append("chain integrity: last chain element does not match jti")

        # Live revocation check.
        try:
            revoked = self._check_revoked(claims.jti)
            if revoked:
                return VerifyResult(valid=False, claims=claims, warnings=["credential has been revoked"])
        except httpx.HTTPError as exc:
            return VerifyResult(valid=False, claims=claims, warnings=[f"revocation check failed due to network error: {exc}"])

        valid = len(warnings) == 0

        if not valid:
            return VerifyResult(valid=False, claims=claims, warnings=warnings)

        # Agent checksum verification.
        if expected_checksum is not None:
            if claims.att_ack != expected_checksum:
                return VerifyResult(
                    valid=False,
                    claims=claims,
                    warnings=[
                        f"agent checksum mismatch: credential has {claims.att_ack!r}, "
                        f"expected {expected_checksum!r}"
                    ],
                )

        return VerifyResult(valid=valid, claims=claims, warnings=warnings)

    def clear_jwks_cache(self) -> None:
        """Clear the cached JWKS, forcing a fresh fetch on the next verify call."""
        with self._lock:
            self._jwks_cache = None

    def verify_evidence_packet(
        self,
        packet: EvidencePacket | dict,
        *,
        jwks: dict | None = None,
    ) -> EvidencePacketVerifyResult:
        """Verify a signed evidence packet offline using the cached org JWKS."""
        packet_obj = packet if isinstance(packet, EvidencePacket) else EvidencePacket.from_dict(packet)
        canonical_json = _canonical_packet_json(packet_obj)
        computed_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        warnings: list[str] = []
        hash_valid = computed_hash == packet_obj.integrity.packet_hash
        if not hash_valid:
            warnings.append(
                f"packet hash mismatch: expected {packet_obj.integrity.packet_hash}, computed {computed_hash}"
            )

        signature_valid = False
        if not packet_obj.integrity.signature_algorithm or not packet_obj.integrity.signature_kid or not packet_obj.integrity.packet_signature:
            warnings.append("packet signature metadata missing")
        elif packet_obj.integrity.signature_algorithm != "RS256":
            warnings.append(f"unsupported signature algorithm: {packet_obj.integrity.signature_algorithm}")
        else:
            try:
                jwks_data = jwks if jwks is not None else self._get_jwks()
                public_key = _build_public_key(jwks_data, packet_obj.integrity.signature_kid)
                signature_valid = self._verify_packet_signature(public_key, canonical_json, packet_obj.integrity.packet_signature)
                if not signature_valid:
                    warnings.append("packet signature verification failed")
            except Exception as exc:
                warnings.append(f"packet signature verification failed: {exc}")

        audit_warnings = _validate_audit_chain(packet_obj.events)
        warnings.extend(audit_warnings)
        audit_chain_valid = packet_obj.integrity.audit_chain_valid and not audit_warnings
        if not packet_obj.integrity.audit_chain_valid and not audit_warnings:
            warnings.append("packet reports invalid audit chain")

        return EvidencePacketVerifyResult(
            valid=hash_valid and signature_valid and audit_chain_valid,
            hash_valid=hash_valid,
            signature_valid=signature_valid,
            audit_chain_valid=audit_chain_valid,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_jwks(self) -> dict:
        with self._lock:
            if self._jwks_cache is not None:
                return self._jwks_cache

        qorg = urllib.parse.quote(self._org_id)
        url = f"{self._base_url}/orgs/{qorg}/jwks.json"
        response = httpx.get(url, timeout=10)
        response.raise_for_status()
        jwks = response.json()

        with self._lock:
            self._jwks_cache = jwks
        return jwks

    def _check_revoked(self, jti: str) -> bool:
        qjti = urllib.parse.quote(jti)
        url = f"{self._base_url}/v1/revoked/{qjti}"
        response = httpx.get(url, timeout=10)
        response.raise_for_status()
        return response.json().get("revoked", False)

    def _verify_packet_signature(self, public_key, canonical_json: str, signature: str) -> bool:  # type: ignore[no-untyped-def]
        padded = signature + "=" * ((4 - len(signature) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        public_key.verify(
            raw,
            canonical_json.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
