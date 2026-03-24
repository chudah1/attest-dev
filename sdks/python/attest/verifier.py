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
from typing import Optional

import httpx
import jwt
import jwt.algorithms

from attest.types import AttestClaims, VerifyResult


_DEFAULT_BASE_URL = "https://api.attestdev.com"


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
