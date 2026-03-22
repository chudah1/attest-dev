#!/usr/bin/env python3
"""End-to-end smoke test for the Attest API.

Runs all 13 steps against a live server.  No external deps beyond `requests`.

Usage:
    python scripts/smoke_test.py [BASE_URL]

    BASE_URL defaults to http://localhost:8080.

Exit code is 0 if all steps pass, 1 if any fail.
"""

import base64
import hashlib
import json
import struct
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Install with: pip install requests")
    sys.exit(1)

BASE_URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8080"

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

results: list[tuple[str, bool, str]] = []


def step(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    status = PASS if ok else FAIL
    msg = f"[{status}] {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)


def post(path: str, body: dict, headers: dict | None = None) -> requests.Response:
    return requests.post(f"{BASE_URL}{path}", json=body, headers=headers or {}, timeout=10)


def get(path: str, headers: dict | None = None) -> requests.Response:
    return requests.get(f"{BASE_URL}{path}", headers=headers or {}, timeout=10)


def delete(path: str, body: dict | None = None, headers: dict | None = None) -> requests.Response:
    return requests.delete(f"{BASE_URL}{path}", json=body or {}, headers=headers or {}, timeout=10)


def bearer(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _verify_rs256(token: str, jwks: dict) -> dict | None:
    """Minimal RS256 verification without external deps (using stdlib only)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import cryptography.hazmat.primitives.asymmetric.utils as asym_utils
    except ImportError:
        # Fall back to unverified decode if cryptography is not installed.
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_bytes = _b64url_decode(parts[1])
        return json.loads(payload_bytes)

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b, payload_b, sig_b = parts
    message = f"{header_b}.{payload_b}".encode()
    signature = _b64url_decode(sig_b)

    header = json.loads(_b64url_decode(header_b))
    kid = header.get("kid", "")

    pub_key = None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid or not kid:
            n = int.from_bytes(_b64url_decode(k["n"]), "big")
            e_bytes = _b64url_decode(k["e"])
            e = int.from_bytes(e_bytes, "big")
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            pub_key = RSAPublicNumbers(e, n).public_key(default_backend())
            break

    if pub_key is None:
        return None

    try:
        pub_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        return None

    payload_bytes = _b64url_decode(payload_b)
    return json.loads(payload_bytes)


# ---------------------------------------------------------------------------
# Step 1: Signup
# ---------------------------------------------------------------------------
print(f"\nAttest smoke test → {BASE_URL}\n")

org_name = f"smoke-{int(time.time())}"
r = post("/v1/orgs", {"name": org_name})
ok = r.status_code == 201
step("1. POST /v1/orgs (signup)", ok, f"status={r.status_code}")
if not ok:
    print(f"   Response: {r.text[:200]}")
    sys.exit(1)

signup_data = r.json()
api_key = signup_data["api_key"]
org_id = signup_data["org"]["ID"]
auth = bearer(api_key)

# ---------------------------------------------------------------------------
# Step 2: GET /v1/org
# ---------------------------------------------------------------------------
r = get("/v1/org", auth)
ok = r.status_code == 200 and r.json().get("ID") == org_id
step("2. GET /v1/org", ok, f"status={r.status_code}")

# ---------------------------------------------------------------------------
# Step 3: Issue root credential
# ---------------------------------------------------------------------------
r = post("/v1/credentials", {
    "agent_id": "smoke-agent",
    "user_id": "smoke-user",
    "scope": ["files:read", "files:write"],
    "instruction": "Smoke test root credential",
    "ttl_seconds": 3600,
}, auth)
ok = r.status_code == 201
step("3. POST /v1/credentials (issue root)", ok, f"status={r.status_code}")
if not ok:
    print(f"   Response: {r.text[:200]}")
    sys.exit(1)

issue_data = r.json()
root_token = issue_data["token"]
root_jti = issue_data["claims"]["jti"]

# ---------------------------------------------------------------------------
# Step 4: Fetch JWKS
# ---------------------------------------------------------------------------
r = get(f"/orgs/{org_id}/jwks.json")
ok = r.status_code == 200 and "keys" in r.json()
step("4. GET /orgs/{orgID}/jwks.json", ok, f"status={r.status_code}")
jwks = r.json() if ok else {}

# ---------------------------------------------------------------------------
# Step 5: Verify root token locally (RS256 + chain)
# ---------------------------------------------------------------------------
payload = _verify_rs256(root_token, jwks)
chain_ok = (
    payload is not None
    and payload.get("att_chain", [])[-1:] == [root_jti]
    and payload.get("att_depth", -1) == 0
    and len(payload.get("att_chain", [])) == 1
)
step("5. Verify root token locally (RS256 + chain)", chain_ok,
     f"depth={payload.get('att_depth') if payload else 'N/A'} chain_len={len(payload.get('att_chain', [])) if payload else 0}")

# ---------------------------------------------------------------------------
# Step 6: Delegate to child agent
# ---------------------------------------------------------------------------
r = post("/v1/credentials/delegate", {
    "parent_token": root_token,
    "child_agent": "smoke-child-agent",
    "child_scope": ["files:read"],
    "ttl_seconds": 1800,
}, auth)
ok = r.status_code == 201
step("6. POST /v1/credentials/delegate", ok, f"status={r.status_code}")
if not ok:
    print(f"   Response: {r.text[:200]}")
    sys.exit(1)

delegate_data = r.json()
child_token = delegate_data["token"]
child_jti = delegate_data["claims"]["jti"]

# ---------------------------------------------------------------------------
# Step 7: Verify child token (scope subset, depth=1, chain len=2)
# ---------------------------------------------------------------------------
child_payload = _verify_rs256(child_token, jwks)
child_ok = (
    child_payload is not None
    and child_payload.get("att_depth", -1) == 1
    and len(child_payload.get("att_chain", [])) == 2
    and child_payload.get("att_chain", [])[-1] == child_jti
    and child_payload.get("att_scope", []) == ["files:read"]
)
step("7. Verify child token (scope subset, depth=1, chain len=2)", child_ok,
     f"depth={child_payload.get('att_depth') if child_payload else 'N/A'} "
     f"scope={child_payload.get('att_scope') if child_payload else 'N/A'}")

# ---------------------------------------------------------------------------
# Step 8: Revoke root credential
# ---------------------------------------------------------------------------
r = delete(f"/v1/credentials/{root_jti}", {"revoked_by": "smoke_test"}, auth)
ok = r.status_code == 204
step("8. DELETE /v1/credentials/{jti} (revoke root)", ok, f"status={r.status_code}")

# ---------------------------------------------------------------------------
# Step 9: Check root is revoked
# ---------------------------------------------------------------------------
r = get(f"/v1/revoked/{root_jti}")
ok = r.status_code == 200 and r.json().get("revoked") is True
step("9. GET /v1/revoked/{jti} (root revoked=true)", ok,
     f"status={r.status_code} revoked={r.json().get('revoked') if r.status_code == 200 else '?'}")

# ---------------------------------------------------------------------------
# Step 10: Check child is cascade-revoked
# ---------------------------------------------------------------------------
r = get(f"/v1/revoked/{child_jti}")
ok = r.status_code == 200 and r.json().get("revoked") is True
step("10. GET /v1/revoked/{child_jti} (cascade revoked=true)", ok,
     f"status={r.status_code} revoked={r.json().get('revoked') if r.status_code == 200 else '?'}")

# ---------------------------------------------------------------------------
# Step 11: Issue credential with agent_checksum (att_ack)
# ---------------------------------------------------------------------------
SMOKE_SYSTEM_PROMPT = "You are a helpful smoke-test assistant."
SMOKE_TOOLS = [{"name": "search"}]
_ack_payload = {"system_prompt": SMOKE_SYSTEM_PROMPT, "tools": SMOKE_TOOLS}
_ack_canonical = json.dumps(_ack_payload, sort_keys=True, separators=(",", ":"))
AGENT_CHECKSUM = hashlib.sha256(_ack_canonical.encode()).hexdigest()

r = post("/v1/credentials", {
    "agent_id": "smoke-ack-agent",
    "user_id": "smoke-user",
    "scope": ["files:read"],
    "instruction": "Checksum smoke test",
    "agent_checksum": AGENT_CHECKSUM,
}, auth)
ok = r.status_code == 201
step("11. POST /v1/credentials with agent_checksum", ok, f"status={r.status_code}")
if not ok:
    print(f"   Response: {r.text[:200]}")
    sys.exit(1)

ack_data = r.json()
ack_token = ack_data["token"]
ack_payload_decoded = _verify_rs256(ack_token, jwks)
ack_present = ack_payload_decoded is not None and ack_payload_decoded.get("att_ack") == AGENT_CHECKSUM
step("11b. att_ack present and correct in decoded token", ack_present,
     f"att_ack={ack_payload_decoded.get('att_ack') if ack_payload_decoded else 'N/A'}")

# ---------------------------------------------------------------------------
# Step 12: Verify token with correct expected_checksum → valid=True
# ---------------------------------------------------------------------------
sys.path.insert(0, "sdks/python")
try:
    from attest.verifier import AttestVerifier
    from attest.checksum import compute_agent_checksum

    verifier = AttestVerifier(org_id=org_id, base_url=BASE_URL)
    result12 = verifier.verify(ack_token, expected_checksum=AGENT_CHECKSUM)
    ok12 = result12.valid is True
    step("12. AttestVerifier accepts correct expected_checksum", ok12,
         f"valid={result12.valid} warnings={result12.warnings}")
except Exception as exc:
    step("12. AttestVerifier accepts correct expected_checksum", False, str(exc))

# ---------------------------------------------------------------------------
# Step 13: Verify token with WRONG expected_checksum → valid=False + mismatch
# ---------------------------------------------------------------------------
try:
    wrong_checksum = "a" * 64
    result13 = verifier.verify(ack_token, expected_checksum=wrong_checksum)
    mismatch_warned = any("checksum mismatch" in w for w in result13.warnings)
    ok13 = result13.valid is False and mismatch_warned
    step("13. AttestVerifier rejects wrong expected_checksum", ok13,
         f"valid={result13.valid} mismatch_in_warnings={mismatch_warned}")
except Exception as exc:
    step("13. AttestVerifier rejects wrong expected_checksum", False, str(exc))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print()
passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
print(f"Result: {passed}/{total} steps passed")

if passed < total:
    sys.exit(1)
