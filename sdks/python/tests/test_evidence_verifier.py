from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from attest.types import EvidencePacket
from attest.verifier import AttestVerifier


FIXTURE_DIR = Path(__file__).resolve().parents[3] / "testdata" / "evidence"


def load_packet() -> dict:
    return json.loads((FIXTURE_DIR / "packet.json").read_text())


def load_jwks() -> dict:
    return json.loads((FIXTURE_DIR / "jwks.json").read_text())


def test_verify_evidence_packet_fixture_is_valid():
    verifier = AttestVerifier(org_id="org_test_fixture")
    packet = EvidencePacket.from_dict(load_packet())
    result = verifier.verify_evidence_packet(packet, jwks=load_jwks())

    assert result.valid is True
    assert result.hash_valid is True
    assert result.signature_valid is True
    assert result.audit_chain_valid is True
    assert result.warnings == []


def test_verify_evidence_packet_detects_tampering():
    verifier = AttestVerifier(org_id="org_test_fixture")
    packet = load_packet()
    packet["summary"]["result"] = "revoked"

    result = verifier.verify_evidence_packet(packet, jwks=load_jwks())

    assert result.valid is False
    assert result.hash_valid is False
    assert result.signature_valid is False
    assert any("packet hash mismatch" in warning for warning in result.warnings)


def test_verify_evidence_packet_detects_audit_chain_break():
    verifier = AttestVerifier(org_id="org_test_fixture")
    packet = deepcopy(load_packet())
    packet["events"][1]["prev_hash"] = "deadbeef" * 8

    result = verifier.verify_evidence_packet(packet, jwks=load_jwks())

    assert result.valid is False
    assert result.audit_chain_valid is False
    assert any("audit chain break" in warning for warning in result.warnings)
