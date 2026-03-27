"""Attest SDK data types."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AttestClaims:
    """Decoded claims from a Attest JWT."""

    iss: str
    sub: str          # "agent:{agent_id}"
    iat: int
    exp: int
    jti: str
    att_tid: str
    att_depth: int
    att_scope: list[str]
    att_intent: str
    att_chain: list[str]
    att_uid: str
    att_pid: str | None = None  # parent jti, absent on root
    att_ack: str | None = None  # SHA-256 checksum of system prompt + tools
    att_idp_iss: str | None = None  # IdP issuer URL
    att_idp_sub: str | None = None  # IdP user subject
    att_hitl_req: str | None = None # HITL request ID
    att_hitl_uid: str | None = None # HITL approver subject ID
    att_hitl_iss: str | None = None # HITL approver IdP issuer

    @classmethod
    def from_dict(cls, d: dict) -> "AttestClaims":
        """Construct AttestClaims from a decoded JWT payload dict."""
        return cls(
            iss=d["iss"],
            sub=d["sub"],
            iat=int(d["iat"]),
            exp=int(d["exp"]),
            jti=d["jti"],
            att_tid=d["att_tid"],
            att_depth=int(d["att_depth"]),
            att_scope=list(d["att_scope"]),
            att_intent=d["att_intent"],
            att_chain=list(d["att_chain"]),
            att_uid=d["att_uid"],
            att_pid=d.get("att_pid"),
            att_ack=d.get("att_ack"),
            att_idp_iss=d.get("att_idp_iss"),
            att_idp_sub=d.get("att_idp_sub"),
            att_hitl_req=d.get("att_hitl_req"),
            att_hitl_uid=d.get("att_hitl_uid"),
            att_hitl_iss=d.get("att_hitl_iss"),
        )

    @property
    def agent_id(self) -> str:
        """Extract the agent ID from the sub claim (strips 'agent:' prefix)."""
        prefix = "agent:"
        if self.sub.startswith(prefix):
            return self.sub.removeprefix(prefix)
        return self.sub


@dataclass
class AttestToken:
    """A root credential issued by the Attest server."""

    token: str
    claims: AttestClaims


@dataclass
class DelegatedToken:
    """A delegated child credential issued by the Attest server."""

    token: str
    claims: AttestClaims


@dataclass
class VerifyResult:
    """Result of offline token verification."""

    valid: bool
    claims: AttestClaims | None
    warnings: list[str] = field(default_factory=list)


@dataclass
class EvidenceOrg:
    id: str
    name: str


@dataclass
class EvidenceTask:
    att_tid: str
    root_jti: str
    root_agent_id: str
    att_uid: str
    depth_max: int
    credential_count: int
    event_count: int
    revoked: bool
    instruction_hash: str | None = None


@dataclass
class EvidenceApproval:
    present: bool
    request_id: str | None = None
    issuer: str | None = None
    subject: str | None = None


@dataclass
class EvidenceIdentity:
    user_id: str
    idp_issuer: str | None = None
    idp_subject: str | None = None
    approval: "EvidenceApproval | None" = None


@dataclass
class EvidenceCredential:
    jti: str
    agent_id: str
    scope: list[str]
    depth: int
    issued_at: str
    expires_at: str
    chain: list[str]
    parent_jti: str | None = None
    intent_hash: str | None = None
    agent_checksum: str | None = None
    idp_issuer: str | None = None
    idp_subject: str | None = None
    hitl_request_id: str | None = None
    hitl_subject: str | None = None
    hitl_issuer: str | None = None


@dataclass
class EvidenceIntegrity:
    audit_chain_valid: bool
    hash_algorithm: str
    packet_hash: str
    notes: list[str] = field(default_factory=list)
    signature_algorithm: str | None = None
    signature_kid: str | None = None
    packet_signature: str | None = None


@dataclass
class EvidenceSummary:
    result: str
    scope_violations: int
    approvals: int
    revocations: int


@dataclass
class EvidencePacket:
    packet_type: str
    schema_version: str
    generated_at: str
    org: EvidenceOrg
    task: EvidenceTask
    identity: EvidenceIdentity
    credentials: list["EvidenceCredential"]
    events: list["AuditEvent"]
    integrity: EvidenceIntegrity
    summary: EvidenceSummary

    @classmethod
    def from_dict(cls, d: dict) -> "EvidencePacket":
        approval = None
        approval_data = d.get("identity", {}).get("approval")
        if approval_data:
            approval = EvidenceApproval(
                present=bool(approval_data.get("present", False)),
                request_id=approval_data.get("request_id"),
                issuer=approval_data.get("issuer"),
                subject=approval_data.get("subject"),
            )

        return cls(
            packet_type=d.get("packet_type", ""),
            schema_version=d.get("schema_version", ""),
            generated_at=d.get("generated_at", ""),
            org=EvidenceOrg(**d.get("org", {})),
            task=EvidenceTask(**d.get("task", {})),
            identity=EvidenceIdentity(
                user_id=d.get("identity", {}).get("user_id", ""),
                idp_issuer=d.get("identity", {}).get("idp_issuer"),
                idp_subject=d.get("identity", {}).get("idp_subject"),
                approval=approval,
            ),
            credentials=[EvidenceCredential(**item) for item in d.get("credentials", [])],
            events=[AuditEvent.from_dict(item) for item in d.get("events", [])],
            integrity=EvidenceIntegrity(**d.get("integrity", {})),
            summary=EvidenceSummary(**d.get("summary", {})),
        )


@dataclass
class EvidencePacketVerifyResult:
    valid: bool
    hash_valid: bool
    signature_valid: bool
    audit_chain_valid: bool
    warnings: list[str] = field(default_factory=list)


@dataclass
class AuditEvent:
    """A single immutable entry in the audit log."""

    id: int | None
    prev_hash: str
    entry_hash: str
    event_type: str
    jti: str
    org_id: str
    att_tid: str
    att_uid: str
    agent_id: str
    scope: list[str]
    meta: dict[str, str] | None
    idp_issuer: str | None
    idp_subject: str | None
    hitl_req: str | None
    hitl_subject: str | None
    hitl_issuer: str | None
    created_at: str

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEvent":
        """Construct AuditEvent from a dict (e.g. JSON response)."""
        return cls(
            id=d.get("id"),
            prev_hash=d.get("prev_hash", ""),
            entry_hash=d.get("entry_hash", ""),
            event_type=d.get("event_type", ""),
            jti=d.get("jti", ""),
            org_id=d.get("org_id", ""),
            att_tid=d.get("att_tid", ""),
            att_uid=d.get("att_uid", ""),
            agent_id=d.get("agent_id", ""),
            scope=list(d.get("scope") or []),
            meta=d.get("meta"),
            idp_issuer=d.get("idp_issuer"),
            idp_subject=d.get("idp_subject"),
            hitl_req=d.get("hitl_req"),
            hitl_subject=d.get("hitl_subject"),
            hitl_issuer=d.get("hitl_issuer"),
            created_at=d.get("created_at", ""),
        )


@dataclass
class AuditChain:
    """All audit events for a given task tree."""

    task_id: str
    events: list[AuditEvent]


@dataclass
class IssueParams:
    """Parameters for issuing a root credential."""

    agent_id: str
    user_id: str
    scope: list[str]
    instruction: str
    ttl_seconds: int | None = None
    agent_checksum: str | None = None
    id_token: str | None = None

@dataclass
class ApprovalChallenge:
    """An active human-in-the-loop approval challenge."""
    challenge_id: str
    status: str


@dataclass
class ApprovalStatus:
    """Status of a polled approval request."""
    id: str
    agent_id: str
    att_tid: str
    intent: str
    requested_scope: list[str]
    status: str
    approved_by: str | None = None
    created_at: str = ""
    resolved_at: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "ApprovalStatus":
        return cls(
            id=d.get("id", ""),
            agent_id=d.get("agent_id", ""),
            att_tid=d.get("att_tid", ""),
            intent=d.get("intent", ""),
            requested_scope=list(d.get("requested_scope") or []),
            status=d.get("status", ""),
            approved_by=d.get("approved_by"),
            created_at=d.get("created_at", ""),
            resolved_at=d.get("resolved_at"),
        )


@dataclass
class DelegateParams:
    """Parameters for delegating to a child agent."""

    parent_token: str
    child_agent: str
    child_scope: list[str]
    ttl_seconds: int | None = None
