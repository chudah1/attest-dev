"""Warrant SDK data types."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WarrantClaims:
    """Decoded claims from a Warrant JWT."""

    iss: str
    sub: str          # "agent:{agent_id}"
    iat: int
    exp: int
    jti: str
    wrt_tid: str
    wrt_depth: int
    wrt_scope: list[str]
    wrt_intent: str
    wrt_chain: list[str]
    wrt_uid: str
    wrt_pid: str | None = None  # parent jti, absent on root

    @classmethod
    def from_dict(cls, d: dict) -> "WarrantClaims":
        """Construct WarrantClaims from a decoded JWT payload dict."""
        return cls(
            iss=d["iss"],
            sub=d["sub"],
            iat=int(d["iat"]),
            exp=int(d["exp"]),
            jti=d["jti"],
            wrt_tid=d["wrt_tid"],
            wrt_depth=int(d["wrt_depth"]),
            wrt_scope=list(d["wrt_scope"]),
            wrt_intent=d["wrt_intent"],
            wrt_chain=list(d["wrt_chain"]),
            wrt_uid=d["wrt_uid"],
            wrt_pid=d.get("wrt_pid"),
        )

    @property
    def agent_id(self) -> str:
        """Extract the agent ID from the sub claim (strips 'agent:' prefix)."""
        prefix = "agent:"
        if self.sub.startswith(prefix):
            return self.sub[len(prefix):]
        return self.sub


@dataclass
class WarrantToken:
    """A root credential issued by the Warrant server."""

    token: str
    claims: WarrantClaims


@dataclass
class DelegatedToken:
    """A delegated child credential issued by the Warrant server."""

    token: str
    claims: WarrantClaims


@dataclass
class VerifyResult:
    """Result of offline token verification."""

    valid: bool
    claims: WarrantClaims | None
    warnings: list[str] = field(default_factory=list)


@dataclass
class AuditEvent:
    """A single immutable entry in the audit log."""

    id: int | None
    prev_hash: str
    entry_hash: str
    event_type: str
    jti: str
    wrt_tid: str
    wrt_uid: str
    agent_id: str
    scope: list[str]
    meta: dict[str, str] | None
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
            wrt_tid=d.get("wrt_tid", ""),
            wrt_uid=d.get("wrt_uid", ""),
            agent_id=d.get("agent_id", ""),
            scope=list(d.get("scope") or []),
            meta=d.get("meta"),
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


@dataclass
class DelegateParams:
    """Parameters for delegating to a child agent."""

    parent_token: str
    child_agent: str
    child_scope: list[str]
    ttl_seconds: int | None = None
