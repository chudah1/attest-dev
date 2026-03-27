"""Attest Python SDK.

Attest issues RS256-signed JWTs to AI agents, carrying cryptographic scope,
delegation lineage, and task-tree provenance.

Quick start::

    from attest import AttestClient, IssueParams

    client = AttestClient(api_key="your-api-key")
    token = client.issue(IssueParams(
        agent_id="my-agent",
        user_id="user-123",
        scope=["files:read", "files:write"],
        instruction="Summarise the quarterly report",
    ))
    print(token.claims.att_tid)   # task tree UUID
    print(token.claims.att_scope) # ["files:read", "files:write"]
"""

from attest.checksum import compute_agent_checksum
from attest.client import (
    AsyncAttestClient,
    AttestAPIError,
    AttestClient,
    AttestError,
    AttestScopeError,
    AttestVerifyError,
)
from attest.scope import is_subset, normalise_scope, parse_scope
from attest.verifier import AttestVerifier
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

# Framework integrations (lazy — only usable when the framework is installed).
from attest.integrations.langgraph import (
    AttestNodes,
    AttestState,
    AttestStateGraph,
    current_attest_token,
    attest_tool,
)
from attest.integrations.openai_agents import (
    AttestContext,
    AttestRunHooks,
    attest_tool_openai,
)
from attest.integrations.anthropic_sdk import (
    AttestSession,
    AsyncAttestSession,
    current_attest_session,
    attest_tool_anthropic,
)

__version__ = "0.1.0"

__all__ = [
    # Clients
    "AttestClient",
    "AsyncAttestClient",
    # Errors
    "AttestError",
    "AttestAPIError",
    "AttestScopeError",
    "AttestVerifyError",
    # Types
    "ApprovalChallenge",
    "ApprovalStatus",
    "AttestClaims",
    "AttestToken",
    "EvidencePacket",
    "EvidencePacketVerifyResult",
    "DelegatedToken",
    "VerifyResult",
    "AuditChain",
    "AuditEvent",
    "IssueParams",
    "DelegateParams",
    # Scope utilities
    "is_subset",
    "parse_scope",
    "normalise_scope",
    # LangGraph integration
    "AttestState",
    "AttestNodes",
    "AttestStateGraph",
    "attest_tool",
    "current_attest_token",
    # OpenAI Agents SDK integration
    "AttestContext",
    "AttestRunHooks",
    "attest_tool_openai",
    # Anthropic SDK integration
    "AttestSession",
    "AsyncAttestSession",
    "current_attest_session",
    "attest_tool_anthropic",
    # Checksum utility
    "compute_agent_checksum",
    # Standalone verifier
    "AttestVerifier",
    # Version
    "__version__",
]
