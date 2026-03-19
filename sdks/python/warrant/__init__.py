"""Warrant Python SDK.

Warrant issues RS256-signed JWTs to AI agents, carrying cryptographic scope,
delegation lineage, and task-tree provenance.

Quick start::

    from warrant import WarrantClient, IssueParams

    client = WarrantClient(api_key="your-api-key")
    token = client.issue(IssueParams(
        agent_id="my-agent",
        user_id="user-123",
        scope=["files:read", "files:write"],
        instruction="Summarise the quarterly report",
    ))
    print(token.claims.wrt_tid)   # task tree UUID
    print(token.claims.wrt_scope) # ["files:read", "files:write"]
"""

from warrant.client import (
    AsyncWarrantClient,
    WarrantAPIError,
    WarrantClient,
    WarrantError,
    WarrantScopeError,
    WarrantVerifyError,
)
from warrant.scope import is_subset, normalise_scope, parse_scope
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

# Framework integrations (lazy — only usable when the framework is installed).
from warrant.integrations.langgraph import (
    WarrantNodes,
    WarrantState,
    WarrantStateGraph,
    current_warrant_token,
    warrant_tool,
)
from warrant.integrations.openai_agents import (
    WarrantContext,
    WarrantRunHooks,
    warrant_tool_openai,
)

__version__ = "0.1.0"

__all__ = [
    # Clients
    "WarrantClient",
    "AsyncWarrantClient",
    # Errors
    "WarrantError",
    "WarrantAPIError",
    "WarrantScopeError",
    "WarrantVerifyError",
    # Types
    "WarrantClaims",
    "WarrantToken",
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
    "WarrantState",
    "WarrantNodes",
    "WarrantStateGraph",
    "warrant_tool",
    "current_warrant_token",
    # OpenAI Agents SDK integration
    "WarrantContext",
    "WarrantRunHooks",
    "warrant_tool_openai",
    # Version
    "__version__",
]
