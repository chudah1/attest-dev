"""LangGraph + Attest: Research-and-email pipeline with credentialed agents.

Each node in the graph gets a delegated Attest credential with narrowed scope.
The orchestrator holds [research:read, gmail:send]; the researcher only gets
[research:read]; the emailer only gets [gmail:send]. Scope is cryptographically
enforced — a compromised researcher node cannot send email.

Requirements:
    pip install attest-sdk[langgraph] langgraph langchain-core

Run:
    export ATTEST_API_KEY=att_live_...
    python main.py
"""

import operator
import os
from typing import Annotated

from attest import AttestClient
from attest.integrations.langgraph import (
    AttestNodes,
    AttestState,
    AttestStateGraph,
    attest_tool,
)


# -- State -------------------------------------------------------------------

class State(AttestState):
    messages: Annotated[list[str], operator.add]  # reducer: accumulate across nodes
    instruction: str
    user_id: str
    research_results: str
    email_draft: str


# -- Node functions ----------------------------------------------------------

def researcher(state: dict) -> dict:
    """Simulated research node — would call a search API in production."""
    instruction = state.get("instruction", "")
    results = f"[Research results for: {instruction}]"
    return {"research_results": results, "messages": [f"Researched: {instruction}"]}


@attest_tool(scope="gmail:send", agent_id="emailer")
def emailer(state: dict) -> dict:
    """Simulated email node — scope-gated by @attest_tool."""
    research = state.get("research_results", "")
    draft = f"Subject: Research Summary\n\n{research}"
    return {"email_draft": draft, "messages": [f"Drafted email"]}


def router(state: dict) -> str:
    """Route: research first, then email, then done."""
    if not state.get("research_results"):
        return "researcher"
    if not state.get("email_draft"):
        return "emailer"
    return "__end__"


# -- Build graph -------------------------------------------------------------

def main():
    client = AttestClient(
        base_url=os.getenv("ATTEST_BASE_URL", "https://api.attestdev.com"),
        api_key=os.getenv("ATTEST_API_KEY", ""),
    )

    graph = AttestStateGraph(
        State,
        client=client,
        scope_map={
            "researcher": ["research:read"],
            "emailer": ["gmail:send"],
        },
        skip_nodes={"__start__", "issue", "cleanup"},
    )

    # Issue root credential at graph entry
    graph.add_node("issue", AttestNodes.issue(
        client=client,
        agent_id="orchestrator",
        scope=["research:read", "gmail:send"],
        instruction_key="instruction",
        user_id_key="user_id",
    ))

    graph.add_node("researcher", researcher)
    graph.add_node("emailer", emailer)

    # Revoke entire tree at cleanup
    graph.add_node("cleanup", AttestNodes.revoke(client=client, agent_id="orchestrator"))

    # Edges
    graph.set_entry_point("issue")
    graph.add_conditional_edges("issue", router)
    graph.add_conditional_edges("researcher", router)
    graph.add_edge("emailer", "cleanup")
    graph.add_edge("cleanup", "__end__")

    compiled = graph.compile()

    result = compiled.invoke({
        "messages": [],
        "instruction": "Research top 3 competitors and summarize findings",
        "user_id": "usr_alice",
        "research_results": "",
        "email_draft": "",
    })

    print("--- Pipeline complete ---")
    print(f"Messages: {result['messages']}")
    print(f"Email draft:\n{result['email_draft']}")
    print(f"Task ID: {result.get('attest_task_id', 'n/a')}")


if __name__ == "__main__":
    main()
