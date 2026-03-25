"""Anthropic Claude + Attest: Tool use with scope-enforced credentials.

Uses AttestSession to issue a root credential, then scope-gates each tool
with @attest_tool_anthropic. The session auto-revokes all credentials on exit.

Requirements:
    pip install attest-sdk[anthropic] anthropic

Run:
    export ATTEST_API_KEY=att_live_...
    export ANTHROPIC_API_KEY=sk-ant-...
    python main.py
"""

import os

import anthropic

from attest import AttestClient
from attest.integrations.anthropic_sdk import AttestSession, attest_tool_anthropic


SYSTEM_PROMPT = """You are a helpful assistant that can search the web and read files.
Use the search_web tool for web queries and read_file for local files."""

# -- Tools (scope-enforced) --------------------------------------------------

@attest_tool_anthropic(scope="web:read")
def search_web(query: str) -> str:
    """Search the web for information."""
    return f"[Search results for '{query}': Example Corp raised $50M Series B...]"


@attest_tool_anthropic(scope="files:read")
def read_file(path: str) -> str:
    """Read a local file."""
    return f"[Contents of {path}: # README\nThis is a sample project...]"


# -- Tool definitions for the Anthropic API ----------------------------------

TOOLS = [
    {
        "name": "search_web",
        "description": "Search the web for information",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Search query"}},
            "required": ["query"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a local file",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path"}},
            "required": ["path"],
        },
    },
]

TOOL_DISPATCH = {"search_web": search_web, "read_file": read_file}


# -- Main loop ---------------------------------------------------------------

def main():
    attest = AttestClient(
        base_url=os.getenv("ATTEST_BASE_URL", "https://api.attestdev.com"),
        api_key=os.getenv("ATTEST_API_KEY", ""),
    )

    claude = anthropic.Anthropic()

    with AttestSession(
        client=attest,
        agent_id="claude-researcher",
        user_id="usr_alice",
        scope=["web:read", "files:read"],
        instruction="Research competitors and summarize the README",
        system_prompt=SYSTEM_PROMPT,
        tools=TOOLS,
    ) as session:

        print(f"Task ID: {session.task_id}")
        print(f"Root scope: {session.claims.att_scope}")
        print(f"Agent checksum (att_ack): {session.claims.att_ack}")
        print()

        messages = [
            {"role": "user", "content": "Search for 'AI agent frameworks' then read README.md"}
        ]

        # Simple tool-use loop
        while True:
            response = claude.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )

            # Process tool calls
            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        tool_fn = TOOL_DISPATCH[block.name]
                        result = tool_fn(**block.input)
                        print(f"  Tool: {block.name}({block.input}) → {result[:60]}...")
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })

                        # Report the action to the audit log
                        attest.report_action(
                            token=session.token,
                            tool=block.name,
                            outcome="success",
                        )

                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": tool_results})
            else:
                # Final text response
                for block in response.content:
                    if hasattr(block, "text"):
                        print(f"\nClaude: {block.text[:200]}...")
                break

    # Session exited — root credential and all children revoked
    print("\nSession closed. All credentials revoked.")


if __name__ == "__main__":
    main()
