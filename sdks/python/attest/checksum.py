"""Agent checksum computation for att_ack claim."""

import hashlib
import json


def compute_agent_checksum(system_prompt: str, tools: list[dict] | None = None) -> str:
    """SHA-256 of canonical JSON of {system_prompt, tools}.

    Uses sort_keys=True and compact separators so the result is deterministic
    regardless of key insertion order or Python version.
    """
    payload = {"system_prompt": system_prompt, "tools": tools or []}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
