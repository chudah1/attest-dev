"""Scope parsing and subset-checking utilities for Attest."""

from __future__ import annotations


def parse_scope(s: str) -> tuple[str, str] | None:
    """Parse a ``"resource:action"`` string into ``(resource, action)``.

    Returns ``None`` if the string is not in the expected format (i.e. does
    not contain exactly one colon with non-empty parts on both sides).
    """
    parts = s.split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return (parts[0], parts[1])


def entry_covers(parent: tuple[str, str], child: tuple[str, str]) -> bool:
    """Return ``True`` if *parent* covers *child*, respecting ``'*'`` wildcards.

    A wildcard in either the resource or action position of the parent matches
    any corresponding value in the child.
    """
    resource_ok = parent[0] == "*" or parent[0] == child[0]
    action_ok = parent[1] == "*" or parent[1] == child[1]
    return resource_ok and action_ok


def is_subset(parent_scope: list[str], child_scope: list[str]) -> bool:
    """Return ``True`` if every entry in *child_scope* is covered by at least
    one entry in *parent_scope*.

    Invalid scope entries in *child_scope* (those that cannot be parsed) are
    treated as uncoverable and cause this function to return ``False``.
    Invalid entries in *parent_scope* are silently skipped.
    """
    for child_entry_str in child_scope:
        child_parsed = parse_scope(child_entry_str)
        if child_parsed is None:
            return False

        covered = False
        for parent_entry_str in parent_scope:
            parent_parsed = parse_scope(parent_entry_str)
            if parent_parsed is None:
                continue
            if entry_covers(parent_parsed, child_parsed):
                covered = True
                break

        if not covered:
            return False

    return True


def normalise_scope(scope: list[str]) -> list[str]:
    """Deduplicate and strip whitespace from scope entries, preserving order.

    Empty strings (after stripping) are dropped.  Duplicate entries (after
    stripping) keep only the first occurrence.
    """
    seen: set[str] = set()
    out: list[str] = []
    for entry in scope:
        stripped = entry.strip()
        if not stripped:
            continue
        if stripped in seen:
            continue
        seen.add(stripped)
        out.append(stripped)
    return out
