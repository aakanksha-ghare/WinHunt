"""Build a simple process tree from normalized Windows process events."""

from __future__ import annotations

from typing import Any


def build_process_tree(process_events: list[dict[str, Any]]) -> dict[str, Any]:
    """Index process records by PID and map parent/child relationships."""
    tree: dict[str, Any] = {
        "by_pid": {},
        "children": {},
        "parent": {},
    }

    for record in process_events:
        pid = record["pid"]
        parent_pid = record["parent_pid"]

        tree["by_pid"][pid] = dict(record)
        tree["parent"][pid] = parent_pid
        tree["children"].setdefault(parent_pid, []).append(pid)

    return tree


def get_process_chain(tree: dict[str, Any], pid: int) -> list[dict[str, Any]]:
    """Return the parent chain from the oldest known ancestor to the requested PID."""
    by_pid = tree.get("by_pid", {})
    if pid not in by_pid:
        return []

    chain: list[dict[str, Any]] = []
    seen: set[int] = set()
    current_pid = pid

    while current_pid in by_pid and current_pid not in seen:
        chain.append(dict(by_pid[current_pid]))
        seen.add(current_pid)

        parent_pid = tree.get("parent", {}).get(current_pid)
        if parent_pid is None or parent_pid not in by_pid:
            break

        current_pid = parent_pid

    chain.reverse()
    return chain
