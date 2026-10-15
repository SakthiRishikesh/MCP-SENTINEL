"""Which MCP clients are connected right now.

The stdio bridge polls the catalog every few seconds with a token that carries the client's own
name (``clientInfo.name`` from ``initialize``), so the last poll per client tells the dashboard
whether Claude Desktop / Claude Code is attached. In memory only: it is a live view, not history.
"""

from __future__ import annotations

import threading
import time
from typing import Any

# clientInfo.name -> product name
KNOWN_CLIENTS = {"claude-ai": "Claude Desktop", "claude-code": "Claude Code", "cursor-vscode": "Cursor", "visual-studio-code": "VS Code"}
CONNECTED_SECONDS = 20  # the bridge polls every 5 s

_seen: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def touch(agent_id: str | None, subject: str = "") -> None:
    if not agent_id or agent_id in {"sentinel-dashboard", "unknown-agent"}:
        return
    with _lock:
        _seen[agent_id] = {"agent_id": agent_id, "subject": subject, "at": time.time()}


def clients(max_age: float = 3600) -> list[dict[str, Any]]:
    now = time.time()
    with _lock:
        rows = [dict(v) for v in _seen.values() if now - v["at"] <= max_age]
    for row in rows:
        agent = row["agent_id"]
        # Claude Desktop's agent mode launches its own copy of each MCP server as local-agent-mode-<server>
        row["name"] = "Claude Desktop (agent mode)" if agent.startswith("local-agent-mode") else KNOWN_CLIENTS.get(agent, agent)
        row["seconds_ago"] = round(now - row["at"], 1)
        row["connected"] = row["seconds_ago"] <= CONNECTED_SECONDS
    return sorted(rows, key=lambda r: r["seconds_ago"])
