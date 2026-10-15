"""Integrity registry: lookups plus the helpers that decide what the model is shown.

Tool rows are written by ``integrity.discovery`` (TOFU pinning + rug-pull analysis); this
module only reads them and derives client-facing names and definitions.
"""

from __future__ import annotations

import re as _re
from typing import Any

from sqlalchemy.orm import Session

from integrity.crypto import canonical_hash
from sentinel.db import ServerRow, ToolRow
from sentinel.dlp import strip_invisible
from sentinel.types import TrustStatus


class IntegrityRegistry:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_server(self, server_id: str) -> ServerRow | None:
        return self.session.get(ServerRow, server_id)

    def get_tool(self, server_id: str, tool_name: str) -> ToolRow | None:
        return (
            self.session.query(ToolRow)
            .filter(ToolRow.server_id == server_id, ToolRow.tool_name == tool_name)
            .one_or_none()
        )


# ── helpers shared by discovery, the gateway and the API ─────────────────────────────────────

HIDDEN_FROM_MODEL = {TrustStatus.QUARANTINED.value, TrustStatus.BLOCKED.value}


def slugify(name: str, max_len: int = 20) -> str:
    slug = _re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")
    slug = _re.sub(r"_(mcp|server|mcp_server)$", "", slug) or "server"
    return slug[:max_len].strip("_") or "server"


def unique_slug(session: Session, name: str, exclude_server_id: str | None = None) -> str:
    base = slugify(name)
    taken = {
        (r.slug or "")
        for r in session.query(ServerRow).all()
        if r.server_id != exclude_server_id
    }
    if base not in taken:
        return base
    for i in range(2, 1000):
        candidate = f"{base[:17]}_{i}"
        if candidate not in taken:
            return candidate
    return f"{base[:12]}_{canonical_hash(name)[:6]}"


def exposed_name_for(slug: str, tool_name: str, *, disambiguate: bool = False) -> str:
    """Namespaced, client-safe tool name (Claude requires ^[a-zA-Z0-9_-]{1,64}$).

    Always namespacing prevents cross-server shadowing through name collisions. Characters
    outside the allowed set are replaced, so two upstream names can map to the same exposed
    name (``files.read`` / ``files_read``); ``disambiguate`` then adds a stable hash suffix.
    """
    clean_tool = _re.sub(r"[^A-Za-z0-9_-]", "_", tool_name) or "tool"
    name = f"{slug}__{clean_tool}"
    if len(name) <= 64 and not disambiguate:
        return name
    suffix = canonical_hash(tool_name)[:6]
    return f"{slug}__{clean_tool[: 64 - len(slug) - 9]}_{suffix}"


def disambiguate_exposed_names(rows: list[ToolRow], slug: str) -> None:
    """Make exposed names unique within one server (active tools win over removed ones)."""
    groups: dict[str, list[ToolRow]] = {}
    for row in rows:
        groups.setdefault(row.exposed_name or "", []).append(row)
    for exposed, group in groups.items():
        if len(group) < 2:
            continue
        # the tool whose name needed no rewriting keeps the plain name; every other one gets a suffix
        group.sort(key=lambda r: (bool(r.removed), exposed_name_for(slug, r.tool_name) != f"{slug}__{r.tool_name}", r.tool_name))
        for row in group[1:]:
            row.exposed_name = exposed_name_for(slug, row.tool_name, disambiguate=True)


def neutral_description(row: ToolRow, findings: int) -> str:
    return (
        f"[MCP-Sentinel] The original description of '{row.tool_name}' is withheld pending security review "
        f"({findings} finding(s)). Calls are evaluated with elevated caution."
    )


def served_definition(row: ToolRow) -> dict[str, Any]:
    """The definition the *model* sees: the pinned (approved) one, never an unreviewed drift."""
    approved = row.approved_definition or {}
    if approved:
        base = dict(approved)
        base["description"] = strip_invisible(str(base.get("description") or ""))
        return base
    live = dict(row.live_definition or {}) or {
        "name": row.tool_name,
        "description": row.description,
        "inputSchema": row.schema_json or {"type": "object"},
        "annotations": row.annotations or {},
    }
    serious = [f for f in (row.scan_findings or []) if f.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}]
    if serious:
        schema = dict(live.get("inputSchema") or {"type": "object"})
        props = schema.get("properties")
        if isinstance(props, dict):
            schema["properties"] = {
                k: {kk: vv for kk, vv in (v or {}).items() if kk not in {"description", "title", "examples", "default"}}
                if isinstance(v, dict) else v
                for k, v in props.items()
            }
        live["inputSchema"] = schema
        live["description"] = neutral_description(row, len(serious))
    else:
        live["description"] = strip_invisible(str(live.get("description") or ""))
    return live


def is_exposed(row: ToolRow, server: ServerRow | None) -> bool:
    if server is None or row.removed or row.review_state == "REJECTED":
        return False
    if row.trust_status in HIDDEN_FROM_MODEL or server.trust_status in HIDDEN_FROM_MODEL:
        return False
    return server.enabled is not False
