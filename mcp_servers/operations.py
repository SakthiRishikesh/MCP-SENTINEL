"""Read-only MCP tools over live MCP-Sentinel posture, registry and events."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from api import SentinelApi
    from protocol import ToolServer
else:
    from .api import SentinelApi
    from .protocol import ToolServer

api = SentinelApi()

TOOLS = [
    {
        "name": "get_live_posture",
        "description": "Read the current health and dashboard summary from this MCP-Sentinel instance.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "list_registered_servers",
        "description": "List actual upstream MCP servers registered in this Sentinel instance.",
        "inputSchema": {
            "type": "object",
            "properties": {"include_disabled": {"type": "boolean", "default": True}},
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "list_security_alerts",
        "description": "List live non-decision security events, with optional event-type filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
                "event_type": {"type": "string", "description": "Optional exact Sentinel event type"},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "inspect_registered_server",
        "description": "Inspect one real registered server and its current tool trust, review, and scan state.",
        "inputSchema": {
            "type": "object",
            "properties": {"server_id": {"type": "string"}},
            "required": ["server_id"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]


def get_live_posture(_args: dict[str, Any]) -> dict[str, Any]:
    return {"health": api.get("/health"), "summary": api.get("/v1/dashboard/summary")}


def list_registered_servers(args: dict[str, Any]) -> dict[str, Any]:
    include_disabled = bool(args.get("include_disabled", True))
    servers = api.get("/v1/servers")
    if not include_disabled:
        servers = [server for server in servers if server.get("enabled", True)]
    safe_fields = (
        "server_id", "server_name", "trust_status", "risk_state", "enabled", "transport", "discovery_status",
        "last_verification_time", "last_discovery_time", "tool_count", "tools_at_risk", "findings",
        "sandbox_classification", "connection",
    )
    return {"count": len(servers), "servers": [{key: server.get(key) for key in safe_fields} for server in servers]}


def list_security_alerts(args: dict[str, Any]) -> dict[str, Any]:
    limit = max(1, min(int(args.get("limit", 25)), 100))
    params: dict[str, Any] = {"limit": min(limit * 3, 300), "exclude_decisions": True}
    event_type = str(args.get("event_type") or "").strip()
    if event_type:
        params["event_type"] = event_type
    events = api.get("/v1/events", params)
    events = [event for event in events if event.get("severity") in {"CRITICAL", "HIGH", "MEDIUM"}]
    return {"count": min(len(events), limit), "events": events[:limit]}


def inspect_registered_server(args: dict[str, Any]) -> dict[str, Any]:
    server_id = str(args.get("server_id") or "").strip()
    if not server_id:
        raise ValueError("server_id is required")
    server = api.get(f"/v1/servers/{server_id}")
    all_tools = api.get("/v1/tools")
    tools = [tool for tool in all_tools if tool.get("server_id") == server_id and not tool.get("removed")]
    selected_server_fields = (
        "server_id", "server_name", "trust_status", "risk_state", "enabled", "transport", "discovery_status",
        "last_verification_time", "last_discovery_time", "tool_count", "tools_at_risk", "findings",
        "sandbox_classification", "safety", "connection", "changes",
    )
    selected_tool_fields = (
        "tool_name", "exposed_name", "capabilities", "sensitivity", "trust_status", "review_state",
        "findings_count", "worst_finding", "flow_roles", "behavior",
    )
    return {
        "server": {key: server.get(key) for key in selected_server_fields},
        "tools": [{key: tool.get(key) for key in selected_tool_fields} for tool in tools],
    }


ToolServer(
    "mcp-sentinel-operations",
    TOOLS,
    {
        "get_live_posture": get_live_posture,
        "list_registered_servers": list_registered_servers,
        "list_security_alerts": list_security_alerts,
        "inspect_registered_server": inspect_registered_server,
    },
).run()
