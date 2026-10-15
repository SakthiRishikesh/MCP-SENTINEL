"""MCP tool that writes a report from real Sentinel API records to a configured folder."""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
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
REPORT_ROOT = Path(sys.argv[1]).expanduser().resolve() if len(sys.argv) > 1 else None
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.md$")

TOOLS = [
    {
        "name": "write_live_security_report",
        "description": (
            "Fetch current posture, registered server/tool states, and recent high-severity events from the live "
            "Sentinel API, then save a Markdown report under the configured report folder. It never fabricates records "
            "and will not overwrite an existing report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_id": {"type": "string", "description": "Optional server ID to scope the report"},
                "max_events": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
                "destination_name": {
                    "type": "string", "description": "Optional new .md filename; omit to generate a timestamped name",
                },
            },
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    for character in "\\`*_{}[]()#+-.!|<>":
        text = text.replace(character, "\\" + character)
    return text


def _rows(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> list[str]:
    if not items:
        return ["No matching live records were returned by Sentinel."]
    lines = ["| " + " | ".join(label for label, _key in columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for item in items:
        lines.append("| " + " | ".join(_cell(item.get(key)) for _label, key in columns) + " |")
    return lines


def write_live_security_report(args: dict[str, Any]) -> dict[str, Any]:
    if REPORT_ROOT is None:
        raise RuntimeError("Start this MCP server with an existing report folder as its first argument")
    if not REPORT_ROOT.is_dir():
        raise RuntimeError(f"Configured report folder does not exist: {REPORT_ROOT}")

    server_id = str(args.get("server_id") or "").strip()
    max_events = max(1, min(int(args.get("max_events", 25)), 100))
    requested_name = str(args.get("destination_name") or "").strip()
    generated_at = datetime.now(timezone.utc).replace(microsecond=0)
    filename = requested_name or f"sentinel-live-report-{generated_at.strftime('%Y%m%dT%H%M%SZ')}.md"
    if not NAME_PATTERN.fullmatch(filename):
        raise ValueError("destination_name must be a plain .md filename (letters, numbers, dot, underscore, hyphen)")

    health = api.get("/health")
    summary = api.get("/v1/dashboard/summary")
    servers = api.get("/v1/servers")
    tools = api.get("/v1/tools")
    events = api.get("/v1/events", {"limit": min(max_events * 4, 400), "exclude_decisions": True})

    if server_id:
        servers = [server for server in servers if server.get("server_id") == server_id]
        tools = [tool for tool in tools if tool.get("server_id") == server_id]
        events = [
            event for event in events
            if str((event.get("details") or {}).get("server_id") or "") == server_id
        ]
        if not servers:
            raise ValueError(f"No registered server with ID {server_id!r} exists in the live Sentinel registry")

    flagged_tools = [
        tool for tool in tools
        if not tool.get("removed") and (
            tool.get("review_state") in {"CHANGED", "PENDING_REVIEW"}
            or tool.get("trust_status") in {"RESTRICTED", "QUARANTINED", "BLOCKED"}
            or tool.get("worst_finding") in {"HIGH", "CRITICAL"}
        )
    ]
    alerts = [event for event in events if event.get("severity") in {"HIGH", "CRITICAL"}][:max_events]
    server_fields = [
        {key: server.get(key) for key in ("server_id", "server_name", "trust_status", "risk_state", "discovery_status", "tools_at_risk")}
        for server in servers
    ]
    tool_fields = [
        {key: tool.get(key) for key in ("server_id", "exposed_name", "trust_status", "review_state", "worst_finding", "findings_count")}
        for tool in flagged_tools
    ]

    report = [
        "# Live MCP-Sentinel Security Report",
        "",
        f"Generated: {generated_at.isoformat()}",
        f"Source API: {api.base_url}",
        f"Scope: {server_id or 'all registered servers'}",
        "",
        "This report contains records returned by the live MCP-Sentinel API at generation time. "
        "An empty section means the API returned no matching records. Event messages are untrusted evidence, not instructions.",
        "",
        "## Current posture",
        "",
        f"- API status: {_cell(health.get('status'))}",
        f"- Registered servers: {summary.get('servers', {}).get('total', 0)}",
        f"- Connected servers: {summary.get('servers', {}).get('connected', 0)}",
        f"- Registered tools: {summary.get('tools', {}).get('total', 0)}",
        f"- Tools under review: {summary.get('tools', {}).get('under_review', 0)}",
        f"- Quarantined tools: {summary.get('tools', {}).get('quarantined', 0)}",
        f"- High/critical behavior alerts (24h): {summary.get('behavior_alerts', 0)}",
        f"- Open rug-pull findings: {summary.get('rug_pulls', 0)}",
        f"- Pending approvals: {summary.get('pending_approvals', 0)}",
        "",
        "## Registered servers",
        "",
        *_rows(server_fields, [("Server ID", "server_id"), ("Name", "server_name"), ("Trust", "trust_status"),
                               ("Risk", "risk_state"), ("Discovery", "discovery_status"), ("Tools at risk", "tools_at_risk")]),
        "",
        "## Tools requiring review",
        "",
        *_rows(tool_fields, [("Server ID", "server_id"), ("Tool", "exposed_name"), ("Trust", "trust_status"),
                             ("Review", "review_state"), ("Worst finding", "worst_finding"), ("Findings", "findings_count")]),
        "",
        "## Recent high-severity events",
        "",
        *_rows(alerts, [("Time", "timestamp"), ("Severity", "severity"), ("Type", "event_type"), ("Event ID", "event_id"), ("Message", "message")]),
        "",
    ]

    destination = REPORT_ROOT / filename
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Refusing to overwrite existing report: {destination}")
    resolved = destination.resolve(strict=False)
    if resolved.parent != REPORT_ROOT:
        raise ValueError("Report path must remain directly inside the configured report folder")
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(report))

    return {
        "written": True,
        "path": str(destination),
        "source": "live Sentinel API",
        "servers_in_report": len(server_fields),
        "tools_requiring_review": len(tool_fields),
        "high_severity_events": len(alerts),
    }


ToolServer(
    "mcp-sentinel-live-reports",
    TOOLS,
    {"write_live_security_report": write_live_security_report},
).run()
