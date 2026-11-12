"""SOC Operations MCP tools for incident management and security operations.

Provides incident lifecycle management (create, update, timeline, correlate)
backed by an in-memory store. Designed for SOC analysts who need to track
incidents directly from the MCP conversation without switching to a ticketing system.
"""

from __future__ import annotations

import sys
import uuid
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

TOOLS = [
    {
        "name": "create_incident",
        "description": (
            "Create a new security incident record. Use this when a Sentinel alert, rug-pull detection, "
            "or suspicious activity warrants formal tracking. Returns the incident ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short incident title"},
                "severity": {
                    "type": "string",
                    "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "description": "Incident severity level",
                },
                "description": {"type": "string", "description": "Detailed incident description"},
                "classification": {
                    "type": "string",
                    "enum": [
                        "unauthorized_access", "data_exfiltration", "malware", "rug_pull",
                        "prompt_injection", "supply_chain", "configuration", "policy_violation", "other",
                    ],
                    "default": "other",
                },
                "affected_assets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of affected servers, tools, or systems",
                },
                "assignee": {"type": "string", "description": "Person assigned to the incident"},
            },
            "required": ["title", "severity", "description"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "update_incident_status",
        "description": "Update the status of an existing incident and optionally add notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string", "description": "The incident ID to update"},
                "status": {
                    "type": "string",
                    "enum": ["OPEN", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED", "FALSE_POSITIVE"],
                },
                "notes": {"type": "string", "description": "Investigation notes or status update"},
                "assignee": {"type": "string", "description": "Reassign the incident to another person"},
                "severity": {
                    "type": "string",
                    "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "description": "Update the severity if the situation has changed",
                },
            },
            "required": ["incident_id", "status"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "list_incidents",
        "description": "List security incidents with optional filters for status, severity, and assignee.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Filter by status (e.g. OPEN, INVESTIGATING)"},
                "severity": {"type": "string", "description": "Filter by severity"},
                "assignee": {"type": "string", "description": "Filter by assignee"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "get_incident_timeline",
        "description": "Get the full timeline of an incident including all status changes, notes, and correlated events.",
        "inputSchema": {
            "type": "object",
            "properties": {"incident_id": {"type": "string"}},
            "required": ["incident_id"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "correlate_events",
        "description": (
            "Link Sentinel security events to an incident. This creates a correlation record that "
            "helps trace the incident back to specific tool calls, blocks, or alerts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
                "event_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of Sentinel event IDs or receipt IDs to correlate",
                },
                "correlation_notes": {"type": "string", "description": "Explain why these events are related"},
            },
            "required": ["incident_id", "event_ids"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]

# ---------------------------------------------------------------------------
# In-memory incident store
# ---------------------------------------------------------------------------
_incidents: dict[str, dict[str, Any]] = {}
_timelines: dict[str, list[dict[str, Any]]] = {}
_correlations: dict[str, list[dict[str, Any]]] = {}

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _add_timeline(incident_id: str, action: str, details: dict[str, Any]) -> None:
    entry = {"timestamp": _now_iso(), "action": action, **details}
    _timelines.setdefault(incident_id, []).append(entry)


def create_incident(args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    severity = str(args.get("severity") or "MEDIUM").upper()
    description = str(args.get("description") or "").strip()
    if not title:
        raise ValueError("title is required")
    if severity not in SEVERITY_RANK:
        raise ValueError(f"severity must be one of {list(SEVERITY_RANK)}")

    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    incident = {
        "incident_id": incident_id,
        "title": title[:256],
        "severity": severity,
        "description": description[:4000],
        "classification": str(args.get("classification") or "other"),
        "affected_assets": list(args.get("affected_assets") or [])[:50],
        "assignee": str(args.get("assignee") or "unassigned")[:256],
        "status": "OPEN",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    _incidents[incident_id] = incident
    _add_timeline(incident_id, "CREATED", {"severity": severity, "assignee": incident["assignee"]})
    return {
        "created": True,
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "status": "OPEN",
    }


def update_incident_status(args: dict[str, Any]) -> dict[str, Any]:
    incident_id = str(args.get("incident_id") or "").strip()
    if incident_id not in _incidents:
        raise ValueError(f"Incident {incident_id} not found")

    incident = _incidents[incident_id]
    new_status = str(args.get("status") or "").upper()
    valid_statuses = {"OPEN", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED", "FALSE_POSITIVE"}
    if new_status not in valid_statuses:
        raise ValueError(f"status must be one of {sorted(valid_statuses)}")

    old_status = incident["status"]
    incident["status"] = new_status
    incident["updated_at"] = _now_iso()

    timeline_details: dict[str, Any] = {"from_status": old_status, "to_status": new_status}
    if args.get("notes"):
        timeline_details["notes"] = str(args["notes"])[:2000]
    if args.get("assignee"):
        incident["assignee"] = str(args["assignee"])[:256]
        timeline_details["assignee"] = incident["assignee"]
    if args.get("severity"):
        old_sev = incident["severity"]
        incident["severity"] = str(args["severity"]).upper()
        timeline_details["severity_change"] = f"{old_sev} → {incident['severity']}"

    _add_timeline(incident_id, "STATUS_CHANGE", timeline_details)
    return {"updated": True, "incident_id": incident_id, "status": new_status, "previous_status": old_status}


def list_incidents(args: dict[str, Any]) -> dict[str, Any]:
    status_filter = str(args.get("status") or "").upper()
    severity_filter = str(args.get("severity") or "").upper()
    assignee_filter = str(args.get("assignee") or "").strip().lower()
    limit = max(1, min(int(args.get("limit", 25)), 100))

    results = []
    for incident in sorted(_incidents.values(), key=lambda i: SEVERITY_RANK.get(i["severity"], 0), reverse=True):
        if status_filter and incident["status"] != status_filter:
            continue
        if severity_filter and incident["severity"] != severity_filter:
            continue
        if assignee_filter and incident.get("assignee", "").lower() != assignee_filter:
            continue
        results.append({
            "incident_id": incident["incident_id"],
            "title": incident["title"],
            "severity": incident["severity"],
            "status": incident["status"],
            "assignee": incident.get("assignee", "unassigned"),
            "classification": incident.get("classification", "other"),
            "created_at": incident["created_at"],
            "updated_at": incident["updated_at"],
        })
        if len(results) >= limit:
            break
    return {"count": len(results), "incidents": results}


def get_incident_timeline(args: dict[str, Any]) -> dict[str, Any]:
    incident_id = str(args.get("incident_id") or "").strip()
    if incident_id not in _incidents:
        raise ValueError(f"Incident {incident_id} not found")

    incident = _incidents[incident_id]
    timeline = _timelines.get(incident_id, [])
    correlations = _correlations.get(incident_id, [])
    return {
        "incident": {
            "incident_id": incident_id,
            "title": incident["title"],
            "severity": incident["severity"],
            "status": incident["status"],
            "assignee": incident.get("assignee"),
            "classification": incident.get("classification"),
            "created_at": incident["created_at"],
        },
        "timeline": timeline,
        "correlated_events": correlations,
    }


def correlate_events(args: dict[str, Any]) -> dict[str, Any]:
    incident_id = str(args.get("incident_id") or "").strip()
    if incident_id not in _incidents:
        raise ValueError(f"Incident {incident_id} not found")

    event_ids = list(args.get("event_ids") or [])
    if not event_ids:
        raise ValueError("At least one event_id is required")

    notes = str(args.get("correlation_notes") or "")[:2000]
    correlation = {
        "correlation_id": f"cor-{uuid.uuid4().hex[:12]}",
        "event_ids": event_ids[:50],
        "notes": notes,
        "correlated_at": _now_iso(),
    }
    _correlations.setdefault(incident_id, []).append(correlation)
    _add_timeline(incident_id, "EVENTS_CORRELATED", {
        "event_count": len(event_ids),
        "event_ids": event_ids[:5],
        "notes": notes[:200],
    })

    return {
        "correlated": True,
        "incident_id": incident_id,
        "correlation_id": correlation["correlation_id"],
        "events_linked": len(event_ids),
    }


ToolServer(
    "mcp-sentinel-soc",
    TOOLS,
    {
        "create_incident": create_incident,
        "update_incident_status": update_incident_status,
        "list_incidents": list_incidents,
        "get_incident_timeline": get_incident_timeline,
        "correlate_events": correlate_events,
    },
).run()
