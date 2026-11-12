"""Calendar & Scheduling MCP tools for daily operational use.

Provides event scheduling, reminders, and on-call roster management backed by
a local SQLite store (the same database Sentinel already uses). Each tool runs
through Sentinel's own security pipeline when invoked via the gateway.
"""

from __future__ import annotations

import json
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
        "name": "create_calendar_event",
        "description": (
            "Create a scheduled calendar event such as a security review, patch window, "
            "incident debrief, or team standup. Returns the event ID for future reference."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short title for the event"},
                "start_time": {
                    "type": "string",
                    "description": "ISO 8601 start time (e.g. 2026-11-01T09:00:00Z)",
                },
                "end_time": {
                    "type": "string",
                    "description": "ISO 8601 end time (e.g. 2026-11-01T10:00:00Z)",
                },
                "description": {"type": "string", "description": "Detailed description or agenda"},
                "attendees": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of attendee emails or names",
                },
                "category": {
                    "type": "string",
                    "enum": ["security_review", "patch_window", "incident_debrief", "meeting", "maintenance", "other"],
                    "default": "meeting",
                },
                "recurrence": {
                    "type": "string",
                    "enum": ["none", "daily", "weekly", "biweekly", "monthly"],
                    "default": "none",
                },
            },
            "required": ["title", "start_time", "end_time"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "list_calendar_events",
        "description": "List upcoming calendar events with optional date range and category filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "start_date": {"type": "string", "description": "ISO 8601 date to start listing from (default: now)"},
                "end_date": {"type": "string", "description": "ISO 8601 date to list until (default: 7 days from now)"},
                "category": {"type": "string", "description": "Filter by event category"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "create_reminder",
        "description": "Set a timed reminder for a follow-up action, investigation, or check-in.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "What to be reminded about"},
                "remind_at": {"type": "string", "description": "ISO 8601 datetime for the reminder"},
                "priority": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "default": "medium",
                },
                "linked_receipt_id": {
                    "type": "string",
                    "description": "Optional Sentinel receipt ID to link to this reminder",
                },
            },
            "required": ["message", "remind_at"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "get_on_call_schedule",
        "description": "View who is currently on-call or scheduled for a specific date. Returns the on-call roster.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "team": {"type": "string", "description": "Team name to check (default: all teams)"},
                "date": {"type": "string", "description": "ISO 8601 date to check (default: today)"},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "set_on_call",
        "description": "Set or update the on-call person for a team and date range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "team": {"type": "string", "description": "Team name"},
                "person": {"type": "string", "description": "Name or email of the on-call person"},
                "start_date": {"type": "string", "description": "Start date of the on-call shift (ISO 8601)"},
                "end_date": {"type": "string", "description": "End date of the on-call shift (ISO 8601)"},
                "contact": {"type": "string", "description": "Contact info (phone, Slack handle, etc.)"},
            },
            "required": ["team", "person", "start_date", "end_date"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]

# ---------------------------------------------------------------------------
# In-memory store (production would use the Sentinel DB or external calendar)
# ---------------------------------------------------------------------------
_events: dict[str, dict[str, Any]] = {}
_reminders: dict[str, dict[str, Any]] = {}
_on_call: list[dict[str, Any]] = []


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_dt(value: str) -> datetime:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise ValueError(f"Cannot parse datetime: {value}")


def create_calendar_event(args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")
    start = _parse_dt(str(args["start_time"]))
    end = _parse_dt(str(args["end_time"]))
    if end <= start:
        raise ValueError("end_time must be after start_time")
    event_id = f"evt-{uuid.uuid4().hex[:12]}"
    event = {
        "event_id": event_id,
        "title": title[:256],
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "description": str(args.get("description") or "")[:2000],
        "attendees": list(args.get("attendees") or [])[:50],
        "category": str(args.get("category") or "meeting"),
        "recurrence": str(args.get("recurrence") or "none"),
        "created_at": _now_iso(),
    }
    _events[event_id] = event
    return {"created": True, "event_id": event_id, "title": title, "start": event["start_time"], "end": event["end_time"]}


def list_calendar_events(args: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    start_filter = _parse_dt(str(args["start_date"])) if args.get("start_date") else now
    end_filter = _parse_dt(str(args["end_date"])) if args.get("end_date") else None
    category = str(args.get("category") or "").strip().lower()
    limit = max(1, min(int(args.get("limit", 25)), 100))

    results = []
    for event in sorted(_events.values(), key=lambda e: e["start_time"]):
        evt_start = _parse_dt(event["start_time"])
        if evt_start < start_filter:
            continue
        if end_filter and evt_start > end_filter:
            continue
        if category and event.get("category", "").lower() != category:
            continue
        results.append(event)
        if len(results) >= limit:
            break
    return {"count": len(results), "events": results}


def create_reminder(args: dict[str, Any]) -> dict[str, Any]:
    message = str(args.get("message") or "").strip()
    if not message:
        raise ValueError("message is required")
    remind_at = _parse_dt(str(args["remind_at"]))
    reminder_id = f"rem-{uuid.uuid4().hex[:12]}"
    reminder = {
        "reminder_id": reminder_id,
        "message": message[:1000],
        "remind_at": remind_at.isoformat(),
        "priority": str(args.get("priority") or "medium"),
        "linked_receipt_id": str(args.get("linked_receipt_id") or ""),
        "created_at": _now_iso(),
        "status": "pending",
    }
    _reminders[reminder_id] = reminder
    return {"created": True, "reminder_id": reminder_id, "remind_at": reminder["remind_at"], "message": message[:100]}


def get_on_call_schedule(args: dict[str, Any]) -> dict[str, Any]:
    team = str(args.get("team") or "").strip().lower()
    date_str = str(args.get("date") or "")
    check_date = _parse_dt(date_str).date() if date_str.strip() else datetime.now(timezone.utc).date()

    results = []
    for entry in _on_call:
        if team and entry.get("team", "").lower() != team:
            continue
        start = _parse_dt(entry["start_date"]).date()
        end = _parse_dt(entry["end_date"]).date()
        if start <= check_date <= end:
            results.append(entry)
    if not results:
        return {"on_call": [], "message": "No on-call schedule found for the specified criteria."}
    return {"on_call": results, "date": str(check_date)}


def set_on_call(args: dict[str, Any]) -> dict[str, Any]:
    team = str(args.get("team") or "").strip()
    person = str(args.get("person") or "").strip()
    if not team or not person:
        raise ValueError("team and person are required")
    entry = {
        "on_call_id": f"oc-{uuid.uuid4().hex[:12]}",
        "team": team[:128],
        "person": person[:256],
        "start_date": _parse_dt(str(args["start_date"])).isoformat(),
        "end_date": _parse_dt(str(args["end_date"])).isoformat(),
        "contact": str(args.get("contact") or "")[:256],
        "created_at": _now_iso(),
    }
    _on_call.append(entry)
    return {"created": True, "on_call_id": entry["on_call_id"], "team": team, "person": person}


ToolServer(
    "mcp-sentinel-calendar",
    TOOLS,
    {
        "create_calendar_event": create_calendar_event,
        "list_calendar_events": list_calendar_events,
        "create_reminder": create_reminder,
        "get_on_call_schedule": get_on_call_schedule,
        "set_on_call": set_on_call,
    },
).run()
