"""Alert Management MCP tools for custom alert rules and acknowledgments.

Provides alert rule creation, listing, acknowledgment, and temporary
suppression. Designed to give SOC analysts fine-grained control over
Sentinel's alerting from within the MCP conversation.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone, timedelta
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
        "name": "create_alert_rule",
        "description": (
            "Define a custom alert rule that triggers when specific patterns are detected. "
            "Rules can match on event type, severity, server, tool, or keywords."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Alert rule name"},
                "description": {"type": "string", "description": "What this rule detects"},
                "condition": {
                    "type": "object",
                    "description": "Matching conditions",
                    "properties": {
                        "event_type": {"type": "string"},
                        "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                        "server_id": {"type": "string"},
                        "tool_name": {"type": "string"},
                        "keyword": {"type": "string", "description": "Keyword to match in event messages"},
                    },
                },
                "severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "default": "MEDIUM",
                },
                "channels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Notification channels (e.g. ['slack', 'email'])",
                },
                "enabled": {"type": "boolean", "default": True},
            },
            "required": ["name", "condition"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "list_alert_rules",
        "description": "List all configured alert rules with their status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "enabled_only": {"type": "boolean", "default": False},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "toggle_alert_rule",
        "description": "Enable or disable an alert rule.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string"},
                "enabled": {"type": "boolean"},
            },
            "required": ["rule_id", "enabled"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "acknowledge_alert",
        "description": "Acknowledge a security event/alert with investigation notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string", "description": "Sentinel event ID to acknowledge"},
                "notes": {"type": "string", "description": "Investigation notes or reason for acknowledgment"},
                "assignee": {"type": "string", "description": "Who is handling this alert"},
            },
            "required": ["event_id"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "suppress_alert",
        "description": (
            "Temporarily suppress a specific alert pattern. Use during maintenance windows "
            "or known-good activity to reduce noise. Suppression automatically expires."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "object",
                    "properties": {
                        "event_type": {"type": "string"},
                        "server_id": {"type": "string"},
                        "tool_name": {"type": "string"},
                    },
                    "description": "The pattern to suppress",
                },
                "duration_hours": {
                    "type": "number",
                    "minimum": 0.5,
                    "maximum": 168,
                    "default": 4,
                    "description": "How many hours to suppress (max 7 days)",
                },
                "reason": {"type": "string", "description": "Why this pattern is being suppressed"},
            },
            "required": ["pattern", "reason"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "list_suppressions",
        "description": "List active alert suppressions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_expired": {"type": "boolean", "default": False},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
_rules: dict[str, dict[str, Any]] = {}
_acknowledgments: dict[str, dict[str, Any]] = {}
_suppressions: list[dict[str, Any]] = []


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_alert_rule(args: dict[str, Any]) -> dict[str, Any]:
    name = str(args.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    condition = args.get("condition") or {}
    if not condition:
        raise ValueError("condition must specify at least one matching criterion")

    rule_id = f"rule-{uuid.uuid4().hex[:12]}"
    rule = {
        "rule_id": rule_id,
        "name": name[:256],
        "description": str(args.get("description") or "")[:1000],
        "condition": {k: str(v)[:256] for k, v in condition.items() if v},
        "severity": str(args.get("severity") or "MEDIUM").upper(),
        "channels": [str(c)[:64] for c in (args.get("channels") or ["log"])][:10],
        "enabled": bool(args.get("enabled", True)),
        "created_at": _now_iso(),
        "matches": 0,
    }
    _rules[rule_id] = rule
    return {"created": True, "rule_id": rule_id, "name": name, "enabled": rule["enabled"]}


def list_alert_rules(args: dict[str, Any]) -> dict[str, Any]:
    enabled_only = bool(args.get("enabled_only", False))
    results = []
    for rule in _rules.values():
        if enabled_only and not rule["enabled"]:
            continue
        results.append({
            "rule_id": rule["rule_id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "enabled": rule["enabled"],
            "condition": rule["condition"],
            "channels": rule["channels"],
            "matches": rule["matches"],
            "created_at": rule["created_at"],
        })
    return {"count": len(results), "rules": results}


def toggle_alert_rule(args: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(args.get("rule_id") or "").strip()
    if rule_id not in _rules:
        raise ValueError(f"Rule {rule_id} not found")
    enabled = bool(args.get("enabled", True))
    _rules[rule_id]["enabled"] = enabled
    return {"updated": True, "rule_id": rule_id, "enabled": enabled}


def acknowledge_alert(args: dict[str, Any]) -> dict[str, Any]:
    event_id = str(args.get("event_id") or "").strip()
    if not event_id:
        raise ValueError("event_id is required")

    ack = {
        "ack_id": f"ack-{uuid.uuid4().hex[:12]}",
        "event_id": event_id,
        "notes": str(args.get("notes") or "")[:2000],
        "assignee": str(args.get("assignee") or "unassigned")[:256],
        "acknowledged_at": _now_iso(),
    }
    _acknowledgments[event_id] = ack
    return {"acknowledged": True, "ack_id": ack["ack_id"], "event_id": event_id}


def suppress_alert(args: dict[str, Any]) -> dict[str, Any]:
    pattern = args.get("pattern") or {}
    reason = str(args.get("reason") or "").strip()
    if not reason:
        raise ValueError("reason is required")
    if not pattern:
        raise ValueError("pattern must specify at least one criterion")

    hours = max(0.5, min(float(args.get("duration_hours", 4)), 168))
    now = datetime.now(timezone.utc)
    suppression = {
        "suppression_id": f"sup-{uuid.uuid4().hex[:12]}",
        "pattern": {k: str(v)[:256] for k, v in pattern.items() if v},
        "reason": reason[:1000],
        "created_at": now.replace(microsecond=0).isoformat(),
        "expires_at": (now + timedelta(hours=hours)).replace(microsecond=0).isoformat(),
        "active": True,
    }
    _suppressions.append(suppression)
    return {
        "created": True,
        "suppression_id": suppression["suppression_id"],
        "expires_at": suppression["expires_at"],
        "duration_hours": hours,
    }


def list_suppressions(args: dict[str, Any]) -> dict[str, Any]:
    include_expired = bool(args.get("include_expired", False))
    now = datetime.now(timezone.utc)
    results = []
    for s in _suppressions:
        try:
            expires = datetime.fromisoformat(s["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            is_active = now < expires
        except (ValueError, KeyError):
            is_active = False
        s["active"] = is_active
        if not include_expired and not is_active:
            continue
        results.append(s)
    return {"count": len(results), "suppressions": results}


ToolServer(
    "mcp-sentinel-alerts",
    TOOLS,
    {
        "create_alert_rule": create_alert_rule,
        "list_alert_rules": list_alert_rules,
        "toggle_alert_rule": toggle_alert_rule,
        "acknowledge_alert": acknowledge_alert,
        "suppress_alert": suppress_alert,
        "list_suppressions": list_suppressions,
    },
).run()
