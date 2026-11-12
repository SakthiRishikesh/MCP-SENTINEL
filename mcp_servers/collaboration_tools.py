"""Collaboration MCP tools for team communication and task tracking.

Provides finding sharing, peer review requests, and task management so
SOC teams can coordinate directly from the MCP conversation without
switching to external project management tools.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from protocol import ToolServer
else:
    from .protocol import ToolServer

TOOLS = [
    {
        "name": "share_finding",
        "description": (
            "Share a security finding with team members. Findings can be linked to a "
            "Sentinel receipt for traceability and include severity classification."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Finding title"},
                "content": {"type": "string", "description": "Finding details and analysis"},
                "recipients": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Team members to notify (names or emails)",
                },
                "severity": {
                    "type": "string",
                    "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "default": "MEDIUM",
                },
                "receipt_id": {"type": "string", "description": "Optional Sentinel receipt ID for context"},
                "incident_id": {"type": "string", "description": "Optional linked incident ID"},
            },
            "required": ["title", "content", "recipients"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "request_review",
        "description": (
            "Request a peer review of a security decision or finding. "
            "Creates a review request that the reviewer can approve, reject, or comment on."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "receipt_id": {"type": "string", "description": "Sentinel receipt ID to review"},
                "reviewer": {"type": "string", "description": "Person to request review from"},
                "notes": {"type": "string", "description": "Context and questions for the reviewer"},
                "priority": {
                    "type": "string",
                    "enum": ["low", "normal", "high", "urgent"],
                    "default": "normal",
                },
            },
            "required": ["reviewer"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "create_task",
        "description": "Create a follow-up task from a security event, finding, or investigation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Task title"},
                "description": {"type": "string", "description": "Task details"},
                "assignee": {"type": "string", "description": "Person assigned to this task"},
                "due_date": {"type": "string", "description": "ISO 8601 due date"},
                "priority": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "default": "medium",
                },
                "category": {
                    "type": "string",
                    "enum": ["remediation", "investigation", "review", "documentation", "follow_up", "other"],
                    "default": "follow_up",
                },
                "linked_incident_id": {"type": "string", "description": "Optional linked incident"},
                "linked_receipt_id": {"type": "string", "description": "Optional linked receipt"},
            },
            "required": ["title", "assignee"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "list_tasks",
        "description": "List pending tasks, optionally filtered by assignee, status, or priority.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assignee": {"type": "string", "description": "Filter by assignee"},
                "status": {
                    "type": "string",
                    "enum": ["open", "in_progress", "done", "cancelled"],
                },
                "priority": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "update_task",
        "description": "Update a task's status, assignee, or add a comment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "status": {"type": "string", "enum": ["open", "in_progress", "done", "cancelled"]},
                "assignee": {"type": "string"},
                "comment": {"type": "string", "description": "Add a progress comment"},
            },
            "required": ["task_id"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "handoff_summary",
        "description": (
            "Generate a shift handoff summary containing open incidents, pending tasks, "
            "active suppressions, and recent findings. Ideal for SOC shift transitions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "outgoing_analyst": {"type": "string", "description": "Name of the analyst ending their shift"},
                "incoming_analyst": {"type": "string", "description": "Name of the analyst starting their shift"},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
_findings: list[dict[str, Any]] = []
_reviews: list[dict[str, Any]] = []
_tasks: dict[str, dict[str, Any]] = {}

PRIORITY_RANK = {"low": 0, "medium": 1, "normal": 1, "high": 2, "critical": 3, "urgent": 3}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def share_finding(args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    content = str(args.get("content") or "").strip()
    recipients = list(args.get("recipients") or [])
    if not title:
        raise ValueError("title is required")
    if not content:
        raise ValueError("content is required")
    if not recipients:
        raise ValueError("at least one recipient is required")

    finding_id = f"find-{uuid.uuid4().hex[:12]}"
    finding = {
        "finding_id": finding_id,
        "title": title[:256],
        "content": content[:5000],
        "recipients": [str(r)[:256] for r in recipients][:20],
        "severity": str(args.get("severity") or "MEDIUM").upper(),
        "receipt_id": str(args.get("receipt_id") or ""),
        "incident_id": str(args.get("incident_id") or ""),
        "shared_at": _now_iso(),
        "status": "shared",
    }
    _findings.append(finding)
    return {
        "shared": True,
        "finding_id": finding_id,
        "title": title,
        "recipients": finding["recipients"],
        "severity": finding["severity"],
    }


def request_review(args: dict[str, Any]) -> dict[str, Any]:
    reviewer = str(args.get("reviewer") or "").strip()
    if not reviewer:
        raise ValueError("reviewer is required")

    review_id = f"rev-{uuid.uuid4().hex[:12]}"
    review = {
        "review_id": review_id,
        "receipt_id": str(args.get("receipt_id") or ""),
        "reviewer": reviewer[:256],
        "notes": str(args.get("notes") or "")[:2000],
        "priority": str(args.get("priority") or "normal"),
        "status": "pending",
        "requested_at": _now_iso(),
    }
    _reviews.append(review)
    return {"created": True, "review_id": review_id, "reviewer": reviewer, "status": "pending"}


def create_task(args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    assignee = str(args.get("assignee") or "").strip()
    if not title:
        raise ValueError("title is required")
    if not assignee:
        raise ValueError("assignee is required")

    task_id = f"task-{uuid.uuid4().hex[:12]}"
    task = {
        "task_id": task_id,
        "title": title[:256],
        "description": str(args.get("description") or "")[:4000],
        "assignee": assignee[:256],
        "due_date": str(args.get("due_date") or ""),
        "priority": str(args.get("priority") or "medium").lower(),
        "category": str(args.get("category") or "follow_up"),
        "status": "open",
        "linked_incident_id": str(args.get("linked_incident_id") or ""),
        "linked_receipt_id": str(args.get("linked_receipt_id") or ""),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "comments": [],
    }
    _tasks[task_id] = task
    return {"created": True, "task_id": task_id, "title": title, "assignee": assignee}


def list_tasks(args: dict[str, Any]) -> dict[str, Any]:
    assignee_filter = str(args.get("assignee") or "").strip().lower()
    status_filter = str(args.get("status") or "").strip().lower()
    priority_filter = str(args.get("priority") or "").strip().lower()
    limit = max(1, min(int(args.get("limit", 25)), 100))

    results = []
    for task in sorted(_tasks.values(), key=lambda t: PRIORITY_RANK.get(t["priority"], 0), reverse=True):
        if assignee_filter and task["assignee"].lower() != assignee_filter:
            continue
        if status_filter and task["status"] != status_filter:
            continue
        if priority_filter and task["priority"] != priority_filter:
            continue
        results.append({
            "task_id": task["task_id"],
            "title": task["title"],
            "assignee": task["assignee"],
            "priority": task["priority"],
            "status": task["status"],
            "category": task["category"],
            "due_date": task.get("due_date", ""),
            "created_at": task["created_at"],
        })
        if len(results) >= limit:
            break
    return {"count": len(results), "tasks": results}


def update_task(args: dict[str, Any]) -> dict[str, Any]:
    task_id = str(args.get("task_id") or "").strip()
    if task_id not in _tasks:
        raise ValueError(f"Task {task_id} not found")

    task = _tasks[task_id]
    changes: list[str] = []

    if args.get("status"):
        old = task["status"]
        task["status"] = str(args["status"]).lower()
        changes.append(f"status: {old} → {task['status']}")
    if args.get("assignee"):
        task["assignee"] = str(args["assignee"])[:256]
        changes.append(f"reassigned to {task['assignee']}")
    if args.get("comment"):
        comment = {
            "text": str(args["comment"])[:2000],
            "at": _now_iso(),
        }
        task["comments"].append(comment)
        changes.append("comment added")

    task["updated_at"] = _now_iso()
    return {"updated": True, "task_id": task_id, "changes": changes}


def handoff_summary(args: dict[str, Any]) -> dict[str, Any]:
    outgoing = str(args.get("outgoing_analyst") or "previous analyst")
    incoming = str(args.get("incoming_analyst") or "next analyst")

    # Gather open items
    open_tasks = [t for t in _tasks.values() if t["status"] in {"open", "in_progress"}]
    pending_reviews = [r for r in _reviews if r["status"] == "pending"]
    recent_findings = _findings[-10:] if _findings else []

    critical_tasks = [t for t in open_tasks if t["priority"] in {"high", "critical"}]
    by_assignee: dict[str, int] = {}
    for t in open_tasks:
        by_assignee[t["assignee"]] = by_assignee.get(t["assignee"], 0) + 1

    return {
        "handoff": {
            "from": outgoing,
            "to": incoming,
            "generated_at": _now_iso(),
        },
        "summary": {
            "open_tasks": len(open_tasks),
            "critical_priority_tasks": len(critical_tasks),
            "pending_reviews": len(pending_reviews),
            "recent_findings_shared": len(recent_findings),
        },
        "critical_tasks": [
            {"task_id": t["task_id"], "title": t["title"], "priority": t["priority"],
             "assignee": t["assignee"], "status": t["status"]}
            for t in critical_tasks
        ],
        "pending_reviews": [
            {"review_id": r["review_id"], "reviewer": r["reviewer"],
             "priority": r["priority"], "requested_at": r["requested_at"]}
            for r in pending_reviews[:5]
        ],
        "recent_findings": [
            {"finding_id": f["finding_id"], "title": f["title"],
             "severity": f["severity"], "shared_at": f["shared_at"]}
            for f in recent_findings[-5:]
        ],
        "task_distribution": by_assignee,
    }


ToolServer(
    "mcp-sentinel-collaboration",
    TOOLS,
    {
        "share_finding": share_finding,
        "request_review": request_review,
        "create_task": create_task,
        "list_tasks": list_tasks,
        "update_task": update_task,
        "handoff_summary": handoff_summary,
    },
).run()
