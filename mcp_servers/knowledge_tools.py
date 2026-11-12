"""Knowledge Base & Note-Taking MCP tools for investigation documentation.

Provides structured note-taking, full-text search, and runbook management.
Designed so SOC analysts can capture findings, document procedures, and
build institutional knowledge directly from the MCP conversation.
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
        "name": "create_note",
        "description": (
            "Create a structured note for investigation findings, analysis results, or general documentation. "
            "Notes are searchable by title, content, tags, and category."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Note title"},
                "content": {"type": "string", "description": "Note content (Markdown supported)"},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tags for categorization",
                },
                "category": {
                    "type": "string",
                    "enum": ["investigation", "analysis", "runbook", "meeting_notes", "finding", "general"],
                    "default": "general",
                },
                "linked_incident_id": {"type": "string", "description": "Optional incident ID to link to"},
                "linked_receipt_id": {"type": "string", "description": "Optional Sentinel receipt ID to link to"},
            },
            "required": ["title", "content"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "search_notes",
        "description": "Full-text search across all notes by keyword, tags, or category.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword (matches title and content)"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter by tags"},
                "category": {"type": "string", "description": "Filter by category"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "get_note",
        "description": "Retrieve a specific note by its ID.",
        "inputSchema": {
            "type": "object",
            "properties": {"note_id": {"type": "string"}},
            "required": ["note_id"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "update_note",
        "description": "Update an existing note's content, tags, or category.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "note_id": {"type": "string"},
                "title": {"type": "string"},
                "content": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "category": {"type": "string"},
            },
            "required": ["note_id"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "create_runbook",
        "description": (
            "Create an incident response runbook with structured steps, trigger conditions, and severity level. "
            "Runbooks can be retrieved during incidents for guided response procedures."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Runbook title (e.g. 'Rug-Pull Response Procedure')"},
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "order": {"type": "integer"},
                            "action": {"type": "string"},
                            "details": {"type": "string"},
                            "responsible": {"type": "string"},
                        },
                        "required": ["action"],
                    },
                    "description": "Ordered list of response steps",
                },
                "triggers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "What events trigger this runbook (e.g. 'rug_pull', 'prompt_injection', 'data_exfiltration')",
                },
                "severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "default": "MEDIUM",
                },
                "description": {"type": "string", "description": "Overview of when and why to use this runbook"},
            },
            "required": ["title", "steps"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "list_runbooks",
        "description": "List available runbooks, optionally filtered by trigger event or severity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "trigger": {"type": "string", "description": "Filter by trigger event type"},
                "severity": {"type": "string", "description": "Filter by minimum severity"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
_notes: dict[str, dict[str, Any]] = {}
_runbooks: dict[str, dict[str, Any]] = {}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_note(args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    content = str(args.get("content") or "").strip()
    if not title:
        raise ValueError("title is required")
    if not content:
        raise ValueError("content is required")

    note_id = f"note-{uuid.uuid4().hex[:12]}"
    note = {
        "note_id": note_id,
        "title": title[:256],
        "content": content[:10000],
        "tags": [str(t).lower()[:64] for t in (args.get("tags") or [])][:20],
        "category": str(args.get("category") or "general"),
        "linked_incident_id": str(args.get("linked_incident_id") or ""),
        "linked_receipt_id": str(args.get("linked_receipt_id") or ""),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    _notes[note_id] = note
    return {"created": True, "note_id": note_id, "title": title}


def search_notes(args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").strip().lower()
    tags = [str(t).lower() for t in (args.get("tags") or [])]
    category = str(args.get("category") or "").strip().lower()
    limit = max(1, min(int(args.get("limit", 20)), 50))

    results = []
    for note in sorted(_notes.values(), key=lambda n: n["updated_at"], reverse=True):
        if query and query not in note["title"].lower() and query not in note["content"].lower():
            continue
        if tags and not set(tags) & set(note["tags"]):
            continue
        if category and note.get("category", "").lower() != category:
            continue
        results.append({
            "note_id": note["note_id"],
            "title": note["title"],
            "tags": note["tags"],
            "category": note["category"],
            "preview": note["content"][:200] + ("…" if len(note["content"]) > 200 else ""),
            "created_at": note["created_at"],
            "updated_at": note["updated_at"],
        })
        if len(results) >= limit:
            break
    return {"count": len(results), "notes": results}


def get_note(args: dict[str, Any]) -> dict[str, Any]:
    note_id = str(args.get("note_id") or "").strip()
    if note_id not in _notes:
        raise ValueError(f"Note {note_id} not found")
    return _notes[note_id]


def update_note(args: dict[str, Any]) -> dict[str, Any]:
    note_id = str(args.get("note_id") or "").strip()
    if note_id not in _notes:
        raise ValueError(f"Note {note_id} not found")

    note = _notes[note_id]
    if args.get("title"):
        note["title"] = str(args["title"]).strip()[:256]
    if args.get("content"):
        note["content"] = str(args["content"]).strip()[:10000]
    if args.get("tags") is not None:
        note["tags"] = [str(t).lower()[:64] for t in args["tags"]][:20]
    if args.get("category"):
        note["category"] = str(args["category"]).strip()
    note["updated_at"] = _now_iso()
    return {"updated": True, "note_id": note_id, "title": note["title"]}


def create_runbook(args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")
    steps = list(args.get("steps") or [])
    if not steps:
        raise ValueError("at least one step is required")

    runbook_id = f"rb-{uuid.uuid4().hex[:12]}"
    formatted_steps = []
    for i, step in enumerate(steps[:50], 1):
        formatted_steps.append({
            "order": step.get("order", i),
            "action": str(step.get("action") or "")[:500],
            "details": str(step.get("details") or "")[:2000],
            "responsible": str(step.get("responsible") or "")[:256],
        })

    runbook = {
        "runbook_id": runbook_id,
        "title": title[:256],
        "description": str(args.get("description") or "")[:2000],
        "steps": formatted_steps,
        "triggers": [str(t).lower()[:64] for t in (args.get("triggers") or [])][:20],
        "severity": str(args.get("severity") or "MEDIUM").upper(),
        "created_at": _now_iso(),
    }
    _runbooks[runbook_id] = runbook
    return {"created": True, "runbook_id": runbook_id, "title": title, "steps_count": len(formatted_steps)}


def list_runbooks(args: dict[str, Any]) -> dict[str, Any]:
    trigger = str(args.get("trigger") or "").strip().lower()
    min_severity = str(args.get("severity") or "").upper()
    limit = max(1, min(int(args.get("limit", 20)), 50))
    min_rank = SEVERITY_RANK.get(min_severity, 0)

    results = []
    for rb in sorted(_runbooks.values(), key=lambda r: SEVERITY_RANK.get(r["severity"], 0), reverse=True):
        if trigger and trigger not in rb.get("triggers", []):
            continue
        if min_rank and SEVERITY_RANK.get(rb["severity"], 0) < min_rank:
            continue
        results.append({
            "runbook_id": rb["runbook_id"],
            "title": rb["title"],
            "severity": rb["severity"],
            "triggers": rb["triggers"],
            "steps_count": len(rb["steps"]),
            "description": rb.get("description", "")[:200],
            "created_at": rb["created_at"],
        })
        if len(results) >= limit:
            break
    return {"count": len(results), "runbooks": results}


ToolServer(
    "mcp-sentinel-knowledge",
    TOOLS,
    {
        "create_note": create_note,
        "search_notes": search_notes,
        "get_note": get_note,
        "update_note": update_note,
        "create_runbook": create_runbook,
        "list_runbooks": list_runbooks,
    },
).run()
