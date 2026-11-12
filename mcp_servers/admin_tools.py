"""System Administration MCP tools for Sentinel operational maintenance.

Provides health checks, database maintenance, and data retention management.
These tools require elevated privileges in production (SECURITY_ADMIN role).
"""

from __future__ import annotations

import os
import shutil
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
        "name": "health_check",
        "description": (
            "Run a comprehensive system health check on the Sentinel instance. "
            "Checks API status, database connectivity, upstream servers, and key subsystems."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "components": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["api", "database", "servers", "receipts", "all"]},
                    "default": ["all"],
                    "description": "Which components to check",
                },
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "get_system_info",
        "description": "Get system information about the Sentinel instance — version, uptime, configuration summary.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "list_active_sessions",
        "description": "List currently connected MCP clients and their last activity time.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "max_age_hours": {"type": "number", "default": 1, "description": "Show clients active within this many hours"},
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "backup_database",
        "description": (
            "Create a backup of the Sentinel SQLite database. The backup is written "
            "to the configured backup directory with a timestamped filename."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "compress": {"type": "boolean", "default": False, "description": "Compress the backup with gzip"},
            },
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "prune_old_data",
        "description": (
            "Preview or execute cleanup of old receipts, events, and audit data. "
            "Use dry_run=true to see what would be removed without actually deleting."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "older_than_days": {
                    "type": "integer",
                    "minimum": 7,
                    "maximum": 365,
                    "default": 90,
                    "description": "Delete data older than this many days",
                },
                "dry_run": {
                    "type": "boolean",
                    "default": True,
                    "description": "If true, only report what would be removed",
                },
            },
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    },
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def health_check(args: dict[str, Any]) -> dict[str, Any]:
    components = list(args.get("components") or ["all"])
    check_all = "all" in components
    results: dict[str, Any] = {"checked_at": _now_iso(), "checks": {}}

    # API health
    if check_all or "api" in components:
        try:
            health = api.get("/health")
            results["checks"]["api"] = {
                "status": "HEALTHY" if health.get("status") == "ok" else "DEGRADED",
                "details": health,
            }
        except Exception as e:
            results["checks"]["api"] = {"status": "UNHEALTHY", "error": str(e)[:500]}

    # Database check (via health endpoint)
    if check_all or "database" in components:
        try:
            health = api.get("/health")
            results["checks"]["database"] = {
                "status": "HEALTHY" if health.get("status") == "ok" else "UNKNOWN",
                "backend": health.get("database", "sqlite"),
            }
        except Exception as e:
            results["checks"]["database"] = {"status": "UNHEALTHY", "error": str(e)[:500]}

    # Upstream servers
    if check_all or "servers" in components:
        try:
            servers = api.get("/v1/servers")
            total = len(servers)
            connected = sum(1 for s in servers if (s.get("connection") or {}).get("connected", False))
            at_risk = sum(1 for s in servers if s.get("tools_at_risk", 0) > 0)
            results["checks"]["servers"] = {
                "status": "HEALTHY" if at_risk == 0 else "DEGRADED",
                "total": total,
                "connected": connected,
                "at_risk": at_risk,
            }
        except Exception as e:
            results["checks"]["servers"] = {"status": "UNKNOWN", "error": str(e)[:500]}

    # Receipt chain integrity
    if check_all or "receipts" in components:
        try:
            chain = api.get("/v1/receipts/chain")
            results["checks"]["receipts"] = {
                "status": "HEALTHY" if chain.get("ok") else "COMPROMISED",
                "checked": chain.get("checked", 0),
                "algorithm": chain.get("algorithm", ""),
            }
        except Exception as e:
            results["checks"]["receipts"] = {"status": "UNKNOWN", "error": str(e)[:500]}

    # Overall status
    statuses = [c.get("status", "UNKNOWN") for c in results["checks"].values()]
    if "UNHEALTHY" in statuses or "COMPROMISED" in statuses:
        results["overall"] = "UNHEALTHY"
    elif "DEGRADED" in statuses:
        results["overall"] = "DEGRADED"
    elif all(s == "HEALTHY" for s in statuses):
        results["overall"] = "HEALTHY"
    else:
        results["overall"] = "UNKNOWN"

    return results


def get_system_info(args: dict[str, Any]) -> dict[str, Any]:
    try:
        health = api.get("/health")
    except Exception:
        health = {}

    return {
        "version": health.get("version", "unknown"),
        "api_url": api.base_url,
        "status": health.get("status", "unknown"),
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "checked_at": _now_iso(),
        "environment": {
            "auth_mode": os.environ.get("SENTINEL_AUTH_MODE", "unknown"),
            "log_level": os.environ.get("SENTINEL_LOG_LEVEL", "INFO"),
            "env": os.environ.get("SENTINEL_ENV", "unknown"),
        },
    }


def list_active_sessions(args: dict[str, Any]) -> dict[str, Any]:
    max_age = max(0.1, min(float(args.get("max_age_hours", 1)), 24))
    try:
        clients = api.get("/v1/clients")
    except Exception:
        clients = []

    active = []
    for c in (clients if isinstance(clients, list) else []):
        seconds_ago = c.get("seconds_ago", float("inf"))
        if seconds_ago <= max_age * 3600:
            active.append({
                "name": c.get("name", "unknown"),
                "agent_id": c.get("agent_id", ""),
                "connected": c.get("connected", False),
                "seconds_ago": round(seconds_ago, 1),
            })
    return {"count": len(active), "max_age_hours": max_age, "clients": active}


def backup_database(args: dict[str, Any]) -> dict[str, Any]:
    compress = bool(args.get("compress", False))
    db_path = Path(os.environ.get("SENTINEL_DATABASE_URL", "sentinel.db").replace("sqlite:///", ""))

    if not db_path.exists():
        # Try default location
        for candidate in [Path("sentinel.db"), Path("./sentinel.db")]:
            if candidate.exists():
                db_path = candidate
                break

    if not db_path.exists():
        return {"backed_up": False, "error": "Database file not found. Set SENTINEL_DATABASE_URL."}

    backup_dir = db_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_name = f"sentinel-backup-{timestamp}.db"

    destination = backup_dir / backup_name
    shutil.copy2(str(db_path), str(destination))

    result: dict[str, Any] = {
        "backed_up": True,
        "source": str(db_path),
        "destination": str(destination),
        "size_bytes": destination.stat().st_size,
        "timestamp": timestamp,
    }

    if compress:
        import gzip
        gz_path = destination.with_suffix(".db.gz")
        with open(str(destination), "rb") as f_in, gzip.open(str(gz_path), "wb") as f_out:
            f_out.writelines(f_in)
        destination.unlink()
        result["destination"] = str(gz_path)
        result["compressed"] = True
        result["compressed_size_bytes"] = gz_path.stat().st_size

    return result


def prune_old_data(args: dict[str, Any]) -> dict[str, Any]:
    older_than_days = max(7, min(int(args.get("older_than_days", 90)), 365))
    dry_run = bool(args.get("dry_run", True))

    # This is a preview tool — actual deletion would require direct DB access
    # For now, we report what would be affected based on the API data
    try:
        events = api.get("/v1/events", {"limit": 300})
    except Exception:
        events = []
    try:
        receipts = api.get("/v1/receipts", {"limit": 300})
    except Exception:
        receipts = []

    cutoff = datetime.now(timezone.utc) - __import__("datetime").timedelta(days=older_than_days)
    cutoff_iso = cutoff.isoformat()

    old_events = sum(1 for e in events if (e.get("timestamp") or "") < cutoff_iso)
    old_receipts = sum(1 for r in receipts if (r.get("timestamp") or "") < cutoff_iso)

    result: dict[str, Any] = {
        "dry_run": dry_run,
        "older_than_days": older_than_days,
        "cutoff_date": cutoff_iso,
        "estimated_events_to_remove": old_events,
        "estimated_receipts_to_remove": old_receipts,
    }

    if not dry_run:
        result["note"] = (
            "Data pruning requires direct database access. Use the Sentinel admin API "
            "or run the prune command from the Sentinel CLI. This preview shows what would be affected."
        )
        result["action"] = "preview_only"

    return result


ToolServer(
    "mcp-sentinel-admin",
    TOOLS,
    {
        "health_check": health_check,
        "get_system_info": get_system_info,
        "list_active_sessions": list_active_sessions,
        "backup_database": backup_database,
        "prune_old_data": prune_old_data,
    },
).run()
