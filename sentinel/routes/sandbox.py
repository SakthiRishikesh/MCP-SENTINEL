"""Sandbox pre-flight: status, image build, run history, behaviour audits and undo."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from sandbox.shadow import get_sandbox, restore
from sentinel.config import Settings, get_settings
from sentinel.db import SandboxRunRow, ServerRow, ToolRow, UndoRow, VulnScanRow, session_scope
from sentinel.deps import admin_identity, db_session, reader
from sentinel.preflight import tool_profile
from sentinel.receipts import AuditStore
from sentinel.types import TrustStatus, utcnow, worse_trust
from sentinel.upstream.manager import server_connection_config

router = APIRouter()
log = logging.getLogger("sentinel.sandbox")
_audits: set[str] = set()
_audits_lock = threading.Lock()


def run_view(r: SandboxRunRow) -> dict[str, Any]:
    return {"run_id": r.run_id, "created_at": r.created_at, "server_id": r.server_id, "tool_name": r.tool_name,
            "exposed_name": r.exposed_name, "workflow_id": r.workflow_id, "subject": r.subject, "verdict": r.verdict,
            "action": r.action, "backend": r.backend, "reasons": r.reasons, "findings": r.findings, "preview": r.preview,
            "receipt_id": r.receipt_id, "approval_id": r.approval_id, "challenge_id": r.challenge_id, "duration_ms": r.duration_ms}


def undo_view(r: UndoRow, *, full: bool = False) -> dict[str, Any]:
    out = {"undo_id": r.undo_id, "created_at": r.created_at, "server_id": r.server_id, "tool_name": r.tool_name,
           "exposed_name": r.exposed_name, "workflow_id": r.workflow_id, "subject": r.subject, "status": r.status,
           "summary": r.summary, "files": len(r.entries or []), "evasion": bool(r.evasion), "restored_at": r.restored_at,
           "restored_by": r.restored_by}
    if full:
        out.update(entries=[{k: v for k, v in e.items() if k in {"path", "change"}} for e in r.entries or []],
                   evasion_detail=r.evasion, report=r.report)
    return out


@router.get("/v1/sandbox/status")
def sandbox_status(_r=Depends(reader)) -> dict[str, Any]:
    return get_sandbox().status()


@router.post("/v1/sandbox/image/build")
def build_image(identity=Depends(admin_identity), session: Session = Depends(db_session)) -> dict[str, Any]:
    mgr = get_sandbox()
    ok, why = mgr.docker.available()
    if not ok:
        raise HTTPException(409, why)
    started = mgr.start_build()
    AuditStore(session).write_event("sandbox_image_build", "INFO", f"sandbox image build requested by {identity.subject}", {})
    return {"started": started, "status": mgr.status()}


@router.get("/v1/sandbox/runs")
def list_runs(server_id: str = "", verdict: str = "", approval_id: str = "", challenge_id: str = "", receipt_id: str = "",
              limit: int = 50, session: Session = Depends(db_session), _r=Depends(reader)) -> list[dict[str, Any]]:
    q = session.query(SandboxRunRow)
    for column, value in ((SandboxRunRow.server_id, server_id), (SandboxRunRow.verdict, verdict), (SandboxRunRow.approval_id, approval_id),
                          (SandboxRunRow.challenge_id, challenge_id), (SandboxRunRow.receipt_id, receipt_id)):
        if value:
            q = q.filter(column == value)
    return [run_view(r) for r in q.order_by(SandboxRunRow.created_at.desc()).limit(max(1, min(limit, 200))).all()]


@router.get("/v1/sandbox/runs/{run_id}")
def get_run(run_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    row = session.get(SandboxRunRow, run_id)
    if row is None:
        raise HTTPException(404, "unknown sandbox run")
    return run_view(row)


# -- behaviour audit ---------------------------------------------------------------------------
def run_behavior_audit(server_id: str) -> dict[str, Any]:
    """Exercise every tool of a local server in the sandbox and fold the result into its safety verdict."""
    from sentinel.routes.scans import apply_safety

    with session_scope() as s:
        row = s.get(ServerRow, server_id)
        if row is None or (row.transport or "") != "stdio":
            return {"status": "SKIPPED", "note": "only local (stdio) servers run code Sentinel can sandbox"}
        _, config = server_connection_config(row)
        tools = [tool_profile(t) for t in s.query(ToolRow).filter(ToolRow.server_id == server_id).all() if not t.removed]
        meta = dict(row.metadata_json or {})
        meta["behavior_audit"] = {"status": "RUNNING", "started_at": utcnow().isoformat(), "tools": {}}
        row.metadata_json = meta
    try:
        report = get_sandbox().audit(server_id, config, tools)
    except Exception as exc:  # noqa: BLE001
        log.exception("behaviour audit failed for %s", server_id)
        report = {"status": "FAILED", "note": str(exc)[:400], "tools": {}}
    with session_scope() as s:
        row = s.get(ServerRow, server_id)
        if row is None:
            return report
        meta = dict(row.metadata_json or {})
        meta["behavior_audit"] = report
        row.metadata_json = meta
        bad = []
        for t in s.query(ToolRow).filter(ToolRow.server_id == server_id).all():
            verdict = (report.get("tools") or {}).get(t.tool_name, {}).get("verdict")
            if verdict == "MALICIOUS":
                t.trust_status = worse_trust(t.trust_status, TrustStatus.QUARANTINED.value)
                bad.append(t.tool_name)
        audit = AuditStore(s)
        audit.write_event("behavior_audit", "CRITICAL" if bad else "INFO",
                          f"{row.server_name}: sandbox audit {report.get('status')} ({report.get('backend')})"
                          + (f"; quarantined {', '.join(bad)}" if bad else ""),
                          {"server_id": server_id, "summary": report.get("summary"), "quarantined": bad})
        latest = s.query(VulnScanRow).filter(VulnScanRow.server_id == server_id).order_by(VulnScanRow.created_at.desc()).first()
        apply_safety(s, row, latest.report if latest else {})
    return report


def start_behavior_audit(server_id: str) -> bool:
    with _audits_lock:
        if server_id in _audits:
            return False
        _audits.add(server_id)

    def run() -> None:
        try:
            run_behavior_audit(server_id)
        finally:
            with _audits_lock:
                _audits.discard(server_id)

    threading.Thread(target=run, name=f"sentinel-audit-{server_id[:8]}", daemon=True).start()
    return True


@router.post("/v1/servers/{server_id}/audit")
def audit_server(server_id: str, wait: bool = False, session: Session = Depends(db_session), _a=Depends(admin_identity),
                 settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    row = session.get(ServerRow, server_id)
    if row is None:
        raise HTTPException(404, f"Server {server_id} not found")
    if (row.transport or "") != "stdio":
        raise HTTPException(422, "remote servers run elsewhere and cannot be sandboxed; their calls are still verified by policy, taint tracking and output guards")
    if wait:
        return {"behavior_audit": run_behavior_audit(server_id)}
    return {"started": start_behavior_audit(server_id), "status": "RUNNING"}


# -- undo ------------------------------------------------------------------------------------------
@router.get("/v1/undo")
def list_undo(server_id: str = "", limit: int = 50, session: Session = Depends(db_session), _r=Depends(reader)) -> list[dict[str, Any]]:
    q = session.query(UndoRow)
    if server_id:
        q = q.filter(UndoRow.server_id == server_id)
    return [undo_view(r) for r in q.order_by(UndoRow.created_at.desc()).limit(max(1, min(limit, 200))).all()]


@router.get("/v1/undo/{undo_id}")
def get_undo(undo_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    row = session.get(UndoRow, undo_id)
    if row is None:
        raise HTTPException(404, "no undo journal for this receipt")
    return undo_view(row, full=True)


@router.post("/v1/undo/{undo_id}")
def undo_call(undo_id: str, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    row = session.get(UndoRow, undo_id)
    if row is None:
        raise HTTPException(404, "no undo journal for this receipt")
    if row.status in {"RESTORED", "EXPIRED"}:
        raise HTTPException(409, f"already {row.status.lower()}")
    reverted = {p for p in ((row.evasion or {}).get("reverted") or {}).get("restored", [])}
    entries = [e for e in row.entries or [] if e["path"] not in reverted]
    report = restore(entries, Path(row.path))
    row.status, row.report, row.restored_at, row.restored_by = "RESTORED", report, utcnow(), identity.subject
    AuditStore(session).write_event("undo", "MEDIUM", f"{identity.subject} undid {row.exposed_name}: {len(report['restored'])} restored, "
                                    f"{len(report['removed'])} removed, {len(report['conflicts'])} conflict(s)",
                                    {"undo_id": undo_id, "server_id": row.server_id, "report": report})
    session.commit()
    return {"undo_id": undo_id, "status": row.status, **report}
