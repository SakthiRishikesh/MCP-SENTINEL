from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from integrity import toxicflow
from integrity.capabilities import infer
from integrity.crypto import canonical_hash
from integrity.registry import is_exposed, served_definition
from monitoring.baseline import drift_likelihood
from sentinel.config import get_settings
from sentinel.db import ServerRow, ToolChangeRow, ToolRow
from sentinel.deps import admin_identity, db_session, reader
from sentinel.leases import CapabilityLeaseManager
from sentinel.receipts import AuditStore
from sentinel.types import Capability, ReviewState, Sensitivity, TrustStatus, max_sensitivity, utcnow, worse_trust

router = APIRouter()


class TrustBody(BaseModel):
    trust_status: str
    reason: str = ""


class ProfileBody(BaseModel):
    capabilities: list[str]
    sensitivity: str | None = None
    resource: str | None = None


class ResolveBody(BaseModel):
    action: str  # accept | reject
    note: str = ""


def tool_view(t: ToolRow, *, detail: bool = False, session: Session | None = None) -> dict[str, Any]:
    findings = t.scan_findings or []
    baseline = t.baseline or {}
    view: dict[str, Any] = {
        "tool_id": t.tool_id,
        "tool_name": t.tool_name,
        "exposed_name": t.exposed_name,
        "server_id": t.server_id,
        "title": t.title,
        "capability": (t.capabilities or [None])[0],
        "capabilities": t.capabilities or [],
        "sensitivity": t.sensitivity,
        "integrity_hash": t.integrity_hash,
        "live_hash": t.live_hash,
        "approved_hash": t.approved_hash,
        "trust_status": t.trust_status,
        "review_state": t.review_state,
        "removed": bool(t.removed),
        "profile_locked": bool(t.profile_locked),
        "flow_roles": t.flow_roles or [],
        "resource": t.resource,
        "version": t.version,
        "description": t.description,
        "findings_count": len(findings),
        "worst_finding": max((f.get("severity") for f in findings), key=lambda s: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s), default=None),
        "confidence": (t.inference or {}).get("confidence"),
        "last_change_id": t.last_change_id,
        "behavior": {
            "samples": baseline.get("n", 0),
            "learning": baseline.get("learning", True),
            "drift": drift_likelihood(baseline),
            "recent_anomalies": (baseline.get("recent_anomalies") or [])[-5:],
        },
        "first_seen": t.first_seen.isoformat() if t.first_seen else None,
        "last_seen": t.last_seen.isoformat() if t.last_seen else None,
    }
    if detail:
        view.update({
            "served_definition": served_definition(t),
            "live_definition": t.live_definition,
            "approved_definition": t.approved_definition,
            "scan_findings": findings,
            "inference": t.inference,
            "baseline": baseline,
        })
        if session is not None:
            view["changes"] = [change_view(c) for c in session.query(ToolChangeRow).filter(ToolChangeRow.tool_id == t.tool_id)
                               .order_by(ToolChangeRow.detected_at.desc()).limit(20).all()]
    return view


def change_view(c: ToolChangeRow, full: bool = False) -> dict[str, Any]:
    view = {
        "change_id": c.change_id,
        "tool_id": c.tool_id,
        "server_id": c.server_id,
        "tool_name": c.tool_name,
        "change_type": c.change_type,
        "classification": c.classification,
        "score": c.score,
        "status": c.status,
        "detected_at": c.detected_at.isoformat(),
        "resolved_by": c.resolved_by,
        "findings": c.findings,
    }
    if full:
        view.update({"diff": c.diff, "old_definition": c.old_definition, "new_definition": c.new_definition})
    return view


def approve_tool(session: Session, tool: ToolRow, who: str, definition: dict[str, Any] | None = None) -> None:
    server = session.get(ServerRow, tool.server_id)
    wire = definition or tool.live_definition or tool.approved_definition or {}
    tool.approved_definition = wire
    tool.approved_hash = canonical_hash(wire)
    tool.review_state = ReviewState.APPROVED.value
    if tool.trust_status in {TrustStatus.QUARANTINED.value, TrustStatus.RESTRICTED.value, TrustStatus.BLOCKED.value}:
        tool.trust_status = TrustStatus.MONITORED.value
    inf = infer(wire, server_transport=(server.transport if server else "http") or "http")
    if not tool.profile_locked:
        tool.capabilities = [c.value for c in inf.capabilities]
        tool.sensitivity = inf.sensitivity.value
        tool.inference = inf.as_dict()
        tool.flow_roles = [r.value for r in inf.flow_roles]
    tool.description = str(wire.get("description") or "")
    tool.schema_json = dict(wire.get("inputSchema") or {"type": "object"})
    tool.annotations = dict(wire.get("annotations") or {})
    tool.integrity_hash = canonical_hash(wire)
    for c in session.query(ToolChangeRow).filter(ToolChangeRow.tool_id == tool.tool_id, ToolChangeRow.status == "OPEN").all():
        c.status = "ACCEPTED"
        c.resolved_by = who
        c.resolved_at = utcnow()
    session.commit()
    AuditStore(session).write_event("tool_approved", "MEDIUM", f"{tool.exposed_name or tool.tool_name} definition approved and pinned by {who}",
                                    {"tool_id": tool.tool_id, "hash": tool.approved_hash})


@router.get("/v1/tools")
def list_tools(session: Session = Depends(db_session), _r=Depends(reader), include_removed: bool = False) -> list[dict[str, Any]]:
    rows = session.query(ToolRow).order_by(ToolRow.server_id, ToolRow.tool_name).all()
    return [tool_view(t) for t in rows if include_removed or not t.removed]


@router.get("/v1/tools/{tool_id:path}/detail")
def get_tool(tool_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    t = session.get(ToolRow, tool_id)
    if not t:
        raise HTTPException(404, "tool not found")
    return tool_view(t, detail=True, session=session)


@router.post("/v1/tools/{tool_id:path}/approve")
def approve(tool_id: str, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    t = session.get(ToolRow, tool_id)
    if not t:
        raise HTTPException(404, "tool not found")
    approve_tool(session, t, identity.subject)
    return tool_view(t)


@router.post("/v1/tools/{tool_id:path}/reject")
def reject(tool_id: str, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    t = session.get(ToolRow, tool_id)
    if not t:
        raise HTTPException(404, "tool not found")
    t.review_state = ReviewState.REJECTED.value
    t.trust_status = TrustStatus.BLOCKED.value
    for c in session.query(ToolChangeRow).filter(ToolChangeRow.tool_id == tool_id, ToolChangeRow.status == "OPEN").all():
        c.status, c.resolved_by, c.resolved_at = "REJECTED", identity.subject, utcnow()
    CapabilityLeaseManager(session, get_settings()).revoke_tool(t.server_id, t.tool_name, "tool rejected")
    session.commit()
    AuditStore(session).write_event("tool_rejected", "HIGH", f"{t.exposed_name or t.tool_name} rejected by {identity.subject}", {"tool_id": tool_id})
    return tool_view(t)


@router.put("/v1/tools/{tool_id:path}/trust")
def tool_trust(tool_id: str, body: TrustBody, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    t = session.get(ToolRow, tool_id)
    if not t:
        raise HTTPException(404, "tool not found")
    if body.trust_status not in {s.value for s in TrustStatus}:
        raise HTTPException(400, "invalid trust status")
    previous = t.trust_status
    t.trust_status = body.trust_status
    if body.trust_status in {TrustStatus.QUARANTINED.value, TrustStatus.BLOCKED.value}:
        CapabilityLeaseManager(session, get_settings()).revoke_tool(t.server_id, t.tool_name, f"tool set to {body.trust_status}")
    session.commit()
    AuditStore(session).write_event("trust_change", "MEDIUM", f"{t.exposed_name}: {previous} → {body.trust_status} by {identity.subject}",
                                    {"tool_id": tool_id, "reason": body.reason})
    return tool_view(t)


@router.put("/v1/tools/{tool_id:path}/profile")
def tool_profile(tool_id: str, body: ProfileBody, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    t = session.get(ToolRow, tool_id)
    if not t:
        raise HTTPException(404, "tool not found")
    try:
        caps = [Capability(c) for c in body.capabilities]
    except ValueError as exc:
        raise HTTPException(422, f"unknown capability: {exc}") from exc
    if not caps:
        raise HTTPException(422, "at least one capability is required")
    sens = Sensitivity(body.sensitivity) if body.sensitivity else max_sensitivity([Sensitivity(t.sensitivity or "LOW")])
    t.capabilities = [c.value for c in Capability if c in caps]
    t.sensitivity = sens.value
    t.profile_locked = True
    inference = dict(t.inference or {})
    inference["locked"] = {"capabilities": t.capabilities, "sensitivity": t.sensitivity, "resource": body.resource or t.resource}
    t.inference = inference
    if body.resource:
        t.resource = body.resource
    session.commit()
    AuditStore(session).write_event("profile_locked", "MEDIUM", f"capability profile of {t.exposed_name} set by {identity.subject}",
                                    {"tool_id": tool_id, "capabilities": t.capabilities, "sensitivity": t.sensitivity})
    return tool_view(t)


@router.get("/v1/integrity/changes")
def list_changes(session: Session = Depends(db_session), _r=Depends(reader), status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    q = session.query(ToolChangeRow)
    if status:
        q = q.filter(ToolChangeRow.status == status.upper())
    return [change_view(c) for c in q.order_by(ToolChangeRow.detected_at.desc()).limit(min(limit, 500)).all()]


@router.get("/v1/integrity/changes/{change_id}")
def get_change(change_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    c = session.get(ToolChangeRow, change_id)
    if not c:
        raise HTTPException(404, "change not found")
    return change_view(c, full=True)


@router.post("/v1/integrity/changes/{change_id}/resolve")
def resolve_change(change_id: str, body: ResolveBody, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    c = session.get(ToolChangeRow, change_id)
    if not c:
        raise HTTPException(404, "change not found")
    if c.status != "OPEN":
        raise HTTPException(409, f"change is already {c.status}")
    tool = session.get(ToolRow, c.tool_id)
    action = body.action.lower()
    if action == "accept":
        if tool is None:
            raise HTTPException(404, "tool no longer exists")
        if c.change_type == "REMOVED":
            c.status = "ACCEPTED"
        else:
            if canonical_hash(c.new_definition or {}) != (tool.live_hash or ""):
                raise HTTPException(409, "the server's live definition changed again; review the newest change instead")
            approve_tool(session, tool, identity.subject, c.new_definition)
        c.status, c.resolved_by, c.resolved_at = "ACCEPTED", identity.subject, utcnow()
    elif action == "reject":
        c.status, c.resolved_by, c.resolved_at = "REJECTED", identity.subject, utcnow()
        if tool is not None:
            tool.trust_status = worse_trust(tool.trust_status, TrustStatus.QUARANTINED.value)
            CapabilityLeaseManager(session, get_settings()).revoke_tool(tool.server_id, tool.tool_name, "change rejected")
    else:
        raise HTTPException(422, "action must be accept or reject")
    session.commit()
    AuditStore(session).write_event("change_resolved", "MEDIUM", f"{c.tool_name} change {action}ed by {identity.subject}",
                                    {"change_id": change_id, "note": body.note})
    return change_view(c, full=True)


@router.get("/v1/integrity/toxic-flows")
def toxic_flows(session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    servers = {s.server_id: s for s in session.query(ServerRow).all()}
    nodes = [
        toxicflow.ToolNode(t.exposed_name or t.tool_name, t.server_id, set(t.flow_roles or []), set(t.capabilities or []))
        for t in session.query(ToolRow).all()
        if is_exposed(t, servers.get(t.server_id))
    ]
    report = toxicflow.analyze(nodes)
    report["server_names"] = {sid: s.server_name for sid, s in servers.items()}
    return report
