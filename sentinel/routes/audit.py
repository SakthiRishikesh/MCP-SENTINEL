from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from dataflow.taint import TaintStore
from mfa.stepup import StepUpManager
from risk.memory import RiskMemory
from monitoring import entity
from sentinel import presence
from sentinel.config import Settings, get_settings
from sentinel.db import (
    ApprovalRow,
    EntityProfileRow,
    EventRow,
    LeaseRow,
    ReceiptRow,
    ServerRow,
    ToolChangeRow,
    ToolRow,
    WorkflowCallRow,
)
from sentinel.deps import admin_identity, current_identity, db_session, get_store, reader
from sentinel.leases import CapabilityLeaseManager
from sentinel.pipeline import get_runtime_flag
from sentinel.receipts import AuditStore, public_key_pem, verify_chain
from sentinel.session_info import explain_receipt, session_status
from sentinel.types import FlowRole, IdentityContext, as_utc, utcnow

router = APIRouter()


def receipt_view(r: ReceiptRow, full: bool = True) -> dict[str, Any]:
    view = {
        "receipt_id": r.receipt_id,
        "workflow_id": r.workflow_id,
        "identity": r.identity,
        "agent": r.agent,
        "server": r.server,
        "tool": r.tool,
        "decision": r.decision,
        "risk_score": r.risk_score,
        "state": r.state,
        "reasons": r.reasons,
        "previous_tools": r.previous_tools,
        "timestamp": as_utc(r.timestamp).isoformat(),
        "seq": r.seq,
        "receipt_hash": r.receipt_hash,
    }
    if full:
        view["payload"] = r.payload
    return view


@router.get("/v1/receipts")
def list_receipts(session: Session = Depends(db_session), _r=Depends(reader), limit: int = 100, workflow_id: str | None = None,
                  decision: str | None = None) -> list[dict[str, Any]]:
    q = session.query(ReceiptRow)
    if workflow_id:
        q = q.filter(ReceiptRow.workflow_id == workflow_id)
    if decision:
        q = q.filter(ReceiptRow.decision == decision.upper())
    return [receipt_view(r) for r in q.order_by(ReceiptRow.timestamp.desc()).limit(min(limit, 1000)).all()]


@router.get("/v1/receipts/{receipt_id}")
def get_receipt(receipt_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    r = session.get(ReceiptRow, receipt_id)
    if r is None:
        raise HTTPException(404, "receipt not found")
    return receipt_view(r)


@router.get("/v1/receipts/{receipt_id}/explain")
def explain(receipt_id: str, session: Session = Depends(db_session), identity: IdentityContext = Depends(current_identity)) -> dict[str, Any]:
    return explain_receipt(session, identity, receipt_id)


@router.get("/v1/audit/verify")
def audit_verify(session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    return verify_chain(session)


@router.get("/v1/audit/public-key")
def audit_public_key() -> dict[str, str]:
    return {"algorithm": "Ed25519", "public_key_pem": public_key_pem()}


@router.get("/v1/events")
def list_events(session: Session = Depends(db_session), _r=Depends(reader), limit: int = 100, event_type: str | None = None,
                exclude_decisions: bool = False) -> list[dict[str, Any]]:
    q = session.query(EventRow)
    if event_type:
        q = q.filter(EventRow.event_type == event_type)
    if exclude_decisions:
        q = q.filter(EventRow.event_type != "decision")
    rows = q.order_by(EventRow.timestamp.desc()).limit(min(limit, 1000)).all()
    return [
        {"event_id": r.event_id, "event_type": r.event_type, "severity": r.severity, "message": r.message, "details": r.details,
         "timestamp": as_utc(r.timestamp).isoformat()}
        for r in rows
    ]


def _workflow_summary(session: Session, settings: Settings, workflow_id: str, calls: list[WorkflowCallRow]) -> dict[str, Any]:
    store = get_store()
    executed = [c for c in calls if c.allowed]
    roles = {r for c in executed for r in (c.flow_roles or [])}
    extras = store.get_json(f"wfx:{workflow_id}") or {}
    untrusted = FlowRole.UNTRUSTED_SOURCE.value in roles or bool(extras.get("untrusted_injection_seen"))
    private = FlowRole.PRIVATE_SOURCE.value in roles
    egress = FlowRole.EGRESS_SINK.value in roles
    return {
        "workflow_id": workflow_id,
        "subject": next((c.subject for c in calls if c.subject), ""),
        "calls": len(calls),
        "executed": len(executed),
        "blocked": sum(1 for c in calls if c.decision == "BLOCK"),
        "max_risk": max((c.risk_score or 0 for c in calls), default=0),
        "last_activity": as_utc(calls[-1].timestamp).isoformat() if calls else None,
        "trifecta": {"private_data": private, "untrusted_content": untrusted, "external_comm": egress,
                     "injection_seen": bool(extras.get("untrusted_injection_seen"))},
        "secret_in_context": bool(extras.get("secret_output_seen")) or any(c.data_class in {"SECRET", "CRITICAL"} for c in executed),
        "tainted_tokens": TaintStore(store, settings.workflow_ttl_seconds).size(workflow_id),
        "risk_memory": {k: round(v["p"], 3) for k, v in RiskMemory(store, settings).snapshot(workflow_id).items()},
        "intent": extras.get("intent", ""),
    }


@router.get("/v1/workflows")
def list_workflows(session: Session = Depends(db_session), settings: Settings = Depends(get_settings), _r=Depends(reader),
                   limit: int = 30) -> list[dict[str, Any]]:
    latest = (
        session.query(WorkflowCallRow.workflow_id, func.max(WorkflowCallRow.id).label("last"))
        .group_by(WorkflowCallRow.workflow_id)
        .order_by(func.max(WorkflowCallRow.id).desc())
        .limit(min(limit, 200))
        .all()
    )
    out = []
    for wf_id, _ in latest:
        calls = session.query(WorkflowCallRow).filter(WorkflowCallRow.workflow_id == wf_id).order_by(WorkflowCallRow.id.asc()).all()
        out.append(_workflow_summary(session, settings, wf_id, calls))
    return out


@router.get("/v1/workflows/{workflow_id}")
def workflow_view(workflow_id: str, session: Session = Depends(db_session), settings: Settings = Depends(get_settings),
                  _r=Depends(reader)) -> dict[str, Any]:
    calls = (
        session.query(WorkflowCallRow)
        .filter(WorkflowCallRow.workflow_id == workflow_id)
        .order_by(WorkflowCallRow.id.asc())
        .all()
    )
    receipts = (
        session.query(ReceiptRow)
        .filter(ReceiptRow.workflow_id == workflow_id)
        .order_by(ReceiptRow.timestamp.asc())
        .all()
    )
    return {
        "workflow_id": workflow_id,
        "summary": _workflow_summary(session, settings, workflow_id, calls),
        "calls": [
            {
                "tool": c.tool_name,
                "server_id": c.server_id,
                "capability": c.capability,
                "resource": c.resource,
                "destination": c.destination,
                "data_class": c.data_class,
                "allowed": c.allowed,
                "decision": c.decision,
                "risk_score": c.risk_score,
                "flow_roles": c.flow_roles or [],
                "timestamp": as_utc(c.timestamp).isoformat(),
            }
            for c in calls
        ],
        "receipts": [
            {
                "tool": r.tool,
                "decision": r.decision,
                "risk_score": r.risk_score,
                "reasons": r.reasons,
                "receipt_id": r.receipt_id,
                "state": r.state,
                "factors": ((r.payload or {}).get("explainability") or {}).get("risk_factors", []),
                "gates": ((r.payload or {}).get("explainability") or {}).get("gates", []),
                "timestamp": as_utc(r.timestamp).isoformat(),
            }
            for r in receipts
        ],
    }


@router.get("/v1/leases")
def list_leases(session: Session = Depends(db_session), _r=Depends(reader), limit: int = 200) -> list[dict[str, Any]]:
    CapabilityLeaseManager(session, get_settings()).expire_due()
    rows = session.query(LeaseRow).order_by(LeaseRow.created_at.desc()).limit(min(limit, 1000)).all()
    return [
        {
            "lease_id": r.lease_id,
            "workflow_id": r.workflow_id,
            "subject": r.subject,
            "capability": r.capability,
            "tool_name": r.tool_name,
            "server_id": r.server_id,
            "action_bound": bool(r.scope_hash),
            "state": r.state,
            "expires_at": as_utc(r.expires_at).isoformat(),
            "created_at": as_utc(r.created_at).isoformat() if r.created_at else None,
            "revoked_reason": r.revoked_reason,
        }
        for r in rows
    ]


@router.post("/v1/leases/{lease_id}/revoke")
def revoke_lease(lease_id: str, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    if session.get(LeaseRow, lease_id) is None:
        raise HTTPException(404, "lease not found")
    CapabilityLeaseManager(session, get_settings()).revoke(lease_id, f"revoked by {identity.subject}")
    AuditStore(session).write_event("lease_revoked", "MEDIUM", f"lease {lease_id[:8]} revoked by {identity.subject}", {"lease_id": lease_id})
    return {"lease_id": lease_id, "state": "REVOKED"}


@router.get("/v1/session/status")
def status(workflow_id: str, session: Session = Depends(db_session), settings: Settings = Depends(get_settings),
           identity: IdentityContext = Depends(current_identity)) -> dict[str, Any]:
    return session_status(session, get_store(), settings, identity, workflow_id)


@router.get("/v1/dashboard/summary")
def dashboard_summary(session: Session = Depends(db_session), settings: Settings = Depends(get_settings), _r=Depends(reader)) -> dict[str, Any]:
    servers = session.query(ServerRow).all()
    counts: dict[str, int] = {}
    for s in servers:
        counts[s.trust_status] = counts.get(s.trust_status, 0) + 1
    now = utcnow()
    window = now - timedelta(hours=24)
    recent = session.query(ReceiptRow).filter(ReceiptRow.timestamp >= window).all()
    last_15 = [r for r in recent if as_utc(r.timestamp) >= now - timedelta(minutes=15)]
    decisions: dict[str, int] = {}
    for r in recent:
        decisions[r.decision] = decisions.get(r.decision, 0) + 1
    tools = session.query(ToolRow).all()
    live_tools = [t for t in tools if not t.removed]
    leases = session.query(LeaseRow).filter(LeaseRow.state.in_(["ACTIVE", "EXPIRING"])).all()
    active_leases = [lease for lease in leases if as_utc(lease.expires_at) > now]
    open_changes = session.query(ToolChangeRow).filter(ToolChangeRow.status == "OPEN").all()
    pending_approvals = session.query(ApprovalRow).filter(ApprovalRow.status == "PENDING").count()
    alerts = session.query(EventRow).filter(EventRow.event_type != "decision", EventRow.timestamp >= window,
                                            EventRow.severity.in_(["HIGH", "CRITICAL"])).count()
    active_risk = max((r.risk_score for r in last_15), default=0)
    return {
        "servers": {
            "total": len(servers),
            "trusted": counts.get("TRUSTED", 0),
            "monitored": counts.get("MONITORED", 0),
            "restricted": counts.get("RESTRICTED", 0),
            "quarantined": counts.get("QUARANTINED", 0),
            "blocked": counts.get("BLOCKED", 0),
            "connected": sum(1 for s in servers if s.discovery_status == "OK"),
        },
        "tools": {
            "total": len(live_tools),
            "quarantined": sum(1 for t in live_tools if t.trust_status in {"QUARANTINED", "BLOCKED"}),
            "under_review": sum(1 for t in live_tools if t.review_state in {"CHANGED", "PENDING_REVIEW"}),
        },
        "decisions_24h": decisions,
        "calls_24h": len(recent),
        "high_risk_calls": sum(1 for r in recent if r.risk_score >= settings.mfa_risk_threshold),
        "blocked_calls": decisions.get("BLOCK", 0),
        "mfa_challenges": decisions.get("MFA_REQUIRED", 0),
        "human_approvals": decisions.get("HUMAN_APPROVAL", 0),
        "pending_approvals": pending_approvals,
        "pending_mfa": len(StepUpManager(get_store(), settings.mfa_ttl_seconds).pending()),
        "active_leases": len(active_leases),
        "tool_changes": len(open_changes),
        "rug_pulls": sum(1 for c in open_changes if c.classification in {"SUSPICIOUS", "MALICIOUS"}),
        "behavior_alerts": alerts,
        "events": session.query(EventRow).filter(EventRow.timestamp >= window).count(),
        "active_risk": active_risk,
        "overall_risk": active_risk,
        "lockdown": get_runtime_flag(session, "lockdown", "off"),
        "store_backend": get_store().backend,
        "clients": presence.clients(max_age=600),
        "entities": session.query(EntityProfileRow).count(),
        "entity_anomalies_24h": session.query(EventRow).filter(
            EventRow.event_type == "entity_anomaly", EventRow.timestamp >= window).count(),
    }


@router.get("/v1/entities")
def list_entities(session: Session = Depends(db_session), _r=Depends(reader)) -> list[dict[str, Any]]:
    """Behavioural baseline for every caller (user / agent), most active first."""
    rows = session.query(EntityProfileRow).order_by(EntityProfileRow.updated_at.desc()).all()
    out = []
    for r in rows:
        out.append({**entity.summary(r.profile or {"subject": r.subject}), "anomalies": r.anomalies,
                    "last_anomaly": r.last_anomaly, "updated_at": r.updated_at.isoformat() if r.updated_at else None})
    return sorted(out, key=lambda e: (-e["anomalies"], -e["calls"]))


@router.get("/v1/entities/{subject}")
def get_entity(subject: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    row = session.get(EntityProfileRow, subject)
    if row is None:
        raise HTTPException(404, f"no behavioural profile for '{subject}' yet")
    events = [
        e for e in session.query(EventRow).filter(EventRow.event_type == "entity_anomaly")
        .order_by(EventRow.timestamp.desc()).limit(300).all()
        if (e.details or {}).get("subject") == subject
    ][:20]
    return {
        **entity.summary(row.profile or {"subject": subject}),
        "anomaly_count": row.anomalies,
        "last_anomaly": row.last_anomaly,
        "recent_anomalies": [
            {"at": e.timestamp.isoformat() if e.timestamp else None, "severity": e.severity, "message": e.message,
             "anomalies": (e.details or {}).get("anomalies", []), "tool": (e.details or {}).get("tool")}
            for e in events
        ],
    }
