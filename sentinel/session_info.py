"""Read-only views used by the meta-tools and the REST API (scoped to the caller)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from mfa.stepup import StepUpManager
from risk.memory import RiskMemory
from sentinel.config import Settings
from sentinel.db import ApprovalRow, LeaseRow, ReceiptRow, ToolChangeRow
from sentinel.pipeline import get_runtime_flag
from sentinel.store import StateStore
from sentinel.types import IdentityContext

ADMIN_ROLES = {"SECURITY_ADMIN", "SYSTEM_ADMIN"}


def session_status(session: Session, store: StateStore, settings: Settings, identity: IdentityContext, workflow_id: str) -> dict[str, Any]:
    challenges = StepUpManager(store, settings.mfa_ttl_seconds).pending(identity.subject)
    approvals = (
        session.query(ApprovalRow)
        .filter(ApprovalRow.subject == identity.subject, ApprovalRow.status == "PENDING")
        .order_by(ApprovalRow.created_at.desc())
        .limit(10)
        .all()
    )
    leases = (
        session.query(LeaseRow)
        .filter(LeaseRow.subject == identity.subject, LeaseRow.state.in_(["ACTIVE", "EXPIRING"]))
        .order_by(LeaseRow.created_at.desc())
        .limit(10)
        .all()
    )
    recent = (
        session.query(ReceiptRow)
        .filter(ReceiptRow.identity == identity.subject, ReceiptRow.decision != "ALLOW")
        .order_by(ReceiptRow.timestamp.desc())
        .limit(5)
        .all()
    )
    open_changes = session.query(ToolChangeRow).filter(ToolChangeRow.status == "OPEN").count()
    memory = RiskMemory(store, settings).snapshot(workflow_id)
    return {
        "subject": identity.subject,
        "workflow_id": workflow_id,
        "lockdown": get_runtime_flag(session, "lockdown", "off"),
        "pending_mfa": [
            {"challenge_id": c.challenge_id, "tool": c.exposed_name or c.tool_name, "risk": c.risk_score,
             "approve_at": f"{settings.dashboard_base_url}/#/approve/mfa/{c.challenge_id}"}
            for c in challenges
        ],
        "pending_approvals": [
            {"approval_id": a.approval_id, "tool": a.tool_name, "risk": a.risk_score,
             "approve_at": f"{settings.dashboard_base_url}/#/approve/approval/{a.approval_id}"}
            for a in approvals
        ],
        "active_leases": [{"capability": lease.capability, "tool": lease.tool_name, "expires_at": lease.expires_at.isoformat()} for lease in leases],
        "recent_non_allow_decisions": [
            {"tool": r.tool, "decision": r.decision, "risk": r.risk_score, "receipt": r.receipt_id[:8], "why": (r.reasons or [""])[0]}
            for r in recent
        ],
        "open_integrity_alerts": open_changes,
        "workflow_risk_memory": {k: round(v["p"], 3) for k, v in memory.items()},
    }


def explain_receipt(session: Session, identity: IdentityContext, receipt_id: str) -> dict[str, Any]:
    receipt_id = receipt_id.strip()
    row = session.get(ReceiptRow, receipt_id)
    if row is None and 4 <= len(receipt_id) < 36:
        row = (
            session.query(ReceiptRow)
            .filter(ReceiptRow.receipt_id.like(f"{receipt_id}%"))
            .order_by(ReceiptRow.timestamp.desc())
            .first()
        )
    if row is None:
        return {"error": "receipt not found"}
    if row.identity != identity.subject and not ADMIN_ROLES & set(identity.roles):
        return {"error": "receipt belongs to another identity"}
    payload = row.payload or {}
    explain = payload.get("explainability") or {}
    return {
        "receipt_id": row.receipt_id,
        "tool": row.tool,
        "decision": row.decision,
        "risk_score": row.risk_score,
        "band": row.state,
        "policy": payload.get("policy_id"),
        "reasons": row.reasons,
        "risk_factors": explain.get("risk_factors", []),
        "likelihood": explain.get("likelihood"),
        "impact": explain.get("impact"),
        "gates": explain.get("gates", []),
        "previous_tools": row.previous_tools,
        "restrictions": payload.get("restrictions", []),
        "ledger": {"seq": row.seq, "hash": row.receipt_hash},
    }
