from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from mfa import enrollment
from mfa.stepup import MfaChallenge, StepUpManager
from sentinel.config import Settings, get_settings
from sentinel.db import ApprovalRow
from sentinel.deps import ADMIN_ROLES, admin_identity, current_identity, db_session, get_store, reader
from sentinel.leases import CapabilityLeaseManager
from sentinel.receipts import AuditStore
from sentinel.types import Capability, IdentityContext, as_utc, utcnow

router = APIRouter()


class MfaCompleteBody(BaseModel):
    challenge_id: str


class VerifyBody(BaseModel):
    code: str | None = None
    demo: bool = False


class CodeBody(BaseModel):
    code: str = ""


class ApprovalBody(BaseModel):
    approval_id: str
    decision: str
    note: str = ""


def _mfa(settings: Settings) -> StepUpManager:
    return StepUpManager(get_store(), settings.mfa_ttl_seconds)


def _challenge_view(c: MfaChallenge, settings: Settings) -> dict[str, Any]:
    data = asdict(c)
    data["kind"] = "mfa"
    data["approve_url"] = f"{settings.dashboard_base_url}/#/approve/mfa/{c.challenge_id}"
    return data


def _grant_after_mfa(session: Session, settings: Settings, challenge: MfaChallenge, subject: str) -> str:
    lease = CapabilityLeaseManager(session, settings).grant(
        workflow_id=challenge.workflow_id,
        subject=subject,
        capability=Capability(challenge.capability),
        tool_name=challenge.tool_name,
        server_id=challenge.server_id,
        scope_hash=challenge.scope_hash,
    )
    return lease.lease_id


@router.post("/v1/mfa/complete")
def mfa_complete(
    body: MfaCompleteBody,
    identity: IdentityContext = Depends(current_identity),
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """IdP step-up path: present a token whose acr/amr proves MFA for the challenge's subject."""
    mgr = _mfa(settings)
    try:
        challenge = mgr.complete(body.challenge_id, identity)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    lease_id = _grant_after_mfa(session, settings, challenge, identity.subject)
    mgr.attach_lease(challenge, lease_id)
    AuditStore(session).write_event("mfa_satisfied", "INFO", f"step-up satisfied (IdP) for {challenge.tool_name}",
                                    {"challenge_id": challenge.challenge_id, "subject": identity.subject, "lease_id": lease_id})
    return {
        "status": "mfa_satisfied",
        "challenge_id": challenge.challenge_id,
        "lease_id": lease_id,
        "note": "MFA increased assurance only. Re-run the tool call; Sentinel will re-evaluate policy and risk.",
    }


@router.get("/v1/mfa/challenges/{challenge_id}")
def get_challenge(challenge_id: str, settings: Settings = Depends(get_settings), identity=Depends(reader)) -> dict[str, Any]:
    challenge = _mfa(settings).get(challenge_id)
    if challenge is None:
        return {"challenge_id": challenge_id, "status": "EXPIRED"}
    if identity is not None and identity.subject != challenge.subject and not ADMIN_ROLES & set(identity.roles):
        raise HTTPException(403, "challenge belongs to another identity")
    return _challenge_view(challenge, settings)


@router.post("/v1/mfa/challenges/{challenge_id}/verify")
def verify_challenge(
    challenge_id: str,
    body: VerifyBody,
    identity: IdentityContext = Depends(current_identity),
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    mgr = _mfa(settings)
    challenge = mgr.get(challenge_id)
    if challenge is None:
        raise HTTPException(404, "unknown or expired MFA challenge")
    if challenge.subject != identity.subject:
        raise HTTPException(403, "only the user who triggered the call can complete its step-up")
    if challenge.status != "PENDING":
        raise HTTPException(409, f"challenge is {challenge.status}")
    if body.code:
        if not enrollment.verify(session, identity.subject, body.code):
            AuditStore(session).write_event("mfa_failed", "MEDIUM", f"invalid TOTP for {challenge.tool_name}",
                                            {"challenge_id": challenge_id, "subject": identity.subject})
            raise HTTPException(400, "invalid or already used TOTP code")
        method = "totp"
    elif body.demo:
        if settings.auth_mode != "demo":
            raise HTTPException(403, "demo confirmation is disabled outside demo mode")
        if enrollment.has_active(session, identity.subject):
            raise HTTPException(400, "an authenticator is enrolled for this user: enter its TOTP code")
        method = "demo_confirm"
    elif identity.mfa_satisfied:
        method = "idp_acr"
    else:
        raise HTTPException(400, "provide a TOTP code")
    challenge = mgr.mark_satisfied(challenge, method)
    lease_id = _grant_after_mfa(session, settings, challenge, identity.subject)
    mgr.attach_lease(challenge, lease_id)
    AuditStore(session).write_event("mfa_satisfied", "INFO", f"step-up satisfied ({method}) for {challenge.exposed_name or challenge.tool_name}",
                                    {"challenge_id": challenge_id, "subject": identity.subject, "lease_id": lease_id, "method": method})
    return {"status": "SATISFIED", "method": method, "lease_id": lease_id, "challenge": _challenge_view(challenge, settings)}


@router.post("/v1/mfa/challenges/{challenge_id}/deny")
def deny_challenge(
    challenge_id: str,
    identity: IdentityContext = Depends(current_identity),
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    try:
        challenge = _mfa(settings).deny(challenge_id, identity)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    AuditStore(session).write_event("mfa_denied", "MEDIUM", f"user denied step-up for {challenge.tool_name}",
                                    {"challenge_id": challenge_id, "subject": identity.subject})
    return {"status": "DENIED"}


@router.get("/v1/mfa/totp/status")
def totp_status(identity: IdentityContext = Depends(current_identity), session: Session = Depends(db_session)) -> dict[str, Any]:
    return enrollment.status(session, identity.subject)


@router.post("/v1/mfa/totp/enroll")
def totp_enroll(body: CodeBody | None = None, identity: IdentityContext = Depends(current_identity),
                session: Session = Depends(db_session)) -> dict[str, Any]:
    # Rotating an active factor requires the current factor (a stolen first-factor token is not enough).
    if enrollment.has_active(session, identity.subject) and not (body and body.code and enrollment.verify(session, identity.subject, body.code)):
        raise HTTPException(400, "an authenticator is already active: provide a current code to rotate it")
    data = enrollment.begin(session, identity.subject)
    AuditStore(session).write_event("mfa_enroll_started", "INFO", f"TOTP enrollment started for {identity.subject}", {})
    return {**data, "subject": identity.subject, "note": "Scan the otpauth URI (or type the secret) into an authenticator app, then activate with a code."}


@router.post("/v1/mfa/totp/activate")
def totp_activate(body: CodeBody, identity: IdentityContext = Depends(current_identity), session: Session = Depends(db_session)) -> dict[str, Any]:
    if not enrollment.activate(session, identity.subject, body.code):
        raise HTTPException(400, "invalid code")
    AuditStore(session).write_event("mfa_enrolled", "INFO", f"TOTP authenticator activated for {identity.subject}", {})
    return enrollment.status(session, identity.subject)


@router.delete("/v1/mfa/totp")
def totp_remove(body: CodeBody, identity: IdentityContext = Depends(current_identity), session: Session = Depends(db_session)) -> dict[str, Any]:
    if enrollment.has_active(session, identity.subject) and not enrollment.verify(session, identity.subject, body.code):
        raise HTTPException(400, "a current TOTP code is required to remove the authenticator")
    enrollment.remove(session, identity.subject)
    AuditStore(session).write_event("mfa_removed", "MEDIUM", f"TOTP authenticator removed for {identity.subject}", {})
    return enrollment.status(session, identity.subject)


def approval_view(row: ApprovalRow, settings: Settings) -> dict[str, Any]:
    expires = as_utc(row.expires_at)
    status = row.status
    if status == "PENDING" and expires is not None and expires < utcnow():
        status = "EXPIRED"
    return {
        "kind": "approval",
        "approval_id": row.approval_id,
        "workflow_id": row.workflow_id,
        "tool_name": row.tool_name,
        "server_id": row.server_id,
        "subject": row.subject,
        "status": status,
        "consumed": bool(row.consumed),
        "risk_score": row.risk_score,
        "reasons": row.reasons or [],
        "request": row.request_json or {},
        "sandbox": (row.request_json or {}).get("sandbox"),  # pre-flight verdict + effect preview
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "expires_at": expires.isoformat() if expires else None,
        "resolver": row.resolver,
        "approve_url": f"{settings.dashboard_base_url}/#/approve/approval/{row.approval_id}",
    }


def _resolve(session: Session, settings: Settings, row: ApprovalRow, identity: IdentityContext, decision: str, note: str = "") -> dict[str, Any]:
    normalized = {"approve": "APPROVED", "approved": "APPROVED", "allow": "APPROVED", "deny": "DENIED", "denied": "DENIED",
                  "reject": "DENIED", "rejected": "DENIED"}.get(decision.strip().lower())
    if normalized is None:
        raise HTTPException(422, "decision must be APPROVED or DENIED")
    if row.status != "PENDING":
        raise HTTPException(409, f"approval is already {row.status}")
    if row.subject == identity.subject and not settings.self_approval_allowed:
        raise HTTPException(403, "separation of duties: you cannot approve your own request")
    row.status = normalized
    row.resolver = identity.subject
    row.resolved_at = utcnow()
    if normalized == "APPROVED":
        row.expires_at = utcnow() + timedelta(seconds=settings.approval_ttl_seconds)  # single use within this window
    session.commit()
    AuditStore(session).write_event("approval_resolved", "MEDIUM", f"{row.tool_name}: {normalized} by {identity.subject}",
                                    {"approval_id": row.approval_id, "subject": row.subject, "note": note})
    return approval_view(row, settings)


@router.get("/v1/approvals")
def list_approvals(session: Session = Depends(db_session), settings: Settings = Depends(get_settings), _r=Depends(reader),
                   status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    q = session.query(ApprovalRow)
    if status:
        q = q.filter(ApprovalRow.status == status.upper())
    return [approval_view(r, settings) for r in q.order_by(ApprovalRow.created_at.desc()).limit(min(limit, 500)).all()]


@router.get("/v1/approvals/{approval_id}")
def get_approval(approval_id: str, session: Session = Depends(db_session), settings: Settings = Depends(get_settings), _r=Depends(reader)) -> dict[str, Any]:
    row = session.get(ApprovalRow, approval_id)
    if not row:
        return {"approval_id": approval_id, "status": "EXPIRED"}
    return approval_view(row, settings)


@router.post("/v1/approvals")
def create_or_resolve_approval(
    body: ApprovalBody,
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
    identity: IdentityContext = Depends(admin_identity),
) -> dict[str, Any]:
    row = session.get(ApprovalRow, body.approval_id)
    if not row:
        raise HTTPException(404, "approval not found")
    return _resolve(session, settings, row, identity, body.decision, body.note)


@router.post("/v1/approvals/{approval_id}/{action}")
def resolve_approval(
    approval_id: str,
    action: str,
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
    identity: IdentityContext = Depends(admin_identity),
) -> dict[str, Any]:
    row = session.get(ApprovalRow, approval_id)
    if not row:
        raise HTTPException(404, "approval not found")
    return _resolve(session, settings, row, identity, action)


@router.get("/v1/inbox")
def inbox(session: Session = Depends(db_session), settings: Settings = Depends(get_settings), identity=Depends(reader)) -> dict[str, Any]:
    """Everything waiting on a human: step-up challenges and approval requests (live dashboard pop-ups)."""
    subject = None if identity is None or ADMIN_ROLES & set(identity.roles) else identity.subject
    challenges = [_challenge_view(c, settings) for c in _mfa(settings).pending(subject)]
    now = utcnow()
    approvals = [
        approval_view(r, settings)
        for r in session.query(ApprovalRow).filter(ApprovalRow.status == "PENDING").order_by(ApprovalRow.created_at.desc()).limit(50).all()
        if (subject is None or r.subject == subject) and (as_utc(r.expires_at) is None or as_utc(r.expires_at) > now)
    ]
    return {"mfa": challenges, "approvals": approvals, "count": len(challenges) + len(approvals)}
