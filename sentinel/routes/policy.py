from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from policy.rules import EFFECTS
from sentinel.config import Settings, get_settings
from sentinel.db import PolicyRuleRow, RuntimeFlagRow
from sentinel.deps import admin_identity, db_session, reader
from sentinel.pipeline import get_runtime_flag
from sentinel.receipts import AuditStore
from sentinel.types import CAPABILITY_SENSITIVITY, ROLE_DEFAULT_CAPABILITIES, SENSITIVE_CAPABILITIES, Capability, utcnow

router = APIRouter()
LOCKDOWN_MODES = {"off", "approve_writes", "deny_all"}


class RuleBody(BaseModel):
    name: str
    effect: str
    match: dict[str, Any] = Field(default_factory=dict)
    priority: int = 100
    enabled: bool = True
    reason: str = ""


class LockdownBody(BaseModel):
    mode: str
    reason: str = ""


def rule_view(r: PolicyRuleRow) -> dict[str, Any]:
    return {"rule_id": r.rule_id, "name": r.name, "effect": r.effect, "match": r.match, "priority": r.priority,
            "enabled": r.enabled, "reason": r.reason, "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None}


@router.get("/v1/policy")
def policy_overview(session: Session = Depends(db_session), settings: Settings = Depends(get_settings), _r=Depends(reader)) -> dict[str, Any]:
    return {
        "roles": {role: sorted(c.value for c in caps) for role, caps in ROLE_DEFAULT_CAPABILITIES.items()},
        "capabilities": {c.value: CAPABILITY_SENSITIVITY[c].value for c in Capability},
        "sensitive_capabilities": sorted(c.value for c in SENSITIVE_CAPABILITIES),
        "thresholds": {
            "monitor": 20,
            "restrict": settings.restrict_risk_threshold,
            "step_up": settings.mfa_risk_threshold,
            "block": settings.block_risk_threshold,
            "alpha": settings.risk_alpha,
        },
        "lockdown": get_runtime_flag(session, "lockdown", "off"),
        "rules": [rule_view(r) for r in session.query(PolicyRuleRow).order_by(PolicyRuleRow.priority).all()],
        "hard_rules": [
            "missing/expired/foreign token → BLOCK",
            "unknown, disabled, quarantined or blocked server/tool → BLOCK",
            "role lacks any requested capability → BLOCK",
            "metadata-service SSRF, dangerous URL schemes, path traversal, credential paths, shell injection → BLOCK",
            "SECRET data (class or tainted content) → external egress → BLOCK",
            "restricted server/tool + sensitive capability → BLOCK",
            "critical runtime deviation → QUARANTINE + BLOCK",
            "risk ≥ block threshold → BLOCK; MFA never overrides this",
        ],
    }


@router.get("/v1/policy/rules")
def list_rules(session: Session = Depends(db_session), _r=Depends(reader)) -> list[dict[str, Any]]:
    return [rule_view(r) for r in session.query(PolicyRuleRow).order_by(PolicyRuleRow.priority).all()]


@router.post("/v1/policy/rules")
def create_rule(body: RuleBody, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    effect = body.effect.upper()
    if effect not in EFFECTS:
        raise HTTPException(422, f"effect must be one of {sorted(EFFECTS)}")
    caps = body.match.get("capabilities") or []
    for c in [caps] if isinstance(caps, str) else caps:
        if c not in {x.value for x in Capability}:
            raise HTTPException(422, f"unknown capability {c}")
    row = PolicyRuleRow(rule_id=uuid.uuid4().hex[:12], name=body.name[:256], effect=effect, match=body.match,
                        priority=body.priority, enabled=body.enabled, reason=body.reason, created_by=identity.subject, created_at=utcnow())
    session.add(row)
    session.commit()
    AuditStore(session).write_event("policy_rule", "MEDIUM", f"rule '{row.name}' ({effect}) created by {identity.subject}", rule_view(row))
    return rule_view(row)


@router.put("/v1/policy/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleBody, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    row = session.get(PolicyRuleRow, rule_id)
    if not row:
        raise HTTPException(404, "rule not found")
    effect = body.effect.upper()
    if effect not in EFFECTS:
        raise HTTPException(422, f"effect must be one of {sorted(EFFECTS)}")
    row.name, row.effect, row.match, row.priority, row.enabled, row.reason = body.name[:256], effect, body.match, body.priority, body.enabled, body.reason
    session.commit()
    AuditStore(session).write_event("policy_rule", "MEDIUM", f"rule '{row.name}' updated by {identity.subject}", rule_view(row))
    return rule_view(row)


@router.delete("/v1/policy/rules/{rule_id}")
def delete_rule(rule_id: str, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    row = session.get(PolicyRuleRow, rule_id)
    if not row:
        raise HTTPException(404, "rule not found")
    session.delete(row)
    session.commit()
    AuditStore(session).write_event("policy_rule", "MEDIUM", f"rule '{row.name}' deleted by {identity.subject}", {"rule_id": rule_id})
    return {"deleted": rule_id}


@router.get("/v1/policy/lockdown")
def get_lockdown(session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    row = session.get(RuntimeFlagRow, "lockdown")
    return {"mode": get_runtime_flag(session, "lockdown", "off"), "updated_by": row.updated_by if row else "",
            "reason": (row.value or {}).get("reason", "") if row else ""}


@router.put("/v1/policy/lockdown")
def set_lockdown(body: LockdownBody, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    mode = body.mode.lower()
    if mode not in LOCKDOWN_MODES:
        raise HTTPException(422, f"mode must be one of {sorted(LOCKDOWN_MODES)}")
    row = session.get(RuntimeFlagRow, "lockdown") or RuntimeFlagRow(key="lockdown")
    row.value = {"value": mode, "reason": body.reason}
    row.updated_by = identity.subject
    row.updated_at = utcnow()
    session.add(row)
    session.commit()
    AuditStore(session).write_event("lockdown", "CRITICAL" if mode != "off" else "INFO", f"lockdown set to {mode} by {identity.subject}",
                                    {"reason": body.reason})
    return {"mode": mode}

