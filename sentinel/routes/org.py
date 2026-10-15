"""Organization admin console: manage members and assign MCP servers/tools to them (RBAC)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sentinel import accounts
from sentinel.accounts import AccountError
from sentinel.db import AccountRow, AssignmentRow, OrganizationRow
from sentinel.deps import current_identity, db_session
from sentinel.receipts import AuditStore
from sentinel.types import IdentityContext

router = APIRouter()


def org_admin(identity: IdentityContext = Depends(current_identity),
              session: Session = Depends(db_session)) -> tuple[IdentityContext, OrganizationRow]:
    if not identity.is_org_admin or not identity.org_id:
        raise HTTPException(403, "organization admin access required")
    org = session.get(OrganizationRow, identity.org_id)
    if org is None:
        raise HTTPException(404, "organization not found")
    return identity, org


class NewMember(BaseModel):
    name: str = ""
    email: str
    role: str = "Security analyst"   # job title
    password: str = ""               # optional; if set the member can log in immediately


class UpdateMember(BaseModel):
    name: str | None = None
    role: str | None = None          # job title -> capability role
    disabled: bool | None = None
    password: str | None = None


class UpdateOrg(BaseModel):
    name: str | None = None
    industry: str | None = None
    size: str | None = None
    region: str | None = None


class Grant(BaseModel):
    server_id: str
    tools: list[str] = Field(default_factory=lambda: ["*"])


class SetAssignments(BaseModel):
    grants: list[Grant] = Field(default_factory=list)


def _member_view(session: Session, account: AccountRow) -> dict[str, Any]:
    view = accounts.account_view(account)
    view["assignments"] = accounts.assignment_view(session, account.account_id) if account.org_role == "employee" else "all"
    view["can_login"] = bool(account.password_hash)
    return view


@router.get("/v1/org")
def get_org(ctx=Depends(org_admin), session: Session = Depends(db_session)) -> dict[str, Any]:
    _identity, org = ctx
    members = session.query(AccountRow).filter(AccountRow.org_id == org.org_id).order_by(AccountRow.created_at).all()
    return {
        "org": {"org_id": org.org_id, "name": org.name, "slug": org.slug, "email": org.email,
                "industry": org.industry, "size": org.size, "region": org.region,
                "created_at": org.created_at.isoformat() if org.created_at else None},
        "members": [_member_view(session, m) for m in members],
        "admins": sum(1 for m in members if m.org_role == "admin"),
        "employees": sum(1 for m in members if m.org_role == "employee"),
    }


@router.patch("/v1/org")
def update_org(body: UpdateOrg, ctx=Depends(org_admin), session: Session = Depends(db_session)) -> dict[str, Any]:
    _identity, org = ctx
    for field in ("name", "industry", "size", "region"):
        value = getattr(body, field)
        if value is not None:
            setattr(org, field, value)
    session.commit()
    return {"ok": True, "org_id": org.org_id}


@router.post("/v1/org/members")
def add_member(body: NewMember, ctx=Depends(org_admin), session: Session = Depends(db_session)) -> dict[str, Any]:
    identity, org = ctx
    try:
        member = accounts.create_account(
            session, email=body.email, password=body.password or None, name=body.name,
            account_type="organization", org_id=org.org_id, org_role="employee",
            roles=accounts.employee_role(body.role), title=body.role,
        )
        session.commit()
    except AccountError as exc:
        session.rollback()
        raise HTTPException(exc.status, exc.message) from exc
    AuditStore(session).write_event("member_added", "INFO", f"{member.email} added to {org.name} by {identity.subject}",
                                    {"org_id": org.org_id, "account_id": member.account_id, "role": body.role})
    return _member_view(session, member)


@router.patch("/v1/org/members/{account_id}")
def update_member(account_id: str, body: UpdateMember, ctx=Depends(org_admin),
                  session: Session = Depends(db_session)) -> dict[str, Any]:
    identity, org = ctx
    member = session.get(AccountRow, account_id)
    if member is None or member.org_id != org.org_id:
        raise HTTPException(404, "member not found in this organization")
    if member.account_id == identity.subject and body.disabled:
        raise HTTPException(400, "you cannot disable your own admin account")
    if body.name is not None:
        member.name = body.name[:256]
    if body.role is not None and member.org_role == "employee":
        member.roles = accounts.employee_role(body.role)
        member.title = body.role[:128]
    if body.disabled is not None:
        member.disabled = body.disabled
    if body.password:
        try:
            member.password_hash = accounts.hash_password(body.password)
        except AccountError as exc:
            raise HTTPException(exc.status, exc.message) from exc
    session.commit()
    return _member_view(session, member)


@router.delete("/v1/org/members/{account_id}")
def remove_member(account_id: str, ctx=Depends(org_admin), session: Session = Depends(db_session)) -> dict[str, Any]:
    identity, org = ctx
    member = session.get(AccountRow, account_id)
    if member is None or member.org_id != org.org_id:
        raise HTTPException(404, "member not found in this organization")
    if member.account_id == identity.subject:
        raise HTTPException(400, "you cannot remove your own admin account")
    if member.org_role == "admin" and sum(1 for m in session.query(AccountRow).filter(AccountRow.org_id == org.org_id, AccountRow.org_role == "admin")) <= 1:
        raise HTTPException(400, "an organization must keep at least one admin")
    session.query(AssignmentRow).filter(AssignmentRow.account_id == account_id).delete()
    session.delete(member)
    session.commit()
    AuditStore(session).write_event("member_removed", "MEDIUM", f"{member.email} removed from {org.name} by {identity.subject}",
                                    {"org_id": org.org_id, "account_id": account_id})
    return {"deleted": account_id}


@router.get("/v1/org/members/{account_id}/assignments")
def get_assignments(account_id: str, ctx=Depends(org_admin), session: Session = Depends(db_session)) -> dict[str, Any]:
    _identity, org = ctx
    member = session.get(AccountRow, account_id)
    if member is None or member.org_id != org.org_id:
        raise HTTPException(404, "member not found in this organization")
    return {"account_id": account_id, "assignments": accounts.assignment_view(session, account_id)}


@router.put("/v1/org/members/{account_id}/assignments")
def set_assignments(account_id: str, body: SetAssignments, ctx=Depends(org_admin),
                    session: Session = Depends(db_session)) -> dict[str, Any]:
    identity, org = ctx
    member = session.get(AccountRow, account_id)
    if member is None or member.org_id != org.org_id:
        raise HTTPException(404, "member not found in this organization")
    if member.org_role != "employee":
        raise HTTPException(400, "assignments apply to employees; admins already have full access")
    accounts.set_member_assignments(session, org.org_id, account_id,
                                    [g.model_dump() for g in body.grants], by=identity.subject)
    session.commit()
    AuditStore(session).write_event("assignments_updated", "MEDIUM",
                                    f"access for {member.email} updated by {identity.subject}",
                                    {"org_id": org.org_id, "account_id": account_id, "servers": len(body.grants)})
    return {"account_id": account_id, "assignments": accounts.assignment_view(session, account_id)}


@router.get("/v1/org/catalog")
def catalog(ctx=Depends(org_admin), session: Session = Depends(db_session)) -> list[dict[str, Any]]:
    return accounts.org_catalog(session)
