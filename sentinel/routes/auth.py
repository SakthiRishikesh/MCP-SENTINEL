"""Account authentication: individual & organization signup, login, and the current account."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sentinel import accounts
from sentinel.accounts import AccountError
from sentinel.config import Settings, get_settings
from sentinel.db import AccountRow, OrganizationRow
from sentinel.deps import current_identity, db_session
from sentinel.receipts import AuditStore
from sentinel.types import IdentityContext

router = APIRouter()


class IndividualSignup(BaseModel):
    name: str = ""
    email: str
    password: str
    team: str = ""


class EmployeeInvite(BaseModel):
    name: str = ""
    email: str = ""
    role: str = "Security analyst"


class OrgSignup(BaseModel):
    organization: str
    organizationEmail: str = ""
    industry: str = ""
    size: str = ""
    region: str = ""
    adminName: str = ""
    adminEmail: str
    password: str
    employees: list[EmployeeInvite] = Field(default_factory=list)


class LoginBody(BaseModel):
    email: str
    password: str
    account_type: str = ""   # optional hint; ignored for verification
    org_role: str = ""


def _issue(settings: Settings, account: AccountRow, org: OrganizationRow | None) -> dict[str, Any]:
    return {
        "access_token": accounts.token_for(settings, account),
        "token_type": "bearer",
        "account": accounts.account_view(account, org),
        "redirect": "/app",
    }


@router.post("/v1/auth/signup/individual")
def signup_individual(body: IndividualSignup, session: Session = Depends(db_session),
                      settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    try:
        account = accounts.create_account(
            session, email=body.email, password=body.password, name=body.name,
            account_type="individual", roles=accounts.ADMIN_ROLES, team=body.team,
        )
        session.commit()
    except AccountError as exc:
        session.rollback()
        raise HTTPException(exc.status, exc.message) from exc
    AuditStore(session).write_event("account_created", "INFO", f"individual account {account.email} created",
                                    {"account_id": account.account_id, "type": "individual"})
    return _issue(settings, account, None)


@router.post("/v1/auth/signup/organization")
def signup_organization(body: OrgSignup, session: Session = Depends(db_session),
                        settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    try:
        org = accounts.create_organization(
            session, name=body.organization, email=body.organizationEmail, industry=body.industry,
            size=body.size, region=body.region, created_by=accounts._norm_email(body.adminEmail),
        )
        admin = accounts.create_account(
            session, email=body.adminEmail, password=body.password, name=body.adminName,
            account_type="organization", org_id=org.org_id, org_role="admin", roles=accounts.ADMIN_ROLES,
        )
        created = 0
        for invite in body.employees:
            if not (invite.email or "").strip():
                continue
            try:
                accounts.create_account(
                    session, email=invite.email, password=None, name=invite.name,
                    account_type="organization", org_id=org.org_id, org_role="employee",
                    roles=accounts.employee_role(invite.role), title=invite.role,
                )
                created += 1
            except AccountError:
                continue  # skip duplicates/invalid invites rather than fail the whole signup
        session.commit()
    except AccountError as exc:
        session.rollback()
        raise HTTPException(exc.status, exc.message) from exc
    AuditStore(session).write_event("account_created", "INFO", f"organization '{org.name}' created with admin {admin.email}",
                                    {"org_id": org.org_id, "admin": admin.account_id, "employees": created})
    return {**_issue(settings, admin, org), "employees_created": created}


@router.post("/v1/auth/login")
def login(body: LoginBody, session: Session = Depends(db_session),
          settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    try:
        account = accounts.authenticate(session, body.email, body.password)
    except AccountError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    org = session.get(OrganizationRow, account.org_id) if account.org_id else None
    session.commit()
    AuditStore(session).write_event("login", "INFO", f"{account.email} signed in",
                                    {"account_id": account.account_id, "type": account.account_type, "org_role": account.org_role or ""})
    return _issue(settings, account, org)


@router.post("/v1/auth/logout")
def logout() -> dict[str, Any]:
    # Tokens are stateless; the client discards it. Returned for a clean UX.
    return {"ok": True}


@router.get("/v1/auth/account")
def current_account(identity: IdentityContext = Depends(current_identity),
                    session: Session = Depends(db_session)) -> dict[str, Any]:
    """Full account record for the signed-in session (joins the organization)."""
    account = session.get(AccountRow, identity.subject)
    if account is None:
        # a legacy demo/bridge token with no account row: synthesize a view from the identity
        return {
            "account_id": identity.subject, "email": "", "name": identity.display_name or identity.subject,
            "account_type": identity.account_type or "individual", "org_id": identity.org_id,
            "org_role": identity.org_role, "roles": identity.roles, "title": "", "team": "",
            "disabled": False, "organization": None, "synthetic": True,
        }
    org = session.get(OrganizationRow, account.org_id) if account.org_id else None
    return accounts.account_view(account, org)
