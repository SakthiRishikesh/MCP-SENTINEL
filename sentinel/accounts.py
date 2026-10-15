"""Real accounts, organizations and RBAC assignments on top of the demo-signed JWTs.

Two kinds of login, as described by the product:

* **Individual** — a personal workspace; full control of its own Sentinel instance (SECURITY_ADMIN).
* **Organization** — a team workspace with an **admin** (manages members and assigns MCP servers /
  tools) and **employees** (can only use the servers/tools the admin assigned, under a limited role).

Passwords are hashed with PBKDF2-HMAC-SHA256 (standard library). The session token is the same
HS256 demo JWT the rest of Sentinel already verifies, carrying the account's subject, roles and
org claims — so every existing gate (identity, RBAC, policy, risk) keeps working unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from typing import Any

from sqlalchemy.orm import Session

from identity.tokens import mint_demo_token
from sentinel.config import Settings
from sentinel.db import AccountRow, AssignmentRow, OrganizationRow, ServerRow, ToolRow
from sentinel.types import utcnow

PBKDF2_ROUNDS = 200_000
SESSION_TTL_SECONDS = 8 * 3600

# Job title (shown in the signup wizard) -> Sentinel capability role.
EMPLOYEE_ROLE_BY_TITLE = {
    "security analyst": "ANALYST",
    "analyst": "ANALYST",
    "developer": "DEVELOPER",
    "viewer": "USER",
}
ADMIN_ROLES = ["SECURITY_ADMIN"]


class AccountError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


# -- passwords --------------------------------------------------------------------------------
def hash_password(password: str) -> str:
    if len(password or "") < 8:
        raise AccountError("Password must be at least 8 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_hex, hash_hex = (encoded or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", (password or "").encode(), bytes.fromhex(salt_hex), int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), hash_hex)


# -- helpers ----------------------------------------------------------------------------------
def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return slug or f"org-{secrets.token_hex(3)}"


def unique_org_slug(session: Session, name: str) -> str:
    base = slugify(name)
    slug = base
    i = 2
    while session.query(OrganizationRow).filter(OrganizationRow.slug == slug).first() is not None:
        slug = f"{base}-{i}"
        i += 1
    return slug


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def get_by_email(session: Session, email: str) -> AccountRow | None:
    return session.query(AccountRow).filter(AccountRow.email == _norm_email(email)).first()


def employee_role(title: str) -> list[str]:
    return [EMPLOYEE_ROLE_BY_TITLE.get((title or "").strip().lower(), "USER")]


# -- creation ---------------------------------------------------------------------------------
def create_account(
    session: Session,
    *,
    email: str,
    password: str | None,
    name: str,
    account_type: str = "individual",
    org_id: str = "",
    org_role: str = "",
    roles: list[str] | None = None,
    title: str = "",
    team: str = "",
    account_id: str | None = None,
) -> AccountRow:
    email = _norm_email(email)
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise AccountError("Enter a valid email address.")
    if get_by_email(session, email) is not None:
        raise AccountError("An account with this email already exists.", status=409)
    row = AccountRow(
        account_id=account_id or f"acct-{uuid.uuid4().hex[:12]}",
        email=email,
        name=(name or email.split("@")[0]).strip()[:256],
        password_hash=hash_password(password) if password else "",
        account_type=account_type,
        org_id=org_id or "",
        org_role=org_role or "",
        roles=roles if roles is not None else ADMIN_ROLES,
        title=title[:128],
        team=team[:256],
    )
    session.add(row)
    session.flush()
    return row


def create_organization(session: Session, *, name: str, email: str = "", industry: str = "",
                         size: str = "", region: str = "", created_by: str = "") -> OrganizationRow:
    if not (name or "").strip():
        raise AccountError("Organization name is required.")
    org = OrganizationRow(
        org_id=f"org-{uuid.uuid4().hex[:12]}",
        name=name.strip()[:256],
        slug=unique_org_slug(session, name),
        email=_norm_email(email),
        industry=industry[:64],
        size=size[:32],
        region=region[:128],
        created_by=created_by,
    )
    session.add(org)
    session.flush()
    return org


# -- authentication / tokens ------------------------------------------------------------------
def authenticate(session: Session, email: str, password: str) -> AccountRow:
    account = get_by_email(session, email)
    if account is None or not account.password_hash or not verify_password(password, account.password_hash):
        raise AccountError("Incorrect email or password.", status=401)
    if account.disabled:
        raise AccountError("This account has been disabled. Contact your organization admin.", status=403)
    account.last_login = utcnow()
    return account


def token_for(settings: Settings, account: AccountRow) -> str:
    return mint_demo_token(
        settings,
        subject=account.account_id,
        roles=list(account.roles or ADMIN_ROLES),
        agent_id="sentinel-dashboard",
        ttl_seconds=SESSION_TTL_SECONDS,
        extra_claims={
            "account_type": account.account_type,
            "org_id": account.org_id or "",
            "org_role": account.org_role or "",
            "name": account.name,
        },
    )


def account_view(account: AccountRow, org: OrganizationRow | None = None) -> dict[str, Any]:
    return {
        "account_id": account.account_id,
        "email": account.email,
        "name": account.name,
        "account_type": account.account_type,
        "org_id": account.org_id or "",
        "org_role": account.org_role or "",
        "roles": list(account.roles or []),
        "title": account.title,
        "team": account.team,
        "disabled": account.disabled,
        "last_login": account.last_login.isoformat() if account.last_login else None,
        "created_at": account.created_at.isoformat() if account.created_at else None,
        "organization": {"org_id": org.org_id, "name": org.name, "slug": org.slug} if org else None,
    }


# -- RBAC assignments -------------------------------------------------------------------------
def assignments_for(session: Session, account_id: str) -> list[AssignmentRow]:
    return session.query(AssignmentRow).filter(AssignmentRow.account_id == account_id).all()


def allowed_server_tools(session: Session, identity) -> dict[str, set[str]] | None:
    """{server_id: {tool_name | "*"}} an org employee may use, or None for unrestricted callers.

    Individuals and org admins are unrestricted (None). Org employees get exactly what the admin
    assigned — an empty dict means "nothing assigned yet".
    """
    if not getattr(identity, "is_org_employee", False):
        return None
    out: dict[str, set[str]] = {}
    for a in assignments_for(session, identity.subject):
        out.setdefault(a.server_id, set()).update(a.tools or ["*"])
    return out


def is_tool_allowed(allowed: dict[str, set[str]] | None, server_id: str, tool_name: str) -> bool:
    if allowed is None:
        return True
    tools = allowed.get(server_id)
    if not tools:
        return False
    return "*" in tools or tool_name in tools


def set_member_assignments(session: Session, org_id: str, account_id: str,
                           grants: list[dict[str, Any]], by: str) -> list[AssignmentRow]:
    """Replace a member's assignments with ``grants`` ([{server_id, tools}])."""
    session.query(AssignmentRow).filter(
        AssignmentRow.org_id == org_id, AssignmentRow.account_id == account_id
    ).delete()
    rows: list[AssignmentRow] = []
    for grant in grants:
        server_id = str(grant.get("server_id") or "")
        if not server_id or session.get(ServerRow, server_id) is None:
            continue
        tools = grant.get("tools")
        tools = ["*"] if not tools or tools == ["*"] else [str(t) for t in tools]
        row = AssignmentRow(
            assignment_id=f"asg-{uuid.uuid4().hex[:12]}", org_id=org_id, account_id=account_id,
            server_id=server_id, tools=tools, created_by=by,
        )
        session.add(row)
        rows.append(row)
    session.flush()
    return rows


def assignment_view(session: Session, account_id: str) -> list[dict[str, Any]]:
    out = []
    for a in assignments_for(session, account_id):
        server = session.get(ServerRow, a.server_id)
        out.append({
            "assignment_id": a.assignment_id, "server_id": a.server_id,
            "server_name": server.server_name if server else a.server_id,
            "tools": list(a.tools or ["*"]),
        })
    return out


def org_catalog(session: Session) -> list[dict[str, Any]]:
    """Servers and their tools available to assign to members."""
    servers = session.query(ServerRow).all()
    out = []
    for s in servers:
        tools = [t.exposed_name or t.tool_name for t in
                 session.query(ToolRow).filter(ToolRow.server_id == s.server_id).all() if not t.removed]
        out.append({"server_id": s.server_id, "server_name": s.server_name, "slug": s.slug,
                    "transport": s.transport, "tools": sorted(tools)})
    return out
