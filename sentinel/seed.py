"""Database initialisation.

MCP-Sentinel ships with an empty registry: every MCP server is added by the user (dashboard,
API, or ``mcp-sentinel import-claude``). When ``seed_demo_accounts`` is on (the default, off in
tests) a small set of ready-to-use accounts is created so the login-gated dashboard can be tried
immediately — an individual, and an organization with an admin and two employees.
"""

from __future__ import annotations

import logging

from sentinel import accounts
from sentinel.config import get_settings
from sentinel.db import AccountRow, ServerRow, init_db, session_scope

log = logging.getLogger("sentinel.seed")

DEMO_PASSWORD = "sentinel"


def reset_interrupted_registrations() -> None:
    with session_scope() as session:
        for row in session.query(ServerRow).filter(ServerRow.discovery_status == "REGISTERING").all():
            row.discovery_status = "NEVER"
        session.commit()


def _assign_first_servers(session, org_id: str, account_id: str, want: list[str], by: str) -> None:
    """Assign the member every server whose name matches one of ``want`` (all of its tools)."""
    grants = []
    for server in session.query(ServerRow).all():
        if any(w.lower() in (server.server_name or "").lower() for w in want):
            grants.append({"server_id": server.server_id, "tools": ["*"]})
    if grants:
        accounts.set_member_assignments(session, org_id, account_id, grants, by=by)


def seed_demo_accounts() -> None:
    with session_scope() as session:
        if session.query(AccountRow).count() > 0:
            return  # already seeded (or real accounts exist)
        try:
            # Individual — shares the bridge's "local-user" subject so its dashboard sees local activity.
            accounts.create_account(
                session, email="you@demo.dev", password=DEMO_PASSWORD, name="Demo User",
                account_type="individual", roles=accounts.ADMIN_ROLES, account_id="local-user",
            )
            org = accounts.create_organization(
                session, name="Northstar Security", email="team@northstar.dev", industry="Technology",
                size="11–50", region="United States", created_by="admin@northstar.dev",
            )
            admin = accounts.create_account(
                session, email="admin@northstar.dev", password=DEMO_PASSWORD, name="Avery Stone",
                account_type="organization", org_id=org.org_id, org_role="admin", roles=accounts.ADMIN_ROLES,
            )
            analyst = accounts.create_account(
                session, email="analyst@northstar.dev", password=DEMO_PASSWORD, name="Jordan Lee",
                account_type="organization", org_id=org.org_id, org_role="employee",
                roles=accounts.employee_role("Security analyst"), title="Security analyst",
            )
            accounts.create_account(
                session, email="dev@northstar.dev", password=DEMO_PASSWORD, name="Riley Park",
                account_type="organization", org_id=org.org_id, org_role="employee",
                roles=accounts.employee_role("Developer"), title="Developer",
            )
            session.flush()
            # Give the analyst a starter set of tools; the admin can change this in the console.
            _assign_first_servers(session, org.org_id, analyst.account_id, ["Time", "Memory"], by=admin.account_id)
            session.commit()
            log.info("seeded demo accounts (you@demo.dev, admin@northstar.dev, analyst@northstar.dev, dev@northstar.dev)")
        except Exception:  # never let seeding break startup
            session.rollback()
            log.exception("demo account seeding failed")


def seed() -> None:
    """Create tables (and add new columns to older databases), then seed demo accounts if enabled."""
    init_db()
    reset_interrupted_registrations()
    if get_settings().seed_demo_accounts:
        seed_demo_accounts()


if __name__ == "__main__":
    seed()
