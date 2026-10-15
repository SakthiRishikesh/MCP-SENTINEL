from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from sentinel.config import Settings
from sentinel.db import LeaseRow
from sentinel.types import Capability, LeaseState, as_utc

LIVE_STATES = [LeaseState.ACTIVE.value, LeaseState.EXPIRING.value]


class CapabilityLeaseManager:
    """Temporary, workflow-scoped capability grants.

    A lease is bound to (workflow, subject, capability, server, tool) and - for CRITICAL
    tools - to the exact action (``scope_hash`` of the canonical arguments): what the user
    approved with MFA is exactly what may run. Leases are revoked on integrity changes,
    runtime compromise, critical risk or hard policy denials.
    """

    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def grant(
        self,
        *,
        workflow_id: str,
        subject: str,
        capability: Capability,
        tool_name: str,
        seconds: int | None = None,
        server_id: str = "",
        scope_hash: str = "",
    ) -> LeaseRow:
        ttl = seconds or self.settings.lease_default_seconds
        row = LeaseRow(
            lease_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            subject=subject,
            capability=capability.value,
            tool_name=tool_name,
            state=LeaseState.ACTIVE.value,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
            server_id=server_id,
            scope_hash=scope_hash,
        )
        self.session.add(row)
        self.session.commit()
        return row

    def active_lease(
        self,
        workflow_id: str,
        subject: str,
        capability: Capability,
        *,
        server_id: str | None = None,
        tool_name: str | None = None,
        scope_hash: str | None = None,
    ) -> LeaseRow | None:
        now = datetime.now(timezone.utc)
        query = self.session.query(LeaseRow).filter(
            LeaseRow.workflow_id == workflow_id,
            LeaseRow.subject == subject,
            LeaseRow.capability == capability.value,
            LeaseRow.state.in_(LIVE_STATES),
        )
        if tool_name is not None:
            query = query.filter(LeaseRow.tool_name == tool_name)
        if server_id is not None:
            query = query.filter(or_(LeaseRow.server_id == server_id, LeaseRow.server_id.is_(None), LeaseRow.server_id == ""))
        rows = query.order_by(LeaseRow.created_at.desc()).all()
        for row in rows:
            expires = as_utc(row.expires_at)
            if expires is None or expires <= now:
                row.state = LeaseState.EXPIRED.value
                self.session.add(row)
                self.session.commit()
                continue
            # Action-bound lease: only the exact approved arguments are covered.
            if row.scope_hash and scope_hash is not None and row.scope_hash != scope_hash:
                continue
            remaining = (expires - now).total_seconds()
            if remaining <= 15 and row.state != LeaseState.EXPIRING.value:
                row.state = LeaseState.EXPIRING.value
                self.session.add(row)
                self.session.commit()
            return row
        return None

    def revoke(self, lease_id: str, reason: str) -> None:
        row = self.session.get(LeaseRow, lease_id)
        if row and row.state in LIVE_STATES:
            row.state = LeaseState.REVOKED.value
            row.revoked_reason = reason
            self.session.add(row)
            self.session.commit()

    def _revoke_query(self, query, reason: str) -> int:
        rows = query.filter(LeaseRow.state.in_(LIVE_STATES)).all()
        for row in rows:
            row.state = LeaseState.REVOKED.value
            row.revoked_reason = reason
            self.session.add(row)
        self.session.commit()
        return len(rows)

    def revoke_workflow(self, workflow_id: str, reason: str) -> int:
        return self._revoke_query(self.session.query(LeaseRow).filter(LeaseRow.workflow_id == workflow_id), reason)

    def revoke_tool(self, server_id: str, tool_name: str, reason: str) -> int:
        return self._revoke_query(
            self.session.query(LeaseRow).filter(LeaseRow.server_id == server_id, LeaseRow.tool_name == tool_name), reason
        )

    def revoke_server(self, server_id: str, reason: str) -> int:
        return self._revoke_query(self.session.query(LeaseRow).filter(LeaseRow.server_id == server_id), reason)

    def expire_due(self) -> int:
        now = datetime.now(timezone.utc)
        rows = self.session.query(LeaseRow).filter(LeaseRow.state.in_(LIVE_STATES)).all()
        count = 0
        for row in rows:
            expires = as_utc(row.expires_at)
            if expires is not None and expires <= now:
                row.state = LeaseState.EXPIRED.value
                self.session.add(row)
                count += 1
        self.session.commit()
        return count
