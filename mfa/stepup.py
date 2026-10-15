from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.store import StateStore
from sentinel.types import IdentityContext


@dataclass
class MfaChallenge:
    challenge_id: str
    workflow_id: str
    subject: str
    capability: str
    tool_name: str
    created_at: str
    expires_at: str
    status: str = "PENDING"
    server_id: str = ""
    exposed_name: str = ""
    arguments_preview: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    scope_hash: str = ""
    receipt_id: str = ""
    method: str = ""
    completed_at: str = ""
    lease_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MfaChallenge":
        known = {f for f in cls.__dataclass_fields__}  # tolerate older payloads in Redis
        return cls(**{k: v for k, v in data.items() if k in known})


class StepUpManager:
    """MFA increases authentication assurance only. It is never a universal allow.

    A satisfied challenge results in a *capability lease* scoped to the workflow, subject,
    server, tool and (for CRITICAL tools) the exact action; Sentinel still re-evaluates the
    request on retry.
    """

    def __init__(self, store: StateStore, ttl_seconds: int = 300) -> None:
        self.store = store
        self.ttl_seconds = ttl_seconds

    def _save(self, challenge: MfaChallenge) -> None:
        self.store.setex(f"mfa:{challenge.challenge_id}", self.ttl_seconds, asdict(challenge))

    def _dedupe_key(self, workflow_id: str, subject: str, capability: str, tool: str, server_id: str, scope: str) -> str:
        return f"mfa-pending:{workflow_id}:{subject}:{server_id}:{tool}:{capability}:{scope}"

    def require(
        self,
        *,
        workflow_id: str,
        subject: str,
        capability: str,
        tool_name: str,
        server_id: str = "",
        exposed_name: str = "",
        arguments_preview: dict[str, Any] | None = None,
        risk_score: int = 0,
        reasons: list[str] | None = None,
        scope_hash: str = "",
        receipt_id: str = "",
    ) -> MfaChallenge:
        dedupe = self._dedupe_key(workflow_id, subject, capability, tool_name, server_id, scope_hash)
        existing_id = self.store.get_json(dedupe)
        if isinstance(existing_id, str):
            existing = self.get(existing_id)
            if existing and existing.status == "PENDING":
                existing.risk_score = risk_score
                existing.reasons = list(reasons or existing.reasons)
                existing.receipt_id = receipt_id or existing.receipt_id
                self._save(existing)
                return existing
        now = datetime.now(timezone.utc)
        challenge = MfaChallenge(
            challenge_id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            subject=subject,
            capability=capability,
            tool_name=tool_name,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=self.ttl_seconds)).isoformat(),
            server_id=server_id,
            exposed_name=exposed_name,
            arguments_preview=arguments_preview or {},
            risk_score=risk_score,
            reasons=list(reasons or []),
            scope_hash=scope_hash,
            receipt_id=receipt_id,
        )
        self._save(challenge)
        self.store.setex(dedupe, self.ttl_seconds, challenge.challenge_id)
        self.store.setex(f"mfa-wf:{workflow_id}:{capability}", self.ttl_seconds, asdict(challenge))
        return challenge

    def get(self, challenge_id: str) -> MfaChallenge | None:
        data = self.store.get_json(f"mfa:{challenge_id}")
        if not isinstance(data, dict):
            return None
        return MfaChallenge.from_dict(data)

    def pending(self, subject: str | None = None) -> list[MfaChallenge]:
        out = []
        for key in self.store.keys("mfa:"):
            ch = self.get(key.split(":", 1)[1])
            if ch and ch.status == "PENDING" and (subject is None or ch.subject == subject):
                out.append(ch)
        return sorted(out, key=lambda c: c.created_at, reverse=True)

    def _load_for(self, challenge_id: str, identity: IdentityContext) -> MfaChallenge:
        challenge = self.get(challenge_id)
        if challenge is None:
            raise ValueError("unknown or expired MFA challenge")
        if identity.subject != challenge.subject:
            raise ValueError("MFA subject mismatch")
        if challenge.status == "DENIED":
            raise ValueError("challenge was denied")
        return challenge

    def complete(self, challenge_id: str, identity: IdentityContext) -> MfaChallenge:
        """IdP step-up path: the presented token itself carries an MFA authentication context."""
        challenge = self._load_for(challenge_id, identity)
        if not identity.mfa_satisfied:
            raise ValueError("authentication context does not include MFA (acr/amr)")
        return self.mark_satisfied(challenge, "idp_acr")

    def mark_satisfied(self, challenge: MfaChallenge, method: str) -> MfaChallenge:
        challenge.status = "SATISFIED"
        challenge.method = method
        challenge.completed_at = datetime.now(timezone.utc).isoformat()
        self._save(challenge)
        self.store.setex(
            f"mfa-ok:{challenge.workflow_id}:{challenge.capability}",
            self.ttl_seconds,
            {"subject": challenge.subject, "challenge_id": challenge.challenge_id},
        )
        return challenge

    def save(self, challenge: MfaChallenge) -> None:
        self._save(challenge)

    def attach_lease(self, challenge: MfaChallenge, lease_id: str) -> None:
        challenge.lease_id = lease_id
        self._save(challenge)

    def deny(self, challenge_id: str, identity: IdentityContext) -> MfaChallenge:
        challenge = self._load_for(challenge_id, identity)
        challenge.status = "DENIED"
        challenge.completed_at = datetime.now(timezone.utc).isoformat()
        self._save(challenge)
        return challenge

    def satisfied(self, workflow_id: str, capability: str, subject: str) -> bool:
        data = self.store.get_json(f"mfa-ok:{workflow_id}:{capability}")
        return bool(isinstance(data, dict) and data.get("subject") == subject)
