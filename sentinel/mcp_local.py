"""In-process backend for the Streamable HTTP MCP endpoint (``/mcp``)."""

from __future__ import annotations

from typing import Any

from identity.verifier import IdentityError, IdentityVerifier
from mfa.stepup import StepUpManager
from sentinel.config import Settings
from sentinel.db import ApprovalRow, session_scope
from sentinel.gateway import Gateway
from sentinel.mcp_frontend import CallContext, text_result, wait_for_stepup
from sentinel.session_info import explain_receipt, session_status
from sentinel.store import StateStore
from sentinel.types import Decision, ToolCallRequest


def poll_status(store: StateStore, settings: Settings, kind: str, ident: str) -> str:
    if kind == "mfa":
        challenge = StepUpManager(store, settings.mfa_ttl_seconds).get(ident)
        return challenge.status if challenge else "EXPIRED"
    with session_scope() as session:
        row = session.get(ApprovalRow, ident)
        return row.status if row else "EXPIRED"


class LocalBackend:
    def __init__(self, authorization: str | None, store: StateStore, settings: Settings, workflow_id: str, agent_hint: str | None = None) -> None:
        self.authorization = authorization
        self.store = store
        self.settings = settings
        self.workflow_id = workflow_id
        self.agent_hint = agent_hint

    def list_tools(self) -> list[dict[str, Any]]:
        with session_scope() as session:
            return Gateway(session, self.store, self.settings).catalog()

    def _invoke(self, name: str, arguments: dict[str, Any]):
        with session_scope() as session:
            gw = Gateway(session, self.store, self.settings)
            row = gw.resolve(name)
            if row is None:
                return None
            request = ToolCallRequest(
                workflow_id=self.workflow_id, server_id=row.server_id, tool_name=row.tool_name, arguments=arguments, user_intent=""
            )
            return gw.call(self.authorization, request, agent_hint=self.agent_hint)

    def call_tool(self, name: str, arguments: dict[str, Any], ctx: CallContext) -> dict[str, Any]:
        outcome = self._invoke(name, arguments)
        if outcome is None:
            return text_result(f"Unknown tool '{name}'. Call sentinel_discover_tools for the current list.", True)
        # hold the call while a person acts; a step-up can be followed by a sandbox escalation, so up to 3 rounds
        for _ in range(3):
            decision = outcome.decision
            pending = None
            if decision.decision == Decision.MFA_REQUIRED and decision.mfa_challenge_id:
                pending = ("mfa", decision.mfa_challenge_id)
            elif decision.decision == Decision.HUMAN_APPROVAL and decision.approval_id:
                pending = ("approval", decision.approval_id)
            if not pending or self.settings.approval_wait_seconds <= 0:
                break
            status = wait_for_stepup(
                kind=pending[0], ident=pending[1], url=outcome.approval_url,
                poll=lambda k, i: poll_status(self.store, self.settings, k, i),
                ctx=ctx, wait_seconds=self.settings.approval_wait_seconds,
            )
            if status not in {"SATISFIED", "APPROVED"}:
                break
            retried = self._invoke(name, arguments)
            if retried is None:
                break
            outcome = retried
        return outcome.mcp_result(self.settings.result_banner)

    def _identity(self):
        try:
            return IdentityVerifier(self.settings).verify(self.authorization)
        except IdentityError:
            return None

    def status(self, ctx: CallContext) -> dict[str, Any]:
        identity = self._identity()
        if identity is None:
            return {"error": "not authenticated"}
        with session_scope() as session:
            return session_status(session, self.store, self.settings, identity, self.workflow_id)

    def explain(self, receipt_id: str, ctx: CallContext) -> dict[str, Any]:
        identity = self._identity()
        if identity is None:
            return {"error": "not authenticated"}
        with session_scope() as session:
            return explain_receipt(session, identity, receipt_id)
