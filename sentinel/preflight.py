"""Zero-trust pre-flight: what the gateway does with a sandbox verdict.

    MALICIOUS     -> BLOCK, even after MFA or a human approval; the tool is quarantined, the
                     workflow's leases are revoked and any pending approval is cancelled
    DANGEROUS     -> BLOCK this call (blast radius); the tool keeps its trust
    SUSPICIOUS    -> HUMAN_APPROVAL with the effect preview, unless a human already approved
                     exactly this request
    INCONCLUSIVE  -> for tools that change things (write / execute / destructive) and
                     SENTINEL_SANDBOX_STRICT: HUMAN_APPROVAL ("could not be verified")
    SAFE          -> execute; the real call's effects are journalled for undo and compared
                     with the prediction (sandbox evasion is reverted and quarantined)

Calls that already need MFA or approval are pre-flighted too, so the approval screen shows
what the call would do - and a malicious call is blocked before anyone can approve it.
"""

from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from integrity.registry import served_definition
from risk.engine import Evidence
from sandbox.shadow import CallContext, get_sandbox
from sentinel.db import ApprovalRow, SandboxRunRow, ServerRow, ToolRow, UndoRow
from sentinel.leases import CapabilityLeaseManager
from sentinel.types import (
    EXECUTABLE_DECISIONS,
    Capability,
    Decision,
    IdentityContext,
    SecurityDecision,
    ToolCallRequest,
    TrustStatus,
    primary_capability,
    utcnow,
    worse_trust,
)
from sentinel.upstream.manager import server_connection_config

log = logging.getLogger("sentinel.preflight")
VERIFY_CAPS = {"WRITE", "CODE_EXECUTION", "INFRASTRUCTURE_CONTROL"}


def tool_profile(tool: ToolRow) -> dict[str, Any]:
    served = served_definition(tool)
    return {"name": tool.tool_name, "capabilities": list(tool.capabilities or ["READ"]),
            "annotations": served.get("annotations") or {}, "inputSchema": served.get("inputSchema") or {}}


class PreflightGuard:
    def __init__(self, gateway: Any) -> None:
        self.gw = gateway
        self.session: Session = gateway.session
        self.cp = gateway.cp
        self.settings = gateway.settings
        self.sandbox = get_sandbox(self.settings)
        self._held: list[CallContext] = []

    def applies(self, server: ServerRow | None, tool: ToolRow | None) -> bool:
        return bool(self.sandbox.enabled and server is not None and tool is not None and (server.transport or "") == "stdio")

    # -- before the real call ------------------------------------------------------------------
    def check(self, server: ServerRow, tool: ToolRow, request: ToolCallRequest, decision: SecurityDecision,
              identity: IdentityContext | None) -> tuple[CallContext | None, SecurityDecision, dict[str, Any] | None]:
        try:
            return self._check(server, tool, request, decision, identity)
        except Exception:
            # never leave the server's verification lock held; the caller's error handling decides the call
            for held in self._held:
                held.release()
            raise

    def _check(self, server: ServerRow, tool: ToolRow, request: ToolCallRequest, decision: SecurityDecision,
               identity: IdentityContext | None) -> tuple[CallContext | None, SecurityDecision, dict[str, Any] | None]:
        _, config = server_connection_config(server)
        meta = server.metadata_json or {}
        profile = tool_profile(tool)
        try:
            ctx = self.sandbox.begin(server.server_id, config, profile, request.arguments, preflight=True,
                                     contract=meta.get("behavior_audit") or {}, learned_hosts=set(meta.get("sandbox_learned_hosts") or []))
        except Exception as exc:  # the sandbox itself failed: treat as unverified, never as clean
            log.exception("sandbox pre-flight failed for %s", tool.exposed_name)
            ctx = None
            pf: dict[str, Any] = {"verdict": "INCONCLUSIVE", "reasons": [f"sandbox error: {exc}"[:300]], "findings": [],
                                  "preview": {"headline": "Not verified in the sandbox", "files": []}, "backend": "none"}
        else:
            self._held.append(ctx)
            pf = ctx.preflight or {}
        if not pf:
            return ctx, decision, None
        verdict = pf.get("verdict", "INCONCLUSIVE")
        caps = set(profile["capabilities"])
        needs_verification = bool(caps & VERIFY_CAPS) or bool(profile["annotations"].get("destructiveHint"))
        info = {"verdict": verdict, "backend": pf.get("backend"), "reasons": pf.get("reasons", []), "findings": pf.get("findings", []),
                "preview": pf.get("preview", {}), "unknown_hosts": pf.get("unknown_hosts", [])}
        run = SandboxRunRow(
            run_id=str(uuid.uuid4()), server_id=server.server_id, tool_name=tool.tool_name, exposed_name=tool.exposed_name or tool.tool_name,
            workflow_id=request.workflow_id, subject=identity.subject if identity else "", verdict=verdict, backend=str(pf.get("backend") or ""),
            reasons=info["reasons"][:10], findings=info["findings"][:20], preview=info["preview"],
            receipt_id=decision.receipt_id or "", approval_id=decision.approval_id or "", challenge_id=decision.mfa_challenge_id or "",
            duration_ms=float(info["preview"].get("duration_ms") or 0.0),
        )
        new = decision
        if verdict in {"MALICIOUS", "DANGEROUS"}:
            new = self._block(server, tool, request, identity, decision, verdict, info)
            run.action = "BLOCKED"
        elif decision.decision in EXECUTABLE_DECISIONS and not decision.approval_consumed and (
            verdict == "SUSPICIOUS" or (verdict == "INCONCLUSIVE" and needs_verification and self.settings.sandbox_strict)
        ):
            new = self._escalate(server, tool, request, identity, decision, verdict, info)
            run.action = "ESCALATED"
        elif decision.decision in EXECUTABLE_DECISIONS:
            run.action = "ALLOWED"
        else:
            run.action = "NOT_RUN"  # waiting for MFA / approval: the preview is shown on the approval screen
            if decision.approval_id:
                self._attach(decision.approval_id, info)
        run.receipt_id = new.receipt_id or run.receipt_id
        run.approval_id = new.approval_id or run.approval_id
        self.session.add(run)
        self.session.commit()
        info["run_id"] = run.run_id
        info["action"] = run.action
        return ctx, new, info

    def _attach(self, approval_id: str, info: dict[str, Any]) -> None:
        row = self.session.get(ApprovalRow, approval_id)
        if row is not None:
            row.request_json = {**(row.request_json or {}), "sandbox": _brief(info)}
            self.session.commit()

    def _block(self, server: ServerRow, tool: ToolRow, request: ToolCallRequest, identity: IdentityContext | None,
               decision: SecurityDecision, verdict: str, info: dict[str, Any]) -> SecurityDecision:
        malicious = verdict == "MALICIOUS"
        reasons = [f"sandbox pre-flight: this call {r}" if not r.startswith(("is ", "was ")) else f"sandbox pre-flight: the tool {r}"
                   for r in info["reasons"][:4]]
        reasons.append("blocked before it touched anything real: Sentinel ran it in an isolated sandbox first"
                       + (" (no approval can override this)" if malicious else ""))
        caps = [Capability(c) for c in (tool.capabilities or ["READ"])]
        impact, impact_reasons = self.cp.risk.impact(caps)
        evidence = [Evidence(f"sandbox_{verdict.lower()}", 0.95 if malicious else 0.8, reasons[0], "anomaly")]
        risk = self.cp.risk.assess(evidence, max(impact, 0.6), hard_block=True, hard_reason=reasons[0], impact_reasons=impact_reasons)
        self.cp.memory.remember(request.workflow_id, evidence)
        if decision.decision in EXECUTABLE_DECISIONS:
            self.gw._mark_executed(self.cp.last_call_id, False)
        if malicious:
            tool.trust_status = worse_trust(tool.trust_status, TrustStatus.QUARANTINED.value)
            leases = CapabilityLeaseManager(self.session, self.settings)
            leases.revoke_workflow(request.workflow_id, "sandbox caught a malicious call")
            leases.revoke_tool(server.server_id, tool.tool_name, "sandbox caught a malicious call")
            self.session.add(tool)
        self._cancel_pending(decision)
        new = self.cp._finish(
            request, identity, Decision.BLOCK, risk, reasons, "deny.sandbox" if malicious else "deny.blast_radius",
            primary_capability(caps),
            explain={"decision": "BLOCK", "policy": "deny.sandbox" if malicious else "deny.blast_radius", "sandbox": _brief(info),
                     "superseded_receipt": decision.receipt_id, "risk_factors": [f.model_dump() for f in risk.factors]},
            record=None,
        )
        self.cp.audit.write_event(
            "sandbox_block", "CRITICAL" if malicious else "HIGH",
            f"{tool.exposed_name}: {info['reasons'][0] if info['reasons'] else verdict.lower()}",
            {"server_id": server.server_id, "tool": tool.tool_name, "verdict": verdict, "receipt_id": new.receipt_id,
             "findings": info["findings"][:10], "quarantined": malicious},
        )
        self.session.commit()
        return new

    def _cancel_pending(self, decision: SecurityDecision) -> None:
        if decision.approval_id:
            row = self.session.get(ApprovalRow, decision.approval_id)
            if row is not None and row.status == "PENDING":
                row.status, row.resolver, row.resolved_at = "REJECTED", "sentinel-sandbox", utcnow()
        if decision.mfa_challenge_id:
            challenge = self.cp.mfa.get(decision.mfa_challenge_id)
            if challenge is not None and challenge.status == "PENDING":
                challenge.status = "DENIED"
                self.cp.mfa.save(challenge)

    def _escalate(self, server: ServerRow, tool: ToolRow, request: ToolCallRequest, identity: IdentityContext | None,
                  decision: SecurityDecision, verdict: str, info: dict[str, Any]) -> SecurityDecision:
        assert identity is not None
        if verdict == "INCONCLUSIVE":
            why = [f"Sentinel could not verify this call in the sandbox ({'; '.join(info['reasons'][:1]) or 'unavailable'}); a person must confirm it"]
        else:
            why = [f"sandbox pre-flight: {r}" for r in info["reasons"][:4]]
        why.append(f"effect preview: {info['preview'].get('headline', '')}")
        request_hash = self.cp.request_hash(request, server.server_id, tool.tool_name, identity.subject)
        approval = self.cp._request_approval(request, identity, server.server_id, tool, request_hash, decision.risk, why)
        approval.request_json = {**(approval.request_json or {}), "sandbox": _brief(info)}
        approval.reasons = why + [r for r in (approval.reasons or []) if r not in why][:3]
        self.session.commit()
        self.gw._mark_executed(self.cp.last_call_id, False)
        return self.cp._finish(
            request, identity, Decision.HUMAN_APPROVAL, decision.risk, why, "escalate.sandbox",
            primary_capability([Capability(c) for c in (tool.capabilities or ["READ"])]), decision.lease_id,
            approval_id=approval.approval_id,
            explain={"decision": "HUMAN_APPROVAL", "policy": "escalate.sandbox", "sandbox": _brief(info),
                     "superseded_receipt": decision.receipt_id},
            record=None,
        )

    # -- after the real call -----------------------------------------------------------------
    def after(self, ctx: CallContext | None, *, executed: bool, server: ServerRow | None = None, tool: ToolRow | None = None,
              request: ToolCallRequest | None = None, decision: SecurityDecision | None = None,
              info: dict[str, Any] | None = None) -> dict[str, Any]:
        if ctx is None:
            return {}
        if not executed or decision is None or server is None or tool is None or request is None:
            self.sandbox.finish(ctx, executed=False)
            return {}
        undo_id = decision.receipt_id or str(uuid.uuid4())
        journal_dir = Path(self.settings.sandbox_dir).expanduser() / "journal" / undo_id
        try:
            result = self.sandbox.finish(ctx, executed=True, journal_dir=journal_dir)
        except Exception:
            log.exception("post-call verification failed for %s", tool.exposed_name)
            return {}
        if info and info.get("unknown_hosts") and decision.approval_consumed:
            meta = dict(server.metadata_json or {})  # a human approved these destinations: learn them
            meta["sandbox_learned_hosts"] = sorted(set(meta.get("sandbox_learned_hosts") or []) | set(info["unknown_hosts"]))[:200]
            server.metadata_json = meta
        changes = result.get("changes") or []
        if not changes:
            shutil.rmtree(journal_dir, ignore_errors=True)
            self.session.commit()
            return result
        counts = {k: sum(1 for c in changes if c["change"] == k) for k in ("created", "modified", "deleted")}
        summary = ", ".join(f"{n} {k}" for k, n in counts.items() if n)
        evasion = result.get("evasion") or {}
        self.session.add(UndoRow(
            undo_id=undo_id, server_id=server.server_id, tool_name=tool.tool_name, exposed_name=tool.exposed_name or tool.tool_name,
            workflow_id=request.workflow_id, subject=(self.cp.last_context.get("identity").subject if self.cp.last_context.get("identity") else ""),
            status="AVAILABLE", summary=summary, entries=result.get("journal") or [], evasion=evasion, path=str(journal_dir),
        ))
        if evasion:
            tool.trust_status = worse_trust(tool.trust_status, TrustStatus.QUARANTINED.value)
            CapabilityLeaseManager(self.session, self.settings).revoke_tool(server.server_id, tool.tool_name, "sandbox evasion")
            self.cp.audit.write_event(
                "sandbox_evasion", "CRITICAL",
                f"{tool.exposed_name}: {evasion.get('message')}; {len((evasion.get('reverted') or {}).get('restored', []))} file(s) restored",
                {"server_id": server.server_id, "tool": tool.tool_name, "receipt_id": undo_id, "evasion": evasion},
            )
        self.session.commit()
        self._prune()
        return result

    def _prune(self) -> None:
        keep = max(10, int(self.settings.undo_retention))
        rows = self.session.query(UndoRow).order_by(UndoRow.created_at.desc()).offset(keep).all()
        for row in rows:
            shutil.rmtree(row.path, ignore_errors=True)
            self.session.delete(row)
        if rows:
            self.session.commit()


def _brief(info: dict[str, Any]) -> dict[str, Any]:
    return {k: info.get(k) for k in ("verdict", "backend", "reasons", "findings", "preview")}
