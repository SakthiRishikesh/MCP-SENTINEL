"""The authoritative security decision path (Policy Enforcement Point + Decision Point).

Gated cascade (mirrors the project's zero-trust flow):

    identity → agent binding → server trust → tool integrity → semantic change → input
    validation → policy (RBAC, capability, trust, destinations, admin rules, lockdown)
    → sequential / contextual / data-flow / behavioural evidence → risk engine
    → obligations (MFA step-up, human approval, capability lease) → decision → receipt

Any failing gate returns BLOCK immediately; the risk engine only grades what passed the gates.
The LLM cannot override any of this: it only ever proposes a tool call.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from dataflow.guard import DataFlowGuard
from dataflow.taint import TaintStore
from identity.verifier import IdentityError, IdentityVerifier
from integrity.crypto import canonical_hash
from integrity.registry import IntegrityRegistry
from mfa.stepup import StepUpManager
from monitoring import entity
from monitoring.baseline import drift_likelihood
from policy import rules as policy_rules
from policy.engine import PolicyEngine
from risk.engine import Evidence, RiskEngine
from risk.memory import RiskMemory
from sentinel import accounts
from sentinel.config import Settings
from sentinel.db import ApprovalRow, EntityProfileRow, PolicyRuleRow, RuntimeFlagRow, ToolChangeRow, WorkflowCallRow
from sentinel.dlp import redact_structure
from sentinel.injection import InjectionGuard
from sentinel.leases import CapabilityLeaseManager
from sentinel.netutil import parse_destination
from sentinel.receipts import AuditStore
from sentinel.response import ResponseController
from sentinel.store import StateStore
from sentinel.types import (
    EXECUTABLE_DECISIONS,
    SENSITIVE_CAPABILITIES,
    Capability,
    DataClass,
    Decision,
    IdentityContext,
    ReviewState,
    RiskResult,
    SecurityDecision,
    Sensitivity,
    ToolCallRequest,
    TrustStatus,
    as_utc,
    primary_capability,
    utcnow,
)
from sentinel.validation import InputValidator
from workflow.analyzer import SequentialAnalyzer, WorkflowState
from workflow.context_engine import ContextualEngine

SEVERITY_LIKELIHOOD = {"LOW": 0.03, "MEDIUM": 0.12, "HIGH": 0.3, "CRITICAL": 0.5}
# vulnerability-scan findings describe the server, not this call: weaker evidence than tool poisoning
VULN_LIKELIHOOD = {"MEDIUM": 0.04, "HIGH": 0.12, "CRITICAL": 0.25}


def arguments_preview(arguments: dict[str, Any], limit: int = 600) -> dict[str, Any]:
    """Redacted, size-bounded view of arguments for approval screens and receipts."""
    redacted, _ = redact_structure(arguments)
    text = json.dumps(redacted, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return redacted
    return {"_truncated": text[:limit] + "…"}


def get_runtime_flag(session: Session, key: str, default: Any = None) -> Any:
    row = session.get(RuntimeFlagRow, key)
    return (row.value or {}).get("value", default) if row else default


class ControlPlane:
    """Authoritative security decision path. The LLM cannot override this."""

    def __init__(self, session: Session, store: StateStore, settings: Settings) -> None:
        self.session = session
        self.store = store
        self.settings = settings
        self.identity = IdentityVerifier(settings)
        self.registry = IntegrityRegistry(session)
        self.policy = PolicyEngine(settings)
        self.leases = CapabilityLeaseManager(session, settings)
        self.seq = SequentialAnalyzer()
        self.context = ContextualEngine()
        self.inject = InjectionGuard()
        self.inputs = InputValidator(settings.internal_domain_list)
        self.dataflow = DataFlowGuard(settings.internal_domain_list, settings.allowed_egress_domain_list)
        self.taint = TaintStore(store, settings.workflow_ttl_seconds)
        self.risk = RiskEngine(settings)
        self.memory = RiskMemory(store, settings)
        self.mfa = StepUpManager(store, settings.mfa_ttl_seconds)
        self.response = ResponseController(settings)
        self.audit = AuditStore(session)
        self.last_call_id: int | None = None
        self.last_context: dict[str, Any] = {}

    # ------------------------------------------------------------------------------------------
    def authorize(
        self,
        authorization: str | None,
        request: ToolCallRequest,
        *,
        agent_hint: str | None = None,
        complete_mfa: bool = False,
        grant_lease_after_mfa: bool = False,
    ) -> tuple[SecurityDecision, IdentityContext | None]:
        evidence: list[Evidence] = []
        reasons: list[str] = []
        gates: list[dict[str, str]] = []
        self.last_call_id = None
        self.last_context = {}
        self._entity_ctx = None

        def gate(name: str, status: str, detail: str = "") -> None:
            gates.append({"gate": name, "status": status, "detail": detail[:300]})

        # 1. identity -------------------------------------------------------------------------
        try:
            identity = self.identity.verify(authorization, agent_hint=agent_hint or request.agent_id)
        except IdentityError as exc:
            gate("identity", "fail", exc.message)
            return self._deny(request, None, [exc.message], f"deny.{exc.code}", gates, [Evidence("identity", 0.9, exc.message, "gate")]), None
        gate("identity", "pass", f"{identity.subject} roles={identity.roles} mfa={identity.mfa_satisfied}")

        # 2. agent binding ----------------------------------------------------------------------
        if identity.agent_id and request.agent_id and request.agent_id != identity.agent_id:
            gate("agent", "fail", "agent mismatch")
            return self._deny(
                request, identity, ["agent identity supplied in MCP request does not match token"], "deny.agent_mismatch",
                gates, [Evidence("agent", 0.9, "agent identity mismatch", "gate")],
            ), identity
        gate("agent", "pass", identity.agent_id)

        # 3. server trust ------------------------------------------------------------------------
        server = self.registry.get_server(request.server_id)
        if server is None:
            gate("server", "fail", "unknown server")
            return self._deny(request, identity, ["server is not in the trust registry"], "deny.unknown_server", gates,
                              [Evidence("server", 0.9, "unknown server", "gate")]), identity
        if server.enabled is False:
            gate("server", "fail", "disabled")
            return self._deny(request, identity, ["server is disabled in Sentinel"], "deny.server_disabled", gates,
                              [Evidence("server", 0.6, "server disabled", "gate")]), identity
        if server.trust_status in {TrustStatus.BLOCKED.value, TrustStatus.QUARANTINED.value}:
            gate("server", "fail", server.trust_status)
            return self._deny(request, identity, [f"server trust status is {server.trust_status}"], "deny.server_trust", gates,
                              [Evidence("server_trust", 0.9, f"server is {server.trust_status}", "gate")]), identity
        gate("server", "pass", server.trust_status)

        # 4. tool integrity ----------------------------------------------------------------------
        tool = self.registry.get_tool(request.server_id, request.tool_name)
        if tool is None or tool.removed:
            gate("tool", "fail", "unknown tool")
            return self._deny(request, identity, ["tool is not in the integrity registry"], "deny.unknown_tool", gates,
                              [Evidence("tool", 0.9, "unknown tool", "gate")]), identity
        capabilities = [Capability(c) for c in (tool.capabilities or ["READ"])]
        primary = primary_capability(capabilities)
        sensitivity = Sensitivity(tool.sensitivity or "LOW")
        inference = tool.inference or {}
        flow_roles = list(tool.flow_roles or [])
        change = self.session.get(ToolChangeRow, tool.last_change_id) if tool.last_change_id else None
        change_cls = change.classification if change is not None and change.status == "OPEN" else None
        if tool.review_state == ReviewState.REJECTED.value:
            gate("tool", "fail", "rejected")
            return self._deny(request, identity, ["tool definition was rejected by an administrator"], "deny.tool_rejected",
                              gates, [Evidence("tool", 0.9, "rejected tool", "gate")], primary), identity
        if tool.trust_status in {TrustStatus.BLOCKED.value, TrustStatus.QUARANTINED.value}:
            why = [f"tool trust status is {tool.trust_status}"]
            if change is not None and change.classification == "MALICIOUS":
                why.append(f"rug pull detected: definition changed after approval (change {change.change_id[:8]})")
            gate("tool", "fail", tool.trust_status)
            return self._deny(request, identity, why, "deny.tool_trust", gates,
                              [Evidence("tool_trust", 0.9, why[-1], "gate")], primary), identity
        gate("tool", "pass", f"{tool.trust_status} {','.join(c.value for c in capabilities)}")

        # 4b. organization RBAC: an employee may only use servers/tools their admin assigned ---------
        if identity.is_org_employee:
            allowed = accounts.allowed_server_tools(self.session, identity)
            if not accounts.is_tool_allowed(allowed, server.server_id, tool.tool_name):
                gate("assignment", "fail", "not assigned to this member")
                return self._deny(
                    request, identity,
                    [f"{tool.exposed_name or tool.tool_name} is not assigned to your account by your organization admin"],
                    "deny.not_assigned", gates, [Evidence("assignment", 0.9, "tool not assigned to this member", "gate")],
                    primary, impact_caps=capabilities,
                ), identity
            gate("assignment", "pass", "assigned by org admin")

        # 5. semantic change / review state --------------------------------------------------------
        if tool.review_state == ReviewState.CHANGED.value:
            p = {"BENIGN": 0.1, "SUSPICIOUS": 0.35}.get(change_cls or "", 0.2)
            evidence.append(Evidence("integrity_drift", p, f"tool definition drifted from its pinned version ({change_cls or 'under review'}); "
                                     "the model is served the pinned definition", "anomaly", memorable=False))
            gate("semantic_change", "warn", change_cls or "changed")
        elif tool.review_state == ReviewState.PENDING_REVIEW.value:
            evidence.append(Evidence("unreviewed_tool", 0.15, "tool has not been reviewed by an administrator", "context", memorable=False))
            gate("semantic_change", "warn", "pending review")
        else:
            gate("semantic_change", "pass", "live definition matches pinned definition")
        serious = [f for f in (tool.scan_findings or []) if f.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}]
        if serious:
            worst = max(serious, key=lambda f: ["MEDIUM", "HIGH", "CRITICAL"].index(f["severity"]))
            evidence.append(Evidence("tool_metadata", SEVERITY_LIKELIHOOD[worst["severity"]],
                                     f"tool metadata scan: {worst['title']}", "context", memorable=False))
        if inference.get("confidence") == "low":
            evidence.append(Evidence("unclassified_semantics", 0.05, "tool semantics could not be classified confidently", "context", memorable=False))
        if server.managed:
            sev = {f.get("severity") for f in (server.findings or [])}
            for level, p in (("CRITICAL", 0.3), ("HIGH", 0.15)):
                if level in sev:
                    evidence.append(Evidence("supply_chain", p, f"{level} supply-chain finding on this server", "context", memorable=False))
                    break

        vuln = (server.metadata_json or {}).get("vuln_scan") or {}
        worst_vuln = vuln.get("worst")
        if worst_vuln in VULN_LIKELIHOOD:
            evidence.append(Evidence("server_vulnerabilities", VULN_LIKELIHOOD[worst_vuln],
                                     f"latest vulnerability scan of this server found {worst_vuln} issue(s)", "context", memorable=False))

        # 6. input validation ---------------------------------------------------------------------
        iv = self.inputs.validate(tool.schema_json or {}, request.arguments, capabilities=capabilities)
        extra_dest = request.destination if isinstance(request.destination, str) else None
        destinations = list(iv.destinations)
        if extra_dest:
            parsed = parse_destination(extra_dest, self.settings.internal_domain_list)
            if parsed is not None and all(d.raw != parsed.raw for d in destinations):
                destinations.append(parsed)
                if parsed.host_class.value == "METADATA":
                    iv.hard_issues.append(f"SSRF-blocked host {parsed.host} (cloud metadata service)")
        if iv.hard_issues:
            gate("input", "fail", iv.hard_issues[0])
            return self._deny(request, identity, iv.hard_issues + [s[2] for s in iv.soft], "deny.input_validation", gates,
                              [Evidence("input", 0.9, iv.hard_issues[0], "gate")], primary, impact_caps=capabilities), identity
        for name, p, why in iv.soft:
            evidence.append(Evidence(name, p, why, "anomaly"))
            reasons.append(why)
        gate("input", "warn" if iv.soft else "pass", f"{len(iv.soft)} soft finding(s)")
        inj_args = self.inject.scan(json.dumps(request.arguments, default=str)[:50_000], field_name="arguments")
        if inj_args.detected:
            evidence.append(Evidence("prompt_injection_args", min(0.5, max(0.2, inj_args.likelihood)),
                                     "arguments contain prompt-injection patterns (possible cross-tool injection relay)", "anomaly"))
            reasons.extend(f"injection:{m}" for m in inj_args.matches[:3])

        # 7. workflow / context --------------------------------------------------------------------
        wf = self._load_workflow(request.workflow_id, request.user_intent, identity.subject)
        lockdown = get_runtime_flag(self.session, "lockdown", "off") or "off"
        rules = self.session.query(PolicyRuleRow).filter(PolicyRuleRow.enabled.is_(True)).all()
        matches = policy_rules.evaluate(
            rules,
            server_id=server.server_id,
            server_slug=server.slug or "",
            tool_name=tool.tool_name,
            exposed_name=tool.exposed_name or "",
            capabilities=[c.value for c in capabilities],
            roles=identity.roles,
        )
        scope_hash = (
            canonical_hash({"server": server.server_id, "tool": tool.tool_name, "arguments": request.arguments})[:32]
            if sensitivity == Sensitivity.CRITICAL else ""
        )
        lease = self.leases.active_lease(
            request.workflow_id, identity.subject, primary,
            server_id=server.server_id, tool_name=tool.tool_name, scope_hash=scope_hash or None,
        )
        mfa_ok = identity.mfa_satisfied or lease is not None
        request_hash = self.request_hash(request, server.server_id, tool.tool_name, identity.subject)
        approval = self._approved(request_hash)
        dest_str = ",".join(d.raw for d in destinations)[:500]

        # 8. policy ---------------------------------------------------------------------------------
        policy = self.policy.evaluate(
            identity=identity,
            server_status=server.trust_status,
            tool_status=tool.trust_status,
            capability=primary,
            destination=extra_dest,
            lease_active=lease is not None,
            mfa_for_request=mfa_ok,
            capabilities=capabilities,
            destinations=[d.raw for d in destinations],
            rule_matches=matches,
            lockdown=str(lockdown),
            review_state=tool.review_state or "APPROVED",
            change_classification=change_cls,
        )
        if not policy.allow and policy.hard_block:
            if lease:
                self.leases.revoke(lease.lease_id, "hard policy deny")
            gate("policy", "fail", policy.policy_id)
            return self._deny(request, identity, reasons + policy.reasons, policy.policy_id, gates,
                              [Evidence("policy", 0.9, policy.reasons[0] if policy.reasons else "policy deny", "gate")],
                              primary, impact_caps=capabilities), identity
        gate("policy", "pass", policy.policy_id)

        # 9. sequential / contextual / data-flow / behavioural evidence ----------------------------------
        data_class = self.dataflow.classify(tool.resource or "", primary, flow_roles)
        df = self.dataflow.evaluate(
            workflow=wf, capability=primary, resource=tool.resource or "", destinations=destinations,
            capabilities=capabilities, flow_roles=flow_roles, taint_sources=self.taint.match(request.workflow_id, request.arguments),
        )
        seq = self.seq.analyze(
            wf, tool.tool_name, primary, dest_str, data_class,
            destination_external=bool(df.external_destinations), velocity_limit=self.settings.velocity_calls_per_minute,
        )
        for name, p, why in seq.signals:
            evidence.append(Evidence(name, p, why, "anomaly"))
        if seq.signals:
            reasons.extend(r for r in seq.reasons if r not in reasons)
        ctx = self.context.evaluate(identity=identity, request=request, tool=None, workflow=wf, capability=primary, sensitivity=sensitivity)
        for name, p, why in ctx.signals:
            evidence.append(Evidence(name, p, why, "anomaly"))
            reasons.append(why)
        for name, p, why in df.signals:
            # structural signals are re-derived on every call; only behavioural ones feed the risk memory
            evidence.append(Evidence(name, p, why, "dataflow", memorable=name not in {"lethal_trifecta", "confidential_transfer"}))
        reasons.extend(r for r in df.reasons if r not in reasons)
        drift = drift_likelihood(tool.baseline)
        if drift >= 0.05:
            recent = (tool.baseline or {}).get("recent_anomalies") or []
            evidence.append(Evidence("behavior_drift", min(0.6, drift),
                                     "recent behavioural anomalies: " + (recent[-1]["message"] if recent else "drift"), "runtime", memorable=False))
        evidence.append(self.risk.trust_prior(server.trust_status, tool.trust_status))
        sensitive = bool(set(capabilities) & SENSITIVE_CAPABILITIES)
        if sensitive and not mfa_ok:
            evidence.append(Evidence("authn_assurance", 0.25, "MFA authentication context not present", "obligation", memorable=False))

        # Entity behaviour analytics: is this call normal for THIS caller (user / agent)?
        row = self.session.get(EntityProfileRow, identity.subject)
        entity_profile = entity.normalize(row.profile if row else None, identity.subject)
        ent = entity.assess(
            entity_profile, agent_id=identity.agent_id, server_id=server.server_id,
            exposed_name=tool.exposed_name or tool.tool_name, capability=primary, sensitivity=sensitivity,
            recent_calls_last_minute=wf.recent_calls_last_minute,
        )
        for name, p, why in ent.evidence:
            evidence.append(Evidence(name, p, why, "behavior"))
            reasons.append(why)
        self._entity_ctx = {
            "profile": entity_profile, "agent_id": identity.agent_id, "server_id": server.server_id,
            "exposed_name": tool.exposed_name or tool.tool_name, "capability": primary,
            "sensitivity": sensitivity, "recent": wf.recent_calls_last_minute, "anomalies": ent.anomalies,
        }
        if ent.evidence:
            worst = max(p for _, p, _ in ent.evidence)
            if worst >= 0.25:
                self.audit.write_event(
                    "entity_anomaly", "HIGH" if worst >= 0.3 else "MEDIUM", f"{identity.subject}: {ent.anomalies[0]}",
                    {"subject": identity.subject, "agent": identity.agent_id, "tool": tool.exposed_name, "anomalies": ent.anomalies[:5]},
                )

        remembered = self.memory.evidence(request.workflow_id, exclude={e.name for e in evidence})
        if remembered is not None:
            evidence.append(remembered)

        impact_class = DataClass.SECRET if (df.egress and wf.has_secret) else data_class
        impact, impact_reasons = self.risk.impact(
            capabilities, sensitivity=sensitivity, data_class=impact_class,
            destructive=bool(inference.get("destructive")), external_egress=bool(df.egress and df.external_destinations),
        )
        explain_base = {
            "who": identity.subject,
            "agent": identity.agent_id,
            "server": server.server_id,
            "server_name": server.server_name,
            "tool": tool.tool_name,
            "exposed_name": tool.exposed_name,
            "capability": primary.value,
            "capabilities": [c.value for c in capabilities],
            "sensitivity": sensitivity.value,
            "flow_roles": flow_roles,
            "resources": [tool.resource],
            "data_class": data_class.value,
            "destinations": [d.as_dict() for d in destinations],
            "previous_actions": wf.tools,
            "workflow_flow_roles": wf.flow_roles,
            "impact_reasons": impact_reasons,
            "gates": gates,
            "matched_rules": policy.matched_rules,
        }

        # 10. hard data-flow outcomes --------------------------------------------------------------------
        if df.block or seq.critical:
            gate("dataflow", "fail", df.reasons[0] if df.reasons else "secret exfiltration")
            if lease:
                self.leases.revoke(lease.lease_id, "data-flow violation")
            self.memory.remember(request.workflow_id, evidence)
            risk = self.risk.assess(evidence, impact, hard_block=True, hard_reason="data-flow violation", impact_reasons=impact_reasons)
            return self._finish(
                request, identity, Decision.BLOCK, risk, reasons + ["mandatory data-flow policy BLOCK"], "deny.dataflow",
                primary, lease.lease_id if lease else None, explain={**explain_base, "gates": gates},
                record=(primary, data_class, flow_roles, dest_str, False),
            ), identity
        gate("dataflow", "warn" if df.signals else "pass", df.reasons[0] if df.reasons else "no sensitive flow")

        # Corroboration: when several independent detectors agree, raise confidence (catch real multi-signal attacks).
        corroborating = {e.name for e in evidence if e.likelihood >= 0.2 and e.category in {"anomaly", "dataflow", "behavior", "runtime"}}
        if len(corroborating) >= 3:
            evidence.append(Evidence("corroboration", 0.25,
                                     f"{len(corroborating)} independent detectors agree this call is risky", "anomaly", memorable=False))

        # 11. risk + response ---------------------------------------------------------------------------------
        risk = self.risk.assess(evidence, impact, impact_reasons=impact_reasons)
        impactful = bool(set(capabilities) - {Capability.READ, Capability.EXTERNAL_LOOKUP})
        decision = self.response.decide(
            key=f"{request.workflow_id}:{request.tool_name}",
            risk=risk,
            policy_hard_block=False,
            require_mfa=policy.require_mfa,
            dataflow_block=False,
            sequence_critical=False,
            runtime_critical=False,
            mfa_satisfied=mfa_ok,
            identity_valid=True,
            require_approval=policy.require_approval,
            approval_satisfied=approval is not None,
            impactful=impactful,
        )
        gate("risk", "fail" if decision == Decision.BLOCK else "pass", f"{risk.score}/100 {risk.band.value}")
        if decision == Decision.BLOCK:
            reasons.append(f"risk {risk.score}/100 is CRITICAL")
            revoked = self.leases.revoke_workflow(request.workflow_id, "risk became CRITICAL")
            if revoked:
                reasons.append(f"{revoked} capability lease(s) revoked for this workflow")

        lease_id = lease.lease_id if lease else None
        challenge = None
        approval_row = None
        if decision == Decision.MFA_REQUIRED:
            challenge = self.mfa.require(
                workflow_id=request.workflow_id,
                subject=identity.subject,
                capability=primary.value,
                tool_name=tool.tool_name,
                server_id=server.server_id,
                exposed_name=tool.exposed_name or tool.tool_name,
                arguments_preview=arguments_preview(request.arguments),
                risk_score=risk.score,
                reasons=[f.reason for f in risk.factors if f.category != "prior"][:4],
                scope_hash=scope_hash,
            )
            reasons.append("step-up MFA required; MFA does not grant unrestricted access")
        elif decision == Decision.HUMAN_APPROVAL:
            approval_row = self._request_approval(request, identity, server.server_id, tool, request_hash, risk, policy.reasons)
            reasons.append("human approval required before this call can run")
        elif decision in EXECUTABLE_DECISIONS:
            if policy.require_lease and lease is None and mfa_ok:
                lease = self.leases.grant(
                    workflow_id=request.workflow_id, subject=identity.subject, capability=primary, tool_name=tool.tool_name,
                    server_id=server.server_id, scope_hash=scope_hash,
                )
                lease_id = lease.lease_id
                reasons.append(f"temporary capability lease granted for {self.settings.lease_default_seconds}s")
            if approval is not None:
                approval.consumed = True
                self.session.add(approval)
                self.session.commit()
                reasons.append(f"human approval {approval.approval_id[:8]} consumed")
        self.memory.remember(request.workflow_id, evidence)
        if not reasons:
            top = [f.reason for f in risk.factors if f.category != "prior" and f.score > 0][:3]
            reasons.extend(top or [f"all security signals consistent; request is {risk.band.value}"])

        restrictions = self.response.restrictions_for(decision)
        finished = self._finish(
            request,
            identity,
            decision,
            risk,
            reasons,
            policy.policy_id,
            primary,
            lease_id,
            challenge.challenge_id if challenge else None,
            approval_id=approval_row.approval_id if approval_row else None,
            restrictions=restrictions,
            explain={
                **explain_base,
                "what": f"tool call {request.tool_name}",
                "policy": policy.policy_id,
                "risk_factors": [f.model_dump() for f in risk.factors],
                "likelihood": risk.likelihood,
                "impact": risk.impact,
                "final_risk": risk.score,
                "decision": decision.value,
                "entity_anomalies": ent.anomalies,
                "mfa_satisfied": mfa_ok,
                "lease_id": lease_id,
                "restrictions": restrictions,
                "gates": gates,
            },
            record=(primary, data_class, flow_roles, dest_str, decision in EXECUTABLE_DECISIONS),
        )
        if challenge is not None:
            challenge.receipt_id = finished.receipt_id or ""
            self.mfa.save(challenge)
        finished.approval_consumed = approval is not None and decision in EXECUTABLE_DECISIONS
        self.last_context = {
            "server": server, "tool": tool, "capabilities": capabilities, "primary": primary, "sensitivity": sensitivity,
            "data_class": data_class, "flow_roles": flow_roles, "identity": identity,
        }
        return finished, identity

    # ------------------------------------------------------------------------------------------
    @staticmethod
    def request_hash(request: ToolCallRequest, server_id: str, tool_name: str, subject: str) -> str:
        """Identity of one exact request (workflow, tool, arguments, user): what an approval is bound to."""
        return canonical_hash({"wf": request.workflow_id, "server": server_id, "tool": tool_name, "args": request.arguments, "sub": subject})[:32]

    def _approved(self, request_hash: str) -> ApprovalRow | None:
        now = utcnow()
        rows = (
            self.session.query(ApprovalRow)
            .filter(ApprovalRow.request_hash == request_hash, ApprovalRow.status == "APPROVED")
            .all()
        )
        for row in rows:
            if row.consumed:
                continue
            expires = as_utc(row.expires_at)
            if expires is not None and expires < now:
                continue
            return row
        return None

    def _request_approval(self, request, identity, server_id, tool, request_hash, risk: RiskResult, policy_reasons) -> ApprovalRow:
        now = utcnow()
        existing = (
            self.session.query(ApprovalRow)
            .filter(ApprovalRow.request_hash == request_hash, ApprovalRow.status == "PENDING")
            .all()
        )
        for row in existing:
            expires = as_utc(row.expires_at)
            if expires is None or expires > now:
                row.risk_score = risk.score
                self.session.commit()
                return row
        row = ApprovalRow(
            approval_id=str(uuid.uuid4()),
            workflow_id=request.workflow_id,
            tool_name=tool.tool_name,
            subject=identity.subject,
            status="PENDING",
            created_at=now,
            server_id=server_id,
            request_hash=request_hash,
            risk_score=risk.score,
            reasons=[r for r in policy_reasons if "checks passed" not in r] + [f.reason for f in risk.factors[:3]],
            expires_at=now + timedelta(seconds=self.settings.approval_ttl_seconds),
            consumed=False,
            request_json={
                "exposed_name": tool.exposed_name,
                "arguments_preview": arguments_preview(request.arguments),
                "capabilities": tool.capabilities,
                "user_intent": request.user_intent[:300],
            },
        )
        self.session.add(row)
        self.session.commit()
        self.audit.write_event("approval_requested", "MEDIUM", f"approval requested for {tool.tool_name}",
                               {"approval_id": row.approval_id, "subject": identity.subject, "risk": risk.score})
        return row

    def _extras(self, workflow_id: str) -> dict[str, Any]:
        data = self.store.get_json(f"wfx:{workflow_id}")
        return data if isinstance(data, dict) else {}

    def update_extras(self, workflow_id: str, **values: Any) -> None:
        data = self._extras(workflow_id)
        data.update(values)
        self.store.setex(f"wfx:{workflow_id}", self.settings.workflow_ttl_seconds, data)

    def _load_workflow(self, workflow_id: str, intent: str, subject: str) -> WorkflowState:
        now = utcnow()
        cutoff = now - timedelta(seconds=self.settings.workflow_ttl_seconds)
        rows = (
            self.session.query(WorkflowCallRow)
            .filter(WorkflowCallRow.workflow_id == workflow_id, WorkflowCallRow.timestamp >= cutoff)
            .order_by(WorkflowCallRow.id.asc())
            .all()
        )
        extras = self._extras(workflow_id)
        if intent and intent != extras.get("intent"):
            self.update_extras(workflow_id, intent=intent[:500])
            extras["intent"] = intent[:500]
        executed = [r for r in rows if r.allowed]
        roles: list[str] = []
        for r in executed:
            for role in r.flow_roles or []:
                if role not in roles:
                    roles.append(role)
        recent = (
            self.session.query(WorkflowCallRow)
            .filter(WorkflowCallRow.subject == subject, WorkflowCallRow.timestamp >= now - timedelta(seconds=60))
            .count()
            if subject else 0
        )
        return WorkflowState(
            workflow_id=workflow_id,
            intent=intent or extras.get("intent", ""),
            tools=[r.tool_name for r in executed],
            capabilities=[r.capability for r in executed],
            resources=[r.resource for r in executed],
            data_classes=[r.data_class for r in executed],
            destinations=[r.destination for r in executed if r.destination],
            servers=[r.server_id or "" for r in executed],
            flow_roles=roles,
            blocked_attempts=sum(1 for r in rows if r.decision == Decision.BLOCK.value),
            untrusted_injection_seen=bool(extras.get("untrusted_injection_seen")),
            secret_output_seen=bool(extras.get("secret_output_seen")),
            recent_calls_last_minute=recent,
        )

    def _record_call(self, request: ToolCallRequest, capability: Capability, data_class: str, allowed: bool, *,
                     decision: str = "", risk_score: int = 0, flow_roles: list[str] | None = None, destination: str = "",
                     subject: str = "", resource: str = "") -> WorkflowCallRow:
        row = WorkflowCallRow(
            workflow_id=request.workflow_id,
            tool_name=request.tool_name,
            capability=capability.value,
            resource=resource or request.resource or "",
            destination=destination[:500],
            data_class=data_class,
            allowed=allowed,
            timestamp=utcnow(),
            server_id=request.server_id,
            decision=decision,
            risk_score=risk_score,
            flow_roles=list(flow_roles or []),
            subject=subject,
        )
        self.session.add(row)
        self.session.commit()
        self.last_call_id = row.id
        return row

    def _update_entity(self, request: ToolCallRequest, identity: IdentityContext, capability: Capability | None,
                       decision: Decision, explain: dict[str, Any]) -> None:
        """Fold this decision into the caller's behavioural baseline (skips calls still awaiting a person)."""
        if decision in {Decision.MFA_REQUIRED, Decision.HUMAN_APPROVAL}:
            return
        ctx = self._entity_ctx
        if ctx is None:  # a gate denied the call before entity analysis ran: record it as a denial
            row = self.session.get(EntityProfileRow, identity.subject)
            ctx = {
                "profile": entity.normalize(row.profile if row else None, identity.subject),
                "agent_id": identity.agent_id, "server_id": request.server_id,
                "exposed_name": explain.get("exposed_name") or request.tool_name,
                "capability": capability or Capability.READ,
                "sensitivity": Sensitivity(explain.get("sensitivity") or "LOW"), "recent": 0, "anomalies": [],
            }
        profile = ctx["profile"]
        entity.record(
            profile, allowed=decision in EXECUTABLE_DECISIONS, agent_id=ctx["agent_id"], server_id=ctx["server_id"],
            exposed_name=ctx["exposed_name"], capability=ctx["capability"], sensitivity=ctx["sensitivity"],
            recent_calls_last_minute=ctx["recent"],
        )
        row = self.session.get(EntityProfileRow, identity.subject)
        if row is None:
            row = EntityProfileRow(subject=identity.subject)
            self.session.add(row)
        row.profile = profile
        row.calls = int(profile.get("calls") or 0)
        row.denied = int(profile.get("denied") or 0)
        if ctx["anomalies"]:
            row.anomalies = int(row.anomalies or 0) + len(ctx["anomalies"])
            row.last_anomaly = ctx["anomalies"][0][:300]
        row.updated_at = utcnow()
        self.session.commit()
        self._entity_ctx = None

    def _deny(
        self,
        request: ToolCallRequest,
        identity: IdentityContext | None,
        reasons: list[str],
        policy_id: str,
        gates: list[dict[str, str]],
        evidence: list[Evidence],
        capability: Capability | None = None,
        impact_caps: list[Capability] | None = None,
    ) -> SecurityDecision:
        impact, impact_reasons = self.risk.impact(impact_caps or ([capability] if capability else [Capability.READ]))
        risk = self.risk.assess(evidence, max(impact, 0.5), hard_block=True, hard_reason=reasons[0] if reasons else policy_id,
                                impact_reasons=impact_reasons)
        record = (capability or Capability.READ, DataClass.INTERNAL, [], "", False) if identity is not None else None
        return self._finish(
            request, identity, Decision.BLOCK, risk, reasons, policy_id, capability,
            explain={"gates": gates, "decision": "BLOCK", "policy": policy_id, "hard_block_reason": risk.hard_block_reason,
                     "risk_factors": [f.model_dump() for f in risk.factors]},
            record=record,
        )

    def _finish(
        self,
        request: ToolCallRequest,
        identity: IdentityContext | None,
        decision: Decision,
        risk: RiskResult,
        reasons: list[str],
        policy_id: str,
        capability: Capability | None = None,
        lease_id: str | None = None,
        challenge_id: str | None = None,
        explain: dict[str, Any] | None = None,
        *,
        approval_id: str | None = None,
        restrictions: list[str] | None = None,
        record: tuple[Capability, DataClass, list[str], str, bool] | None = None,
    ) -> SecurityDecision:
        previous = list((explain or {}).get("previous_actions") or [])
        reasons = list(dict.fromkeys(reasons))
        payload = {
            "workflow_id": request.workflow_id,
            "identity": identity.subject if identity else "anonymous",
            "agent": identity.agent_id if identity else request.agent_id or "unknown",
            "server": request.server_id,
            "tool": request.tool_name,
            "decision": decision.value,
            "risk_score": risk.score,
            "state": risk.band.value,
            "reasons": reasons,
            "previous_tools": previous,
            "policy_id": policy_id,
            "capability": capability.value if capability else None,
            "lease_id": lease_id,
            "mfa_challenge_id": challenge_id,
            "approval_id": approval_id,
            "restrictions": restrictions or [],
            "arguments_preview": arguments_preview(request.arguments),
            "timestamp": utcnow().isoformat(),
            "explainability": explain or {},
        }
        receipt = self.audit.write_receipt(payload)
        self.audit.write_event(
            "decision",
            risk.band.value,
            f"{decision.value} {request.tool_name}",
            {"receipt_id": receipt.receipt_id, "risk": risk.score, "workflow_id": request.workflow_id, "server": request.server_id},
        )
        if record is not None and identity is not None:
            cap, data_class, roles, dest, allowed = record
            self._record_call(
                request, cap, data_class.value, allowed, decision=decision.value, risk_score=risk.score,
                flow_roles=roles if allowed else [], destination=dest, subject=identity.subject,
                resource=str((explain or {}).get("resources", [""])[0] or ""),
            )
            self._update_entity(request, identity, capability, decision, explain or {})
        return SecurityDecision(
            decision=decision,
            risk=risk,
            reasons=reasons,
            required_capability=capability,
            lease_id=lease_id,
            policy_id=policy_id,
            mfa_challenge_id=challenge_id,
            approval_id=approval_id,
            receipt_id=receipt.receipt_id,
            restrictions=restrictions or [],
            explainability=explain or payload,
        )
