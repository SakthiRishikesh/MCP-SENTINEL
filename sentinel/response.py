from __future__ import annotations

from sentinel.config import Settings
from sentinel.types import Decision, RiskBand, RiskResult, TrustStatus

DECISION_ORDER = [
    Decision.ALLOW,
    Decision.MONITOR,
    Decision.RESTRICT,
    Decision.MFA_REQUIRED,
    Decision.HUMAN_APPROVAL,
    Decision.QUARANTINE,
    Decision.BLOCK,
]


class ResponseController:
    """Adaptive response ladder (the decision layer of the zero-trust flow).

        hard gate / policy deny / data-flow / critical runtime      -> BLOCK
        risk >= block threshold (CRITICAL)                          -> BLOCK
        human-approval obligation not yet satisfied                 -> HUMAN_APPROVAL
        step-up needed (policy obligation, HIGH risk, or SUSPICIOUS
          risk on a state-changing capability) and not satisfied    -> MFA_REQUIRED
        SUSPICIOUS / HIGH risk with assurance satisfied             -> RESTRICT (execute under restrictions)
        MONITOR band                                                -> MONITOR (execute, heightened monitoring)
        otherwise                                                   -> ALLOW

    MFA raises assurance, it never converts a CRITICAL score or a hard deny into an allow.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def decide(
        self,
        *,
        key: str = "",
        risk: RiskResult,
        policy_hard_block: bool,
        require_mfa: bool,
        dataflow_block: bool,
        sequence_critical: bool,
        runtime_critical: bool,
        mfa_satisfied: bool,
        identity_valid: bool,
        require_approval: bool = False,
        approval_satisfied: bool = False,
        impactful: bool = True,
    ) -> Decision:
        if not identity_valid or policy_hard_block or dataflow_block or risk.hard_block:
            return Decision.BLOCK
        if sequence_critical or runtime_critical or risk.score >= self.settings.block_risk_threshold:
            return Decision.BLOCK
        if require_approval and not approval_satisfied:
            return Decision.HUMAN_APPROVAL
        needs_stepup = (
            require_mfa
            or risk.score >= self.settings.mfa_risk_threshold
            or (risk.score >= self.settings.restrict_risk_threshold and impactful)
        )
        if needs_stepup and not mfa_satisfied:
            return Decision.MFA_REQUIRED
        if risk.band in {RiskBand.SUSPICIOUS, RiskBand.HIGH_RISK} or risk.score >= self.settings.restrict_risk_threshold:
            return Decision.RESTRICT
        if risk.band == RiskBand.MONITOR:
            return Decision.MONITOR
        return Decision.ALLOW

    def restrictions_for(self, decision: Decision) -> list[str]:
        if decision == Decision.RESTRICT:
            return ["strict_output_sanitization", "secrets_redacted", "prompt_injection_quarantined", "no_lease_extension"]
        if decision == Decision.MONITOR:
            return ["enhanced_monitoring", "secrets_redacted"]
        return []

    def _rank(self, decision: Decision) -> int:
        return DECISION_ORDER.index(decision)

    def trust_after(self, decision: Decision, current: str) -> TrustStatus | None:
        """Kept for API compatibility. Tool trust is no longer degraded because of *workflow*
        behaviour (a user's risky sequence is not evidence that the tool is compromised); it
        changes only on tool-attributable evidence: integrity drift, runtime anomalies,
        poisoned outputs."""
        return None
