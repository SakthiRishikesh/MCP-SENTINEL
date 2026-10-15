"""Evidence-fusion risk engine: Risk = Likelihood × Impact (NIST SP 800-30 style).

Why not add up points?  The previous additive model saturated: five individually weak
signals summed past the block threshold, so a perfectly normal ``get_credentials`` in an incident
investigation was hard-blocked instead of stepped-up. Here every security signal is an
independent piece of *evidence* with a likelihood ``p_i`` that the call is unsafe:

    L = 1 - Π (1 - p_i)                    (noisy-OR fusion: diminishing returns, never > 1)
    I = impact of the action               (capability, data class, destructiveness, egress)
    R = 100 · L · (α + (1 - α) · I)        (α: share of risk carried by likelihood alone)

Each factor's displayed contribution is its share of ``-ln(1 - p_i)`` (log-odds-like), so the
contributions add up to the final score and the dashboard can draw a risk waterfall.

Hard policy (identity, trust, RBAC, SSRF, data-flow exfiltration, …) is decided by gates
*before* this engine and always overrides the score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from sentinel.config import Settings
from sentinel.types import (
    Capability,
    DataClass,
    RiskBand,
    RiskFactor,
    RiskResult,
    Sensitivity,
    TrustStatus,
)

CAPABILITY_IMPACT: dict[Capability, float] = {
    Capability.READ: 0.25,
    Capability.EXTERNAL_LOOKUP: 0.30,
    Capability.WRITE: 0.50,
    Capability.DATA_TRANSFER: 0.80,
    Capability.SECRET_ACCESS: 0.90,
    Capability.INFRASTRUCTURE_CONTROL: 0.95,
    Capability.CODE_EXECUTION: 1.00,
}

TRUST_PRIOR: dict[str, float] = {
    TrustStatus.TRUSTED.value: 0.02,
    TrustStatus.MONITORED.value: 0.06,
    TrustStatus.RESTRICTED.value: 0.25,
    TrustStatus.QUARANTINED.value: 0.90,
    TrustStatus.BLOCKED.value: 0.95,
}


@dataclass
class Evidence:
    name: str
    likelihood: float
    reason: str
    category: str = "anomaly"  # prior | anomaly | obligation | context | memory
    memorable: bool = True  # remembered by the workflow risk memory

    def clamp(self) -> "Evidence":
        self.likelihood = max(0.0, min(0.99, float(self.likelihood)))
        return self


def band_for(score: int, settings: Settings | None = None) -> RiskBand:
    monitor = 20
    suspicious = settings.restrict_risk_threshold if settings else 40
    high = settings.mfa_risk_threshold if settings else 60
    critical = settings.block_risk_threshold if settings else 80
    if score >= critical:
        return RiskBand.CRITICAL
    if score >= high:
        return RiskBand.HIGH_RISK
    if score >= suspicious:
        return RiskBand.SUSPICIOUS
    if score >= monitor:
        return RiskBand.MONITOR
    return RiskBand.NORMAL


class RiskEngine:
    """Explainable, deterministic risk. Scores never override hard policy blocks."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- core --------------------------------------------------------------------------------
    def assess(
        self,
        evidence: list[Evidence],
        impact: float,
        *,
        hard_block: bool = False,
        hard_reason: str | None = None,
        impact_reasons: list[str] | None = None,
    ) -> RiskResult:
        items = [e.clamp() for e in evidence if e.likelihood > 0]
        remaining = 1.0
        for e in items:
            remaining *= 1.0 - e.likelihood
        likelihood = 1.0 - remaining
        impact = max(0.05, min(1.0, impact))
        alpha = max(0.0, min(1.0, self.settings.risk_alpha))
        score = int(round(100.0 * likelihood * (alpha + (1.0 - alpha) * impact)))
        score = max(0, min(100, score))
        weights = [-math.log(1.0 - e.likelihood) for e in items]
        total_w = sum(weights) or 1.0
        factors = [
            RiskFactor(
                name=e.name,
                score=int(round(score * w / total_w)),
                reason=e.reason,
                likelihood=round(e.likelihood, 3),
                category=e.category,
            )
            for e, w in sorted(zip(items, weights), key=lambda x: -x[1])
        ]
        return RiskResult(
            score=score,
            band=band_for(score, self.settings),
            factors=factors,
            hard_block=hard_block,
            hard_block_reason=hard_reason,
            likelihood=round(likelihood, 4),
            impact=round(impact, 3),
        )

    # -- impact ------------------------------------------------------------------------------
    def impact(
        self,
        capabilities: list[Capability],
        *,
        sensitivity: Sensitivity | str | None = None,
        data_class: DataClass | None = None,
        destructive: bool = False,
        external_egress: bool = False,
    ) -> tuple[float, list[str]]:
        reasons: list[str] = []
        caps = capabilities or [Capability.READ]
        top = max(caps, key=lambda c: CAPABILITY_IMPACT[c])
        value = CAPABILITY_IMPACT[top]
        reasons.append(f"{top.value} capability (impact {value:.2f})")
        if sensitivity is not None and Sensitivity(sensitivity) == Sensitivity.CRITICAL and value < 0.9:
            value = 0.9
            reasons.append("tool sensitivity is CRITICAL")
        if destructive:
            value = min(1.0, value + 0.15)
            reasons.append("destructive / irreversible action")
        if data_class in {DataClass.SECRET, DataClass.CRITICAL}:
            value = max(value, 0.9)
            reasons.append(f"{data_class.value} data involved")
        elif data_class == DataClass.CONFIDENTIAL:
            value = max(value, 0.6)
            reasons.append("CONFIDENTIAL data involved")
        if external_egress:
            value = min(1.0, value + 0.1)
            reasons.append("data leaves the trust boundary")
        return value, reasons

    # -- standard evidence helpers -----------------------------------------------------------
    def trust_prior(self, server_status: str, tool_status: str) -> Evidence:
        p = max(TRUST_PRIOR.get(server_status, 0.1), TRUST_PRIOR.get(tool_status, 0.1))
        worst = server_status if TRUST_PRIOR.get(server_status, 0.1) >= TRUST_PRIOR.get(tool_status, 0.1) else tool_status
        return Evidence("trust_prior", p, f"server/tool trust baseline ({worst})", "prior", memorable=False)
