from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any

from sentinel.types import Capability, DataClass, FlowRole

# (previous capability, next capability) -> (likelihood, explanation)
SUSPICIOUS_TRANSITIONS: dict[tuple[Capability, Capability], tuple[float, str]] = {
    (Capability.EXTERNAL_LOOKUP, Capability.SECRET_ACCESS): (0.35, "secret access right after ingesting external content"),
    (Capability.READ, Capability.SECRET_ACCESS): (0.15, "secret access follows a read"),
    (Capability.SECRET_ACCESS, Capability.DATA_TRANSFER): (0.50, "data transfer right after secret access"),
    (Capability.SECRET_ACCESS, Capability.EXTERNAL_LOOKUP): (0.40, "external request right after secret access (URL exfiltration channel)"),
    (Capability.SECRET_ACCESS, Capability.CODE_EXECUTION): (0.35, "code execution right after secret access"),
    (Capability.EXTERNAL_LOOKUP, Capability.CODE_EXECUTION): (0.35, "code execution right after ingesting external content (injection-to-RCE)"),
    (Capability.EXTERNAL_LOOKUP, Capability.DATA_TRANSFER): (0.20, "data transfer right after ingesting external content"),
    (Capability.EXTERNAL_LOOKUP, Capability.INFRASTRUCTURE_CONTROL): (0.30, "infrastructure control right after ingesting external content"),
}

ESCALATION_ORDER = [
    Capability.READ, Capability.EXTERNAL_LOOKUP, Capability.WRITE, Capability.DATA_TRANSFER,
    Capability.SECRET_ACCESS, Capability.INFRASTRUCTURE_CONTROL, Capability.CODE_EXECUTION,
]


@dataclass
class WorkflowState:
    """Executed calls of a short-lived workflow (sliding window) plus derived flow facts."""

    workflow_id: str
    intent: str = ""
    tools: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    data_classes: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    flow_roles: list[str] = field(default_factory=list)
    blocked_attempts: int = 0
    untrusted_injection_seen: bool = False
    secret_output_seen: bool = False
    recent_calls_last_minute: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkflowState":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})

    @property
    def has_secret(self) -> bool:
        return self.secret_output_seen or any(d in {DataClass.SECRET.value, DataClass.CRITICAL.value} for d in self.data_classes)


@dataclass
class SequenceFinding:
    risk_delta: int
    reasons: list[str]
    critical: bool = False
    likelihood: float = 0.0
    signals: list[tuple[str, float, str]] = field(default_factory=list)


class SequentialAnalyzer:
    """Capability-transition detector over the executed calls of a workflow."""

    def analyze(
        self,
        state: WorkflowState,
        next_tool: str,
        next_cap: Capability,
        destination: str | None,
        data_class: DataClass,
        *,
        destination_external: bool | None = None,
        velocity_limit: int = 30,
    ) -> SequenceFinding:
        signals: list[tuple[str, float, str]] = []
        critical = False
        prev_cap = Capability(state.capabilities[-1]) if state.capabilities else None
        if prev_cap is not None and (prev_cap, next_cap) in SUSPICIOUS_TRANSITIONS:
            p, why = SUSPICIOUS_TRANSITIONS[(prev_cap, next_cap)]
            signals.append(("sequence_transition", p, f"unusual capability transition {prev_cap.value} -> {next_cap.value}: {why}"))
        if next_cap == Capability.DATA_TRANSFER and state.has_secret:
            if destination_external is None:
                dest = (destination or "").lower()
                destination_external = bool(dest) and not any(x in dest for x in ("internal", "localhost", "127.0.0.1"))
            if destination_external:
                signals.append(("sequence_exfiltration", 0.9, "SECRET data flowing into DATA_TRANSFER toward an external destination"))
                critical = True
            else:
                signals.append(("sequence_secret_transfer", 0.35, "dangerous legitimate-looking sequence: secret access then transfer"))
        elif next_cap == Capability.SECRET_ACCESS and Capability.EXTERNAL_LOOKUP.value in state.capabilities and (
            prev_cap is None or (prev_cap, next_cap) not in SUSPICIOUS_TRANSITIONS
        ):
            signals.append(("sequence_lookup_then_secret", 0.2, "SECRET_ACCESS follows an external lookup earlier in the workflow"))
        # Non-adjacent kill chain: untrusted content ingested *anywhere* earlier, then a sensitive action.
        sensitive_next = next_cap in {Capability.SECRET_ACCESS, Capability.INFRASTRUCTURE_CONTROL, Capability.CODE_EXECUTION}
        untrusted_seen = state.untrusted_injection_seen or FlowRole.UNTRUSTED_SOURCE.value in set(state.flow_roles)
        if sensitive_next and untrusted_seen and (prev_cap is None or (prev_cap, next_cap) not in SUSPICIOUS_TRANSITIONS):
            why = ("a tool output carried a prompt injection" if state.untrusted_injection_seen else "untrusted external content was ingested")
            signals.append(("untrusted_then_sensitive", 0.3,
                            f"{next_cap.value} after {why} earlier in this workflow (indirect-injection kill chain)"))
        if len(state.capabilities) >= 2:
            ladder = [Capability(c) for c in state.capabilities[-3:]] + [next_cap]
            ranks = [ESCALATION_ORDER.index(c) for c in ladder]
            if all(b > a for a, b in zip(ranks, ranks[1:])) and ranks[-1] >= ESCALATION_ORDER.index(Capability.SECRET_ACCESS):
                signals.append(("privilege_escalation", 0.15, "monotonic privilege escalation across consecutive calls"))
        if state.blocked_attempts >= 2:
            signals.append(("probing", min(0.5, 0.15 * state.blocked_attempts), f"{state.blocked_attempts} denied attempts earlier in this workflow (probing)"))
        if state.recent_calls_last_minute >= velocity_limit:
            signals.append(("velocity", 0.25, f"{state.recent_calls_last_minute} calls in the last minute (automation burst)"))

        reasons = [s[2] for s in signals] or ["no suspicious capability transition in this workflow"]
        remaining = 1.0
        for _, p, _ in signals:
            remaining *= 1.0 - p
        likelihood = 1.0 - remaining
        return SequenceFinding(
            risk_delta=int(round(likelihood * 50)),
            reasons=reasons,
            critical=critical,
            likelihood=likelihood,
            signals=signals,
        )
