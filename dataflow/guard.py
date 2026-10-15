from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from sentinel.netutil import Destination, HostClass, is_allowed_egress, parse_destination
from sentinel.types import Capability, DataClass, FlowRole
from workflow.analyzer import WorkflowState

RESOURCE_CLASS = {
    "security_logs": DataClass.INTERNAL,
    "threat_intel": DataClass.INTERNAL,
    "incidents": DataClass.CONFIDENTIAL,
    "secrets_vault": DataClass.SECRET,
    "data_export": DataClass.CONFIDENTIAL,
    "edr": DataClass.CRITICAL,
}

EGRESS_CAPABILITIES = {Capability.DATA_TRANSFER, Capability.CODE_EXECUTION}


@dataclass
class DataFlowFinding:
    data_class: DataClass
    reasons: list[str] = field(default_factory=list)
    risk_delta: int = 0
    block: bool = False
    signals: list[tuple[str, float, str]] = field(default_factory=list)
    external_destinations: list[str] = field(default_factory=list)
    egress: bool = False
    trifecta: bool = False


class DataFlowGuard:
    """What data is moving where?  SECRET → external egress is a hard BLOCK."""

    def __init__(self, internal_domains: Iterable[str] = (), allowed_egress: Iterable[str] = ()) -> None:
        self.internal_domains = list(internal_domains) or ["internal", "local", "localhost"]
        self.allowed_egress = list(allowed_egress)

    def classify(self, resource: str, capability: Capability, flow_roles: Iterable[str] = ()) -> DataClass:
        if capability == Capability.SECRET_ACCESS:
            return DataClass.SECRET
        if resource in RESOURCE_CLASS:
            return RESOURCE_CLASS[resource]
        if FlowRole.PRIVATE_SOURCE.value in set(flow_roles):
            return DataClass.CONFIDENTIAL
        return DataClass.INTERNAL

    def _external(self, dests: list[Destination]) -> list[Destination]:
        return [
            d for d in dests
            if d.host_class == HostClass.PUBLIC and not is_allowed_egress(d.host, self.allowed_egress)
        ]

    def evaluate(
        self,
        *,
        workflow: WorkflowState,
        capability: Capability,
        resource: str,
        destination: str | None = None,
        destinations: list[Destination] | None = None,
        capabilities: Iterable[Capability] = (),
        flow_roles: Iterable[str] = (),
        taint_sources: list[str] | None = None,
    ) -> DataFlowFinding:
        roles = set(flow_roles)
        caps = set(capabilities) | {capability}
        current = self.classify(resource, capability, roles)
        dests = list(destinations or [])
        if destination and not any(d.raw == destination for d in dests):
            parsed = parse_destination(destination, self.internal_domains)
            if parsed is not None:
                dests.append(parsed)
        external = self._external(dests)
        egress = bool(caps & EGRESS_CAPABILITIES) or FlowRole.EGRESS_SINK.value in roles or (
            Capability.EXTERNAL_LOOKUP in caps and bool(external)
        )
        finding = DataFlowFinding(data_class=current, egress=egress, external_destinations=[d.host for d in external])

        def signal(name: str, p: float, reason: str) -> None:
            finding.signals.append((name, p, reason))
            finding.reasons.append(reason)

        prior_secret = workflow.has_secret
        # 1. Content taint: the actual secret values are in the outgoing arguments.
        if taint_sources:
            if egress:
                signal("taint_exfiltration", 0.97, f"arguments contain secret material first returned by {', '.join(taint_sources[:3])}")
                finding.block = True
            else:
                signal("taint_propagation", 0.4, f"secret material from {', '.join(taint_sources[:3])} is being propagated")
        # 2. Class-level rule: SECRET/CRITICAL in the workflow + transfer to an external destination.
        if capability == Capability.DATA_TRANSFER or Capability.DATA_TRANSFER in caps:
            if (prior_secret or current in {DataClass.SECRET, DataClass.CRITICAL}) and external:
                signal("secret_to_external", 0.95, "unauthorized SECRET/CRITICAL data transfer to an external destination")
                finding.block = True
            elif (prior_secret or current in {DataClass.SECRET, DataClass.CRITICAL}) and not dests:
                signal("secret_to_implicit_sink", 0.5, "SECRET data in this workflow and the transfer destination is implicit (third-party sink)")
            elif current in {DataClass.CONFIDENTIAL, DataClass.SECRET}:
                signal("confidential_transfer", 0.3, "confidential data transfer requires additional controls")
        elif egress and prior_secret and external:
            signal("secret_then_egress", 0.6, "workflow holds SECRET data and this call reaches an external destination")
        # 3. Lethal trifecta: private data + untrusted content + external communication.
        seen = set(workflow.flow_roles)
        if egress and FlowRole.PRIVATE_SOURCE.value in seen and (FlowRole.UNTRUSTED_SOURCE.value in seen or workflow.untrusted_injection_seen):
            finding.trifecta = True
            if workflow.untrusted_injection_seen:
                signal("lethal_trifecta_injected", 0.7,
                       "lethal trifecta: private data was read, a tool output contained a prompt injection, and this call can send data out")
            else:
                signal("lethal_trifecta", 0.45, "lethal trifecta completes: private data + untrusted content + external communication")
        remaining = 1.0
        for _, p, _ in finding.signals:
            remaining *= 1.0 - p
        finding.risk_delta = int(round((1.0 - remaining) * 50))
        return finding
