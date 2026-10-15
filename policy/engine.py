from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from policy.rules import RuleMatch
from sentinel.config import Settings
from sentinel.netutil import HostClass, parse_destination
from sentinel.types import (
    ROLE_DEFAULT_CAPABILITIES,
    SENSITIVE_CAPABILITIES,
    Capability,
    IdentityContext,
    TrustStatus,
)


@dataclass
class PolicyDecision:
    allow: bool
    policy_id: str
    reasons: list[str] = field(default_factory=list)
    hard_block: bool = False
    require_mfa: bool = False
    require_lease: bool = False
    capability: Capability | None = None
    require_approval: bool = False
    matched_rules: list[str] = field(default_factory=list)


class PolicyEngine:
    """Policy Decision Point. Hard rules always override risk scores."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(
        self,
        *,
        identity: IdentityContext,
        server_status: str,
        tool_status: str,
        capability: Capability,
        destination: str | None,
        lease_active: bool,
        mfa_for_request: bool,
        capabilities: Iterable[Capability] | None = None,
        destinations: Iterable[str] = (),
        rule_matches: list[RuleMatch] | None = None,
        lockdown: str = "off",
        review_state: str = "APPROVED",
        change_classification: str | None = None,
    ) -> PolicyDecision:
        return self._local(
            identity=identity,
            server_status=server_status,
            tool_status=tool_status,
            capability=capability,
            capabilities=list(capabilities or [capability]),
            destinations=[d for d in [destination, *destinations] if d],
            lease_active=lease_active,
            mfa_for_request=mfa_for_request,
            rule_matches=rule_matches or [],
            lockdown=lockdown,
            review_state=review_state,
            change_classification=change_classification,
        )

    def _local(
        self,
        *,
        identity: IdentityContext,
        server_status: str,
        tool_status: str,
        capability: Capability,
        capabilities: list[Capability],
        destinations: list[str],
        lease_active: bool,
        mfa_for_request: bool,
        rule_matches: list[RuleMatch],
        lockdown: str,
        review_state: str,
        change_classification: str | None,
    ) -> PolicyDecision:
        reasons: list[str] = []
        if not identity.token_valid or not identity.subject:
            return PolicyDecision(False, "deny.invalid_identity", ["invalid token"], hard_block=True)
        if not identity.roles:
            return PolicyDecision(False, "deny.no_roles", ["no authorized roles in identity token"], hard_block=True)
        if server_status in {TrustStatus.BLOCKED.value, TrustStatus.QUARANTINED.value}:
            return PolicyDecision(False, "deny.server_trust", [f"server trust status is {server_status}"], hard_block=True)
        if tool_status in {TrustStatus.BLOCKED.value, TrustStatus.QUARANTINED.value}:
            return PolicyDecision(False, "deny.tool_trust", [f"tool trust status is {tool_status}"], hard_block=True)
        granted: set[Capability] = set()
        for role in identity.roles:
            granted |= ROLE_DEFAULT_CAPABILITIES.get(role, set())
        missing = [c for c in capabilities if c not in granted]
        if missing:
            return PolicyDecision(
                False,
                "deny.unauthorized_capability",
                [f"roles {identity.roles} do not include {', '.join(c.value for c in missing)}"],
                hard_block=True,
            )
        for dest in destinations:
            if self._forbidden_destination(dest):
                return PolicyDecision(False, "deny.forbidden_destination", [f"forbidden destination {dest}"], hard_block=True)
        sensitive = bool(set(capabilities) & SENSITIVE_CAPABILITIES)
        if server_status == TrustStatus.RESTRICTED.value and sensitive:
            return PolicyDecision(
                False, "deny.restricted_server", ["restricted server cannot use sensitive capabilities"], hard_block=True
            )
        if tool_status == TrustStatus.RESTRICTED.value and sensitive:
            return PolicyDecision(
                False, "deny.restricted_tool", ["restricted tool cannot use sensitive capabilities until re-approved"], hard_block=True
            )
        deny = [m for m in rule_matches if m.effect == "DENY"]
        if deny:
            return PolicyDecision(False, f"deny.rule.{deny[0].rule_id}", [f"policy rule '{deny[0].name}': {deny[0].reason}"],
                                  hard_block=True, matched_rules=[m.rule_id for m in rule_matches])
        if lockdown == "deny_all":
            return PolicyDecision(False, "deny.lockdown", ["Sentinel is in LOCKDOWN: all tool calls are denied"], hard_block=True)

        require_lease = sensitive
        require_mfa = sensitive and not identity.mfa_satisfied
        require_approval = False
        policy_id = "allow.default"
        if any(m.effect == "REQUIRE_MFA" for m in rule_matches):
            require_mfa = True
            require_lease = True
            reasons.append("policy rule requires step-up MFA")
        if any(m.effect == "REQUIRE_APPROVAL" for m in rule_matches):
            require_approval = True
            reasons.append("policy rule requires human approval")
        impactful = bool(set(capabilities) - {Capability.READ, Capability.EXTERNAL_LOOKUP})
        if lockdown == "approve_writes" and impactful:
            require_approval = True
            reasons.append("lockdown mode: state-changing calls need human approval")
        if review_state == "CHANGED" and change_classification in {"SUSPICIOUS", "MALICIOUS"} and impactful:
            require_approval = True
            reasons.append("tool definition changed after approval: a human must approve state-changing use")
        if require_approval:
            policy_id = "allow.with_approval"
        elif require_mfa:
            policy_id = "allow.with_stepup"
        reasons.append("identity, role, server, tool, and capability checks passed")
        return PolicyDecision(
            True,
            policy_id,
            reasons,
            require_mfa=require_mfa,
            require_lease=require_lease,
            capability=capability,
            require_approval=require_approval,
            matched_rules=[m.rule_id for m in rule_matches],
        )

    def _forbidden_destination(self, destination: str) -> bool:
        parsed = parse_destination(destination, self.settings.internal_domain_list)
        return parsed is not None and parsed.host_class == HostClass.METADATA
