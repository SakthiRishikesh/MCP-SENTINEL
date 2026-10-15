"""Administrator policy-as-code rules evaluated by the PDP after the built-in hard rules.

A rule matches on server (id or slug glob), tool (name or exposed-name glob), capability and
role; its effect is DENY, REQUIRE_MFA or REQUIRE_APPROVAL. DENY always wins. Rules can only
make a decision *stricter* - they never bypass identity, trust, RBAC or data-flow gates.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Iterable

EFFECTS = {"DENY", "REQUIRE_MFA", "REQUIRE_APPROVAL"}


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    effect: str
    reason: str


def _glob_any(patterns: Iterable[str] | str | None, values: Iterable[str]) -> bool:
    if patterns in (None, "", []):
        return True
    pats = [patterns] if isinstance(patterns, str) else list(patterns)
    vals = [v for v in values if v]
    return any(fnmatch.fnmatchcase(v.lower(), p.lower()) for p in pats for v in vals)


def matches(rule_match: dict[str, Any], *, server_id: str, server_slug: str, tool_name: str, exposed_name: str,
            capabilities: Iterable[str], roles: Iterable[str]) -> bool:
    if not _glob_any(rule_match.get("server"), [server_id, server_slug]):
        return False
    if not _glob_any(rule_match.get("tool"), [tool_name, exposed_name]):
        return False
    caps = rule_match.get("capabilities") or rule_match.get("capability")
    if caps:
        wanted = {caps} if isinstance(caps, str) else set(caps)
        if not wanted & set(capabilities):
            return False
    rls = rule_match.get("roles")
    if rls:
        wanted_roles = {rls} if isinstance(rls, str) else set(rls)
        if not wanted_roles & set(roles):
            return False
    return True


def evaluate(rules: list[Any], **ctx: Any) -> list[RuleMatch]:
    out = []
    for rule in sorted(rules, key=lambda r: (getattr(r, "priority", 100) or 100)):
        if not getattr(rule, "enabled", True) or getattr(rule, "effect", "") not in EFFECTS:
            continue
        if matches(getattr(rule, "match", None) or {}, **ctx):
            out.append(RuleMatch(rule.rule_id, rule.name, rule.effect, rule.reason or rule.name))
    return out
