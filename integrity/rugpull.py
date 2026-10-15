"""Rug-pull analysis: what changed between the pinned (approved) and the live tool definition?

Pinning covers the *raw wire object* the server returned (every field, including
annotations, outputSchema and ``_meta``), not only what an approval dialog would display -
hashing only the displayed fields misses most real-world changes.

Classification
* COSMETIC   - whitespace / punctuation / letter-case only; auto re-pinned
* BENIGN     - low-impact drift (wording tweak, version metadata); keeps working, flagged
* SUSPICIOUS - capability / privilege / schema expansion or large rewrite; restricted
* MALICIOUS  - new poisoning indicators (hidden instructions, secrecy, shadowing,
               smuggling, credential exfiltration); quarantined
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

from integrity.capabilities import Inference
from integrity.scanner import POISONING_CATEGORIES, SEVERITY_WEIGHT, Finding, ScanResult
from sentinel.types import SENSITIVITY_ORDER, ChangeClass, Sensitivity

SENSITIVE_PARAM_HINTS = {
    "url", "uri", "endpoint", "webhook", "destination", "command", "cmd", "script", "path", "file", "token",
    "secret", "password", "key", "sidenote", "context", "conversation", "history", "system_prompt", "email",
    "recipient", "to", "cc", "bcc", "callback",
}
ANNOTATION_RISK_FLIPS = {
    # hint: (safe value, risky value)
    "readOnlyHint": (True, False),
    "destructiveHint": (False, True),
    "openWorldHint": (False, True),
    "idempotentHint": (True, False),
}


@dataclass
class ChangeReport:
    classification: ChangeClass
    score: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    diff: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"classification": self.classification.value, "score": self.score, "findings": self.findings, "diff": self.diff}


def _normalize_text(text: str) -> str:
    return re.sub(r"[\s\W_]+", "", (text or "").lower())


def _props(defn: dict[str, Any]) -> dict[str, Any]:
    schema = defn.get("inputSchema") or defn.get("schema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}


def _required(defn: dict[str, Any]) -> set[str]:
    schema = defn.get("inputSchema") or defn.get("schema") or {}
    req = schema.get("required") if isinstance(schema, dict) else None
    return {str(r) for r in req} if isinstance(req, list) else set()


def _relaxed_constraints(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    relaxed = []
    for key in ("enum", "const", "pattern", "maxLength", "maximum", "format"):
        if key in old and key not in new:
            relaxed.append(key)
    if old.get("type") and new.get("type") and old.get("type") != new.get("type"):
        relaxed.append(f"type {old.get('type')}→{new.get('type')}")
    return relaxed


def text_diff(old: str, new: str, limit: int = 60) -> list[str]:
    lines = list(difflib.unified_diff((old or "").splitlines(), (new or "").splitlines(), "pinned", "live", lineterm="", n=1))
    return lines[:limit]


def analyze(
    old_def: dict[str, Any],
    new_def: dict[str, Any],
    *,
    old_scan: ScanResult,
    new_scan: ScanResult,
    old_inf: Inference,
    new_inf: Inference,
) -> ChangeReport:
    findings: list[dict[str, Any]] = []

    def add(severity: str, category: str, title: str, evidence: str = "") -> None:
        findings.append({"severity": severity, "category": category, "title": title, "evidence": evidence[:300]})

    # 1. New poisoning indicators (present now, absent in the pinned definition).
    old_keys = {f.key() for f in old_scan.findings}
    new_poison: list[Finding] = [f for f in new_scan.findings if f.key() not in old_keys]
    for f in new_poison:
        add(f.severity, f"new_{f.category}", f"introduced: {f.title}", f"{f.field}: {f.evidence}")

    # 2. Description / title.
    old_desc, new_desc = str(old_def.get("description") or ""), str(new_def.get("description") or "")
    diff: dict[str, Any] = {}
    if old_desc != new_desc:
        ratio = difflib.SequenceMatcher(None, old_desc, new_desc).ratio()
        diff["description"] = {"old": old_desc, "new": new_desc, "similarity": round(ratio, 3), "unified": text_diff(old_desc, new_desc)}
        if _normalize_text(old_desc) != _normalize_text(new_desc):
            if ratio < 0.5:
                add("MEDIUM", "description_rewrite", "description substantially rewritten", f"similarity {ratio:.2f}")
            elif len(new_desc) > 2 * max(len(old_desc), 1) and len(new_desc) - len(old_desc) > 300:
                add("MEDIUM", "description_growth", "description grew substantially", f"{len(old_desc)} → {len(new_desc)} chars")
            else:
                add("LOW", "description_edit", "description wording changed", f"similarity {ratio:.2f}")
    if (old_def.get("title") or "") != (new_def.get("title") or ""):
        diff["title"] = {"old": old_def.get("title"), "new": new_def.get("title")}
        if _normalize_text(str(old_def.get("title") or "")) != _normalize_text(str(new_def.get("title") or "")):
            add("LOW", "title_change", "display title changed")

    # 3. Input schema.
    old_props, new_props = _props(old_def), _props(new_def)
    added = sorted(set(new_props) - set(old_props))
    removed = sorted(set(old_props) - set(new_props))
    changed: list[dict[str, Any]] = []
    for name in sorted(set(old_props) & set(new_props)):
        if old_props[name] != new_props[name]:
            entry: dict[str, Any] = {"param": name}
            o, n = old_props[name] if isinstance(old_props[name], dict) else {}, new_props[name] if isinstance(new_props[name], dict) else {}
            relaxed = _relaxed_constraints(o, n)
            if relaxed:
                entry["relaxed"] = relaxed
                add("MEDIUM", "validation_relaxed", f"parameter '{name}' validation relaxed", ", ".join(relaxed))
            if (o.get("description") or "") != (n.get("description") or ""):
                entry["description"] = {"old": o.get("description"), "new": n.get("description")}
            changed.append(entry)
    new_required = sorted(_required(new_def) - _required(old_def))
    if added or removed or changed or new_required:
        diff["params"] = {"added": added, "removed": removed, "changed": changed, "newly_required": new_required}
    for name in added:
        sensitive = any(h == name.lower() or h in name.lower().split("_") for h in SENSITIVE_PARAM_HINTS)
        if sensitive:
            add("HIGH", "sensitive_param_added", f"security-sensitive parameter added: '{name}'")
        elif name in new_required:
            add("MEDIUM", "required_param_added", f"new required parameter '{name}'")
        else:
            add("LOW", "optional_param_added", f"new optional parameter '{name}'")
    if removed:
        add("LOW", "param_removed", "parameters removed", ", ".join(removed))
    if (old_def.get("outputSchema") or {}) != (new_def.get("outputSchema") or {}):
        diff["outputSchema"] = {"old": old_def.get("outputSchema"), "new": new_def.get("outputSchema")}
        add("LOW", "output_schema_change", "output schema changed")

    # 4. Annotations (risk-increasing flips only matter).
    old_ann, new_ann = old_def.get("annotations") or {}, new_def.get("annotations") or {}
    ann_diff = {}
    for hint, (safe, risky) in ANNOTATION_RISK_FLIPS.items():
        o, n = old_ann.get(hint), new_ann.get(hint)
        if o != n:
            ann_diff[hint] = [o, n]
            if o == safe and n in (risky, None):
                add("MEDIUM", "annotation_flip", f"{hint} flipped toward higher risk", f"{o} → {n}")
    if ann_diff:
        diff["annotations"] = ann_diff

    # 5. Capability semantics.
    old_caps = {c.value for c in old_inf.capabilities}
    new_caps = {c.value for c in new_inf.capabilities}
    if old_caps != new_caps or old_inf.sensitivity != new_inf.sensitivity:
        diff["capabilities"] = {"old": sorted(old_caps), "new": sorted(new_caps),
                                "sensitivity": [old_inf.sensitivity.value, new_inf.sensitivity.value]}
    expansion = new_caps - old_caps - {"READ"}
    if expansion:
        privileged = expansion & {"SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL", "CODE_EXECUTION"}
        add("HIGH" if privileged else "MEDIUM", "capability_expansion", "inferred capability expansion", ", ".join(sorted(expansion)))
    if SENSITIVITY_ORDER.index(Sensitivity(new_inf.sensitivity)) > SENSITIVITY_ORDER.index(Sensitivity(old_inf.sensitivity)):
        add("MEDIUM", "sensitivity_increase", "sensitivity increased", f"{old_inf.sensitivity.value} → {new_inf.sensitivity.value}")
    gained_roles = {r.value for r in new_inf.flow_roles} - {r.value for r in old_inf.flow_roles}
    if gained_roles:
        add("MEDIUM" if "EGRESS_SINK" in gained_roles else "LOW", "flow_role_gain", "tool gained toxic-flow roles", ", ".join(sorted(gained_roles)))

    # 6. Anything else in the wire object (e.g. _meta, icons, execution).
    core = {"name", "title", "description", "inputSchema", "outputSchema", "annotations"}
    other_changed = sorted(
        k for k in (set(old_def) | set(new_def)) - core if old_def.get(k) != new_def.get(k)
    )
    if other_changed:
        diff["other_fields"] = other_changed
        add("LOW", "metadata_change", "other definition fields changed", ", ".join(other_changed))

    # Score and classify.
    remaining = 1.0
    for f in findings:
        remaining *= 1.0 - SEVERITY_WEIGHT.get(f["severity"], 0) / 100.0
    score = int(round((1.0 - remaining) * 100))
    poison_high = any(
        f.severity == "CRITICAL" or (f.severity == "HIGH" and f.category in POISONING_CATEGORIES) for f in new_poison
    )
    severities = {f["severity"] for f in findings}
    if poison_high:
        cls = ChangeClass.MALICIOUS
    elif severities & {"HIGH", "MEDIUM"} or any(f.severity in {"MEDIUM", "HIGH"} for f in new_poison):
        cls = ChangeClass.SUSPICIOUS
    elif not findings:
        cls = ChangeClass.COSMETIC
    elif severities <= {"LOW", "INFO"} and _only_cosmetic(old_def, new_def):
        cls = ChangeClass.COSMETIC
    else:
        cls = ChangeClass.BENIGN
    return ChangeReport(cls, score, findings, diff)


def _only_cosmetic(old_def: dict[str, Any], new_def: dict[str, Any]) -> bool:
    keys = set(old_def) | set(new_def)
    for k in keys:
        o, n = old_def.get(k), new_def.get(k)
        if o == n:
            continue
        if isinstance(o, str) and isinstance(n, str) and _normalize_text(o) == _normalize_text(n):
            continue
        return False
    return True
