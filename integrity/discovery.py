"""Tool discovery + rug-pull detection.

Every ``tools/list`` result from an upstream server is reconciled against Sentinel's
integrity registry:

* **new tool** → capability inference + poisoning scan → TOFU-pinned when clean,
  held for review (RESTRICTED / QUARANTINED) when suspicious or malicious
* **changed tool** (live hash ≠ pinned hash) → rug-pull analysis → COSMETIC auto re-pin,
  BENIGN flagged, SUSPICIOUS restricted + leases revoked, MALICIOUS quarantined + server
  restricted + all server leases revoked
* **removed tool** → hidden from the model
* the model keeps seeing the **pinned** definition until an admin accepts a change, so a
  poisoned description never reaches the LLM
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Any

from sqlalchemy.orm import Session

from integrity import rugpull, scanner
from integrity.capabilities import Inference, infer
from integrity.crypto import canonical_hash, canonical_json
from integrity.registry import disambiguate_exposed_names, exposed_name_for, slugify
from integrity.supplychain import analyze_http, analyze_stdio
from sentinel import notify
from sentinel.config import get_settings
from sentinel.db import ServerRow, ToolChangeRow, ToolRow
from sentinel.leases import CapabilityLeaseManager
from sentinel.receipts import AuditStore
from sentinel.secrets_box import decrypt_json
from sentinel.types import (
    Capability,
    ChangeClass,
    ReviewState,
    Sensitivity,
    TrustStatus,
    max_sensitivity,
    utcnow,
    worse_trust,
)

log = logging.getLogger("sentinel.discovery")


def _json_safe(value: Any) -> Any:
    return json.loads(canonical_json(value))


def _profiled(server: ServerRow, row: ToolRow | None, wire: dict[str, Any]) -> tuple[Inference, Inference]:
    """(raw, profiled) inference. Raw semantics are compared across versions (apples to apples);
    the profiled view applies an administrator-locked capability profile."""
    raw = infer(wire, server_transport=server.transport or "http")
    profiled = infer(wire, server_transport=server.transport or "http")
    override = (row.inference or {}).get("locked") if row is not None and row.profile_locked else None
    if override:
        profiled.capabilities = sorted(
            {Capability(c) for c in override.get("capabilities") or []} or set(raw.capabilities),
            key=lambda c: list(Capability).index(c),
        )
        profiled.sensitivity = Sensitivity(override.get("sensitivity") or raw.sensitivity.value)
        profiled.resource = override.get("resource") or raw.resource
        profiled.evidence.insert(0, "capability profile locked by an administrator")
        profiled.confidence = "locked"
    return raw, profiled


def _authorization_profile(approved: Inference, live: Inference | None) -> tuple[list[str], str]:
    """Capabilities used for authorization: the union of the pinned and the live semantics.

    A rug pull can therefore never *lower* the required privilege, and any expansion is gated.
    """
    caps = {c.value for c in approved.capabilities}
    sens = [approved.sensitivity]
    if live is not None:
        caps |= {c.value for c in live.capabilities}
        sens.append(live.sensitivity)
    ordered = [c.value for c in Capability if c.value in caps]
    return ordered, max_sensitivity(sens).value


def _other_tool_names(session: Session, server_id: str) -> list[str]:
    return [
        r.tool_name
        for r in session.query(ToolRow).filter(ToolRow.server_id != server_id).all()
        if not r.removed
    ]


def _event(session: Session, kind: str, severity: str, message: str, details: dict[str, Any]) -> None:
    AuditStore(session).write_event(kind, severity, message, details)


def _record_change(
    session: Session,
    row: ToolRow,
    change_type: str,
    classification: ChangeClass,
    score: int,
    findings: list[dict[str, Any]],
    diff: dict[str, Any],
    old: dict[str, Any],
    new: dict[str, Any],
    status: str,
) -> ToolChangeRow:
    change = ToolChangeRow(
        change_id=str(uuid.uuid4()),
        tool_id=row.tool_id,
        server_id=row.server_id,
        tool_name=row.tool_name,
        change_type=change_type,
        classification=classification.value,
        score=score,
        findings=_json_safe(findings),
        diff=_json_safe(diff),
        old_definition=_json_safe(old),
        new_definition=_json_safe(new),
        status=status,
        detected_at=utcnow(),
    )
    session.add(change)
    row.last_change_id = change.change_id
    return change


def server_findings(server: ServerRow) -> list[dict[str, Any]]:
    config = decrypt_json(server.config_encrypted or "", default={}) or {}
    if (server.transport or "") == "stdio":
        return analyze_stdio(str(config.get("command") or ""), list(config.get("args") or []), dict(config.get("env") or {}))
    return analyze_http(str(config.get("url") or server.endpoint or ""), dict(config.get("headers") or {}))


def apply_tool_list(
    session: Session,
    server: ServerRow,
    tools: list[dict[str, Any]],
    info: dict[str, Any] | None = None,
    reason: str = "discovery",
) -> dict[str, Any]:
    settings = get_settings()
    info = info or {}
    leases = CapabilityLeaseManager(session, settings)
    first_discovery = server.last_discovery_time is None and not (server.metadata_json or {}).get("baseline_established")
    slug = server.slug or slugify(server.server_name)
    if not server.slug:
        server.slug = slug
    existing = {r.tool_name: r for r in session.query(ToolRow).filter(ToolRow.server_id == server.server_id).all()}
    own_names = {str(t.get("name") or "") for t in tools if isinstance(t, dict)}
    others = [n for n in _other_tool_names(session, server.server_id) if n not in own_names]
    summary: dict[str, Any] = {"server_id": server.server_id, "reason": reason, "added": [], "changed": [], "removed": [],
                               "unchanged": 0, "alerts": []}
    seen: set[str] = set()

    for raw in tools:
        wire = _json_safe(raw)
        name = str(wire.get("name") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        live_hash = canonical_hash(wire)
        row = existing.get(name)
        live_raw, live_inf = _profiled(server, row, wire)
        live_scan = scanner.scan_tool(wire, other_tool_names=others, annotation_conflicts=live_raw.annotation_conflicts)

        if row is None:
            row = ToolRow(
                tool_id=f"{server.server_id}:{name}",
                server_id=server.server_id,
                tool_name=name,
                version=str((info.get("serverInfo") or {}).get("version") or server.version or "unknown"),
                integrity_hash=live_hash,
                sensitivity=live_inf.sensitivity.value,
                first_seen=utcnow(),
            )
            session.add(row)
            verdict = live_scan.verdict
            if verdict == "MALICIOUS":
                row.review_state, row.trust_status = ReviewState.PENDING_REVIEW.value, TrustStatus.QUARANTINED.value
                row.approved_definition, row.approved_hash = {}, ""
            elif verdict == "SUSPICIOUS" or not settings.auto_pin_clean_tools:
                row.review_state = ReviewState.PENDING_REVIEW.value
                row.trust_status = TrustStatus.RESTRICTED.value if verdict == "SUSPICIOUS" else TrustStatus.MONITORED.value
                row.approved_definition, row.approved_hash = {}, ""
            else:
                row.review_state = ReviewState.APPROVED.value
                row.trust_status = TrustStatus.MONITORED.value  # trusted only after an admin verifies the server
                row.approved_definition, row.approved_hash = wire, live_hash  # trust on first use
            caps, sens = _authorization_profile(live_inf, None)
            _apply_live(row, wire, live_hash, live_inf, live_scan, slug, caps, sens, server)
            entry = {"tool": name, "verdict": verdict, "capabilities": caps}
            summary["added"].append(entry)
            if verdict != "CLEAN":
                summary["alerts"].append({"tool": name, "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
                                          "message": f"new tool '{name}' failed the poisoning scan ({verdict})"})
            if not first_discovery:
                cls = ChangeClass.MALICIOUS if verdict == "MALICIOUS" else (
                    ChangeClass.SUSPICIOUS if verdict == "SUSPICIOUS" or sens == "CRITICAL" else ChangeClass.BENIGN)
                _record_change(session, row, "ADDED", cls, live_scan.score, [f.as_dict() for f in live_scan.findings],
                               {"added_capabilities": caps}, {}, wire,
                               "OPEN" if row.review_state != ReviewState.APPROVED.value or cls != ChangeClass.BENIGN else "AUTO_ACCEPTED")
                _event(session, "tool_added", "HIGH" if cls in {ChangeClass.SUSPICIOUS, ChangeClass.MALICIOUS} else "INFO",
                       f"tool '{name}' appeared on {server.server_name} after its baseline", {"server_id": server.server_id, "tool": name, "verdict": verdict})
            continue

        row.removed = False
        prev_live_hash = row.live_hash or ""
        if row.approved_hash and live_hash == row.approved_hash:
            if row.review_state == ReviewState.CHANGED.value:
                row.review_state = ReviewState.APPROVED.value
                for ch in session.query(ToolChangeRow).filter(ToolChangeRow.tool_id == row.tool_id, ToolChangeRow.status == "OPEN").all():
                    ch.status = "SUPERSEDED"
                    ch.resolved_by = "sentinel:reverted"
                _event(session, "tool_reverted", "MEDIUM", f"'{name}' reverted to its pinned definition",
                       {"server_id": server.server_id, "tool": name})
            caps, sens = _authorization_profile(live_inf, None)
            _apply_live(row, wire, live_hash, live_inf, live_scan, slug, caps, sens, server)
            summary["unchanged"] += 1
            continue

        if not row.approved_hash:
            # Never approved: re-assess the live definition (no pin to compare against yet).
            caps, sens = _authorization_profile(live_inf, None)
            _apply_live(row, wire, live_hash, live_inf, live_scan, slug, caps, sens, server)
            if live_hash != prev_live_hash:
                if live_scan.verdict == "MALICIOUS":
                    row.trust_status = TrustStatus.QUARANTINED.value
                elif live_scan.verdict == "SUSPICIOUS":
                    row.trust_status = worse_trust(row.trust_status, TrustStatus.RESTRICTED.value)
                summary["changed"].append({"tool": name, "classification": "UNREVIEWED_DRIFT", "verdict": live_scan.verdict})
            else:
                summary["unchanged"] += 1
            continue

        # Drift from the pinned definition: possible rug pull.
        open_changes = (
            session.query(ToolChangeRow)
            .filter(ToolChangeRow.tool_id == row.tool_id, ToolChangeRow.status == "OPEN")
            .order_by(ToolChangeRow.detected_at.desc())
            .all()
        )
        if open_changes and canonical_hash(open_changes[0].new_definition or {}) == live_hash:
            _old_raw, old_prof = _profiled(server, row, row.approved_definition or wire)
            caps, sens = _authorization_profile(old_prof, live_raw)
            _apply_live(row, wire, live_hash, None, live_scan, slug, caps, sens, server)
            row.flow_roles = sorted({r.value for r in old_prof.flow_roles} | {r.value for r in live_raw.flow_roles})
            summary["unchanged"] += 1
            continue
        for ch in open_changes:
            ch.status = "SUPERSEDED"
        old = dict(row.approved_definition or {})
        old_raw, old_prof = _profiled(server, row, old)
        old_scan = scanner.scan_tool(old, other_tool_names=others, annotation_conflicts=old_raw.annotation_conflicts)
        report = rugpull.analyze(old, wire, old_scan=old_scan, new_scan=live_scan, old_inf=old_raw, new_inf=live_raw)
        cls = report.classification
        status = "AUTO_ACCEPTED" if cls == ChangeClass.COSMETIC else "OPEN"
        change = _record_change(session, row, "MODIFIED", cls, report.score, report.findings, report.diff, old, wire, status)
        if cls == ChangeClass.COSMETIC:
            row.approved_definition, row.approved_hash = wire, live_hash
            row.review_state = ReviewState.APPROVED.value
            caps, sens = _authorization_profile(live_inf, None)
        else:
            row.review_state = ReviewState.CHANGED.value
            caps, sens = _authorization_profile(old_prof, live_raw)
            if cls == ChangeClass.BENIGN:
                row.trust_status = worse_trust(row.trust_status, TrustStatus.MONITORED.value)
            elif cls == ChangeClass.SUSPICIOUS:
                row.trust_status = worse_trust(row.trust_status, TrustStatus.RESTRICTED.value)
                leases.revoke_tool(server.server_id, name, "tool definition changed (suspicious)")
            else:
                row.trust_status = TrustStatus.QUARANTINED.value
                server.trust_status = worse_trust(server.trust_status, TrustStatus.RESTRICTED.value)
                server.risk_state = "CRITICAL"
                leases.revoke_server(server.server_id, f"rug pull detected on '{name}'")
        _apply_live(row, wire, live_hash, live_inf if cls == ChangeClass.COSMETIC else None, live_scan, slug, caps, sens, server)
        if cls != ChangeClass.COSMETIC:
            row.flow_roles = sorted({r.value for r in old_prof.flow_roles} | {r.value for r in live_raw.flow_roles})
        severity = {"COSMETIC": "INFO", "BENIGN": "LOW", "SUSPICIOUS": "HIGH", "MALICIOUS": "CRITICAL"}[cls.value]
        message = (
            f"RUG PULL: '{name}' on {server.server_name} changed after approval ({cls.value})"
            if cls in {ChangeClass.SUSPICIOUS, ChangeClass.MALICIOUS}
            else f"'{name}' on {server.server_name} changed ({cls.value})"
        )
        _event(session, "rug_pull" if cls in {ChangeClass.SUSPICIOUS, ChangeClass.MALICIOUS} else "tool_changed", severity,
               message, {"server_id": server.server_id, "tool": name, "change_id": change.change_id, "score": report.score,
                         "classification": cls.value, "top_findings": report.findings[:5]})
        summary["changed"].append({"tool": name, "classification": cls.value, "score": report.score, "change_id": change.change_id})
        if cls in {ChangeClass.SUSPICIOUS, ChangeClass.MALICIOUS}:
            summary["alerts"].append({"tool": name, "severity": severity, "message": message})
        if cls == ChangeClass.MALICIOUS:
            notify.notify(session, "rug_pull", title=f"'{name}' on {server.server_name} changed after approval",
                          message=message + ". The tool is quarantined and the model keeps receiving the approved definition.",
                          url=f"{get_settings().dashboard_base_url}/#/integrity/{change.change_id}", severity="CRITICAL",
                          details={"server_id": server.server_id, "tool": name, "change_id": change.change_id})

    for name, row in existing.items():
        if name in seen or row.removed:
            continue
        row.removed = True
        row.last_seen = utcnow()
        _record_change(session, row, "REMOVED", ChangeClass.BENIGN, 0, [], {}, row.approved_definition or {}, {}, "AUTO_ACCEPTED")
        leases.revoke_tool(server.server_id, name, "tool removed by upstream server")
        _event(session, "tool_removed", "INFO", f"'{name}' disappeared from {server.server_name}",
               {"server_id": server.server_id, "tool": name})
        summary["removed"].append(name)

    disambiguate_exposed_names(
        [r for r in session.query(ToolRow).filter(ToolRow.server_id == server.server_id).all()], slug
    )
    _reconcile_server(session, server, info, summary)
    session.commit()
    return summary


def _apply_live(
    row: ToolRow,
    wire: dict[str, Any],
    live_hash: str,
    inference: Inference | None,
    scan: scanner.ScanResult,
    slug: str,
    capabilities: list[str],
    sensitivity: str,
    server: ServerRow,
) -> None:
    served = row.approved_definition or wire
    row.live_definition = wire
    row.live_hash = live_hash
    row.last_seen = utcnow()
    row.title = str(wire.get("title") or (wire.get("annotations") or {}).get("title") or "")[:256]
    row.exposed_name = exposed_name_for(slug, row.tool_name)
    row.scan_findings = [f.as_dict() for f in scan.findings]
    # Fields used by validation / policy reflect the *served* (pinned) definition.
    row.description = str(served.get("description") or "")
    row.schema_json = dict(served.get("inputSchema") or {"type": "object"})
    row.annotations = dict(served.get("annotations") or {})
    row.integrity_hash = canonical_hash(served)
    if not row.profile_locked or not row.capabilities:
        row.capabilities = capabilities
        row.sensitivity = sensitivity
    elif set(capabilities) - set(row.capabilities):
        # locked profile, but the live definition expands semantics: gate the expansion too
        row.capabilities = [c.value for c in Capability if c.value in set(row.capabilities) | set(capabilities)]
        row.sensitivity = max_sensitivity([row.sensitivity, sensitivity]).value
    if inference is not None:
        data = inference.as_dict()
        if row.profile_locked and (row.inference or {}).get("locked"):
            data["locked"] = (row.inference or {}).get("locked")
        row.inference = data
        row.flow_roles = data["flow_roles"]
        if not row.resource or not row.profile_locked:
            row.resource = inference.resource


def _reconcile_server(session: Session, server: ServerRow, info: dict[str, Any], summary: dict[str, Any]) -> None:
    server.last_discovery_time = utcnow()
    server.discovery_status = "OK"
    server.last_error = ""
    meta0 = dict(server.metadata_json or {})
    meta0["baseline_established"] = True
    server.metadata_json = meta0
    if info:
        server.server_info = _json_safe(info)
        si = info.get("serverInfo") or {}
        pinned = server.pinned_server_info or {}
        current = {"name": si.get("name"), "version": si.get("version")}
        if not pinned and (current["name"] or current["version"]):
            server.pinned_server_info = current
        elif pinned and current != pinned and (current["name"] or current["version"]):
            server.trust_status = worse_trust(server.trust_status, TrustStatus.MONITORED.value)
            _event(session, "server_drift", "MEDIUM",
                   f"{server.server_name} now reports {current['name']} {current['version']} (pinned {pinned.get('name')} {pinned.get('version')})",
                   {"server_id": server.server_id, "pinned": pinned, "current": current})
            summary["alerts"].append({"severity": "MEDIUM", "message": "server implementation/version changed"})
            server.pinned_server_info = current
        if si.get("version"):
            server.version = str(si.get("version"))[:64]
    findings = server_findings(server) if server.managed else list(server.findings or [])
    instructions = str(info.get("instructions") or "")
    if instructions:
        inst_scan = scanner.scan_server_instructions(instructions)
        for f in inst_scan.findings:
            findings.append({"severity": f.severity, "category": f"instructions_{f.category}", "title": f.title, "evidence": f.evidence})
        if inst_scan.verdict == "MALICIOUS":
            server.trust_status = worse_trust(server.trust_status, TrustStatus.RESTRICTED.value)
            summary["alerts"].append({"severity": "HIGH", "message": "server instructions contain injection indicators"})
    server.findings = _json_safe(findings)
    meta = dict(server.metadata_json or {})
    meta["tool_count"] = len([t for t in session.query(ToolRow).filter(ToolRow.server_id == server.server_id).all() if not t.removed])
    meta["last_discovery_summary"] = {k: summary[k] for k in ("added", "changed", "removed", "unchanged")}
    server.metadata_json = _json_safe(meta)
    if any(a.get("severity") == "CRITICAL" for a in summary["alerts"]):
        server.risk_state = "CRITICAL"
    elif summary["alerts"]:
        server.risk_state = "ELEVATED"
    elif server.risk_state in {None, "", "PENDING_VERIFICATION", "MONITOR"}:
        server.risk_state = "NORMAL"


_discovery_locks: dict[str, threading.Lock] = {}
_discovery_locks_guard = threading.Lock()


def _discovery_lock(server_id: str) -> threading.Lock:
    with _discovery_locks_guard:
        return _discovery_locks.setdefault(server_id, threading.Lock())


def discover_server(session: Session, server_id: str, reason: str = "manual", manager: Any = None) -> dict[str, Any]:
    """List the server's tools and reconcile them with the pins.

    Discoveries of the same server are serialised: registration, the background loop
    (schedule or ``tools/list_changed``), just-in-time checks and manual re-checks can
    otherwise race and pin the same new tool twice.
    """
    lock = _discovery_lock(server_id)
    if not lock.acquire(timeout=180):
        return {"server_id": server_id, "error": "another discovery of this server is still running"}
    try:
        session.expire_all()  # another discovery may have just committed newer state
        return _discover_locked(session, server_id, reason, manager)
    finally:
        lock.release()


def _discover_locked(session: Session, server_id: str, reason: str, manager: Any) -> dict[str, Any]:
    from sentinel.upstream import get_manager

    server = session.get(ServerRow, server_id)
    if server is None:
        return {"server_id": server_id, "error": "unknown server"}
    if not server.managed:
        return {"server_id": server_id, "skipped": "server is not managed by Sentinel (no live connection)"}
    if server.enabled is False:
        return {"server_id": server_id, "skipped": "server disabled"}
    manager = manager or get_manager()
    try:
        tools, info = manager.list_tools(server)
    except Exception as exc:
        server.discovery_status = "ERROR"
        server.last_error = str(exc)[:1000]
        session.commit()  # last_discovery_time unchanged: a failed scan never becomes the baseline
        manager.note_discovered(server_id)
        log.warning("discovery of %s failed: %s", server_id, exc)
        return {"server_id": server_id, "error": str(exc)}
    manager.note_discovered(server_id)
    return apply_tool_list(session, server, tools, info, reason)
