from __future__ import annotations

import json
import shlex
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from integrity.crypto import canonical_hash
from integrity.discovery import discover_server, server_findings
from integrity.registry import unique_slug
from sandbox.honeypot import run_honeypot
from sandbox.shadow import get_sandbox
from sentinel import clientconfig
from sentinel.config import Settings, get_settings
from sentinel.db import LeaseRow, ServerRow, ToolChangeRow, ToolRow
from sentinel.deps import admin_identity, db_session, reader
from sentinel.leases import CapabilityLeaseManager
from sentinel.receipts import AuditStore
from sentinel.safety import assess as safety_assess
from sentinel.safety import blocking_reasons
from sentinel.secrets_box import decrypt_json, encrypt_json, mask_mapping
from sentinel.types import TrustStatus, utcnow, worse_trust
from sentinel.upstream import get_manager

router = APIRouter()

class RegisterServerBody(BaseModel):
    server_name: str
    endpoint: str = ""
    publisher: str = ""
    version: str = "1.0.0"
    transport: str = "http"
    capabilities: list[str] = Field(default_factory=lambda: ["READ"])
    description: str = ""
    run_sandbox: bool = True
    connect: bool = True
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    bearer_token: str = ""
    verify_tls: bool = True
    auth_scheme: str = "none"
    auth_audience: str = ""
    auth_scopes: list[str] = Field(default_factory=list)


class UpdateServerBody(BaseModel):
    enabled: bool | None = None
    server_name: str | None = None
    publisher: str | None = None
    description: str | None = None
    command: str | None = None
    args: list[str] | None = None
    env: dict[str, str] | None = None
    cwd: str | None = None
    url: str | None = None
    headers: dict[str, str] | None = None


class UpdateTrustBody(BaseModel):
    trust_status: str
    reason: str = ""


class ImportBody(BaseModel):
    config: dict[str, Any] | str
    connect: bool = True
    run_sandbox: bool = False
    project: str = ""  # Claude Code: also import this project's local-scope servers from ~/.claude.json


def _display_endpoint(transport: str, config: dict[str, Any]) -> str:
    if transport == "stdio":
        args = [a if not any(k in a.lower() for k in ("token", "key", "secret", "password")) else "••••" for a in config.get("args") or []]
        return " ".join([str(config.get("command") or ""), *args])[:500]
    return str(config.get("url") or "")[:500]


def _audit_brief(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report:
        return None
    return {k: report.get(k) for k in ("status", "backend", "summary", "note", "startup_hosts", "startup_processes",
                                        "tool_list_mismatch", "started_at", "finished_at")} | {
        "tools": {name: {k: v for k, v in t.items() if k in {"verdict", "reasons", "hosts", "processes", "writes", "deletes", "error", "duration_ms"}}
                  for name, t in (report.get("tools") or {}).items()}}


def server_view(row: ServerRow, session: Session, *, detail: bool = False) -> dict[str, Any]:
    manager = get_manager()
    meta = row.metadata_json or {}
    config = decrypt_json(row.config_encrypted or "", default={}) or {}
    tools = [t for t in session.query(ToolRow).filter(ToolRow.server_id == row.server_id).all() if not t.removed]
    view: dict[str, Any] = {
        "server_id": row.server_id,
        "server_name": row.server_name,
        "slug": row.slug,
        "publisher": row.publisher,
        "version": row.version,
        "trust_status": row.trust_status,
        "risk_state": row.risk_state,
        "enabled": row.enabled is not False,
        "managed": row.managed is not False,
        "transport": row.transport,
        "endpoint": row.endpoint,
        "last_verification_time": row.last_verification_time.isoformat() if row.last_verification_time else None,
        "last_discovery_time": row.last_discovery_time.isoformat() if row.last_discovery_time else None,
        "discovery_status": row.discovery_status or "NEVER",
        "last_error": row.last_error or "",
        "approved_capabilities": row.approved_capabilities,
        "integrity_hash": row.integrity_hash,
        "server_info": (row.server_info or {}).get("serverInfo") or {},
        "protocol_version": (row.server_info or {}).get("protocolVersion"),
        "findings": row.findings or [],
        "tool_count": len(tools),
        "tools_at_risk": sum(1 for t in tools if t.trust_status in {"RESTRICTED", "QUARANTINED", "BLOCKED"} or t.review_state in {"CHANGED", "PENDING_REVIEW"}),
        "description": meta.get("description", ""),
        "sandbox_classification": (meta.get("sandbox_report") or {}).get("classification"),
        "vuln_scan": meta.get("vuln_scan"),
        "safety": meta.get("safety"),
        "behavior_audit": _audit_brief(meta.get("behavior_audit")),
        "sandbox_learned_hosts": meta.get("sandbox_learned_hosts") or [],
        "auth_scheme": meta.get("auth_scheme", "none"),
        "auth_audience": meta.get("auth_audience", ""),
        "auth_scopes": meta.get("auth_scopes", []),
        "connection": {k: v for k, v in manager.status(row.server_id).items() if k != "logs"},
        "config": {
            "command": config.get("command"),
            "args": config.get("args"),
            "cwd": config.get("cwd"),
            "url": config.get("url"),
            "env": mask_mapping(config.get("env")),
            "headers": mask_mapping(config.get("headers")),
        },
    }
    if detail:
        view["tools"] = [
            {"tool_id": t.tool_id, "tool_name": t.tool_name, "exposed_name": t.exposed_name, "capabilities": t.capabilities,
             "sensitivity": t.sensitivity, "trust_status": t.trust_status, "review_state": t.review_state, "flow_roles": t.flow_roles}
            for t in tools
        ]
        view["logs"] = manager.status(row.server_id).get("logs", [])
        view["sandbox_report"] = meta.get("sandbox_report")
        view["last_discovery_summary"] = meta.get("last_discovery_summary")
        view["changes"] = [
            {"change_id": c.change_id, "tool": c.tool_name, "classification": c.classification, "status": c.status,
             "detected_at": c.detected_at.isoformat(), "score": c.score}
            for c in session.query(ToolChangeRow).filter(ToolChangeRow.server_id == row.server_id)
            .order_by(ToolChangeRow.detected_at.desc()).limit(20).all()
        ]
    return view


def _apply_sandbox(session: Session, row: ServerRow, report: dict[str, Any]) -> None:
    meta = dict(row.metadata_json or {})
    meta["sandbox_report"] = report
    row.metadata_json = meta
    cls = report.get("classification")
    if cls == "MALICIOUS_OR_COMPROMISED":
        row.trust_status = TrustStatus.QUARANTINED.value
        row.risk_state = "CRITICAL"
    elif cls == "HIGH_RISK":
        row.trust_status = worse_trust(row.trust_status, TrustStatus.RESTRICTED.value)
        row.risk_state = "HIGH"
    row.last_verification_time = utcnow()
    session.commit()
    AuditStore(session).write_event(
        "sandbox", "CRITICAL" if cls == "MALICIOUS_OR_COMPROMISED" else ("HIGH" if cls == "HIGH_RISK" else "INFO"),
        f"honeypot sandbox: {row.server_name} → {cls}", {"server_id": row.server_id, "anomalies": report.get("anomalies", [])[:10]},
    )


def register(session: Session, settings: Settings, body: RegisterServerBody, registered_by: str) -> dict[str, Any]:
    transport = (body.transport or "http").lower()
    if transport in {"streamable-http", "streamable_http"}:
        transport = "http"
    if transport not in {"http", "sse", "stdio"}:
        raise HTTPException(422, "transport must be http, sse, or stdio")
    if body.auth_scheme not in {"none", "bearer", "oauth2", "mtls"}:
        raise HTTPException(422, "auth_scheme must be none, bearer, oauth2, or mtls")
    config: dict[str, Any] = {}
    if transport == "stdio":
        if not settings.allow_stdio_servers:
            raise HTTPException(403, "local stdio servers are disabled on this Sentinel (SENTINEL_ALLOW_STDIO_SERVERS=false)")
        command, args = body.command.strip(), list(body.args)
        if not command and body.endpoint.strip():
            parts = shlex.split(body.endpoint.strip(), posix=True)
            command, args = parts[0], parts[1:]
        if not command:
            raise HTTPException(422, "stdio servers need a command (e.g. npx, uvx, python, node)")
        config = {"command": command, "args": args, "env": dict(body.env), "cwd": body.cwd or None}
    else:
        url = (body.endpoint or "").strip()
        if not url.startswith(("https://", "http://")):
            raise HTTPException(422, "HTTP/SSE endpoints must use an http:// or https:// URL")
        headers = dict(body.headers)
        if body.bearer_token:
            headers["Authorization"] = f"Bearer {body.bearer_token}"
        config = {"url": url, "headers": headers, "verify_tls": body.verify_tls}
    server_id = f"server-{uuid.uuid4().hex[:8]}"
    row = ServerRow(
        server_id=server_id,
        server_name=body.server_name.strip()[:256] or server_id,
        publisher=body.publisher or "unknown",
        version=body.version,
        endpoint=_display_endpoint(transport, config),
        transport=transport,
        trust_status=TrustStatus.MONITORED.value,
        approved_capabilities=body.capabilities,
        integrity_hash=canonical_hash({"transport": transport, "command": config.get("command"), "args": config.get("args"), "url": config.get("url")}),
        risk_state="PENDING_VERIFICATION",
        metadata_json={
            "description": body.description,
            "auth_scheme": body.auth_scheme,
            "auth_audience": body.auth_audience,
            "auth_scopes": body.auth_scopes,
            "registered_by": registered_by,
        },
        slug=unique_slug(session, body.server_name),
        enabled=True,
        managed=True,
        config_encrypted=encrypt_json(config),
        # the background discovery loop skips servers that are still being registered: launching
        # the same `npx`/`uvx` package twice at once corrupts the package manager's cache
        discovery_status="REGISTERING",
        findings=[],
    )
    session.add(row)
    session.commit()
    row.findings = server_findings(row)
    if any(f["severity"] == "CRITICAL" for f in row.findings):
        row.trust_status = TrustStatus.QUARANTINED.value
        row.risk_state = "CRITICAL"
    session.commit()
    AuditStore(session).write_event("server_registered", "INFO", f"server '{row.server_name}' registered ({transport})",
                                    {"server_id": server_id, "by": registered_by, "findings": row.findings[:5]})
    sandbox = None
    # with the shadow sandbox on, every tool is exercised in containment after discovery (behaviour audit);
    # the process-level honeypot is the fallback when the sandbox is switched off
    use_audit = transport == "stdio" and settings.sandbox_audit_on_register and get_sandbox().enabled
    if body.run_sandbox and transport == "stdio" and not use_audit and row.trust_status != TrustStatus.QUARANTINED.value:
        sandbox = run_honeypot(server_id, config, timeout=settings.upstream_connect_timeout_seconds)
        _apply_sandbox(session, row, sandbox)
    discovery = None
    try:
        if body.connect and row.trust_status != TrustStatus.QUARANTINED.value:
            discovery = discover_server(session, server_id, "initial discovery")
            session.refresh(row)
    except Exception as exc:  # the server stays registered; the background loop retries discovery
        session.rollback()
        discovery = {"server_id": server_id, "error": f"discovery failed: {str(exc)[:300]}"}
        session.refresh(row)
    finally:
        if row.discovery_status == "REGISTERING":
            row.discovery_status = "NEVER"
            session.commit()
    scan = None
    if settings.scan_on_register and discovery and not discovery.get("error"):
        from sentinel.routes.scans import run_server_scan, scan_view

        try:
            scan_row = run_server_scan(session, row, active=False, by=registered_by, settings=settings)
            scan = {**scan_view(scan_row), "vulnerabilities": scan_row.report.get("vulnerabilities", [])}
        except Exception as exc:  # a scan problem never blocks registration
            scan = {"error": str(exc)[:300]}
    audit = None
    if use_audit and discovery and not discovery.get("error") and row.trust_status != TrustStatus.QUARANTINED.value:
        from sentinel.routes.sandbox import start_behavior_audit

        start_behavior_audit(server_id)
        audit = {"status": "RUNNING", "backend": get_sandbox().status()["active_backend"],
                 "note": "every tool is being exercised in the sandbox on a synthetic workspace; the verdict updates when it finishes"}
    return {
        "server_id": server_id,
        "slug": row.slug,
        "trust_status": row.trust_status,
        "risk_state": row.risk_state,
        "integrity_hash": row.integrity_hash,
        "findings": row.findings,
        "auth_scheme": body.auth_scheme,
        "auth_audience": body.auth_audience,
        "auth_scopes": body.auth_scopes,
        "sandbox": sandbox,
        "behavior_audit": audit,
        "discovery": discovery,
        "scan": scan,
        "safety": (row.metadata_json or {}).get("safety") or safety_assess(scan=None, findings=row.findings or [], honeypot=sandbox),
        "message": f"Server '{row.server_name}' registered" + (" and connected." if discovery and not discovery.get("error") else "."),
    }


@router.get("/v1/servers")
def list_servers(session: Session = Depends(db_session), identity=Depends(reader)) -> list[dict[str, Any]]:
    rows = session.query(ServerRow).order_by(ServerRow.registration_time).all()
    if identity is not None and getattr(identity, "is_org_employee", False):
        from sentinel import accounts

        allowed = accounts.allowed_server_tools(session, identity) or {}
        rows = [r for r in rows if r.server_id in allowed]
    return [server_view(r, session) for r in rows]


@router.get("/v1/servers/{server_id}")
def get_server(server_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")
    return server_view(row, session, detail=True)


@router.post("/v1/servers")
def register_server(
    body: RegisterServerBody,
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
    identity=Depends(admin_identity),
) -> dict[str, Any]:
    """Register an MCP server, sandbox it (stdio), connect, discover and pin its tools."""
    return register(session, settings, body, identity.subject)


@router.post("/v1/servers/import")
def import_servers(
    body: ImportBody,
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
    identity=Depends(admin_identity),
) -> dict[str, Any]:
    """Import servers from a Claude Desktop, Claude Code (``~/.claude.json`` / ``.mcp.json``), Cursor or
    VS Code MCP configuration. ``${VAR}`` references are expanded from Sentinel's environment."""
    config = body.config
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError as exc:
            raise HTTPException(422, f"config is not valid JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise HTTPException(422, "expected a JSON object")
    raw_entries = (config.get("mcpServers") or config.get("servers") or {}) if isinstance(config, dict) else {}
    entries = clientconfig.extract_servers(config, project=body.project or None)
    if not entries and not raw_entries:
        raise HTTPException(422, "expected an object with an 'mcpServers' (or VS Code 'servers') map")
    results = [{"name": n, "skipped": "this is MCP-Sentinel itself"} for n in raw_entries if n not in entries]
    for name, spec in entries.items():
        if spec.get("disabled"):
            results.append({"name": name, "skipped": "disabled in the source config"})
            continue
        spec = clientconfig.expand_env(spec)
        missing = clientconfig.unresolved_refs(spec)
        if missing:
            results.append({"name": name, "error": "unresolved variables: " + ", ".join(missing)})
            continue
        reg = clientconfig.to_registration(name, spec)
        if reg is None:
            results.append({"name": name, "skipped": "unrecognised server entry"})
            continue
        body_in = RegisterServerBody(**reg, connect=body.connect, publisher="imported",
                                     run_sandbox=body.run_sandbox and reg["transport"] == "stdio")
        try:
            out = register(session, settings, body_in, identity.subject)
            results.append({"name": name, "server_id": out["server_id"], "trust_status": out["trust_status"],
                            "tools": len((out.get("discovery") or {}).get("added") or []),
                            "error": (out.get("discovery") or {}).get("error")})
        except HTTPException as exc:
            results.append({"name": name, "error": exc.detail})
    return {"imported": [r for r in results if r.get("server_id")], "results": results}


@router.patch("/v1/servers/{server_id}")
def update_server(
    server_id: str,
    body: UpdateServerBody,
    session: Session = Depends(db_session),
    identity=Depends(admin_identity),
) -> dict[str, Any]:
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")
    config = decrypt_json(row.config_encrypted or "", default={}) or {}
    changed_config = False
    for key in ("command", "args", "env", "cwd", "url", "headers"):
        value = getattr(body, key)
        if value is not None:
            config[key] = value
            changed_config = True
    if changed_config:
        row.config_encrypted = encrypt_json(config)
        row.endpoint = _display_endpoint(row.transport or "http", config)
        row.findings = server_findings(row)
        row.trust_status = worse_trust(row.trust_status, TrustStatus.MONITORED.value)
        get_manager().disconnect(server_id)
    if body.enabled is not None:
        row.enabled = body.enabled
        if not body.enabled:
            get_manager().disconnect(server_id)
    meta = dict(row.metadata_json or {})
    if body.description is not None:
        meta["description"] = body.description
    row.metadata_json = meta
    if body.server_name:
        row.server_name = body.server_name[:256]
    if body.publisher is not None:
        row.publisher = body.publisher
    session.commit()
    AuditStore(session).write_event("server_updated", "MEDIUM" if changed_config else "INFO", f"server '{row.server_name}' updated by {identity.subject}",
                                    {"server_id": server_id, "config_changed": changed_config, "enabled": row.enabled})
    discovery = discover_server(session, server_id, "configuration changed") if changed_config and row.enabled is not False else None
    session.refresh(row)
    return {**server_view(row, session), "discovery": discovery}


@router.delete("/v1/servers/{server_id}")
def delete_server(server_id: str, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")
    get_manager().disconnect(server_id)
    get_sandbox().forget(server_id)
    CapabilityLeaseManager(session, get_settings()).revoke_server(server_id, "server removed")
    for tool in session.query(ToolRow).filter(ToolRow.server_id == server_id).all():
        session.delete(tool)
    name = row.server_name
    session.delete(row)
    session.commit()
    AuditStore(session).write_event("server_removed", "MEDIUM", f"server '{name}' removed by {identity.subject}", {"server_id": server_id})
    return {"deleted": server_id}


@router.post("/v1/servers/{server_id}/discover")
def rediscover(server_id: str, session: Session = Depends(db_session), _identity=Depends(admin_identity)) -> dict[str, Any]:
    if not session.get(ServerRow, server_id):
        raise HTTPException(404, f"Server {server_id} not found")
    return discover_server(session, server_id, "manual re-scan")


@router.post("/v1/servers/{server_id}/sandbox")
def sandbox_server(
    server_id: str,
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
    _identity=Depends(admin_identity),
) -> dict[str, Any]:
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")
    if row.transport != "stdio":
        raise HTTPException(422, "the honeypot sandbox launches local stdio servers; remote servers are verified via discovery")
    config = decrypt_json(row.config_encrypted or "", default={}) or {}
    if not config.get("command"):
        raise HTTPException(422, "server has no launch command configured")
    report = run_honeypot(server_id, config, timeout=settings.upstream_connect_timeout_seconds)
    _apply_sandbox(session, row, report)
    return {"server_id": server_id, "trust_status": row.trust_status, "sandbox": report}


@router.post("/v1/servers/{server_id}/verify")
def verify_server(
    server_id: str,
    session: Session = Depends(db_session),
    settings: Settings = Depends(get_settings),
    identity=Depends(admin_identity),
) -> dict[str, Any]:
    """Full verification: honeypot sandbox (stdio) + live discovery + poisoning/supply-chain review."""
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")
    sandbox: dict[str, Any] | None = None
    config = decrypt_json(row.config_encrypted or "", default={}) or {}
    if row.transport == "stdio" and config.get("command"):
        sandbox = run_honeypot(server_id, config, timeout=settings.upstream_connect_timeout_seconds)
        _apply_sandbox(session, row, sandbox)
    discovery = discover_server(session, server_id, "admin verification") if row.managed is not False else {"skipped": "not managed"}
    session.refresh(row)
    tools = [t for t in session.query(ToolRow).filter(ToolRow.server_id == server_id).all() if not t.removed]
    findings = list(row.findings or [])
    severities = {f.get("severity") for f in findings}
    tool_findings = [f for t in tools for f in (t.scan_findings or []) if f.get("severity") in {"HIGH", "CRITICAL"}]
    sandbox_cls = (sandbox or {}).get("classification", "CLEAN")
    if sandbox_cls == "MALICIOUS_OR_COMPROMISED" or "CRITICAL" in severities:
        row.trust_status, row.risk_state = TrustStatus.QUARANTINED.value, "CRITICAL"
    elif discovery.get("error"):
        row.trust_status, row.risk_state = worse_trust(row.trust_status, TrustStatus.MONITORED.value), "UNREACHABLE"
    elif sandbox_cls == "HIGH_RISK" or "HIGH" in severities or tool_findings:
        row.trust_status, row.risk_state = TrustStatus.RESTRICTED.value, "HIGH"
    elif sandbox_cls == "SUSPICIOUS":
        row.trust_status, row.risk_state = TrustStatus.MONITORED.value, "ELEVATED"
    else:
        row.trust_status, row.risk_state = TrustStatus.TRUSTED.value, "NORMAL"
        for t in tools:
            clean = not [f for f in (t.scan_findings or []) if f.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}]
            if clean and t.review_state == "APPROVED" and t.trust_status == TrustStatus.MONITORED.value:
                t.trust_status = TrustStatus.TRUSTED.value
    row.last_verification_time = utcnow()
    session.commit()
    AuditStore(session).write_event("server_verified", "INFO", f"{row.server_name} verified → {row.trust_status} by {identity.subject}",
                                    {"server_id": server_id, "sandbox": sandbox_cls})
    if sandbox is None:
        sandbox = {
            "mode": "remote",
            "classification": "CLEAN" if row.trust_status == TrustStatus.TRUSTED.value else row.risk_state,
            "risk_score": 0 if row.trust_status == TrustStatus.TRUSTED.value else 40,
            "anomalies": [f["title"] for f in findings if f.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}],
            "evidence": {"transport_findings": findings, "discovery": discovery},
            "note": "Remote servers cannot be launched locally; Sentinel verified transport security, live tool definitions and poisoning indicators.",
        }
    return {"server_id": server_id, "trust_status": row.trust_status, "risk_state": row.risk_state, "sandbox": sandbox, "discovery": discovery}


@router.put("/v1/servers/{server_id}/trust")
def update_server_trust(
    server_id: str,
    body: UpdateTrustBody,
    session: Session = Depends(db_session),
    identity=Depends(admin_identity),
) -> dict[str, Any]:
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")
    valid = {s.value for s in TrustStatus}
    if body.trust_status not in valid:
        raise HTTPException(400, f"Invalid trust status. Must be one of: {sorted(valid)}")
    previous = row.trust_status
    row.trust_status = body.trust_status
    meta = dict(row.metadata_json or {})
    if body.trust_status in {TrustStatus.TRUSTED.value, TrustStatus.MONITORED.value} and (meta.get("safety") or {}).get("verdict") == "UNSAFE":
        meta["safety_accepted"] = blocking_reasons(meta["safety"])  # an admin accepted these risks; re-scans keep it
        meta["safety_accepted_by"] = identity.subject
        row.metadata_json = meta
    if body.trust_status in {TrustStatus.QUARANTINED.value, TrustStatus.BLOCKED.value}:
        CapabilityLeaseManager(session, get_settings()).revoke_server(server_id, f"server set to {body.trust_status}")
        if body.trust_status == TrustStatus.BLOCKED.value:
            get_manager().disconnect(server_id)
    session.commit()
    AuditStore(session).write_event("trust_change", "MEDIUM", f"{row.server_name}: {previous} → {body.trust_status} by {identity.subject}",
                                    {"server_id": server_id, "reason": body.reason})
    return {"server_id": server_id, "trust_status": row.trust_status, "updated": True}


@router.get("/v1/servers/{server_id}/logs")
def server_logs(server_id: str, _r=Depends(reader)) -> dict[str, Any]:
    status = get_manager().status(server_id)
    return {"server_id": server_id, "logs": status.get("logs", []), "connection": {k: v for k, v in status.items() if k != "logs"}}


@router.get("/v1/leases/server/{server_id}")
def server_leases(server_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> list[dict[str, Any]]:
    rows = session.query(LeaseRow).filter(LeaseRow.server_id == server_id).order_by(LeaseRow.created_at.desc()).limit(50).all()
    return [{"lease_id": r.lease_id, "tool_name": r.tool_name, "state": r.state, "capability": r.capability} for r in rows]
