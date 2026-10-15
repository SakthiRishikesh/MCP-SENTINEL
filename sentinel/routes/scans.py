"""MCP vulnerability scans (SecureMCP port): registered servers and ad-hoc targets."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from integrity.vulnscan import ScanReport, scan_config
from sentinel import notify, safety
from sentinel.config import Settings, get_settings
from sentinel.db import ServerRow, ToolRow, VulnScanRow
from sentinel.deps import admin_identity, db_session, reader
from sentinel.receipts import AuditStore
from sentinel.secrets_box import decrypt_json
from sentinel.types import TrustStatus, utcnow
from sentinel.upstream import get_manager

router = APIRouter()
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


class ServerScanBody(BaseModel):
    active: bool = False


def scan_view(row: VulnScanRow) -> dict[str, Any]:
    return {
        "scan_id": row.scan_id, "server_id": row.server_id, "name": row.name, "target": row.target,
        "transport": row.transport, "active": row.active, "grade": row.grade, "worst": row.worst,
        "summary": row.summary, "created_at": row.created_at.isoformat() if row.created_at else None, "created_by": row.created_by,
    }


def store_scan(session: Session, report: ScanReport, server_id: str | None, by: str) -> VulnScanRow:
    data = report.as_dict()
    summary = data["summary"]
    row = VulnScanRow(
        scan_id=report.scan_id, server_id=server_id, target=report.target[:512], name=report.name[:256],
        transport=report.transport, active=report.active, grade=summary["grade"], worst=summary["worst"],
        summary=summary, report=data, created_at=utcnow(), created_by=by,
    )
    session.add(row)
    if server_id:
        server = session.get(ServerRow, server_id)
        if server is not None:
            meta = dict(server.metadata_json or {})
            meta["vuln_scan"] = {"scan_id": report.scan_id, "grade": summary["grade"], "worst": summary["worst"],
                                 "score": summary["score"], "active": report.active, "at": data["scan_time"],
                                 "counts": {k: summary[k] for k in ("critical_count", "high_count", "medium_count", "low_count")}}
            server.metadata_json = meta
    session.commit()
    severity = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}.get(summary["worst"], "INFO")
    AuditStore(session).write_event("vulnerability_scan", severity,
                                    f"{report.name}: grade {summary['grade']} ({summary['total_vulnerabilities']} finding(s))",
                                    {"scan_id": report.scan_id, "server_id": server_id, "summary": summary})
    return row


def run_server_scan(session: Session, row: ServerRow, *, active: bool, by: str, settings: Settings) -> VulnScanRow:
    config = decrypt_json(row.config_encrypted or "", default={}) or {}
    transport = row.transport or "http"
    if transport == "stdio" and not config.get("command"):
        raise HTTPException(422, "server has no launch command configured")
    if transport != "stdio" and not config.get("url"):
        raise HTTPException(422, "server has no URL configured")
    others = [t.tool_name for t in session.query(ToolRow).filter(ToolRow.server_id != row.server_id).all() if not t.removed]
    client = None
    if not (active and transport == "stdio") and row.enabled is not False:
        try:  # reuse the live connection: no second launch of the server
            client = get_manager().get_client(row)
        except Exception:
            client = None
    report = scan_config(config, transport, name=row.server_name, active=active, client=client, other_tool_names=others,
                         timeout=min(settings.upstream_timeout_seconds, 30.0), server_id=row.server_id)
    scan = store_scan(session, report, row.server_id, by)
    apply_safety(session, row, scan.report)
    return scan


def apply_safety(session: Session, row: ServerRow, report: dict[str, Any]) -> dict[str, Any]:
    """Condense scan + honeypot + sandbox audit + supply chain into the server's safety verdict."""
    meta = dict(row.metadata_json or {})
    verdict = safety.assess(scan=report, findings=row.findings or [], honeypot=meta.get("sandbox_report"),
                            audit=meta.get("behavior_audit"))
    meta["safety"] = verdict
    row.metadata_json = meta
    accepted = set(meta.get("safety_accepted") or [])
    new_issues = set(safety.blocking_reasons(verdict)) - accepted
    if verdict["verdict"] == "UNSAFE" and new_issues and row.trust_status in {TrustStatus.TRUSTED.value, TrustStatus.MONITORED.value}:
        row.trust_status = TrustStatus.RESTRICTED.value
        AuditStore(session).write_event("server_unsafe", "HIGH", f"{row.server_name} is not safe to use: {verdict['reasons'][0] if verdict['reasons'] else 'severe findings'}",
                                        {"server_id": row.server_id, "safety": verdict})
        notify.notify(session, "server_unsafe", title=f"{row.server_name} is NOT SAFE", message=verdict["headline"]
                      + (" Fix first: " + verdict["recommendations"][0] if verdict.get("recommendations") else ""),
                      url=f"{get_settings().dashboard_base_url}/#/servers/{row.server_id}", severity="HIGH",
                      details={"server_id": row.server_id, "reasons": verdict["reasons"][:5]})
    session.commit()
    return verdict


@router.post("/v1/servers/{server_id}/scan")
def scan_server(server_id: str, body: ServerScanBody, session: Session = Depends(db_session),
                settings: Settings = Depends(get_settings), identity=Depends(admin_identity)) -> dict[str, Any]:
    row = session.get(ServerRow, server_id)
    if not row:
        raise HTTPException(404, f"Server {server_id} not found")
    scan = run_server_scan(session, row, active=body.active, by=identity.subject, settings=settings)
    return {**scan_view(scan), "report": scan.report, "safety": (row.metadata_json or {}).get("safety")}


@router.get("/v1/scans")
def list_scans(session: Session = Depends(db_session), _r=Depends(reader), server_id: str | None = None,
               limit: int = 50) -> list[dict[str, Any]]:
    q = session.query(VulnScanRow)
    if server_id:
        q = q.filter(VulnScanRow.server_id == server_id)
    return [scan_view(r) for r in q.order_by(VulnScanRow.created_at.desc()).limit(min(limit, 200)).all()]


def _get(session: Session, scan_id: str) -> VulnScanRow:
    row = session.get(VulnScanRow, scan_id)
    if row is None:
        raise HTTPException(404, "scan not found")
    return row


@router.get("/v1/scans/{scan_id}")
def get_scan(scan_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    row = _get(session, scan_id)
    return {**scan_view(row), "report": row.report}


@router.get("/v1/scans/{scan_id}/report.html")
def scan_report_html(scan_id: str, download: bool = False, session: Session = Depends(db_session), _r=Depends(reader)) -> HTMLResponse:
    row = _get(session, scan_id)
    headers = {"Content-Security-Policy": REPORT_CSP, "X-Content-Type-Options": "nosniff"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="mcp-scan-{scan_id[:8]}.html"'
    return HTMLResponse(ScanReport.from_dict(row.report).to_html(), headers=headers)


@router.get("/v1/scans/{scan_id}/report.json")
def scan_report_json(scan_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> JSONResponse:
    row = _get(session, scan_id)
    return JSONResponse(row.report, headers={"Content-Disposition": f'attachment; filename="mcp-scan-{scan_id[:8]}.json"'})
