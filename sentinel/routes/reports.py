"""Workflow replay and signed incident reports."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from sentinel.deps import db_session, reader
from sentinel.incident import build_report, render_html, verify_report
from sentinel.routes.scans import REPORT_CSP

router = APIRouter()


def _report(session: Session, workflow_id: str) -> dict[str, Any]:
    report = build_report(session, workflow_id)
    if report is None:
        raise HTTPException(404, "nothing recorded for this workflow")
    return report


def _filename(workflow_id: str, ext: str) -> str:
    return f"incident-{re.sub(r'[^A-Za-z0-9_.-]', '_', workflow_id)[:60]}.{ext}"


@router.get("/v1/workflows/{workflow_id}/report")
def workflow_report(workflow_id: str, session: Session = Depends(db_session), _r=Depends(reader)) -> dict[str, Any]:
    return _report(session, workflow_id)


@router.get("/v1/workflows/{workflow_id}/report.json")
def workflow_report_json(workflow_id: str, download: bool = False, session: Session = Depends(db_session), _r=Depends(reader)) -> JSONResponse:
    headers = {"Content-Disposition": f'attachment; filename="{_filename(workflow_id, "json")}"'} if download else {}
    return JSONResponse(_report(session, workflow_id), headers=headers)


@router.get("/v1/workflows/{workflow_id}/report.html")
def workflow_report_html(workflow_id: str, download: bool = False, session: Session = Depends(db_session), _r=Depends(reader)) -> HTMLResponse:
    headers = {"Content-Security-Policy": REPORT_CSP, "X-Content-Type-Options": "nosniff"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{_filename(workflow_id, "html")}"'
    return HTMLResponse(render_html(_report(session, workflow_id)), headers=headers)


@router.post("/v1/reports/verify")
def verify(report: dict[str, Any] = Body(...), _r=Depends(reader)) -> dict[str, Any]:
    """Check an exported incident report: was it signed by this Sentinel and left unchanged?"""
    return {"valid": verify_report(report), "workflow_id": report.get("workflow_id")}
