from __future__ import annotations

import json
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from identity.verifier import IdentityError, IdentityVerifier
from sentinel import presence
from sentinel.config import Settings, get_settings
from sentinel.deps import gateway, get_store, reader
from sentinel.gateway import Gateway
from sentinel.mcp_frontend import SUPPORTED_PROTOCOLS, McpFrontend
from sentinel.mcp_local import LocalBackend
from sentinel.types import EXECUTABLE_DECISIONS, ToolCallRequest

router = APIRouter()


class CallBody(BaseModel):
    workflow_id: str
    server_id: str = ""
    tool_name: str = ""
    exposed_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_intent: str = ""
    agent_id: str | None = None
    destination: str | None = None
    resource: str | None = None


@router.get("/v1/mcp/tools/list")
def tools_list(gw: Gateway = Depends(gateway), identity=Depends(reader)) -> dict[str, Any]:
    if identity is not None:
        presence.touch(identity.agent_id, identity.subject)
    tools = gw.catalog()
    if identity is not None and getattr(identity, "is_org_employee", False):
        from sentinel import accounts

        allowed = accounts.allowed_server_tools(gw.session, identity)
        tools = [t for t in tools if accounts.is_tool_allowed(allowed, t.get("server_id", ""), t.get("tool_name", ""))]
    return {"tools": tools, "version": gw.catalog_version()}


@router.get("/v1/mcp/catalog/version")
def catalog_version(gw: Gateway = Depends(gateway), identity=Depends(reader)) -> dict[str, Any]:
    if identity is not None:
        presence.touch(identity.agent_id, identity.subject)
    return {"version": gw.catalog_version(), "count": len(gw.catalog())}


@router.post("/v1/mcp/tools/call")
def tools_call(
    body: CallBody,
    gw: Gateway = Depends(gateway),
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    server_id, tool_name = body.server_id, body.tool_name
    if body.exposed_name:
        row = gw.resolve(body.exposed_name)
        if row is None:
            raise HTTPException(404, f"unknown tool '{body.exposed_name}'")
        server_id, tool_name = row.server_id, row.tool_name
    if not tool_name or not server_id:
        raise HTTPException(422, "exposed_name, or server_id + tool_name, is required")
    request = ToolCallRequest(
        workflow_id=body.workflow_id,
        server_id=server_id,
        tool_name=tool_name,
        arguments=body.arguments,
        user_intent=body.user_intent,
        agent_id=body.agent_id,
        destination=body.destination,
        resource=body.resource,
    )
    outcome = gw.call(authorization, request)
    d = outcome.decision
    result: dict[str, Any] = {
        "decision": d.decision.value,
        "risk_score": d.risk.score,
        "state": d.risk.band.value,
        "likelihood": d.risk.likelihood,
        "impact": d.risk.impact,
        "reasons": d.reasons,
        "factors": [f.model_dump() for f in d.risk.factors],
        "receipt_id": d.receipt_id,
        "policy_id": d.policy_id,
        "lease_id": d.lease_id,
        "mfa_challenge_id": d.mfa_challenge_id,
        "approval_id": d.approval_id,
        "approval_url": outcome.approval_url,
        "restrictions": d.restrictions,
        "exposed_name": outcome.exposed_name,
        "explainability": d.explainability,
        "mcp_result": outcome.mcp_result(settings.result_banner),
        "sandbox": outcome.sandbox,
    }
    if d.decision not in EXECUTABLE_DECISIONS:
        return result
    result["execution"] = {"executed": outcome.executed}
    if not outcome.executed:
        result["execution"].update({
            "error": outcome.error,
            "note": "Sentinel could not obtain a valid response from the configured server. No successful tool output is reported.",
        })
        return result
    result["output"] = {"content": outcome.content, "structuredContent": outcome.structured, "isError": outcome.is_error}
    result["output_report"] = outcome.output_report
    report = outcome.output_report
    issues = []
    if report.get("redacted"):
        issues.append(f"secrets redacted: {', '.join(report['redacted'])}")
    if (report.get("injection") or {}).get("detected"):
        issues.append("untrusted tool output contains injection patterns")
    issues.extend(a["message"] for a in report.get("behavior_anomalies") or [])
    result["output_issues"] = issues
    result["telemetry"] = outcome.telemetry
    result["note"] = "Tool output is untrusted and never authorizes a later high-risk action."
    return result


# ── Streamable HTTP MCP endpoint ────────────────────────────────────────────────────────────

_sessions: dict[str, dict[str, Any]] = {}
_sessions_lock = threading.Lock()
SESSION_TTL = 8 * 3600


def _origin_allowed(origin: str | None, settings: Settings) -> bool:
    if not origin:
        return True  # non-browser clients do not send Origin
    if origin in set(settings.cors_origin_list):
        return True
    host = (urlsplit(origin).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}  # exact host match (not a prefix: localhost.evil.com)


def _gc_sessions() -> None:
    now = time.time()
    with _sessions_lock:
        for sid in [s for s, v in _sessions.items() if now - v.get("last", now) > SESSION_TTL]:
            _sessions.pop(sid, None)


@router.post("/mcp")
async def mcp_post(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    if not _origin_allowed(request.headers.get("origin"), settings):
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Origin not allowed"}}, status_code=403)
    authorization = request.headers.get("authorization")
    try:
        identity = IdentityVerifier(settings).verify(authorization)
    except IdentityError as exc:
        return JSONResponse({"error": exc.message}, status_code=401, headers={"WWW-Authenticate": 'Bearer realm="mcp-sentinel"'})
    version = request.headers.get("mcp-protocol-version")
    if version and version not in SUPPORTED_PROTOCOLS:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32600, "message": f"unsupported MCP-Protocol-Version {version}"}}, status_code=400)
    try:
        message = json.loads(await request.body())
    except ValueError:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status_code=400)
    if not isinstance(message, dict):
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "batching is not supported"}}, status_code=400)
    _gc_sessions()
    session_id = request.headers.get("mcp-session-id")
    headers: dict[str, str] = {}
    if message.get("method") == "initialize":
        session_id = secrets.token_urlsafe(24)
        state = {"subject": identity.subject, "last": time.time(), "workflow_id": f"mcp-{session_id[:12]}"}
        with _sessions_lock:
            _sessions[session_id] = state
        headers["Mcp-Session-Id"] = session_id
    else:
        with _sessions_lock:
            state = _sessions.get(session_id or "")
        if session_id and state is None:
            return JSONResponse({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32600, "message": "session expired"}}, status_code=404)
        if state is None:  # stateless client
            state = {"subject": identity.subject, "workflow_id": f"mcp-stateless-{identity.subject}"[:120]}
        if state.get("subject") != identity.subject:
            return JSONResponse({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32600, "message": "session belongs to another identity"}}, status_code=403)
        state["last"] = time.time()
    if "id" not in message or "method" not in message:
        return Response(status_code=202, headers=headers)
    backend = LocalBackend(authorization, get_store(), settings, state["workflow_id"], agent_hint=(state.get("client_info") or {}).get("name"))
    frontend = McpFrontend(backend, expose_meta_tools=settings.expose_meta_tools)
    response = await run_in_threadpool(frontend.handle, message, state)
    if response is None:
        return Response(status_code=202, headers=headers)
    return JSONResponse(response, headers=headers)


@router.get("/mcp")
def mcp_get() -> Response:
    # No server-initiated stream: Sentinel answers every request on its POST.
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})


@router.delete("/mcp")
def mcp_delete(request: Request) -> Response:
    sid = request.headers.get("mcp-session-id")
    with _sessions_lock:
        _sessions.pop(sid or "", None)
    return Response(status_code=204)
