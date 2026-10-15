from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from identity.verifier import IdentityError
from integrity.discovery import discover_server
from monitoring.process import classify_children, remote_hosts
from sentinel import __version__
from sentinel.config import get_settings
from sentinel.db import ServerRow, init_db, session_scope
from sentinel.deps import set_store
from sentinel.logging import configure_logging
from sentinel.receipts import AuditStore
from sentinel.routes import approvals, audit, auth, core, gateway, notifications, org, policy, reports, sandbox, scans, servers, tools
from sentinel.seed import seed
from sentinel.store import StateStore
from sentinel.types import TrustStatus, worse_trust
from sentinel.upstream.manager import get_manager, reset_manager

log = logging.getLogger("sentinel.app")
PROCESS_LEARNING_SECONDS = 120


def _discover(server_id: str, reason: str) -> None:
    with session_scope() as session:
        discover_server(session, server_id, reason)


def _list_servers() -> list[tuple[str, bool]]:
    with session_scope() as session:
        return [
            (s.server_id, s.enabled is not False and s.managed is not False and s.trust_status != TrustStatus.BLOCKED.value
             and s.discovery_status != "REGISTERING")
            for s in session.query(ServerRow).all()
        ]


def _monitor(server_id: str, snap: dict[str, Any]) -> None:
    """Learn each stdio server's process/network baseline, then alert on new behaviour."""
    with session_scope() as session:
        row = session.get(ServerRow, server_id)
        if row is None:
            return
        meta = dict(row.metadata_json or {})
        base = dict(meta.get("process_baseline") or {"started": time.time(), "children": [], "hosts": [], "alerted": []})
        names = {c.get("name", "") for c in snap.get("children") or []}
        hosts = remote_hosts(snap.get("remote_endpoints") or [])
        new_names = names - set(base["children"])
        new_hosts = hosts - set(base["hosts"])
        dirty = time.time() - float(meta.get("process_saved_at", 0)) > 60
        if time.time() - float(base["started"]) < PROCESS_LEARNING_SECONDS:
            if new_names or new_hosts:
                base["children"] = sorted(set(base["children"]) | names)[:60]
                base["hosts"] = sorted(set(base["hosts"]) | hosts)[:60]
                dirty = True
        else:
            fresh = sorted((new_names | new_hosts) - set(base.get("alerted") or []))
            if fresh:
                suspicious, unusual = classify_children(sorted(new_names))
                severity = "HIGH" if suspicious else "MEDIUM"
                if suspicious:
                    row.trust_status = worse_trust(row.trust_status, TrustStatus.RESTRICTED.value)
                    row.risk_state = "HIGH"
                AuditStore(session).write_event(
                    "process_anomaly", severity,
                    f"{row.server_name}: new runtime behaviour outside its baseline ({', '.join(fresh[:4])})",
                    {"server_id": server_id, "new_children": sorted(new_names), "new_hosts": sorted(new_hosts), "suspicious": suspicious},
                )
                base["alerted"] = sorted(set(base.get("alerted") or []) | set(fresh))[:200]
                dirty = True
        if dirty:
            meta["process_baseline"] = base
            meta["process_snapshot"] = snap
            meta["process_saved_at"] = time.time()
            row.metadata_json = meta
            session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()
    seed()
    set_store(StateStore(settings.redis_url))
    manager = get_manager()
    manager.discovery_callback = _discover
    manager.server_lister = _list_servers
    manager.monitor_callback = _monitor
    if settings.background_jobs_enabled:
        manager.start()
    yield
    reset_manager()


app = FastAPI(
    title="MCP-Sentinel",
    description="Adaptive Zero-Trust Security Control Plane for Model Context Protocol",
    version=__version__,
    lifespan=lifespan,
)

_settings = get_settings()
if "*" not in _settings.allowed_host_list:
    # DNS-rebinding defence: a malicious web page cannot reach the local control plane via its own hostname.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_settings.allowed_host_list)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id", "MCP-Protocol-Version"],
    expose_headers=["Mcp-Session-Id"],
)


@app.exception_handler(IdentityError)
async def identity_error_handler(_request: Request, exc: IdentityError) -> JSONResponse:
    return JSONResponse({"detail": exc.message, "code": exc.code}, status_code=401, headers={"WWW-Authenticate": "Bearer"})


for module in (core, auth, org, gateway, servers, scans, sandbox, tools, approvals, audit, policy, notifications, reports):
    app.include_router(module.router)

# Static sites: the landing + auth site at /, the login-gated dashboard at /app.
_dash = Path(_settings.static_dashboard_dir)
_web = Path(_settings.static_web_dir)
_web_index = _web / "index.html"
_dash_index = _dash / "index.html"

if _web_index.exists():
    # The landing/auth site uses history routing, so these paths must fall back to its index.html.
    @app.get("/auth")
    @app.get("/auth/{rest:path}")
    async def _auth_spa(rest: str = "") -> FileResponse:  # noqa: ARG001
        return FileResponse(_web_index)

if _dash_index.exists():
    @app.get("/app")
    async def _app_root() -> FileResponse:
        return FileResponse(_dash_index)

    app.mount("/app", StaticFiles(directory=str(_dash), html=True), name="dashboard")

if _web_index.exists():
    app.mount("/", StaticFiles(directory=str(_web), html=True), name="web")
elif _dash_index.exists():
    # No landing build yet: serve the dashboard at the root so the app still works.
    app.mount("/", StaticFiles(directory=str(_dash), html=True), name="dashboard-root")
