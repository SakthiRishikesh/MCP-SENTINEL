from __future__ import annotations

import json
import sys
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from identity.tokens import mint_demo_token
from sentinel import __version__, clientconfig, presence
from sentinel.config import REPO_ROOT, Settings, get_settings
from sentinel.deps import current_identity, get_store
from sentinel.types import IdentityContext

router = APIRouter()
LOOPBACK_CLIENTS = {"127.0.0.1", "::1", "localhost", "testclient"}


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "component": "mcp-sentinel", "version": __version__, "store": get_store().backend}


@router.post("/v1/demo/token")
def demo_token(
    request: Request,
    role: str = "ANALYST",
    subject: str = "user-123",
    mfa: bool = False,
    agent_id: str = "mcp-agent",
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if settings.auth_mode != "demo":
        raise HTTPException(403, "demo tokens disabled")
    client = request.client.host if request.client else ""
    if settings.demo_token_loopback_only and client not in LOOPBACK_CLIENTS:
        raise HTTPException(403, "demo tokens can only be minted from this machine (SENTINEL_DEMO_TOKEN_LOOPBACK_ONLY)")
    if role not in settings.role_list:
        raise HTTPException(422, f"unknown role {role}")
    token = mint_demo_token(
        settings,
        subject=subject[:128],
        roles=[role],
        agent_id=agent_id[:128],
        acr=settings.mfa_acr if mfa else None,
        amr=["pwd", "otp"] if mfa else ["pwd"],
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600, "subject": subject, "role": role}


@router.get("/v1/auth/whoami")
def whoami(identity: IdentityContext = Depends(current_identity)) -> dict[str, Any]:
    return identity.model_dump(mode="json")


def claude_desktop_entry(settings: Settings) -> dict[str, Any]:
    token = None if settings.auth_mode == "demo" else "<short-lived user access token from your IdP>"
    return clientconfig.sentinel_bridge_entry(settings.api_base_url, token=token)


@router.get("/v1/integrations/claude-desktop")
def claude_desktop(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    entry = claude_desktop_entry(settings)
    code_spec = json.dumps({"type": "stdio", **entry})
    return {
        "config": {"mcpServers": {clientconfig.SENTINEL_ENTRY_NAME: entry}},
        "desktop": clientconfig.claude_desktop_status(),
        "clients": presence.clients(),
        "cli": f"{sys.executable} -m sentinel.cli install-claude",
        "import_cli": f"{sys.executable} -m sentinel.cli import-claude --replace",
        "claude_code_cli": f"{sys.executable} -m sentinel.cli install-claude-code",
        "claude_code_import_cli": f"{sys.executable} -m sentinel.cli import-claude --from code --replace",
        "claude_code": f"claude mcp add-json --scope user {clientconfig.SENTINEL_ENTRY_NAME} '{code_spec}'",
        "claude_code_http": f"claude mcp add --transport http {clientconfig.SENTINEL_ENTRY_NAME} {settings.api_base_url}/mcp "
                            f"--header \"Authorization: Bearer <token>\"",
        "streamable_http_url": f"{settings.api_base_url}/mcp",
        "repo_root": str(REPO_ROOT),
        "notes": [
            "Claude Desktop caches its tool list: after adding servers in Sentinel, toggle the mcp-sentinel connector "
            "off/on (or restart Claude) to see them as native tools; they are usable immediately via sentinel_invoke.",
            "Claude Code launches the same stdio bridge; run /mcp in Claude Code to reconnect after adding servers.",
            "Keep the API on 127.0.0.1; the bridge talks to it locally.",
        ],
    }


@router.get("/v1/integrations/info")
def integrations_info(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    return {
        "api_url": settings.api_base_url,
        "dashboard_url": settings.dashboard_base_url,
        "auth_mode": settings.auth_mode,
        "approval_wait_seconds": settings.approval_wait_seconds,
        "expose_meta_tools": settings.expose_meta_tools,
        "allow_stdio_servers": settings.allow_stdio_servers,
    }
