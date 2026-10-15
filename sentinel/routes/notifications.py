"""Notification channels (Slack / Teams / ntfy / webhooks) for approvals and security alerts."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinel import notify
from sentinel.config import Settings, get_settings
from sentinel.deps import admin_identity, db_session
from sentinel.pipeline import get_runtime_flag
from sentinel.receipts import AuditStore
from sentinel.secrets_box import decrypt_json

router = APIRouter()


class ChannelBody(BaseModel):
    type: str
    url: str
    name: str = ""
    secret: str = ""
    token: str = ""


class KindsBody(BaseModel):
    kinds: list[str]


def _stored(session: Session) -> tuple[list[dict[str, Any]], list[str] | None]:
    flag = get_runtime_flag(session, notify.FLAG_KEY, {}) or {}
    return list(decrypt_json(flag.get("channels_encrypted") or "", default=[]) or []), flag.get("kinds")


@router.get("/v1/notifications")
def get_notifications(session: Session = Depends(db_session), settings: Settings = Depends(get_settings),
                      _a=Depends(admin_identity)) -> dict[str, Any]:
    channels, _ = _stored(session)
    _, kinds = notify.load_config(session, settings)
    return {"channels": [notify.masked(c) for c in channels], "env_channels": [notify.masked(c) for c in notify.env_channels(settings)],
            "kinds": kinds, "available_kinds": [k for k in notify.KINDS if k != "test"], "history": notify.history()}


@router.post("/v1/notifications/channels")
def add_channel(body: ChannelBody, session: Session = Depends(db_session), settings: Settings = Depends(get_settings),
                identity=Depends(admin_identity)) -> dict[str, Any]:
    channels, _ = _stored(session)
    _, kinds = notify.load_config(session, settings)
    channel = {"type": body.type, "url": body.url.strip(), "name": body.name.strip() or body.type, "secret": body.secret, "token": body.token}
    try:
        notify.save_config(session, channels + [channel], kinds, identity.subject)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    AuditStore(session).write_event("notify_channel_added", "INFO", f"{identity.subject} added a {body.type} notification channel",
                                    {"channel": notify.masked(channel)})
    return {"added": notify.masked(channel)}


@router.delete("/v1/notifications/channels/{index}")
def remove_channel(index: int, session: Session = Depends(db_session), settings: Settings = Depends(get_settings),
                   identity=Depends(admin_identity)) -> dict[str, Any]:
    channels, _ = _stored(session)
    if not 0 <= index < len(channels):
        raise HTTPException(404, "no such channel")
    removed = channels.pop(index)
    _, kinds = notify.load_config(session, settings)
    notify.save_config(session, channels, kinds, identity.subject)
    AuditStore(session).write_event("notify_channel_removed", "INFO", f"{identity.subject} removed a notification channel",
                                    {"channel": notify.masked(removed)})
    return {"removed": notify.masked(removed)}


@router.put("/v1/notifications/kinds")
def set_kinds(body: KindsBody, session: Session = Depends(db_session), identity=Depends(admin_identity)) -> dict[str, Any]:
    unknown = [k for k in body.kinds if k not in notify.KINDS]
    if unknown:
        raise HTTPException(422, f"unknown notification kinds: {unknown}")
    channels, _ = _stored(session)
    notify.save_config(session, channels, body.kinds, identity.subject)
    return {"kinds": body.kinds}


@router.post("/v1/notifications/test")
def send_test(session: Session = Depends(db_session), settings: Settings = Depends(get_settings),
              identity=Depends(admin_identity)) -> dict[str, Any]:
    channels, _ = notify.load_config(session, settings)
    if not channels:
        raise HTTPException(409, "no notification channel is configured")
    n = notify.build("test", title="MCP-Sentinel is connected", message=f"Test notification sent by {identity.subject}.",
                     url=f"{settings.dashboard_base_url}/#/alerts", severity="INFO")
    return {"deliveries": notify.send(n, channels, wait=True)}
