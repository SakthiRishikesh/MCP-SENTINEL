"""Out-of-band notifications: approvals and security alerts pushed to where people are.

When Sentinel pauses a call for step-up or human approval, or blocks something serious, it
tells a person right away - with the sandbox's effect preview - instead of waiting for
someone to open the dashboard:

* Slack (incoming webhook, Block Kit with a "Review" button)
* Microsoft Teams (Workflows webhook, Adaptive Card)
* ntfy (mobile / desktop push; self-hosted or ntfy.sh) with a tap-to-open action
* generic JSON webhooks, optionally HMAC-SHA256 signed (``X-Sentinel-Signature``)

Links open Sentinel's approval page, where the person must still authenticate and pass
step-up: a notification never carries a credential or approves anything by itself.
Channels are configured in the dashboard (stored encrypted) or with SENTINEL_NOTIFY_* env vars.
Delivery runs on a background thread and never slows down or fails a tool call.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

import httpx

from sentinel.config import Settings, get_settings

log = logging.getLogger("sentinel.notify")
KINDS = ("approval", "mfa", "sandbox_block", "sandbox_evasion", "server_unsafe", "rug_pull", "test")
KIND_LABEL = {
    "approval": "Approval needed", "mfa": "Step-up needed", "sandbox_block": "Call blocked by the sandbox",
    "sandbox_evasion": "Sandbox evasion: changes reverted", "server_unsafe": "MCP server is NOT SAFE",
    "rug_pull": "Rug pull detected", "test": "Test notification",
}
SEVERITY_PRIORITY = {"INFO": "default", "LOW": "default", "MEDIUM": "default", "HIGH": "high", "CRITICAL": "urgent"}
CHANNEL_TYPES = ("slack", "teams", "ntfy", "webhook")
FLAG_KEY = "notifications"

_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sentinel-notify")
_history: deque[dict[str, Any]] = deque(maxlen=50)
_lock = threading.Lock()
_cache: tuple[float, list[dict[str, Any]], list[str]] | None = None


# -- configuration -----------------------------------------------------------------------------
def env_channels(settings: Settings) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if settings.notify_slack_webhook_url:
        out.append({"type": "slack", "url": settings.notify_slack_webhook_url, "name": "Slack (env)"})
    if settings.notify_teams_webhook_url:
        out.append({"type": "teams", "url": settings.notify_teams_webhook_url, "name": "Teams (env)"})
    if settings.notify_ntfy_url:
        out.append({"type": "ntfy", "url": settings.notify_ntfy_url, "name": "ntfy (env)", "token": settings.notify_ntfy_token})
    for i, url in enumerate(u.strip() for u in settings.notify_webhook_urls.split(",") if u.strip()):
        out.append({"type": "webhook", "url": url, "name": f"Webhook {i + 1} (env)", "secret": settings.notify_webhook_secret})
    return out


def load_config(session: Any, settings: Settings | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    """(channels, enabled kinds): dashboard-configured channels (encrypted) plus env channels."""
    from sentinel.pipeline import get_runtime_flag
    from sentinel.secrets_box import decrypt_json

    settings = settings or get_settings()
    stored = get_runtime_flag(session, FLAG_KEY, {}) or {}
    channels = list(decrypt_json(stored.get("channels_encrypted") or "", default=[]) or [])
    kinds = stored.get("kinds") or [k.strip() for k in settings.notify_events.split(",") if k.strip()]
    return channels + env_channels(settings), [k for k in kinds if k in KINDS]


def save_config(session: Any, channels: list[dict[str, Any]], kinds: list[str], by: str) -> None:
    from sentinel.db import RuntimeFlagRow
    from sentinel.secrets_box import encrypt_json
    from sentinel.types import utcnow

    clean = []
    for ch in channels:
        if ch.get("type") not in CHANNEL_TYPES:
            raise ValueError(f"unknown channel type {ch.get('type')!r}")
        parts = urlsplit(str(ch.get("url") or ""))
        if parts.scheme not in {"https", "http"} or not parts.hostname:
            raise ValueError("a channel needs an http(s) URL")
        clean.append({k: str(v) for k, v in ch.items() if k in {"type", "url", "name", "secret", "token"} and v})
    row = session.get(RuntimeFlagRow, FLAG_KEY) or RuntimeFlagRow(key=FLAG_KEY)
    row.value = {"value": {"channels_encrypted": encrypt_json(clean), "kinds": [k for k in kinds if k in KINDS]}}
    row.updated_at, row.updated_by = utcnow(), by
    session.merge(row)
    session.commit()
    invalidate()


def invalidate() -> None:
    global _cache
    with _lock:
        _cache = None


def masked(channel: dict[str, Any]) -> dict[str, Any]:
    parts = urlsplit(str(channel.get("url") or ""))
    path = parts.path or "/"
    return {"type": channel.get("type"), "name": channel.get("name") or channel.get("type"),
            "url": f"{parts.scheme}://{parts.hostname}{(':' + str(parts.port)) if parts.port else ''}{path[:12]}{'…' if len(path) > 12 else ''}",
            "signed": bool(channel.get("secret")), "env": "(env)" in str(channel.get("name") or "")}


def history() -> list[dict[str, Any]]:
    return list(_history)[::-1]


# -- building messages ---------------------------------------------------------------------------
def build(kind: str, *, title: str, message: str, url: str | None = None, severity: str = "HIGH",
          details: dict[str, Any] | None = None, preview: dict[str, Any] | None = None) -> dict[str, Any]:
    """A channel-neutral notification. Arguments are never included, only the effect summary."""
    files = [f"{f.get('change')}: {f.get('path')}" for f in (preview or {}).get("files", [])[:5]]
    return {"event": kind, "label": KIND_LABEL.get(kind, kind), "title": title[:200], "message": message[:1500],
            "severity": severity, "url": url, "preview_headline": (preview or {}).get("headline"), "files": files,
            "details": details or {}, "timestamp": time.time()}


def slack_payload(n: dict[str, Any]) -> dict[str, Any]:
    text = f"*{n['label']}* · {n['title']}\n{n['message']}"
    if n.get("preview_headline"):
        text += f"\n*Effect (tested in the sandbox):* {n['preview_headline']}"
    blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}]
    if n.get("files"):
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": "\n".join(n["files"])[:1900]}]})
    if n.get("url"):
        blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Review in Sentinel"},
                                                        "url": n["url"], "style": "primary" if n["event"] in {"approval", "mfa"} else "danger"}]})
    return {"text": f"{n['label']}: {n['title']}", "blocks": blocks}


def teams_payload(n: dict[str, Any]) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": n["label"], "wrap": True,
         "color": "Attention" if n["severity"] in {"HIGH", "CRITICAL"} else "Default"},
        {"type": "TextBlock", "text": n["title"], "wrap": True, "weight": "Bolder"},
        {"type": "TextBlock", "text": n["message"], "wrap": True},
    ]
    if n.get("preview_headline"):
        body.append({"type": "TextBlock", "text": f"Effect (tested in the sandbox): {n['preview_headline']}", "wrap": True, "isSubtle": True})
    for line in n.get("files") or []:
        body.append({"type": "TextBlock", "text": line, "wrap": True, "fontType": "Monospace", "size": "Small"})
    card: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
    if n.get("url"):
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Review in Sentinel", "url": n["url"]}]
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def ntfy_request(n: dict[str, Any], token: str = "") -> tuple[bytes, dict[str, str]]:
    body = n["message"] + (f"\nEffect: {n['preview_headline']}" if n.get("preview_headline") else "")
    headers = {"Title": f"{n['label']}: {n['title']}"[:250].encode("ascii", "replace").decode(),
               "Priority": SEVERITY_PRIORITY.get(n["severity"], "default"),
               "Tags": "shield" if n["event"] in {"approval", "mfa"} else "rotating_light"}
    if n.get("url"):
        headers["Click"] = n["url"]
        headers["Actions"] = f"view, Review, {n['url']}"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return body.encode("utf-8"), headers


def signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# -- delivery -------------------------------------------------------------------------------------------
def _deliver(channel: dict[str, Any], n: dict[str, Any]) -> dict[str, Any]:
    kind = channel.get("type")
    url = str(channel.get("url") or "")
    headers: dict[str, str] = {"User-Agent": "MCP-Sentinel"}
    if kind == "slack":
        body, headers["Content-Type"] = json.dumps(slack_payload(n)).encode(), "application/json"
    elif kind == "teams":
        body, headers["Content-Type"] = json.dumps(teams_payload(n)).encode(), "application/json"
    elif kind == "ntfy":
        body, extra = ntfy_request(n, str(channel.get("token") or ""))
        headers.update(extra)
    else:
        body = json.dumps(n, default=str).encode()
        headers["Content-Type"] = "application/json"
        if channel.get("secret"):
            headers["X-Sentinel-Signature"] = signature(str(channel["secret"]), body)
    record = {"at": time.time(), "event": n["event"], "title": n["title"], "channel": masked(channel)}
    for attempt in range(2):
        try:
            resp = httpx.post(url, content=body, headers=headers, timeout=6.0)
            record.update(status=resp.status_code, ok=resp.status_code < 300)
            if resp.status_code < 500:
                break
        except httpx.HTTPError as exc:
            record.update(status=None, ok=False, error=str(exc)[:200])
        time.sleep(1.0 + attempt)
    _history.append(record)
    if not record.get("ok"):
        log.warning("notification to %s failed: %s", record["channel"]["url"], record.get("error") or record.get("status"))
    return record


def send(n: dict[str, Any], channels: list[dict[str, Any]], *, wait: bool = False) -> list[dict[str, Any]]:
    futures = [_pool.submit(_deliver, ch, n) for ch in channels]
    if wait:
        return [f.result(timeout=20) for f in futures]
    return []


def notify(session: Any, kind: str, *, title: str, message: str, url: str | None = None, severity: str = "HIGH",
           details: dict[str, Any] | None = None, preview: dict[str, Any] | None = None) -> None:
    """Fire-and-forget: look up the configured channels and deliver in the background."""
    global _cache
    try:
        with _lock:
            cached = _cache if _cache and time.time() - _cache[0] < 30 else None
        if cached is None:
            channels, kinds = load_config(session)
            with _lock:
                _cache = (time.time(), channels, kinds)
        else:
            _, channels, kinds = cached
        if not channels or kind not in kinds:
            return
        send(build(kind, title=title, message=message, url=url, severity=severity, details=details, preview=preview), channels)
    except Exception:  # notifications must never break enforcement
        log.exception("notification dispatch failed")
