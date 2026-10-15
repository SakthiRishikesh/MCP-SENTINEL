"""Local desktop integration: Claude Desktop status, connected clients, timestamps, bridge auto-start."""

from __future__ import annotations

import json
from types import SimpleNamespace

from identity.tokens import mint_demo_token
from monitoring.process import _is_launcher
from sentinel import clientconfig, presence
from sentinel.bridge import ensure_api
from sentinel.config import get_settings


def test_api_timestamps_carry_utc_offset(client):
    events = client.get("/v1/events?limit=5").json()
    assert events, "registering the fixture server writes an event"
    stamp = events[0]["timestamp"]
    # a naive timestamp would be read as local time by the browser (hours off outside UTC)
    assert stamp.endswith("Z") or stamp.endswith("+00:00"), stamp


def test_claude_desktop_status_flags_bypasses(tmp_path):
    config = tmp_path / "claude_desktop_config.json"
    config.write_text(json.dumps({"mcpServers": {
        "mcp-sentinel": {"command": "/venv/bin/python", "args": ["-m", "sentinel.bridge"]},
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
        "old": {"command": "npx", "args": ["x"], "disabled": True},
    }}))
    settings_dir = tmp_path / "Claude Extensions Settings"
    settings_dir.mkdir()
    (settings_dir / "ant.fs.json").write_text(json.dumps({"isEnabled": True}))
    (settings_dir / "ant.off.json").write_text(json.dumps({"isEnabled": False}))
    (tmp_path / "Claude Extensions" / "ant.fs").mkdir(parents=True)
    (tmp_path / "Claude Extensions" / "ant.fs" / "manifest.json").write_text(json.dumps({"display_name": "Filesystem"}))

    status = clientconfig.claude_desktop_status(str(config))
    assert status["exists"] and status["installed"] and not status["error"]
    assert status["unprotected_servers"] == ["github"]
    assert {(e["name"], e["enabled"]) for e in status["extensions"]} == {("Filesystem", True), ("ant.off", False)}


def test_claude_desktop_status_without_config(tmp_path):
    status = clientconfig.claude_desktop_status(str(tmp_path / "missing.json"))
    assert not status["exists"] and not status["installed"] and status["extensions"] == []


def test_catalog_poll_marks_client_connected(app_client):
    token = mint_demo_token(get_settings(), subject="local-user", roles=["SECURITY_ADMIN"], agent_id="claude-ai")
    assert app_client.get("/v1/mcp/catalog/version", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    clients = {c["name"]: c for c in app_client.get("/v1/dashboard/summary").json()["clients"]}
    assert clients["Claude Desktop"]["connected"] and clients["Claude Desktop"]["subject"] == "local-user"


def test_presence_names_agent_mode():
    presence.touch("local-agent-mode-mcp-sentinel", "local-user")
    presence.touch("sentinel-dashboard", "local-user")  # the dashboard is not an MCP client
    names = {c["name"] for c in presence.clients()}
    assert "Claude Desktop (agent mode)" in names and "sentinel-dashboard" not in names


def test_package_launchers_are_not_the_server():
    # npx shows up as "npm exec <pkg>" and keeps its registry connection open; uvx runs as "uv"
    assert _is_launcher(SimpleNamespace(name=lambda: "npm exec @modelcontextprotocol/server-memory"))
    assert _is_launcher(SimpleNamespace(name=lambda: "uv"))
    assert not _is_launcher(SimpleNamespace(name=lambda: "node"))
    assert not _is_launcher(SimpleNamespace(name=lambda: "python"))


def test_bridge_autostart_only_for_local_api(monkeypatch):
    started = []
    monkeypatch.setattr("sentinel.bridge.subprocess.Popen", lambda *a, **k: started.append(a))
    assert ensure_api("http://sentinel.invalid:8443", wait=0.1) is False  # remote API: never launched locally
    monkeypatch.setenv("SENTINEL_AUTOSTART", "0")
    assert ensure_api("http://127.0.0.1:9", wait=0.1) is False  # opted out
    assert started == []
