from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{(TMP / 'initial.db').as_posix()}"
os.environ["SENTINEL_AUTH_MODE"] = "demo"
os.environ["SENTINEL_REDIS_URL"] = ""
os.environ["SENTINEL_DEMO_JWT_SECRET"] = "test-secret-not-for-production"
os.environ["SENTINEL_JWT_ISSUER"] = "http://localhost:8080/realms/mcp-sentinel"
os.environ["SENTINEL_JWT_AUDIENCE"] = "mcp-sentinel"
os.environ["SENTINEL_BACKGROUND_JOBS_ENABLED"] = "false"
os.environ["SENTINEL_APPROVAL_WAIT_SECONDS"] = "0"
os.environ["SENTINEL_SECRETS_KEY_FILE"] = str(TMP / "sentinel.key")
os.environ["SENTINEL_RECEIPT_KEY_FILE"] = str(TMP / "receipt_ed25519.pem")
os.environ["SENTINEL_STATIC_DASHBOARD_DIR"] = str(TMP / "no-dashboard")
os.environ["SENTINEL_SANDBOX_DIR"] = str(TMP / "sandbox")
os.environ["SENTINEL_SANDBOX_MODE"] = "process"  # deterministic and fast; the Docker backend has its own test
os.environ["SENTINEL_SANDBOX_AUDIT_ON_REGISTER"] = "false"  # tests run the audit synchronously where needed
os.environ["SENTINEL_SEED_DEMO_ACCOUNTS"] = "false"  # auth tests create their own accounts

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sentinel.config import get_settings  # noqa: E402
from sentinel.db import reset_engine  # noqa: E402
from tests.fixtures import mcp_test_server  # noqa: E402
from tests.helpers import headers  # noqa: E402

FIXTURE_SCRIPT = str(Path(mcp_test_server.__file__).resolve())


@pytest.fixture(autouse=True)
def _reset_db():
    """A brand-new SQLite file per test.

    Re-creating a database at the same path while a previous test's worker thread still holds a
    connection lets SQLite pick up the old WAL; a fresh path per test isolates tests completely.
    """
    from sandbox.shadow import reset_sandbox
    from sentinel import notify
    from sentinel.upstream.manager import reset_manager

    reset_sandbox()
    notify.invalidate()  # cached channel config belongs to the previous test's database
    os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{(TMP / f'test-{uuid.uuid4().hex[:12]}.db').as_posix()}"
    get_settings.cache_clear()
    reset_manager()
    reset_engine()
    mcp_test_server.STATE.update({"rugpull": False, "compromised": False})
    yield
    reset_manager()
    reset_sandbox()
    reset_engine()


def serve_app(app) -> tuple[str, object]:
    """Run an ASGI app on a free local port; returns (base_url, server)."""
    import socket
    import threading
    import time

    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="session")
def fixture_endpoint() -> str:
    """The test MCP server, running for real (Streamable HTTP) on a free local port."""
    base, server = serve_app(mcp_test_server.build_app())
    yield f"{base}/mcp"
    server.should_exit = True


@pytest.fixture
def app_client(_reset_db) -> TestClient:
    """Sentinel with an empty registry (what a fresh install looks like)."""
    from sentinel.app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def client(app_client: TestClient, fixture_endpoint: str) -> TestClient:
    """Sentinel with the test MCP server registered through the API, exactly like a user would."""
    resp = app_client.post("/v1/servers", headers=headers("SECURITY_ADMIN", subject="admin"), json={
        "server_name": "fixture", "transport": "http", "endpoint": fixture_endpoint, "run_sandbox": False,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert not (data.get("discovery") or {}).get("error"), data
    app_client.server_id = data["server_id"]
    return app_client


@pytest.fixture
def stdio_fixture_config() -> dict:
    return {"command": sys.executable, "args": [FIXTURE_SCRIPT]}


@pytest.fixture
def workspace(tmp_path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "report.txt").write_text("quarterly numbers v1")
    (ws / "keep.txt").write_text("keep me")
    return ws


@pytest.fixture
def stdio_server(client, stdio_fixture_config, workspace):
    """The test server over stdio, configured with a workspace folder (a sandbox root)."""
    resp = client.post("/v1/servers", headers=headers("SECURITY_ADMIN"), json={
        "server_name": "local", "transport": "stdio", "command": stdio_fixture_config["command"],
        "args": [*stdio_fixture_config["args"], str(workspace)], "run_sandbox": False,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()["server_id"]
