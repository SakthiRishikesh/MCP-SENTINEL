from __future__ import annotations

import base64
import json
import time

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from integrity.vulnscan import ScanReport, _analyze_token, check_oauth, scan_config
from tests.conftest import serve_app
from tests.fixtures import mcp_test_server
from tests.helpers import headers


def _jwt(header: dict, claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc(header)}.{enc(claims)}.sig"


def _ids(report: ScanReport) -> set[str]:
    return {v.id for v in report.vulnerabilities}


def test_token_analysis():
    r = ScanReport(target="t", name="t", transport="http", active=False)
    _analyze_token(r, _jwt({"alg": "none"}, {"scope": "repo admin"}), "header Authorization")
    assert {"SMCP-JWT-ALG-NONE", "SMCP-JWT-NO-EXP", "SMCP-JWT-SCOPE", "SMCP-JWT-NO-AUD"} <= _ids(r)
    r2 = ScanReport(target="t", name="t", transport="http", active=False)
    _analyze_token(r2, _jwt({"alg": "RS256"}, {"exp": int(time.time()) + 3600, "aud": "mcp", "scope": "files:read"}), "h")
    assert not r2.vulnerabilities  # a well-formed, short-lived, audience-bound token is fine
    r3 = ScanReport(target="t", name="t", transport="http", active=False)
    _analyze_token(r3, "ghp_" + "a" * 36, "env GITHUB_TOKEN")
    assert "SMCP-TOKEN-SCOPE" in _ids(r3)


def test_static_configuration_checks():
    report = scan_config({"command": "definitely-not-a-real-binary-xyz", "args": ["--token=abc123secret"]}, "stdio", timeout=5)
    assert "SMCP-CFG-SECRET_IN_ARGS" in _ids(report)
    assert report.errors  # the handshake failed and is reported, not hidden
    url = scan_config({"url": "http://mcp.example.com/mcp?api_key=XYZ"}, "http", timeout=2)
    assert {"SMCP-CFG-PLAINTEXT_TRANSPORT", "SMCP-TOKEN-URL"} <= _ids(url)


def test_http_probes_against_real_fixture(fixture_endpoint):
    report = scan_config({"url": fixture_endpoint}, "http", timeout=10)
    ids = _ids(report)
    assert "SMCP-ORIGIN" in ids  # the fixture accepts any Origin (local server → DNS rebinding risk)
    assert report.inventory["tools"] == 6
    assert "SMCP-CAP-SECRETS" in ids  # get_credentials hands secrets to the model
    assert report.summary["grade"] in {"A", "B", "C", "D", "F"}
    html = report.to_html()
    assert "<script" not in html and "MCP Security Scan Report" in html


def test_detects_auth_bypass_and_missing_www_authenticate():
    async def mcp(request):
        if not request.headers.get("authorization"):
            return Response(status_code=401)  # rejects anonymous requests, without WWW-Authenticate …
        message = json.loads(await request.body())
        return JSONResponse(mcp_test_server.handle(message) or {})  # … but accepts any token at all

    base, server = serve_app(Starlette(routes=[Route("/mcp", mcp, methods=["POST", "DELETE"])]))
    try:
        report = scan_config({"url": f"{base}/mcp", "headers": {"Authorization": "Bearer real-token"}}, "http", timeout=10)
    finally:
        server.should_exit = True
    ids = _ids(report)
    assert "SMCP-AUTH-BYPASS" in ids and "SMCP-AUTH-WWW" in ids
    assert report.summary["grade"] == "F"


def test_oauth_metadata_checks():
    async def prm(request):
        return JSONResponse({"resource": str(request.base_url).rstrip("/") + "/mcp", "authorization_servers": [str(request.base_url).rstrip("/")]})

    async def asm(request):
        return JSONResponse({"issuer": "x", "authorization_endpoint": "https://as.example/authorize", "token_endpoint": "https://as.example/token",
                             "response_types_supported": ["code", "token"], "code_challenge_methods_supported": ["plain"]})

    base, server = serve_app(Starlette(routes=[
        Route("/.well-known/oauth-protected-resource/mcp", prm), Route("/.well-known/oauth-authorization-server", asm),
    ]))
    try:
        report = ScanReport(target="t", name="t", transport="http", active=False)
        check_oauth(report, f"{base}/mcp", "", 5)
    finally:
        server.should_exit = True
    assert {"SMCP-OAUTH-PKCE", "SMCP-OAUTH-PKCE-PLAIN", "SMCP-OAUTH-IMPLICIT"} <= _ids(report)


def test_active_probes_find_injected_output(fixture_endpoint):
    mcp_test_server.STATE["compromised"] = True  # search_logs now returns instruction-style text
    report = scan_config({"url": fixture_endpoint}, "http", active=True, timeout=10)
    assert "search_logs" in report.inventory["active_probe"]["probed_tools"]
    assert "SMCP-PI-OUTPUT" in _ids(report)
    # write / secret / egress tools are never called by the active probes
    assert not {"create_ticket", "get_credentials", "send_data", "isolate_host", "lookup_ip"} & set(report.inventory["active_probe"]["probed_tools"])


def test_scan_api_and_report_download(client):
    admin = headers("SECURITY_ADMIN")
    out = client.post(f"/v1/servers/{client.server_id}/scan", headers=admin, json={"active": False}).json()
    assert out["grade"] and out["report"]["summary"]["total_vulnerabilities"] >= 1
    servers = {s["server_id"]: s for s in client.get("/v1/servers").json()}
    assert servers[client.server_id]["vuln_scan"]["scan_id"] == out["scan_id"]
    page = client.get(f"/v1/scans/{out['scan_id']}/report.html")
    assert page.status_code == 200 and "default-src 'none'" in page.headers["content-security-policy"]
    assert client.get(f"/v1/scans/{out['scan_id']}/report.json").json()["scan_id"] == out["scan_id"]
    assert any(s["scan_id"] == out["scan_id"] for s in client.get("/v1/scans", params={"server_id": client.server_id}).json())
    assert client.post(f"/v1/servers/{client.server_id}/scan", headers=headers("ANALYST"), json={}).status_code == 403
    assert out["safety"]["verdict"] in {"SAFE", "CAUTION", "UNSAFE"} and out["safety"]["recommendations"]
