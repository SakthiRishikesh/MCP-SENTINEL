"""Real accounts, organization RBAC and employee tool-assignment enforcement."""

from __future__ import annotations

from sentinel.accounts import hash_password, verify_password


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_password_hash_roundtrip():
    encoded = hash_password("correct horse")
    assert verify_password("correct horse", encoded)
    assert not verify_password("wrong", encoded)
    assert encoded != hash_password("correct horse")  # salted


def test_individual_signup_and_login(app_client):
    r = app_client.post("/v1/auth/signup/individual", json={"name": "Dana", "email": "dana@demo.dev", "password": "supersecret"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["account"]["account_type"] == "individual" and body["redirect"] == "/app"
    who = app_client.get("/v1/auth/account", headers=_bearer(body["access_token"])).json()
    assert who["email"] == "dana@demo.dev" and who["account_type"] == "individual"
    # duplicate email is rejected
    assert app_client.post("/v1/auth/signup/individual", json={"email": "dana@demo.dev", "password": "supersecret"}).status_code == 409
    # login works, wrong password does not
    assert app_client.post("/v1/auth/login", json={"email": "dana@demo.dev", "password": "supersecret"}).status_code == 200
    assert app_client.post("/v1/auth/login", json={"email": "dana@demo.dev", "password": "nope"}).status_code == 401


def test_org_signup_creates_admin_and_employees(app_client):
    r = app_client.post("/v1/auth/signup/organization", json={
        "organization": "Acme", "organizationEmail": "team@acme.dev", "adminName": "Admin", "adminEmail": "admin@acme.dev",
        "password": "supersecret", "employees": [{"name": "Emp One", "email": "e1@acme.dev", "role": "Developer"}],
    })
    assert r.status_code == 200, r.text
    admin_token = r.json()["access_token"]
    assert r.json()["employees_created"] == 1
    org = app_client.get("/v1/org", headers=_bearer(admin_token)).json()
    assert org["admins"] == 1 and org["employees"] == 1
    emails = {m["email"] for m in org["members"]}
    assert {"admin@acme.dev", "e1@acme.dev"} <= emails
    # a non-admin cannot reach the org console
    app_client.post("/v1/auth/signup/individual", json={"email": "solo@acme.dev", "password": "supersecret"})
    solo = app_client.post("/v1/auth/login", json={"email": "solo@acme.dev", "password": "supersecret"}).json()["access_token"]
    assert app_client.get("/v1/org", headers=_bearer(solo)).status_code == 403


def test_admin_member_crud_and_assignments(client):
    # the `client` fixture has a registered server named "fixture"
    server = client.get("/v1/servers").json()[0]
    sid = server["server_id"]
    admin_token = client.post("/v1/auth/signup/organization", json={
        "organization": "Northwind", "adminName": "Boss", "adminEmail": "boss@northwind.dev", "password": "supersecret",
    }).json()["access_token"]
    ah = _bearer(admin_token)
    # CREATE a member with a password so they can log in
    member = client.post("/v1/org/members", headers=ah, json={"name": "Sam", "email": "sam@northwind.dev", "role": "Security analyst", "password": "employeepass"}).json()
    mid = member["account_id"]
    assert member["assignments"] == [] and member["can_login"] is True
    # assign only one tool of the server
    client.put(f"/v1/org/members/{mid}/assignments", headers=ah, json={"grants": [{"server_id": sid, "tools": ["search_logs"]}]})
    asg = client.get(f"/v1/org/members/{mid}/assignments", headers=ah).json()["assignments"]
    assert asg and asg[0]["tools"] == ["search_logs"]
    # UPDATE role, then DELETE
    assert client.patch(f"/v1/org/members/{mid}", headers=ah, json={"role": "Viewer"}).json()["roles"] == ["USER"]
    assert client.delete(f"/v1/org/members/{mid}", headers=ah).json()["deleted"] == mid
    assert client.get(f"/v1/org/members/{mid}/assignments", headers=ah).status_code == 404


def test_employee_can_only_call_assigned_tools(client):
    server = client.get("/v1/servers").json()[0]
    sid, slug = server["server_id"], server["slug"]
    admin_token = client.post("/v1/auth/signup/organization", json={
        "organization": "Vault Co", "adminName": "Boss", "adminEmail": "boss@vault.dev", "password": "supersecret",
    }).json()["access_token"]
    ah = _bearer(admin_token)
    member = client.post("/v1/org/members", headers=ah, json={"email": "emp@vault.dev", "role": "Security analyst", "password": "employeepass"}).json()
    mid = member["account_id"]
    client.put(f"/v1/org/members/{mid}/assignments", headers=ah, json={"grants": [{"server_id": sid, "tools": ["search_logs"]}]})
    emp = _bearer(client.post("/v1/auth/login", json={"email": "emp@vault.dev", "password": "employeepass"}).json()["access_token"])

    # the catalog the employee sees is filtered to assigned tools
    tools = {t["name"] for t in client.get("/v1/mcp/tools/list", headers=emp).json()["tools"]}
    assert f"{slug}__search_logs" in tools and f"{slug}__create_ticket" not in tools

    def call(tool):
        return client.post("/v1/mcp/tools/call", headers=emp, json={"workflow_id": "wf-emp", "exposed_name": f"{slug}__{tool}", "arguments": {"query": "x"}}).json()

    assert call("search_logs")["decision"] in {"ALLOW", "MONITOR", "RESTRICT"}
    blocked = call("create_ticket")
    assert blocked["decision"] == "BLOCK" and blocked["policy_id"] == "deny.not_assigned"
