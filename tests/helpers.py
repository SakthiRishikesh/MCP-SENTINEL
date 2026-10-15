from __future__ import annotations

from typing import Any

from identity.tokens import mint_demo_token
from sentinel.config import get_settings

INTENT = "Investigate failed logins from 10.10.20.30."
SLUG = "fixture"  # slug of the test server registered by the ``client`` fixture


def headers(role: str = "ANALYST", mfa: bool = False, subject: str = "user-123") -> dict[str, str]:
    s = get_settings()
    token = mint_demo_token(s, subject=subject, roles=[role], acr=s.mfa_acr if mfa else None, amr=["otp"] if mfa else ["pwd"])
    return {"Authorization": f"Bearer {token}"}


def call(client, workflow: str, tool: str, arguments: dict[str, Any], hdrs: dict[str, str], **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "workflow_id": workflow,
        "arguments": arguments,
        "user_intent": extra.pop("user_intent", INTENT),
        "agent_id": "mcp-agent",
        **extra,
    }
    if "server_id" in body:
        body["tool_name"] = tool
    else:
        body["exposed_name"] = f"{SLUG}__{tool}"
    resp = client.post("/v1/mcp/tools/call", headers=hdrs, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()
