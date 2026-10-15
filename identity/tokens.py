from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from sentinel.config import Settings


def mint_demo_token(
    settings: Settings,
    *,
    subject: str = "user-123",
    roles: list[str] | None = None,
    scopes: list[str] | None = None,
    agent_id: str = "mcp-agent",
    acr: str | None = None,
    amr: list[str] | None = None,
    ttl_seconds: int = 3600,
    issuer: str | None = None,
    audience: str | None = None,
    expired: bool = False,
    extra_claims: dict | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    exp = now - timedelta(seconds=30) if expired else now + timedelta(seconds=ttl_seconds)
    claims = {
        "sub": subject,
        "iss": issuer or settings.jwt_issuer,
        "aud": audience or settings.jwt_audience,
        "exp": int(exp.timestamp()),
        "iat": int(now.timestamp()),
        "roles": roles or ["ANALYST"],
        "scope": " ".join(scopes or ["mcp.invoke"]),
        "agent_id": agent_id,
        "sid": f"sess-{subject}",
    }
    if acr:
        claims["acr"] = acr
    if amr:
        claims["amr"] = amr
    if extra_claims:
        claims.update({k: v for k, v in extra_claims.items() if v not in (None, "")})
    return jwt.encode(claims, settings.demo_jwt_secret, algorithm="HS256")
