from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

import jwt
from jwt import PyJWKClient

from sentinel.config import Settings
from sentinel.types import IdentityContext, Role

# Older tokens / IdP realms used SOC_ANALYST for what is now the generic ANALYST role.
ROLE_ALIASES = {"SOC_ANALYST": "ANALYST"}


class IdentityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


_jwks_lock = threading.Lock()
_jwks_clients: dict[str, PyJWKClient] = {}


def _jwks_client(url: str) -> PyJWKClient:
    # PyJWKClient caches signing keys per instance; share one per JWKS URL so the IdP is not
    # queried on every tool call.
    with _jwks_lock:
        client = _jwks_clients.get(url)
        if client is None:
            client = PyJWKClient(url, cache_keys=True, lifespan=300)
            _jwks_clients[url] = client
        return client


class IdentityVerifier:
    """OIDC/JWT identity verifier. Roles come from the IdP token, never from MCP request body."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._jwks: PyJWKClient | None = None
        if settings.auth_mode == "oidc" and settings.oidc_jwks_url:
            self._jwks = _jwks_client(settings.oidc_jwks_url)

    def verify(self, authorization: str | None, *, agent_hint: str | None = None) -> IdentityContext:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise IdentityError("missing_token", "Bearer token required")
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = self._decode(token)
        except jwt.ExpiredSignatureError as exc:
            raise IdentityError("expired_token", "Token expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityError("wrong_issuer", "Token issuer is not trusted") from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityError("wrong_audience", "Token audience is not mcp-sentinel") from exc
        except jwt.InvalidTokenError as exc:
            raise IdentityError("invalid_token", str(exc)) from exc
        except jwt.PyJWTError as exc:  # e.g. PyJWKClientError when the IdP's JWKS is unreachable
            raise IdentityError("jwks_unavailable", f"could not obtain signing keys: {exc}") from exc
        if not str(claims.get("sub") or "").strip():
            raise IdentityError("invalid_token", "token has an empty subject")

        roles = self._extract_roles(claims)
        allowed_roles = set(self.settings.role_list)
        roles = [r for r in roles if r in allowed_roles]
        scopes = self._extract_scopes(claims)
        acr = claims.get("acr")
        amr = claims.get("amr") or []
        if isinstance(amr, str):
            amr = [amr]
        mfa = self._mfa_satisfied(acr, amr)
        agent_id = claims.get("agent_id") or claims.get("azp") or agent_hint or "unknown-agent"
        exp = claims.get("exp")
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None
        return IdentityContext(
            subject=str(claims.get("sub") or ""),
            agent_id=str(agent_id),
            issuer=str(claims.get("iss") or ""),
            audience=claims.get("aud") or "",
            expires_at=expires_at,
            scopes=scopes,
            roles=roles,
            acr=str(acr) if acr else None,
            amr=list(amr),
            token_valid=True,
            mfa_satisfied=mfa,
            session_id=str(claims.get("sid") or claims.get("session_state") or ""),
            account_type=str(claims.get("account_type") or ""),
            org_id=str(claims.get("org_id") or ""),
            org_role=str(claims.get("org_role") or ""),
            display_name=str(claims.get("name") or claims.get("display_name") or ""),
        )

    def _decode(self, token: str) -> dict[str, Any]:
        options = {
            "require": ["exp", "iss", "aud", "sub"],
            "verify_iss": True,
            "verify_aud": True,
            "verify_exp": True,
        }
        if self.settings.auth_mode == "demo":
            return jwt.decode(
                token,
                self.settings.demo_jwt_secret,
                algorithms=self.settings.jwt_algorithm_list,
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                options=options,
            )
        if self._jwks is None:
            raise IdentityError("jwks_unavailable", "OIDC JWKS client is not configured")
        signing_key = self._jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=self.settings.jwt_algorithm_list,
            issuer=self.settings.jwt_issuer,
            audience=self.settings.jwt_audience,
            options=options,
        )

    def _extract_roles(self, claims: dict[str, Any]) -> list[str]:
        realm = ((claims.get("realm_access") or {}).get("roles")) or []
        resource = ((claims.get("resource_access") or {}).get(self.settings.oidc_client_id) or {}).get(
            "roles"
        ) or []
        direct = claims.get("roles") or claims.get("role") or []
        if isinstance(direct, str):
            direct = [direct]
        out: list[str] = []
        for item in list(realm) + list(resource) + list(direct):
            name = ROLE_ALIASES.get(str(item).upper(), str(item).upper())
            if name in Role.__members__ or name in self.settings.role_list:
                if name not in out:
                    out.append(name)
        return out

    def _extract_scopes(self, claims: dict[str, Any]) -> list[str]:
        scope = claims.get("scope") or claims.get("scp") or []
        if isinstance(scope, str):
            return [s for s in scope.split(" ") if s]
        return list(scope)

    def _mfa_satisfied(self, acr: Any, amr: list[str]) -> bool:
        if acr and str(acr) in {self.settings.mfa_acr, "mfa", "aal2", "2"}:
            return True
        mfa_amr = {"mfa", "otp", "hwk", "webauthn", "pwd+otp"}
        return any(str(a).lower() in mfa_amr for a in amr)

    def require_scopes(self, identity: IdentityContext, required: list[str]) -> None:
        missing = [s for s in required if s not in identity.scopes]
        if missing:
            raise IdentityError("missing_scopes", f"Missing scopes: {', '.join(missing)}")
