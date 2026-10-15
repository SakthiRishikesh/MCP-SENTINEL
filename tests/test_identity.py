from __future__ import annotations

import pytest

from identity.tokens import mint_demo_token
from identity.verifier import IdentityError, IdentityVerifier
from sentinel.config import get_settings


def test_valid_token():
    settings = get_settings()
    token = mint_demo_token(settings, roles=["ANALYST"], scopes=["mcp.invoke"])
    ident = IdentityVerifier(settings).verify(f"Bearer {token}")
    assert ident.subject == "user-123"
    assert "ANALYST" in ident.roles
    assert ident.token_valid


def test_expired_token():
    settings = get_settings()
    token = mint_demo_token(settings, expired=True)
    with pytest.raises(IdentityError) as exc:
        IdentityVerifier(settings).verify(f"Bearer {token}")
    assert exc.value.code == "expired_token"


def test_wrong_issuer():
    settings = get_settings()
    token = mint_demo_token(settings, issuer="http://evil")
    with pytest.raises(IdentityError) as exc:
        IdentityVerifier(settings).verify(f"Bearer {token}")
    assert exc.value.code == "wrong_issuer"


def test_wrong_audience():
    settings = get_settings()
    token = mint_demo_token(settings, audience="other-api")
    with pytest.raises(IdentityError) as exc:
        IdentityVerifier(settings).verify(f"Bearer {token}")
    assert exc.value.code == "wrong_audience"


def test_missing_scopes():
    settings = get_settings()
    token = mint_demo_token(settings, scopes=["openid"])
    ident = IdentityVerifier(settings).verify(f"Bearer {token}")
    with pytest.raises(IdentityError) as exc:
        IdentityVerifier(settings).require_scopes(ident, ["mcp.invoke"])
    assert exc.value.code == "missing_scopes"


def test_invalid_role_not_trusted_from_request_body():
    settings = get_settings()
    token = mint_demo_token(settings, roles=["NOT_A_ROLE", "SOC_ANALYST"])
    ident = IdentityVerifier(settings).verify(f"Bearer {token}")
    assert ident.roles == ["ANALYST"]  # legacy role name is mapped to its replacement
