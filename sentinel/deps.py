"""FastAPI dependencies shared by all route modules."""

from __future__ import annotations

from typing import Iterator

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from identity.verifier import IdentityError, IdentityVerifier
from sentinel.config import Settings, get_settings
from sentinel.db import get_session_factory
from sentinel.gateway import Gateway
from sentinel.pipeline import ControlPlane
from sentinel.store import StateStore
from sentinel.types import IdentityContext

_state: dict[str, StateStore] = {"store": StateStore()}

ADMIN_ROLES = {"SECURITY_ADMIN", "SYSTEM_ADMIN"}


def get_store() -> StateStore:
    return _state["store"]


def set_store(store: StateStore) -> None:
    _state["store"] = store


def db_session() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def plane(session: Session = Depends(db_session), settings: Settings = Depends(get_settings)) -> ControlPlane:
    return ControlPlane(session, get_store(), settings)


def gateway(session: Session = Depends(db_session), settings: Settings = Depends(get_settings)) -> Gateway:
    return Gateway(session, get_store(), settings)


def verify(authorization: str | None, settings: Settings) -> IdentityContext:
    try:
        return IdentityVerifier(settings).verify(authorization)
    except IdentityError as exc:
        raise HTTPException(401, exc.message, headers={"WWW-Authenticate": "Bearer"}) from exc


def current_identity(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> IdentityContext:
    return verify(authorization, settings)


def admin_identity(identity: IdentityContext = Depends(current_identity)) -> IdentityContext:
    if not ADMIN_ROLES & set(identity.roles):
        raise HTTPException(403, "operation requires SECURITY_ADMIN or SYSTEM_ADMIN")
    return identity


def reader(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> IdentityContext | None:
    """Read endpoints are open in local demo mode and require a valid token in OIDC mode."""
    if authorization or settings.auth_mode == "oidc":
        return verify(authorization, settings)
    return None
