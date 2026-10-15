"""TOTP enrollment storage (secrets encrypted at rest)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from mfa import totp
from sentinel.db import MfaEnrollmentRow
from sentinel.secrets_box import decrypt_json, encrypt_json


def status(session: Session, subject: str) -> dict[str, Any]:
    row = session.get(MfaEnrollmentRow, subject)
    return {"subject": subject, "enrolled": bool(row and row.active), "pending_activation": bool(row and not row.active)}


def has_active(session: Session, subject: str) -> bool:
    row = session.get(MfaEnrollmentRow, subject)
    return bool(row and row.active)


def begin(session: Session, subject: str) -> dict[str, str]:
    """Create (or rotate) a pending enrollment. It becomes active after the first valid code."""
    secret = totp.generate_secret()
    row = session.get(MfaEnrollmentRow, subject)
    if row is None:
        row = MfaEnrollmentRow(subject=subject, secret_encrypted=encrypt_json(secret), active=False, last_step=0)
    else:
        row.secret_encrypted = encrypt_json(secret)
        row.active = False
        row.last_step = 0
    session.add(row)
    session.commit()
    return {"secret": secret, "otpauth_uri": totp.provisioning_uri(secret, subject)}


def activate(session: Session, subject: str, code: str) -> bool:
    row = session.get(MfaEnrollmentRow, subject)
    if row is None:
        return False
    secret = decrypt_json(row.secret_encrypted)
    step = totp.verify(secret, code, last_step=row.last_step or 0) if secret else None
    if step is None:
        return False
    row.active = True
    row.last_step = step
    session.add(row)
    session.commit()
    return True


def verify(session: Session, subject: str, code: str) -> bool:
    row = session.get(MfaEnrollmentRow, subject)
    if row is None or not row.active:
        return False
    secret = decrypt_json(row.secret_encrypted)
    step = totp.verify(secret, code, last_step=row.last_step or 0) if secret else None
    if step is None:
        return False
    row.last_step = step  # replay protection: the same code can never be used twice
    session.add(row)
    session.commit()
    return True


def remove(session: Session, subject: str) -> None:
    row = session.get(MfaEnrollmentRow, subject)
    if row is not None:
        session.delete(row)
        session.commit()
