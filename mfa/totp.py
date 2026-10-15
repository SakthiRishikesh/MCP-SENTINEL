"""RFC 6238 TOTP (compatible with Google Authenticator, Authy, 1Password, Microsoft Authenticator)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    cleaned = secret.replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def code_at(secret: str, step: int, digits: int = DIGITS) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(value).zfill(digits)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def verify(secret: str, code: str, *, last_step: int = 0, window: int = 1, now: float | None = None) -> int | None:
    """Return the matched time-step (for replay protection) or None.

    A code is only accepted for a step strictly greater than ``last_step`` so an
    intercepted code cannot be replayed within its validity window.
    """
    candidate = "".join(ch for ch in str(code) if ch.isdigit())
    if len(candidate) != DIGITS:
        return None
    step = current_step(now)
    for offset in range(-window, window + 1):
        s = step + offset
        if s <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, s), candidate):
            return s
    return None


def provisioning_uri(secret: str, account: str, issuer: str = "MCP-Sentinel") -> str:
    label = quote(f"{issuer}:{account}")
    query = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{query}"
