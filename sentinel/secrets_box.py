"""At-rest encryption for upstream server configuration (commands, env vars, headers, tokens).

Upstream MCP servers frequently need credentials (e.g. ``GITHUB_PERSONAL_ACCESS_TOKEN``).
Sentinel stores them Fernet-encrypted, never returns them through the API, and never
exposes them to the model.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from sentinel.config import get_settings

_lock = threading.Lock()
_cache: dict[str, Fernet] = {}

SENSITIVE_KEY_HINTS = ("token", "secret", "password", "passwd", "key", "auth", "credential", "cookie", "session")


def _load_or_create_key(path: str) -> bytes:
    env_key = os.environ.get("SENTINEL_SECRETS_KEY")
    if env_key:
        return env_key.encode()
    p = Path(path)
    if p.exists():
        return p.read_bytes().strip()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    # Create with owner-only permissions where the platform supports it.
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def _fernet() -> Fernet:
    path = get_settings().secrets_key_file
    with _lock:
        f = _cache.get(path)
        if f is None:
            f = Fernet(_load_or_create_key(path))
            _cache[path] = f
        return f


def encrypt_json(value: Any) -> str:
    return _fernet().encrypt(json.dumps(value, separators=(",", ":")).encode()).decode()


def decrypt_json(token: str | None, default: Any = None) -> Any:
    if not token:
        return default
    try:
        return json.loads(_fernet().decrypt(token.encode()).decode())
    except (InvalidToken, ValueError):
        return default


def is_sensitive_key(name: str) -> bool:
    lowered = name.lower()
    return any(h in lowered for h in SENSITIVE_KEY_HINTS)


def mask_mapping(mapping: dict[str, Any] | None) -> dict[str, str]:
    """Mask every value; keys stay visible so admins can see *what* is configured."""
    out: dict[str, str] = {}
    for k, v in (mapping or {}).items():
        s = str(v)
        if not is_sensitive_key(k) and len(s) <= 64 and not any(c in s for c in ("@", ":")):
            out[k] = s if len(s) <= 12 else s[:4] + "…" + s[-2:]
        else:
            out[k] = "••••••••"
    return out
