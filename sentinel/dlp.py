"""Data-loss prevention primitives.

* secret detection + redaction for tool outputs ("secrets never reach the model by accident")
* invisible-Unicode / ANSI smuggling detection (ASCII smuggling via Unicode tags, bidi
  overrides, zero-width runs, terminal escape sequences)
* salted fingerprints of sensitive tokens for content-level taint tracking
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

CANARY_PREFIX = "SENTINEL-CANARY-"


@dataclass
class DlpMatch:
    kind: str
    value: str
    start: int
    end: int
    severity: str = "HIGH"

    def as_dict(self) -> dict[str, Any]:
        preview = self.value[:4] + "…" if len(self.value) > 8 else "…"
        return {"kind": self.kind, "severity": self.severity, "preview": preview, "length": len(self.value)}


# (kind, pattern, group-to-redact, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], int, str]] = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]{16,}?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"), 0, "CRITICAL"),
    ("sentinel_canary", re.compile(re.escape(CANARY_PREFIX) + r"[A-Za-z0-9_-]{6,}"), 0, "CRITICAL"),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), 0, "HIGH"),
    ("aws_secret_access_key", re.compile(r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"), 1, "CRITICAL"),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), 0, "CRITICAL"),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), 0, "CRITICAL"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0, "CRITICAL"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"), 0, "HIGH"),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0, "CRITICAL"),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0, "CRITICAL"),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"), 0, "CRITICAL"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0, "HIGH"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0, "HIGH"),
    ("connection_string_password", re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"']{1,64}:([^\s@/\"']{3,128})@"), 1, "HIGH"),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b"
            r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;{}]{6,200})"
        ),
        1,
        "HIGH",
    ),
]

INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b\u200c\u200e\u200f\u202a-\u202e"
    "\u2060-\u2064\u2066-\u2069\u3164\ufeff\uffa0]"
)
ZWJ = "\u200d"
TAG_RE = re.compile("[\U000E0000-\U000E007F]")
VARIATION_RE = re.compile("[\ufe00-\ufe0f\U000E0100-\U000E01EF]")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[PX^_][^\x1b]*\x1b\\")


@dataclass
class SmugglingReport:
    invisible: int = 0
    tag_chars: int = 0
    variation_selectors: int = 0
    ansi_sequences: int = 0
    decoded_hidden_text: str = ""

    @property
    def suspicious(self) -> bool:
        return self.tag_chars > 0 or self.invisible >= 3 or self.ansi_sequences > 0 or self.variation_selectors >= 8

    def as_dict(self) -> dict[str, Any]:
        return {
            "invisible": self.invisible,
            "tag_chars": self.tag_chars,
            "variation_selectors": self.variation_selectors,
            "ansi_sequences": self.ansi_sequences,
            "decoded_hidden_text": self.decoded_hidden_text[:300],
        }


def detect_smuggling(text: str) -> SmugglingReport:
    if not text:
        return SmugglingReport()
    tags = TAG_RE.findall(text)
    decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)
    return SmugglingReport(
        invisible=len(INVISIBLE_RE.findall(text)),
        tag_chars=len(tags),
        variation_selectors=len(VARIATION_RE.findall(text)),
        ansi_sequences=len(ANSI_RE.findall(text)),
        decoded_hidden_text=decoded,
    )


def strip_invisible(text: str) -> str:
    """Remove characters that are invisible to the human reviewer but readable by the model."""
    if not text:
        return text
    cleaned = ANSI_RE.sub("", text)
    cleaned = TAG_RE.sub("", cleaned)
    cleaned = INVISIBLE_RE.sub("", cleaned)
    # Long runs of variation selectors are a known data-smuggling channel; single ones are emoji styling.
    cleaned = re.sub("[\ufe00-\ufe0f\U000E0100-\U000E01EF]{2,}", "", cleaned)
    return cleaned


def scan_secrets(text: str) -> list[DlpMatch]:
    if not text:
        return []
    matches: list[DlpMatch] = []
    taken: list[tuple[int, int]] = []
    for kind, pattern, group, severity in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span(group)
            if start < 0 or any(start < e and s < end for s, e in taken):
                continue
            value = m.group(group)
            if kind == "credential_assignment" and _looks_like_placeholder(value):
                continue
            taken.append((start, end))
            matches.append(DlpMatch(kind, value, start, end, severity))
    return sorted(matches, key=lambda x: x.start)


def _looks_like_placeholder(value: str) -> bool:
    v = value.strip("<>{}[]()*").lower()
    return v in {"", "none", "null", "true", "false", "redacted", "xxxxxx", "changeme", "password"} or set(v) <= {"*", "x", "."}


def redact_text(text: str) -> tuple[str, list[DlpMatch]]:
    matches = scan_secrets(text)
    if not matches:
        return text, []
    out: list[str] = []
    cursor = 0
    for m in matches:
        out.append(text[cursor:m.start])
        out.append(f"[REDACTED:{m.kind}]")
        cursor = m.end
    out.append(text[cursor:])
    return "".join(out), matches


def redact_structure(value: Any, depth: int = 0) -> tuple[Any, list[DlpMatch]]:
    """Redact secrets inside any JSON-like structure, preserving types and shape."""
    if depth > 20:
        return value, []
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        found: list[DlpMatch] = []
        for k, v in value.items():
            nv, m = redact_structure(v, depth + 1)
            out[k] = nv
            found.extend(m)
        return out, found
    if isinstance(value, list):
        items = []
        found = []
        for v in value:
            nv, m = redact_structure(v, depth + 1)
            items.append(nv)
            found.extend(m)
        return items, found
    return value, []


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


TOKEN_RE = re.compile(r"[A-Za-z0-9_+/=.@:#$%!^&*-]{8,}")


def fingerprint(token: str, salt: str) -> str:
    return hashlib.sha256((salt + "\x00" + token).encode("utf-8", "ignore")).hexdigest()[:24]
