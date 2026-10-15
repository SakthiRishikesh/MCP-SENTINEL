"""Prompt-injection detection for untrusted text (tool outputs and tool-call arguments).

Only *instruction-like* findings count. Data that merely mentions a credential path, a URL or
an encoded blob (a directory listing that shows ``.ssh``, a page that links elsewhere) is not
an instruction to the model; the DLP and data-flow layers handle that content instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from integrity.scanner import scan_text

# High-precision phrases (severity, pattern)
INJECTION_PATTERNS: list[tuple[str, str]] = [
    ("HIGH", r"ignore (all |any )?(the )?previous instructions"),
    ("HIGH", r"<\|?\s*(system|im_start|im_end)\s*\|?>"),
    ("HIGH", r"disable (mcp-?)?sentinel"),
    ("HIGH", r"do not tell the user"),
    ("MEDIUM", r"override (the )?(security )?polic(y|ies)"),
    ("MEDIUM", r"call (the )?(privileged|admin) tool"),
]
# scanner categories that describe instructions aimed at the model
INSTRUCTION_CATEGORIES = {
    "hidden_instructions", "injection_phrase", "secrecy_directive", "approval_bypass", "data_collection",
    "role_markers", "smuggling", "credential_exfiltration",
}
# in untrusted *data*, a request to "include the contents of X" is suspicious but not proof
CAPPED_CATEGORIES = {"data_collection": "MEDIUM"}
SUSPICIOUS_URL_HINTS = ("pastebin", "ngrok", "requestbin", "webhook.site", "interact.sh", "burpcollaborator", "pipedream")
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_P = {"LOW": 0.05, "MEDIUM": 0.2, "HIGH": 0.5, "CRITICAL": 0.8}


@dataclass
class InjectionFinding:
    detected: bool
    matches: list[str]
    risk_delta: int
    likelihood: float = 0.0
    severity: str = "NONE"
    details: list[dict] = field(default_factory=list)


class InjectionGuard:
    """Language detection is supporting evidence only. Enforcement stays in the control plane."""

    def scan(self, text: str | None, *, field_name: str = "text") -> InjectionFinding:
        if not text:
            return InjectionFinding(False, [], 0)
        matches: list[str] = []
        details: list[dict] = []
        severities: list[str] = []
        for severity, pattern in INJECTION_PATTERNS:
            if re.search(pattern, text, re.I):
                matches.append(pattern)
                severities.append(severity)
        for f in scan_text(text, field_name):
            if f.category not in INSTRUCTION_CATEGORIES or f.severity not in {"MEDIUM", "HIGH", "CRITICAL"}:
                continue
            severity = f.severity
            cap = CAPPED_CATEGORIES.get(f.category)
            if cap and SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(cap):
                severity = cap
            matches.append(f"{f.category}: {f.title}")
            details.append({**f.as_dict(), "severity": severity})
            severities.append(severity)
        for url in re.findall(r"https?://[^\s\"'<>]+", text):
            if any(bad in url.lower() for bad in SUSPICIOUS_URL_HINTS):
                matches.append(f"suspicious url: {url[:120]}")
                severities.append("MEDIUM")
        matches = list(dict.fromkeys(matches))
        if not matches:
            return InjectionFinding(False, [], 0)
        worst = max(severities, key=SEVERITY_ORDER.index)
        remaining = 1.0
        for s in severities:
            remaining *= 1.0 - SEVERITY_P[s]
        likelihood = max(1.0 - remaining, SEVERITY_P[worst])
        return InjectionFinding(
            True,
            matches,
            min(12 * len(matches), 36),
            likelihood=min(0.95, likelihood),
            severity=worst,
            details=details,
        )
