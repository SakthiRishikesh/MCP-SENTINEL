"""Input and output validation.

Input validation distinguishes *hard* findings (always BLOCK: SSRF to metadata services,
path traversal, credential-file access, dangerous URL schemes, shell-injection chains in
non-shell parameters, destructive / exfiltrating shell commands) from *soft* findings that
feed the risk engine as evidence (schema violations, private-network destinations, hidden
characters). The previous ``[;&|`$]`` check hard-blocked any argument containing a dollar
sign, ampersand or semicolon - i.e. ordinary SQL, prices or source code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from sentinel.dlp import detect_smuggling, scan_secrets
from sentinel.netutil import DANGEROUS_SCHEMES, Destination, HostClass, extract_destinations, walk_strings
from sentinel.types import Capability

SSRF_HOSTS = {"169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0", "::1"}

PATH_KEYS = {"path", "file", "filename", "filepath", "file_path", "dir", "directory", "folder", "source", "target",
             "destination_path", "src", "dst", "paths", "root", "cwd", "location"}
# Free-text payloads are data, not commands: shell metacharacters there are expected.
CONTENT_KEYS = {"content", "contents", "text", "body", "message", "code", "data", "payload", "html", "markdown",
                "description", "comment", "note", "notes", "patch", "diff", "edits", "newtext", "oldtext", "new_string",
                "old_string", "query", "sql", "prompt", "thought", "summary", "title", "input", "value", "values"}
TRAVERSAL_RE = re.compile(r"(^|[\\/])\.\.([\\/]|$)|%2e%2e(%2f|%5c|/|\\)|\.\.%2f|\.\.%5c", re.I)
SENSITIVE_PATH_RE = re.compile(
    r"([\\/]\.ssh([\\/]|$)|\bid_(rsa|dsa|ecdsa|ed25519)\b|[\\/]\.aws[\\/](credentials|config)|[\\/]\.env(\.|$)|^\.env(\.|$)|"
    r"/etc/(shadow|sudoers|gshadow)|/etc/passwd|/proc/(self|\d+)/(environ|mem|maps|cmdline)|claude_desktop_config\.json|"
    r"[\\/]\.cursor[\\/]mcp\.json|[\\/]\.kube[\\/]config|[\\/]\.docker[\\/]config\.json|\.git-credentials|[\\/]\.npmrc|"
    r"[\\/]\.pypirc|[\\/]\.netrc|[\\/]\.gnupg([\\/]|$)|Login Data|wallet\.dat|\.keychain(-db)?\b|[\\/]\.config[\\/]gcloud)",
    re.I,
)
SHELL_CHAIN_RE = re.compile(
    r"([;&|]{1,2}|\n)\s*(sudo\s+)?(rm|curl|wget|nc|ncat|netcat|bash|sh|zsh|powershell|pwsh|python[23]?|perl|ruby|php|"
    r"cmd(\.exe)?|certutil|chmod|chown|mkfifo|base64|scp|ssh|telnet|socat|dd|mkfs|shutdown|reboot|kill)\b"
    r"|\$\([^)]{2,}\)|`[^`]{2,}`|\|\s*(sh|bash|zsh|python|node|iex)\b|>\s*/dev/tcp/",
    re.I,
)
DANGEROUS_COMMAND_RE = re.compile(
    r"rm\s+-[a-z]*r[a-z]*f?\s+(/|~|\*|\$HOME)(\s|$)|rm\s+-[a-z]*f[a-z]*r\s+(/|~|\*)|mkfs(\.\w+)?\s|dd\s+if=.*of=/dev/|"
    r":\(\)\s*\{\s*:\|:&\s*\};:|/dev/tcp/|\bnc\b.*\s-e\s|\bncat\b.*--exec|(curl|wget|iwr|invoke-webrequest)[^|;]*\|\s*(sh|bash|iex|python)|"
    r"chmod\s+(-R\s+)?777\s+/|setenforce\s+0|Set-MpPreference\s+-Disable|reg\s+add\s+.*\\Run\b|"
    r"(cat|type|Get-Content)\s+[^|;]*(\.ssh[\\/]id_|\.aws[\\/]credentials|\.env\b|/etc/shadow)|"
    r"base64[^|;]*\|\s*(curl|wget|nc)|history\s+-c|shred\s|format\s+[a-z]:",
    re.I,
)


@dataclass
class ValidationResult:
    ok: bool
    issues: list[str]
    risk_delta: int
    hard_issues: list[str] = field(default_factory=list)
    soft: list[tuple[str, float, str]] = field(default_factory=list)
    destinations: list[Destination] = field(default_factory=list)


def _looks_like_path(key: str, value: str) -> bool:
    if key.lower() in PATH_KEYS:
        return True
    v = value.strip()
    return bool(re.match(r"^(~|\.{1,2})?[\\/]", v) or re.match(r"^[A-Za-z]:[\\/]", v) or ("/" in v and " " not in v and len(v) < 512))


class InputValidator:
    def __init__(self, internal_domains: Iterable[str] = ()) -> None:
        self.internal_domains = list(internal_domains)

    def validate(
        self,
        schema: dict[str, Any] | None,
        arguments: dict[str, Any],
        *,
        capabilities: Iterable[Capability] = (),
    ) -> ValidationResult:
        caps = set(capabilities)
        hard: list[str] = []
        soft: list[tuple[str, float, str]] = []
        if schema:
            try:
                validator = Draft202012Validator(schema)
                errors = [f"schema: {e.message}" for e in validator.iter_errors(arguments)]
            except SchemaError:
                errors = []
            if errors:
                soft.append(("schema_violation", min(0.35, 0.12 * len(errors)), "; ".join(errors[:3])))
        strings = walk_strings(arguments)
        exec_tool = Capability.CODE_EXECUTION in caps
        secret_tool = Capability.SECRET_ACCESS in caps
        total = 0
        for key, value in strings:
            total += len(value)
            free_text = key.lower() in CONTENT_KEYS
            path_like = _looks_like_path(key, value) and not free_text
            if path_like and TRAVERSAL_RE.search(value):
                hard.append(f"path traversal in '{key}'")
            if (path_like or key.lower() in {"url", "uri"}) and SENSITIVE_PATH_RE.search(value) and not secret_tool:
                hard.append(f"access to a credential / client-config path in '{key}'")
            if exec_tool:
                if DANGEROUS_COMMAND_RE.search(value):
                    hard.append(f"destructive or exfiltrating shell command in '{key}'")
            elif not free_text and SHELL_CHAIN_RE.search(value):
                hard.append(f"possible command injection in '{key}'")
            smuggling = detect_smuggling(value)
            if smuggling.suspicious:
                soft.append(("hidden_characters", 0.3, f"hidden/invisible characters in '{key}'"))
        if total > 1_000_000:
            soft.append(("oversized_arguments", 0.2, f"arguments are unusually large ({total} characters)"))
        if exec_tool and strings and not hard:
            soft.append(("shell_command", 0.1, "arbitrary command execution requested"))
        destinations = extract_destinations(arguments, self.internal_domains)
        for d in destinations:
            if d.host_class == HostClass.METADATA:
                hard.append(f"SSRF-blocked host {d.host} (cloud metadata service)")
            elif d.scheme in DANGEROUS_SCHEMES:
                hard.append(f"disallowed URL scheme {d.scheme}")
            elif d.host_class in {HostClass.LOOPBACK, HostClass.PRIVATE, HostClass.LINK_LOCAL, HostClass.RESERVED}:
                soft.append(("internal_destination", 0.35, f"destination {d.host} is on an internal/loopback network (SSRF risk)"))
        secrets_in_args = scan_secrets(" ".join(v for _, v in strings)[:200_000])
        if secrets_in_args and not secret_tool:
            soft.append(("secret_in_arguments", 0.3, f"arguments contain secret-like values ({', '.join(sorted({m.kind for m in secrets_in_args}))})"))
        issues = list(dict.fromkeys(hard)) + [s[2] for s in soft]
        risk = 0 if not issues else min(10 + 8 * len(issues), 40)
        return ValidationResult(
            ok=not hard and not soft,
            issues=issues,
            risk_delta=risk,
            hard_issues=list(dict.fromkeys(hard)),
            soft=soft,
            destinations=destinations,
        )

    def _url_issues(self, url: str) -> list[str]:  # kept for API compatibility
        result = self.validate({}, {"url": url})
        return result.hard_issues
