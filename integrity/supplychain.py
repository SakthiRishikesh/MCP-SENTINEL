"""Server-level supply-chain analysis of how an MCP server is launched or reached.

An unpinned ``npx -y some-server`` is a rug pull waiting to happen: the code that runs can
change on the next launch without any tool definition changing. This module flags that, plus
typosquatted package names, secrets on the command line, opaque shell wrappers, plaintext
remote transports and dangerous container flags.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from sentinel.dlp import scan_secrets
from sentinel.netutil import HostClass, classify_host

KNOWN_PACKAGES = [
    "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-maps", "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer", "@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/server-slack", "@modelcontextprotocol/server-redis",
    "@modelcontextprotocol/server-gdrive", "@modelcontextprotocol/server-aws-kb-retrieval", "@modelcontextprotocol/server-everart",
    "mcp-server-fetch", "mcp-server-git", "mcp-server-time", "mcp-server-sqlite", "mcp-server-sentry",
    "@playwright/mcp", "@upstash/context7-mcp", "@notionhq/notion-mcp-server", "@stripe/mcp", "@sentry/mcp-server",
    "@cloudflare/mcp-server-cloudflare", "@executeautomation/playwright-mcp-server", "@wonderwhy-er/desktop-commander",
    "firecrawl-mcp", "@supabase/mcp-server-supabase", "@browserbasehq/mcp", "exa-mcp-server", "@heroku/mcp-server",
    "mcp-remote", "@azure/mcp", "tavily-mcp", "@modelcontextprotocol/inspector", "awslabs.aws-documentation-mcp-server",
]
RUNNERS = {"npx", "npx.cmd", "bunx", "pnpx", "uvx", "uvx.exe", "pipx", "deno"}
SHELLS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}


def _finding(severity: str, category: str, title: str, evidence: str = "") -> dict[str, Any]:
    return {"severity": severity, "category": category, "title": title, "evidence": evidence[:240]}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _split_spec(spec: str) -> tuple[str, str]:
    """'@scope/pkg@1.2.3' -> ('@scope/pkg', '1.2.3'); 'pkg==1.0' -> ('pkg', '1.0')."""
    if "==" in spec:
        name, _, ver = spec.partition("==")
        return name, ver
    if spec.startswith("@"):
        rest = spec[1:]
        if "@" in rest:
            name, _, ver = rest.partition("@")
            return "@" + name, ver
        return spec, ""
    if "@" in spec:
        name, _, ver = spec.partition("@")
        return name, ver
    return spec, ""


def _package_spec(command: str, args: list[str]) -> str | None:
    base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base not in RUNNERS:
        return None
    it = iter(args)
    for arg in it:
        if arg in {"--package", "-p", "--from"}:
            return next(it, None)
        if arg.startswith(("--package=", "--from=")):
            return arg.split("=", 1)[1]
        if arg in {"--with", "--python", "--registry", "--cache"}:
            next(it, None)  # flag value, not the package
            continue
        if arg == "run" and base == "pipx":
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def analyze_stdio(command: str, args: list[str], env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    joined = " ".join([command, *args])
    spec = _package_spec(command, args)
    if spec:
        name, version = _split_spec(spec)
        if not version or version in {"latest", "next", "*"}:
            findings.append(_finding(
                "MEDIUM", "unpinned_package",
                "package is not pinned to a version — the server code can change on any launch (supply-chain rug pull)",
                f"{base} {spec}  →  pin it, e.g. {name}@<version>",
            ))
        else:
            findings.append(_finding("INFO", "pinned_package", "package version pinned", f"{name}@{version}"))
        lowered = name.lower()
        if lowered not in {p.lower() for p in KNOWN_PACKAGES}:
            for known in KNOWN_PACKAGES:
                distance = levenshtein(lowered, known.lower())
                if 0 < distance <= 2 and len(known) > 6:
                    findings.append(_finding("HIGH", "typosquat", "package name is one or two edits away from a well-known MCP server", f"{name} ≈ {known}"))
                    break
    if base in SHELLS and any(a.lower() in {"-c", "/c", "-command", "/k", "-encodedcommand", "-e"} for a in args):
        sev = "CRITICAL" if re.search(r"(curl|wget|iwr|invoke-webrequest)[^|]*\|\s*(sh|bash|iex|python|node)", joined, re.I) else "MEDIUM"
        title = "remote script piped into a shell" if sev == "CRITICAL" else "opaque shell wrapper hides what actually runs"
        findings.append(_finding(sev, "shell_wrapper", title, joined[:200]))
    if base in {"docker", "docker.exe", "podman"}:
        if "--privileged" in args:
            findings.append(_finding("HIGH", "container_privileged", "container runs --privileged"))
        if any("docker.sock" in a for a in args):
            findings.append(_finding("CRITICAL", "container_docker_socket", "Docker socket mounted into the server container"))
        if any(re.match(r"^(-v|--volume)?=?/:/", a) or a.startswith("/:/") for a in args):
            findings.append(_finding("HIGH", "container_host_root", "host root filesystem mounted"))
        if "--network=host" in args or ("--network" in args and "host" in args):
            findings.append(_finding("MEDIUM", "container_host_network", "container shares the host network"))
        image = next((a for a in reversed(args) if not a.startswith("-") and ("/" in a or ":" in a)), "")
        if image and "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
            findings.append(_finding("MEDIUM", "unpinned_image", "container image is not pinned to a tag/digest", image))
    for m in scan_secrets(" ".join(args)):
        findings.append(_finding("MEDIUM", "secret_in_args", "secret passed on the command line (visible in the process list)", m.kind))
    for arg in args:
        if re.match(r"(?i)^--?(token|api[-_]?key|password|secret)(=|$)", arg):
            findings.append(_finding("MEDIUM", "secret_in_args", "credential flag on the command line — prefer an environment variable", arg.split("=")[0]))
            break
    secret_env = [k for k in (env or {}) if re.search(r"(?i)token|secret|password|key", k)]
    if secret_env:
        findings.append(_finding("INFO", "secret_env", "credentials provided via environment (stored encrypted by Sentinel)", ", ".join(secret_env)))
    return findings


def analyze_http(url: str, headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return [_finding("HIGH", "invalid_url", "endpoint URL cannot be parsed", url)]
    host = (parts.hostname or "").lower()
    host_class = classify_host(host)
    if parts.scheme == "http" and host_class not in {HostClass.LOOPBACK, HostClass.PRIVATE, HostClass.INTERNAL_NAME}:
        findings.append(_finding("HIGH", "plaintext_transport", "remote MCP server over plain HTTP — traffic and tokens can be read or tampered with", url))
    if host_class == HostClass.METADATA:
        findings.append(_finding("CRITICAL", "metadata_endpoint", "endpoint points at a cloud metadata service", host))
    if parts.username or parts.password:
        findings.append(_finding("MEDIUM", "credentials_in_url", "credentials embedded in the endpoint URL"))
    if any(k.lower() == "authorization" for k in (headers or {})):
        findings.append(_finding("INFO", "auth_header", "authorization header configured (stored encrypted by Sentinel)"))
    return findings
