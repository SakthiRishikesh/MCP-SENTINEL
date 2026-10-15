"""MCP client configuration files: where they live, how to read them, and the Sentinel entry.

Supported formats
* Claude Desktop  - ``claude_desktop_config.json``: ``{"mcpServers": {name: {command, args, env} | {url}}}``
* Claude Code     - ``~/.claude.json`` (user scope ``mcpServers`` and per-project ``projects[path].mcpServers``)
                    and a project's ``.mcp.json``; entries carry ``type`` (stdio / http / sse) and may use
                    ``${VAR}`` / ``${VAR:-default}`` environment references
* Cursor          - ``~/.cursor/mcp.json`` (same shape as Claude Desktop)
* VS Code         - ``.vscode/mcp.json``: ``{"servers": {name: {type, command, args, env, url, headers}}}``
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping

SELF_MARKERS = ("sentinel.bridge", "mcp-sentinel-bridge", "sentinel_mcp_adapter")
SENTINEL_ENTRY_NAME = "mcp-sentinel"
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


# -- locations ------------------------------------------------------------------------------------
def claude_desktop_config_candidates() -> list[Path]:
    home = Path.home()
    paths: list[Path] = []
    if sys.platform == "darwin":
        paths.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
        local = os.environ.get("LOCALAPPDATA")
        if local:  # Microsoft Store (MSIX) installs virtualise %APPDATA%
            paths += [Path(p) for p in glob.glob(os.path.join(local, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"))]
    else:
        paths.append(home / ".config" / "Claude" / "claude_desktop_config.json")
    return paths


def find_claude_desktop_config(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    for p in claude_desktop_config_candidates():
        if p.exists():
            return p
    return claude_desktop_config_candidates()[0]


def claude_code_user_config() -> Path:
    return Path.home() / ".claude.json"


# -- reading --------------------------------------------------------------------------------------
def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    return json.loads(text) if text else {}


def is_sentinel_entry(name: str, spec: Mapping[str, Any]) -> bool:
    blob = json.dumps(spec)
    return name.lower() in {SENTINEL_ENTRY_NAME, "sentinel"} or any(m in blob for m in SELF_MARKERS)


def extract_servers(config: Mapping[str, Any], *, project: str | None = None) -> dict[str, dict[str, Any]]:
    """Server entries from any supported config shape (Sentinel's own entry excluded)."""
    found: dict[str, dict[str, Any]] = {}
    for key in ("mcpServers", "servers"):
        block = config.get(key)
        if isinstance(block, dict):
            found.update({str(k): dict(v) for k, v in block.items() if isinstance(v, dict)})
    projects = config.get("projects")
    if project and isinstance(projects, dict):  # Claude Code "local" scope
        entry = projects.get(project) or projects.get(str(Path(project).resolve()))
        if isinstance(entry, dict) and isinstance(entry.get("mcpServers"), dict):
            found.update({str(k): dict(v) for k, v in entry["mcpServers"].items() if isinstance(v, dict)})
    return {k: v for k, v in found.items() if not is_sentinel_entry(k, v)}


def expand_env(value: Any, env: Mapping[str, str] | None = None) -> Any:
    """Expand ``${VAR}`` and ``${VAR:-default}`` like Claude Code does for ``.mcp.json``."""
    env = os.environ if env is None else env
    if isinstance(value, str):
        return _ENV_REF.sub(lambda m: env.get(m.group(1), m.group(2) if m.group(2) is not None else m.group(0)), value)
    if isinstance(value, list):
        return [expand_env(v, env) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v, env) for k, v in value.items()}
    return value


def unresolved_refs(spec: Mapping[str, Any]) -> list[str]:
    """``${VAR}`` references left after expansion (and VS Code ``${input:…}`` prompts)."""
    blob = json.dumps(spec)
    names = {m.group(1) for m in _ENV_REF.finditer(blob)}
    inputs = {f"input:{i}" for i in re.findall(r"\$\{input:([^}]+)\}", blob)}
    return sorted(names) + sorted(inputs)


def to_registration(name: str, spec: Mapping[str, Any]) -> dict[str, Any] | None:
    """Translate one client entry into the body of ``POST /v1/servers``."""
    kind = str(spec.get("type") or spec.get("transport") or "").lower()
    if spec.get("command"):
        return {
            "server_name": name, "transport": "stdio", "command": str(spec["command"]),
            "args": [str(a) for a in spec.get("args") or []],
            "env": {str(k): str(v) for k, v in (spec.get("env") or {}).items()},
            "cwd": str(spec.get("cwd") or ""),
        }
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    if url:
        return {
            "server_name": name, "transport": "sse" if kind == "sse" else "http", "endpoint": str(url),
            "headers": {str(k): str(v) for k, v in (spec.get("headers") or {}).items()},
        }
    return None


def claude_desktop_status(explicit: str | None = None) -> dict[str, Any]:
    """Is Sentinel installed in Claude Desktop, and does anything there bypass it?

    Bypasses are other MCP servers in ``claude_desktop_config.json`` and enabled Desktop Extensions
    (``Claude Extensions Settings/<id>.json``): Claude reaches those directly, without Sentinel.
    """
    path = find_claude_desktop_config(explicit)
    status: dict[str, Any] = {"config_path": str(path), "exists": path.exists(), "installed": False,
                              "unprotected_servers": [], "extensions": [], "error": ""}
    try:
        config = load_json(path)
    except (OSError, ValueError) as exc:
        status["error"] = f"cannot read {path.name}: {exc}"
        return status
    servers = config.get("mcpServers") if isinstance(config.get("mcpServers"), dict) else {}
    status["installed"] = any(isinstance(spec, dict) and is_sentinel_entry(name, spec) for name, spec in servers.items())
    status["unprotected_servers"] = sorted(n for n, spec in extract_servers(config).items() if not spec.get("disabled"))
    settings_dir = path.parent / "Claude Extensions Settings"
    for file in sorted(settings_dir.glob("*.json")) if settings_dir.is_dir() else []:
        try:
            enabled = bool(json.loads(file.read_text(encoding="utf-8")).get("isEnabled"))
        except (OSError, ValueError):
            continue
        name = file.stem
        try:
            manifest = json.loads((path.parent / "Claude Extensions" / file.stem / "manifest.json").read_text(encoding="utf-8"))
            name = str(manifest.get("display_name") or manifest.get("name") or name)
        except (OSError, ValueError):
            pass
        status["extensions"].append({"id": file.stem, "name": name, "enabled": enabled})
    return status


# -- the Sentinel entry ---------------------------------------------------------------------------
def sentinel_bridge_entry(api_url: str, *, subject: str = "local-user", role: str = "SECURITY_ADMIN",
                          token: str | None = None, python: str | None = None) -> dict[str, Any]:
    """stdio entry that launches the Sentinel bridge (works for Claude Desktop and Claude Code)."""
    env = {"SENTINEL_API_URL": api_url}
    if token:
        env["SENTINEL_TOKEN"] = token
    else:
        env.update({"SENTINEL_SUBJECT": subject, "SENTINEL_ROLE": role})
    return {"command": python or sys.executable, "args": ["-m", "sentinel.bridge"], "env": env}
