"""MCP-Sentinel command line.

    mcp-sentinel serve                       run the control plane (API + dashboard if built)
    mcp-sentinel stop                        stop a running control plane (e.g. one Claude's bridge auto-started)
    mcp-sentinel doctor                      check Python, Docker, the sandbox, npx/uvx and the Claude Desktop setup
    mcp-sentinel bridge                      run the stdio MCP bridge (what Claude launches)
    mcp-sentinel install-claude              add Sentinel to Claude Desktop (claude_desktop_config.json, with a backup)
    mcp-sentinel install-claude-code         add Sentinel to Claude Code (`claude mcp add-json`)
    mcp-sentinel import-claude [--from code] move existing Claude Desktop / Claude Code servers behind Sentinel
    mcp-sentinel claude-config               print the client configuration without changing anything
    mcp-sentinel token / init                demo token / initialise the database
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from identity.tokens import mint_demo_token
from sentinel import clientconfig
from sentinel.config import get_settings


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.sentinel-backup-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(path, backup)
    return backup


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _api_admin_token(api_url: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    import httpx

    resp = httpx.post(f"{api_url}/v1/demo/token", params={"role": "SECURITY_ADMIN", "subject": "local-admin"}, timeout=10, trust_env=False)
    if resp.status_code != 200:
        raise SystemExit(f"could not mint a demo admin token ({resp.status_code}); pass --token")
    return resp.json()["access_token"]


def _local_url(host: str, port: int) -> str:
    host = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


def _serve(settings: Any, host: str | None, port: int | None) -> None:
    import uvicorn

    from sentinel.bridge import DATA_DIR, api_healthy

    host, port = host or settings.gateway_host, port or settings.gateway_port
    url = _local_url(host, port)
    if api_healthy(url):
        print(f"MCP-Sentinel is already running at {url} (stop it with: mcp-sentinel stop)")
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    pidfile = DATA_DIR / "sentinel.pid"
    pidfile.write_text(str(os.getpid()), encoding="utf-8")

    def _cleanup() -> None:
        try:
            if pidfile.read_text(encoding="utf-8").strip() == str(os.getpid()):
                pidfile.unlink()
        except OSError:
            pass

    atexit.register(_cleanup)
    print(f"MCP-Sentinel {url}  (dashboard: {settings.dashboard_base_url})", flush=True)
    uvicorn.run("sentinel.app:app", host=host, port=port)


def _stop() -> int:
    import psutil

    from sentinel.bridge import DATA_DIR

    pidfile = DATA_DIR / "sentinel.pid"
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
        proc = psutil.Process(pid)
        if "sentinel" not in " ".join(proc.cmdline()):
            raise psutil.NoSuchProcess(pid)
    except (OSError, ValueError, psutil.Error):
        print("MCP-Sentinel is not running (no live process in ~/.mcp-sentinel/sentinel.pid)")
        pidfile.unlink(missing_ok=True)
        return 1
    try:
        proc.terminate()
    except psutil.Error:
        pass
    try:
        proc.wait(timeout=15)
    except psutil.TimeoutExpired:
        proc.kill()
    pidfile.unlink(missing_ok=True)
    print(f"stopped MCP-Sentinel (pid {pid})")
    return 0


def _doctor(settings: Any) -> int:
    """Everything the live demo depends on, checked in one go."""
    import httpx

    from sandbox.shadow import get_sandbox
    from sentinel.bridge import api_healthy

    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        # Doctor may print non-ASCII file paths and status markers. Python can otherwise inherit
        # a legacy console code page that cannot encode those characters.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    marks = {"ok": "\033[32m✓\033[0m", "warn": "\033[33m!\033[0m", "bad": "\033[31m✕\033[0m"}
    if not sys.stdout.isatty():
        marks = {"ok": "OK  ", "warn": "WARN", "bad": "FAIL"}
    failures = 0

    def line(tone: str, text: str, hint: str = "") -> None:
        nonlocal failures
        failures += tone == "bad"
        # Keep CLI output printable in Windows terminals using legacy code pages (for example cp1252).
        print(f" {marks[tone]} {text}" + (f"\n     -> {hint}" if hint else ""))

    def version(cmd: list[str]) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
        except (OSError, subprocess.TimeoutExpired, IndexError):
            return ""

    print("MCP-Sentinel doctor\n")
    py = sys.version_info
    line("ok" if py >= (3, 11) else "bad", f"Python {py.major}.{py.minor}.{py.micro} ({sys.executable})",
         "" if py >= (3, 11) else "Python 3.11+ is required")
    url = settings.api_base_url
    up = api_healthy(url)
    line("ok" if up else "warn", f"control plane {'running' if up else 'not running'} at {url}",
         "" if up else "run `mcp-sentinel serve` (Claude Desktop's bridge also starts it automatically)")
    dist = Path(settings.static_dashboard_dir) / "index.html"
    line("ok" if dist.exists() else "warn", "dashboard built" if dist.exists() else "dashboard not built",
         "" if dist.exists() else "cd dashboard && npm install && npm run build")
    node = version(["node", "--version"]) if shutil.which("node") else ""
    line("ok" if node and shutil.which("npx") else "bad", f"Node.js {node or 'not found'} / npx {'found' if shutil.which('npx') else 'missing'}",
         "" if node else "install Node.js 18+ for npx-based MCP servers and the dashboard build")
    uv = version(["uvx", "--version"]) if shutil.which("uvx") else ""
    line("ok" if uv else "warn", uv or "uvx not found", "" if uv else "install uv (https://docs.astral.sh/uv/) for Python MCP servers")
    sandbox = get_sandbox(settings).status()
    docker = sandbox["docker"]
    if sandbox["active_backend"] == "docker":
        line("ok", f"sandbox: Docker containment ({docker['detail']}, image {docker['image']} ready)")
    elif docker["available"] and not docker["image_ready"]:
        line("warn", f"sandbox: {docker['detail']}, but the image {docker['image']} is not built",
             "Dashboard -> Sandbox -> Build image (or: docker build -t mcp-sentinel/sandbox:1 -f docker/sandbox-runtime.Dockerfile docker/)")
    else:
        line("warn", f"sandbox: {sandbox['active_backend']} backend - {docker['detail']}", "start Docker Desktop for full containment")
    desk = clientconfig.claude_desktop_status()
    if desk["error"]:
        line("bad", f"Claude Desktop config: {desk['error']}")
    elif not desk["exists"]:
        line("warn", f"no Claude Desktop config at {desk['config_path']}", "install Claude Desktop, or run `mcp-sentinel install-claude`")
    else:
        line("ok" if desk["installed"] else "bad", f"Claude Desktop config {desk['config_path']}: "
             + ("MCP-Sentinel installed" if desk["installed"] else "MCP-Sentinel missing"), "" if desk["installed"] else "run `mcp-sentinel install-claude`")
    for name in desk["unprotected_servers"]:
        line("warn", f"Claude Desktop server '{name}' bypasses Sentinel", "move it behind Sentinel: `mcp-sentinel import-claude --replace`")
    for ext in desk["extensions"]:
        if ext["enabled"]:
            line("warn", f"Claude Desktop extension '{ext['name']}' is enabled and bypasses Sentinel",
                 "turn it off in Claude Desktop -> Settings -> Extensions, and connect that server through Sentinel instead")
    if up:
        try:
            clients = httpx.get(f"{url}/v1/integrations/claude-desktop", timeout=10, trust_env=False).json().get("clients") or []
        except (httpx.HTTPError, ValueError):
            clients = []
        live = [c for c in clients if c.get("connected")]
        line("ok" if live else "warn", "connected MCP clients: " + (", ".join(sorted({c['name'] for c in live})) or "none right now"),
             "" if live else "start or restart Claude Desktop; it launches the bridge on startup")
    print("\n" + ("All set." if not failures else f"{failures} problem(s) need attention."))
    return 1 if failures else 0


def _claude_cli() -> str | None:
    return shutil.which("claude")


def _install_claude_code(entry: dict[str, Any], scope: str, cwd: str | None = None) -> bool:
    claude = _claude_cli()
    spec = json.dumps({"type": "stdio", **entry})
    if not claude:
        print("The `claude` CLI was not found on PATH. Add MCP-Sentinel to Claude Code with:\n")
        print(f"  claude mcp add-json --scope {scope} {clientconfig.SENTINEL_ENTRY_NAME} '{spec}'\n")
        return False
    subprocess.run([claude, "mcp", "remove", clientconfig.SENTINEL_ENTRY_NAME, "--scope", scope],
                   cwd=cwd, capture_output=True, text=True)
    done = subprocess.run([claude, "mcp", "add-json", "--scope", scope, clientconfig.SENTINEL_ENTRY_NAME, spec],
                          cwd=cwd, capture_output=True, text=True)
    if done.returncode != 0:
        print(f"`claude mcp add-json` failed: {(done.stderr or done.stdout).strip()}")
        return False
    print(f"added {clientconfig.SENTINEL_ENTRY_NAME} to Claude Code ({scope} scope)")
    return True


def _post_import(api_url: str, token: str | None, entries: dict[str, Any], sandbox: bool) -> list[dict[str, Any]]:
    import httpx

    admin = _api_admin_token(api_url, token)
    resp = httpx.post(
        f"{api_url}/v1/servers/import",
        json={"config": {"mcpServers": entries}, "connect": True, "run_sandbox": sandbox},
        headers={"Authorization": f"Bearer {admin}"},
        timeout=900,
        trust_env=False,
    )
    if resp.status_code != 200:
        raise SystemExit(f"import failed: {resp.status_code} {resp.text[:300]}")
    results = resp.json().get("results", [])
    for r in results:
        status = r.get("error") or r.get("skipped") or f"{r.get('trust_status')} · {r.get('tools', 0)} tools"
        print(f"  {r['name']:28} {status}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp-sentinel", description="MCP-Sentinel CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="initialise the database", aliases=["seed"])
    token = sub.add_parser("token", help="mint a demo JWT")
    token.add_argument("--role", default="ANALYST")
    token.add_argument("--subject", default="user-123")
    token.add_argument("--mfa", action="store_true")
    serve = sub.add_parser("serve", help="run the control plane")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    sub.add_parser("stop", help="stop a running control plane")
    sub.add_parser("doctor", help="check the local setup (Python, Docker sandbox, npx/uvx, Claude Desktop)")
    sub.add_parser("bridge", help="run the stdio MCP bridge (Claude Desktop / Claude Code)")

    for name in ("claude-config", "install-claude", "install-claude-code", "import-claude"):
        p = sub.add_parser(name)
        p.add_argument("--api", default=None, help="Sentinel API URL")
        p.add_argument("--subject", default="local-user")
        p.add_argument("--role", default="SECURITY_ADMIN")
        p.add_argument("--token", default=None, help="user/admin token (OIDC mode)")
        if name in {"install-claude", "import-claude"}:
            p.add_argument("--config", default=None, help="path to the client config file to read/update")
        if name in {"install-claude-code", "import-claude"}:
            p.add_argument("--scope", default="user", choices=["user", "project", "local"], help="Claude Code scope for Sentinel")
            p.add_argument("--project", default=None, help="Claude Code project directory (local/project scope servers)")
        if name == "import-claude":
            p.add_argument("--from", dest="source", default="desktop", choices=["desktop", "code"],
                           help="import from Claude Desktop (default) or Claude Code")
            p.add_argument("--replace", action="store_true", help="after importing, leave only Sentinel in the client config")
            p.add_argument("--sandbox", action="store_true", help="run the honeypot sandbox for each imported stdio server")
    args = parser.parse_args()
    settings = get_settings()

    if args.cmd in {"init", "seed"}:
        from sentinel.seed import seed

        seed()
        print("database initialised")
        return
    if args.cmd == "token":
        value = mint_demo_token(
            settings, subject=args.subject, roles=[args.role],
            acr=settings.mfa_acr if args.mfa else None, amr=["pwd", "otp"] if args.mfa else ["pwd"],
        )
        print(json.dumps({"access_token": value}))
        return
    if args.cmd == "serve":
        _serve(settings, args.host, args.port)
        return
    if args.cmd == "stop":
        raise SystemExit(_stop())
    if args.cmd == "doctor":
        raise SystemExit(_doctor(settings))
    if args.cmd == "bridge":
        from sentinel.bridge import main as bridge_main

        raise SystemExit(bridge_main())

    api_url = (args.api or settings.api_base_url).rstrip("/")
    entry = clientconfig.sentinel_bridge_entry(
        api_url, subject=args.subject, role=args.role, token=args.token if settings.auth_mode == "oidc" else None
    )
    if args.cmd == "claude-config":
        print("Claude Desktop (claude_desktop_config.json):")
        print(json.dumps({"mcpServers": {clientconfig.SENTINEL_ENTRY_NAME: entry}}, indent=2))
        print("\nClaude Code:")
        print(f"  claude mcp add-json --scope user {clientconfig.SENTINEL_ENTRY_NAME} '{json.dumps({'type': 'stdio', **entry})}'")
        return
    if args.cmd == "install-claude-code":
        _install_claude_code(entry, args.scope, cwd=args.project)
        print("Start a new Claude Code session (or run /mcp) to load MCP-Sentinel.")
        return

    if args.cmd == "import-claude" and args.source == "code":
        project = str(Path(args.project or ".").resolve())
        user_cfg = clientconfig.load_json(clientconfig.claude_code_user_config())
        sources: dict[str, tuple[str, dict[str, Any]]] = {}
        for name, spec in clientconfig.extract_servers({"mcpServers": user_cfg.get("mcpServers") or {}}).items():
            sources[name] = ("user", spec)
        for name, spec in clientconfig.extract_servers({"projects": user_cfg.get("projects") or {}}, project=project).items():
            sources[name] = ("local", spec)
        project_file = Path(args.config) if args.config else Path(project) / ".mcp.json"
        for name, spec in clientconfig.extract_servers(clientconfig.load_json(project_file)).items():
            sources[name] = ("project", spec)
        if not sources:
            print("no Claude Code MCP servers found (checked ~/.claude.json and .mcp.json)")
        else:
            results = _post_import(api_url, args.token, {n: s for n, (_, s) in sources.items()}, args.sandbox)
            if args.replace and _claude_cli():
                for r in results:
                    if r.get("server_id") and not r.get("error"):
                        scope = sources[r["name"]][0]
                        subprocess.run([_claude_cli(), "mcp", "remove", r["name"], "--scope", scope], cwd=project, capture_output=True)
                        print(f"  removed {r['name']} from Claude Code ({scope} scope) - it now runs behind Sentinel")
            elif args.replace:
                print("`claude` CLI not found: remove the imported servers from Claude Code manually (claude mcp remove <name>).")
        _install_claude_code(entry, args.scope, cwd=project)
        return

    # Claude Desktop
    path = clientconfig.find_claude_desktop_config(args.config)
    config = clientconfig.load_json(path)
    servers = dict(config.get("mcpServers") or {})
    if args.cmd == "import-claude":
        others = clientconfig.extract_servers(config)
        if not others:
            print(f"no servers to import in {path}")
        else:
            results = _post_import(api_url, args.token, others, args.sandbox)
            if args.replace:
                for r in results:
                    if r.get("server_id") and not r.get("error"):
                        servers.pop(r["name"], None)
    servers[clientconfig.SENTINEL_ENTRY_NAME] = entry
    config["mcpServers"] = servers
    backup = _backup(path)
    _write(path, config)
    print(f"updated {path}" + (f" (backup: {backup.name})" if backup else ""))
    print("Restart Claude Desktop (or toggle the connector) to load MCP-Sentinel.")


if __name__ == "__main__":
    main()
