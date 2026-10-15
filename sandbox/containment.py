"""Run the *real* local MCP server inside a hardened container (per-server opt-in).

The shadow sandbox tests each call on a copy; this goes one step further for servers you do
not fully trust: the live server itself runs in a container that can only see the folders it
was configured with, never your home directory, credentials or the rest of the disk.

    docker run -i --rm --read-only --cap-drop ALL --security-opt no-new-privileges
      --pids-limit 256 --memory 1g [--runtime runsc] [--network none]
      --tmpfs /tmp --tmpfs /home/sandbox (empty home: no ~/.ssh, no cloud credentials)
      -v <each configured folder>:<same path>   (paths in arguments keep working unchanged)
      -v <package>:/opt/mcp/pkg:ro               (installed with install scripts disabled)
      -e KEY (values passed through the docker CLI's environment, not its command line)
      mcp-sentinel/sandbox:1 <entry> <args>

Network is on by default (API-backed servers need it) and can be cut per server for servers
that only work on local files. POSIX hosts only: folders are mounted at the same absolute path,
which a Linux container cannot do for Windows paths.
"""

from __future__ import annotations

import re
import sys
from typing import Any

from sandbox import launch
from sandbox.workspace import discover_roots

ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ContainmentError(RuntimeError):
    pass


def can_contain(config: dict[str, Any]) -> tuple[bool, str]:
    if sys.platform == "win32":
        return False, "container isolation of live servers needs a Linux or macOS host (folders are mounted at the same path)"
    plan = launch.plan_for(config)
    if not plan.supported:
        return False, plan.reason
    roots = discover_roots(config, exclude=plan.own_paths())
    if any(r.home for r in roots):
        return False, "the server is configured with your whole home folder; give it a project folder to contain it"
    return True, ""


def contained_config(server_id: str, slug: str, config: dict[str, Any], manager: Any, *, network: bool = True) -> dict[str, Any]:
    """Translate a stdio launch config into a hardened ``docker run`` launch config."""
    ok, why = can_contain(config)
    if not ok:
        raise ContainmentError(why)
    docker = manager.docker
    available, detail = docker.available()
    if not available:
        raise ContainmentError(detail)
    if not docker.image_ready():
        raise ContainmentError("the sandbox image is not built yet (Sandbox → Build image)")
    plan = launch.plan_for(config)
    entry, pkg_dir = docker.prepare(plan)
    roots = discover_roots(config, exclude=plan.own_paths() + [str(manager.base)])
    settings = manager.settings
    name = re.sub(r"[^a-zA-Z0-9_.-]", "-", f"sentinel-live-{slug or server_id[:8]}")[:60]
    args = ["run", "-i", "--rm", "--name", name, "--label", "mcp-sentinel.live=1",
            "--read-only", "--tmpfs", "/tmp:rw,size=256m", "--tmpfs", "/home/sandbox:rw,size=64m,uid=10001,gid=10001",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "1g",
            "-u", docker._user(), "-e", "HOME=/home/sandbox"]
    if settings.sandbox_runtime:
        args += ["--runtime", settings.sandbox_runtime]
    if not network:
        args += ["--network", "none"]
    if pkg_dir is not None:
        args += ["-v", f"{pkg_dir}:{launch.PKG}:ro"]
    app = docker.app_mount(plan)
    if app:
        args += ["-v", f"{app}:{launch.APP}:ro"]
    for root in roots:  # a file root is mounted on its own, never its (possibly home) folder
        if not docker.mountable(root.real):
            raise ContainmentError(f"Docker cannot see {root.real}: add it under Docker Desktop -> Settings -> Resources -> File sharing")
        args += ["-v", f"{root.real}:{root.real}"]
    cwd = str(config.get("cwd") or "")
    first_dir = next((r.real for r in roots if not r.is_file), "")
    args += ["-w", cwd if cwd and any(cwd == r.real or cwd.startswith(r.real.rstrip("/") + "/") for r in roots) else (first_dir or "/tmp")]
    cli_env: dict[str, str] = {}
    for key, value in (config.get("env") or {}).items():
        if ENV_NAME.match(str(key)):
            args += ["-e", str(key)]  # docker reads the value from its own environment
            cli_env[str(key)] = str(value)
    args += [settings.sandbox_image, *entry, *[str(a) for a in plan.args]]
    return {"command": "docker", "args": args, "env": cli_env, "contained": True, "container": name}
