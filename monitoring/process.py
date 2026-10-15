"""Process / network monitor for MCP servers that Sentinel launches locally (stdio).

Sentinel owns the server's process tree, so it can observe - independently of anything the
server claims - which child processes it spawns, which remote endpoints it connects to and
how much CPU / memory it uses. Observations are compared against a learned per-server
baseline and attributed to individual tool calls (before/after snapshots).
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any

try:  # psutil is a hard dependency in pyproject, but keep Sentinel importable without it
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

BENIGN_CHILD_NAMES = {
    # package runners commonly used to launch MCP servers (npx -> node, uvx -> python)
    "node", "node.exe", "npm", "npm.cmd", "npx", "npx.cmd", "python", "python.exe", "python3", "uv", "uv.exe",
    "uvx", "uvx.exe", "deno", "deno.exe", "bun", "bun.exe", "conhost.exe", "cmd.exe", "sh", "bash", "docker",
    "docker.exe", "java", "java.exe", "dotnet", "dotnet.exe",
}
SUSPICIOUS_CHILD_NAMES = {
    "curl", "curl.exe", "wget", "wget.exe", "nc", "ncat", "netcat", "powershell", "powershell.exe", "pwsh",
    "pwsh.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "osascript",
    "ssh", "scp", "sftp", "telnet", "socat", "base64", "openssl", "nslookup", "dig", "ftp", "tftp",
}


@dataclass
class ProcessSnapshot:
    pid: int
    alive: bool
    children: list[dict[str, Any]] = field(default_factory=list)
    remote_endpoints: list[str] = field(default_factory=list)
    open_files: list[str] = field(default_factory=list)
    cpu_percent: float = 0.0
    rss_mb: float = 0.0
    taken_at: float = field(default_factory=time.time)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "alive": self.alive,
            "children": self.children[:30],
            "remote_endpoints": self.remote_endpoints[:50],
            "open_files": self.open_files[:30],
            "cpu_percent": round(self.cpu_percent, 1),
            "rss_mb": round(self.rss_mb, 1),
            "taken_at": self.taken_at,
            "errors": self.errors[:5],
        }


def _is_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
        return addr.is_loopback or addr.is_unspecified
    except ValueError:
        return False


def _is_launcher(proc) -> bool:
    """``npx`` (``npm exec ...``) and ``uv``/``uvx``: they fetch the package from the registry and keep
    that connection open, but never run the server's code themselves (it runs in a child)."""
    name = proc.name().lower()
    return name.startswith(("npm exec", "npx")) or name in {"uv", "uvx", "uv.exe", "uvx.exe"}


def _connections(proc) -> list[Any]:
    getter = getattr(proc, "net_connections", None) or getattr(proc, "connections")
    return getter(kind="inet")


def snapshot(pid: int | None, *, include_files: bool = False) -> ProcessSnapshot | None:
    if psutil is None or not pid:
        return None
    try:
        root = psutil.Process(pid)
    except psutil.Error:
        return ProcessSnapshot(pid=pid, alive=False)
    snap = ProcessSnapshot(pid=pid, alive=root.is_running())
    try:
        tree = [root, *root.children(recursive=True)]
    except psutil.Error as exc:
        snap.errors.append(f"children: {type(exc).__name__}")
        tree = [root]
    endpoints: set[str] = set()
    files: set[str] = set()
    for proc in tree:
        try:
            with proc.oneshot():
                if proc.pid != pid:
                    try:
                        cmd = " ".join(proc.cmdline())[:200]
                    except psutil.Error:
                        cmd = ""
                    snap.children.append({"pid": proc.pid, "name": proc.name(), "cmdline": cmd})
                snap.cpu_percent += proc.cpu_percent(interval=None)
                snap.rss_mb += proc.memory_info().rss / (1024 * 1024)
        except psutil.Error as exc:
            snap.errors.append(f"{proc.pid}: {type(exc).__name__}")
            continue
        try:
            if proc.pid == pid and _is_launcher(proc):
                continue  # registry traffic of the package launcher, not the server
            for conn in _connections(proc):
                if conn.raddr and getattr(conn.raddr, "ip", None):
                    endpoints.add(f"{conn.raddr.ip}:{conn.raddr.port}")
        except (psutil.Error, OSError) as exc:  # macOS may deny connection listing for some processes
            snap.errors.append(f"net {proc.pid}: {type(exc).__name__}")
        if include_files:
            try:
                for f in proc.open_files():
                    files.add(f.path)
            except (psutil.Error, OSError):
                pass
    snap.remote_endpoints = sorted(endpoints)
    snap.open_files = sorted(files)
    return snap


def remote_hosts(endpoints: list[str], *, include_loopback: bool = False) -> set[str]:
    hosts = set()
    for ep in endpoints:
        ip = ep.rsplit(":", 1)[0].strip("[]")
        if include_loopback or not _is_loopback(ip):
            hosts.add(ip)
    return hosts


def diff(before: ProcessSnapshot | None, after: ProcessSnapshot | None) -> dict[str, Any]:
    """Behaviour that appeared between two snapshots (attributed to the call in between)."""
    if before is None or after is None:
        return {"available": False}
    before_children = {c["pid"] for c in before.children}
    new_children = [c for c in after.children if c["pid"] not in before_children]
    new_hosts = sorted(remote_hosts(after.remote_endpoints) - remote_hosts(before.remote_endpoints))
    return {
        "available": True,
        "new_children": new_children,
        "new_child_names": sorted({c["name"] for c in new_children}),
        "new_remote_hosts": new_hosts,
        "cpu_percent": after.cpu_percent,
        "rss_mb": after.rss_mb,
        "alive": after.alive,
    }


def classify_children(names: list[str]) -> tuple[list[str], list[str]]:
    """Split child process names into (suspicious, unusual)."""
    suspicious, unusual = [], []
    for name in names:
        lowered = name.lower()
        if lowered in SUSPICIOUS_CHILD_NAMES:
            suspicious.append(name)
        elif lowered not in BENIGN_CHILD_NAMES:
            unusual.append(name)
    return suspicious, unusual
