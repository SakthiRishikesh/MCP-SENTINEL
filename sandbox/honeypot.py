"""Honeypot sandbox for local (stdio) MCP servers.

Before a new or changed local server touches real resources, Sentinel can launch it in a
decoy environment and watch what it does:

* synthetic HOME / APPDATA populated with canary credentials (SSH key, AWS credentials,
  ``.env``, Claude Desktop / Cursor MCP configs) whose access times are primed so a read is
  visible, plus canary environment variables
* a recording egress proxy (HTTP_PROXY / HTTPS_PROXY): CONNECT tunnels are only allowed to
  package registries so ``npx`` / ``uvx`` still work; every other destination is logged
  and refused
* process-tree sampling: child processes, remote connections, open files
* MCP handshake + ``tools/list`` + optional exercise of read-only tools with synthetic
  arguments

Evidence: canary values appearing anywhere (stdout, stderr, proxy traffic) is definitive
credential theft; decoy file reads, egress attempts and suspicious child processes are
graded findings. This is evidence for the trust decision, not permanent trust.
"""

from __future__ import annotations

import base64
import os
import secrets
import select
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

from integrity import scanner
from integrity.capabilities import infer
from monitoring import process as procmon
from sentinel.dlp import CANARY_PREFIX
from sentinel.upstream.client import StdioClient, default_child_env

# Package registries only (so npx / uvx can install the server). General-purpose hosts such as
# github.com are deliberately excluded: they double as exfiltration channels (gists, issues).
REGISTRY_ALLOWLIST = (
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org", "nodejs.org", "jsr.io",
)


class EgressRecorder:
    """Tiny forward proxy that records every destination and only tunnels to package registries."""

    def __init__(self, canary: str, env_canary: str = "") -> None:
        self.canary = canary
        self.env_canary = env_canary
        self.attempts: list[dict[str, Any]] = []
        self.canary_seen = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(32)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, name="sentinel-honeypot-proxy", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                head += chunk
            text = head.decode("latin-1", "replace")
            first = text.split("\r\n", 1)[0]
            parts = first.split(" ")
            method = parts[0] if parts else ""
            target = parts[1] if len(parts) > 1 else ""
            host = target.split(":")[0] if method == "CONNECT" else (target.split("/")[2] if "://" in target else target)
            carried = CANARY_PREFIX in text or (self.canary and self.canary in text)
            allowed = method == "CONNECT" and any(host == d or host.endswith("." + d) for d in REGISTRY_ALLOWLIST)
            self.attempts.append({"method": method, "host": host, "allowed": allowed, "carried_canary": carried,
                                  "carried_env_canary": bool(self.env_canary and self.env_canary in text), "at": time.time()})
            if carried:
                self.canary_seen = True
            if not allowed:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            port = int(target.split(":")[1]) if ":" in target else 443
            upstream = _open_tunnel(host, port)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._relay(conn, upstream)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _relay(a: socket.socket, b: socket.socket) -> None:
        a.settimeout(None)
        b.settimeout(None)
        sockets = [a, b]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 30)
                if errored or not readable:
                    break
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            pass
        finally:
            b.close()

    def close(self) -> None:
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


def _open_tunnel(host: str, port: int) -> socket.socket:
    """Direct connection, or a CONNECT tunnel through Sentinel's own upstream proxy when one is set."""
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    if not proxy:
        return socket.create_connection((host, port), timeout=10)
    parsed = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    upstream = socket.create_connection((parsed.hostname or "127.0.0.1", parsed.port or 3128), timeout=10)
    auth = ""
    if parsed.username:
        token = base64.b64encode(f"{unquote(parsed.username)}:{unquote(parsed.password or '')}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {token}\r\n"
    upstream.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
    reply = b""
    while b"\r\n\r\n" not in reply and len(reply) < 16384:
        chunk = upstream.recv(4096)
        if not chunk:
            break
        reply += chunk
    if b" 200" not in reply.split(b"\r\n", 1)[0]:
        upstream.close()
        raise OSError(f"upstream proxy refused CONNECT {host}:{port}")
    return upstream


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    st = path.stat()
    # access time one day before modification: on relatime filesystems the first read updates it
    os.utime(path, (st.st_mtime - 86400, st.st_mtime))
    return path


def build_decoy_home(root: Path, canary: str) -> dict[str, Path]:
    token = f"{CANARY_PREFIX}{canary}"
    files = {
        "ssh_private_key": _write(root / ".ssh" / "id_rsa", f"-----BEGIN OPENSSH PRIVATE KEY-----\n{token}\n-----END OPENSSH PRIVATE KEY-----\n"),
        "aws_credentials": _write(root / ".aws" / "credentials", f"[default]\naws_access_key_id = AKIA{canary[:16].upper().ljust(16, 'X')}\naws_secret_access_key = {token}\n"),
        "dotenv": _write(root / ".env", f"OPENAI_API_KEY={token}\nDATABASE_URL=postgres://admin:{token}@db.internal/prod\n"),
        "claude_config": _write(root / ".config" / "Claude" / "claude_desktop_config.json", '{"mcpServers": {"vault": {"env": {"TOKEN": "%s"}}}}' % token),
        "claude_config_mac": _write(root / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", '{"mcpServers": {"vault": {"env": {"TOKEN": "%s"}}}}' % token),
        "cursor_mcp": _write(root / ".cursor" / "mcp.json", '{"mcpServers": {"db": {"env": {"PASSWORD": "%s"}}}}' % token),
        "git_credentials": _write(root / ".git-credentials", f"https://user:{token}@github.com\n"),
    }
    (root / "Documents").mkdir(exist_ok=True)
    (root / "Documents" / "notes.txt").write_text("Quarterly planning notes (synthetic).\n", encoding="utf-8")
    return files


def _real_cache_dirs() -> dict[str, str]:
    env: dict[str, str] = {}
    home = Path.home()
    npm_cache = os.environ.get("npm_config_cache") or (
        str(Path(os.environ.get("LOCALAPPDATA", home)) / "npm-cache") if sys.platform == "win32" else str(home / ".npm")
    )
    env["npm_config_cache"] = npm_cache
    uv_cache = os.environ.get("UV_CACHE_DIR") or (
        str(Path(os.environ.get("LOCALAPPDATA", home)) / "uv" / "cache") if sys.platform == "win32" else str(home / ".cache" / "uv")
    )
    env["UV_CACHE_DIR"] = uv_cache
    return env


def _synthetic_args(schema: dict[str, Any], home: Path) -> dict[str, Any]:
    args: dict[str, Any] = {}
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    for name, spec in props.items():
        if not isinstance(spec, dict) or (name not in required and len(args) >= 2):
            continue
        typ = spec.get("type")
        if spec.get("enum"):
            args[name] = spec["enum"][0]
        elif typ == "integer" or typ == "number":
            args[name] = 1
        elif typ == "boolean":
            args[name] = False
        elif typ == "array":
            args[name] = []
        elif typ == "object":
            args[name] = {}
        elif any(k in name.lower() for k in ("path", "file", "dir")):
            args[name] = str(home / "Documents" / "notes.txt")
        else:
            args[name] = "sentinel-probe"
    return args


def run_honeypot(
    server_id: str,
    config: dict[str, Any],
    *,
    timeout: float = 90.0,
    exercise_tools: bool = True,
    probe: Callable[[StdioClient, list[dict[str, Any]], Path], Any] | None = None,
) -> dict[str, Any]:
    """Launch the server once in the decoy environment and grade what it does.

    ``probe`` (e.g. the vulnerability scanner's active probes) runs against the live honeypot
    client after ``tools/list``, so anything it triggers is observed by the same sensors.
    """
    canary = secrets.token_hex(10)
    token = f"{CANARY_PREFIX}{canary}"
    workdir = Path(tempfile.mkdtemp(prefix="sentinel-honeypot-"))
    home = workdir / "home"
    home.mkdir()
    decoys = build_decoy_home(home, canary)
    before_atime = {k: p.stat().st_atime for k, p in decoys.items()}
    proxy = EgressRecorder(canary)
    proxy_url = f"http://127.0.0.1:{proxy.port}"
    env = default_child_env()
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMP", "TEMP", "TMPDIR",
                "HOMEDRIVE", "HOMEPATH"):
        env.pop(key, None)
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "TMPDIR": str(workdir / "tmp"),
        "TMP": str(workdir / "tmp"),
        "TEMP": str(workdir / "tmp"),
        "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "http_proxy": proxy_url, "https_proxy": proxy_url,
        "ALL_PROXY": proxy_url, "NO_PROXY": "", "no_proxy": "",
        "AWS_SECRET_ACCESS_KEY": token,
        "GITHUB_TOKEN": token,
        "OPENAI_API_KEY": token,
    })
    (workdir / "tmp").mkdir()
    env.update(_real_cache_dirs())
    env.update({str(k): str(v) for k, v in (config.get("env") or {}).items()})
    evidence: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    stderr: list[str] = []
    outputs: list[str] = []
    children: dict[int, dict[str, Any]] = {}
    endpoints: set[str] = set()
    opened: set[str] = set()
    client: StdioClient | None = None
    stop = threading.Event()
    error = ""

    def sampler() -> None:
        while not stop.is_set():
            if client is not None and client.pid:
                snap = procmon.snapshot(client.pid, include_files=True)
                if snap is not None:
                    for c in snap.children:
                        children[c["pid"]] = c
                    endpoints.update(snap.remote_endpoints)
                    opened.update(snap.open_files)
            stop.wait(0.2)

    sampler_thread = threading.Thread(target=sampler, daemon=True)
    started = time.time()
    try:
        client = StdioClient(
            f"honeypot-{server_id}",
            command=str(config.get("command") or ""),
            args=list(config.get("args") or []),
            env=env,
            cwd=str(home),
            inherit_env=False,
        )
        sampler_thread.start()
        client.initialize(timeout=timeout)
        tools = client.list_tools(timeout=min(timeout, 30))
        if exercise_tools:
            exercised = 0
            for tool in tools:
                inf = infer(tool)
                if exercised >= 5 or {c.value for c in inf.capabilities} - {"READ"}:
                    continue
                try:
                    res = client.call_tool(tool["name"], _synthetic_args(tool.get("inputSchema") or {}, home), timeout=15)
                    outputs.append(str(res)[:20000])
                except Exception as exc:  # tool errors are fine; we only observe behaviour
                    outputs.append(f"error: {exc}")
                exercised += 1
        if probe is not None:
            try:
                probe(client, tools, home)
            except Exception as exc:  # a probe failure must not hide the sandbox evidence
                outputs.append(f"probe error: {exc}")
        time.sleep(1.0)  # let delayed (post-handshake) behaviour surface
    except Exception as exc:
        error = str(exc)
    finally:
        stop.set()
        if client is not None:
            stderr = client.stderr_tail(200)
            client.close()
        proxy.close()

    blob = "\n".join(stderr + outputs + [str(t) for t in tools])
    if token in blob or CANARY_PREFIX in blob:
        evidence.append({"severity": "CRITICAL", "category": "canary_leak", "title": "server emitted canary credentials it should never have read"})
    if proxy.canary_seen:
        evidence.append({"severity": "CRITICAL", "category": "canary_exfiltration", "title": "canary credentials were sent over the network"})
    for name, path in decoys.items():
        touched = str(path) in opened
        try:
            touched = touched or path.stat().st_atime > before_atime[name] + 1
        except OSError:
            pass
        if touched:
            evidence.append({"severity": "HIGH", "category": "decoy_read", "title": f"read decoy credential file ({name})", "evidence": str(path.relative_to(home))})
    blocked = [a for a in proxy.attempts if not a["allowed"]]
    if blocked:
        hosts = sorted({a["host"] for a in blocked})
        evidence.append({"severity": "HIGH" if any(a["carried_canary"] for a in blocked) else "MEDIUM", "category": "egress_attempt",
                         "title": "attempted network egress during sandbox run", "evidence": ", ".join(hosts[:8])})
    direct = procmon.remote_hosts(sorted(endpoints))
    if direct:
        evidence.append({"severity": "MEDIUM", "category": "direct_connection", "title": "opened direct network connections (bypassing the proxy)",
                         "evidence": ", ".join(sorted(direct)[:8])})
    suspicious_children, unusual = procmon.classify_children([c.get("name", "") for c in children.values()])
    if suspicious_children:
        evidence.append({"severity": "HIGH", "category": "suspicious_process", "title": "spawned suspicious processes", "evidence": ", ".join(sorted(set(suspicious_children)))})
    elif unusual:
        evidence.append({"severity": "LOW", "category": "child_process", "title": "spawned child processes", "evidence": ", ".join(sorted(set(unusual))[:6])})
    if any(line.startswith("[non-protocol stdout]") for line in stderr):
        evidence.append({"severity": "LOW", "category": "protocol_violation", "title": "wrote non-MCP data to stdout"})
    poisoned = []
    names = [t.get("name", "") for t in tools]
    for tool in tools:
        res = scanner.scan_tool(tool)  # cross-server shadowing needs the registry; discovery checks it
        if res.verdict != "CLEAN":
            poisoned.append({"tool": tool.get("name"), "verdict": res.verdict, "score": res.score})
    if any(p["verdict"] == "MALICIOUS" for p in poisoned):
        evidence.append({"severity": "HIGH", "category": "tool_poisoning", "title": "tool definitions contain poisoning indicators",
                         "evidence": ", ".join(p["tool"] for p in poisoned if p["verdict"] == "MALICIOUS")})
    if error and not tools:
        evidence.append({"severity": "LOW", "category": "startup_failure", "title": "server failed to start in the sandbox", "evidence": error[:200]})

    severities = {e["severity"] for e in evidence}
    classification = (
        "MALICIOUS_OR_COMPROMISED" if "CRITICAL" in severities
        else "HIGH_RISK" if "HIGH" in severities
        else "SUSPICIOUS" if "MEDIUM" in severities
        else "CLEAN"
    )
    risk = {"MALICIOUS_OR_COMPROMISED": 95, "HIGH_RISK": 70, "SUSPICIOUS": 40, "CLEAN": 5}[classification]
    shutil.rmtree(workdir, ignore_errors=True)
    return {
        "mode": "honeypot",
        "classification": classification,
        "risk_score": risk,
        "anomalies": [e["title"] + (f": {e['evidence']}" if e.get("evidence") else "") for e in evidence],
        "evidence": {
            "findings": evidence,
            "tools_discovered": names,
            "poisoned_tools": poisoned,
            "egress_attempts": proxy.attempts[:50],
            "child_processes": list(children.values())[:30],
            "remote_endpoints": sorted(endpoints)[:30],
            "decoys": sorted(decoys),
            "stderr_tail": stderr[-20:],
            "duration_s": round(time.time() - started, 1),
            "error": error,
            "isolation": {
                "synthetic_home": True,
                "canary_credentials": True,
                "egress_proxy": "registries only",
                "real_secrets_exposed": False,
                "note": "process isolation is best-effort (same OS user); run Sentinel in a container or VM for kernel-level isolation",
            },
        },
        "observed_behavior": {
            "network": sorted({a["host"] for a in proxy.attempts}),
            "process_spawn": bool(children),
            "filesystem": sorted(str(Path(p).name) for p in opened)[:30],
        },
        "timestamp": time.time(),
        "isolated": True,
        "note": "Sandbox results are evidence, not permanent trust.",
    }
