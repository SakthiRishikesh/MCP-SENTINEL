"""Shadow execution: every local tool call is first run in a sandbox, then (maybe) for real.

    begin()   sync the server's workspace mirror (pre-call state) and, for calls in scope,
              launch a throw-away copy of the server in the sandbox and make the same call
              against a copy of the files, with decoy credentials and no real network
    judge     sandbox/verdict.py turns what was observed into SAFE / SUSPICIOUS / DANGEROUS /
              MALICIOUS / INCONCLUSIVE plus a human-readable effect preview
    finish()  after the real call: diff the real workspace, journal every change for undo, and
              compare it with the prediction - a server that does more outside the sandbox
              than inside it (sandbox evasion) is reverted on the spot and quarantined

Backends
    docker   ``docker run --network none --read-only --cap-drop ALL`` with the in-container
             supervisor (sandbox/agent.py: DNS sinkhole, connection sinks, inotify, process log,
             command shims). Real containment: nothing the server does can leave the box.
    process  the server runs as a normal process with a decoy HOME, credentials swapped for
             canaries, a recording egress proxy and command shims. Observation, not containment,
             so tools that execute code or send data are never pre-flighted with it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from monitoring import process as procmon
from sandbox import launch
from sandbox.honeypot import REGISTRY_ALLOWLIST, EgressRecorder, build_decoy_home
from sandbox.verdict import LOCAL_HOSTS, NETWORK_TOOLS, Limits, Observation, hosts_in, judge
from sandbox.workspace import (
    Change,
    Manifest,
    PathMap,
    Root,
    copy_tree,
    diff,
    discover_roots,
    join_real,
    make_writable,
    scan,
    sync_mirror,
    text_diff,
)
from sandbox.workspace import (
    Limits as WorkspaceLimits,
)
from sentinel.dlp import CANARY_PREFIX
from sentinel.injection import InjectionGuard
from sentinel.upstream.client import StdioClient, default_child_env

log = logging.getLogger("sentinel.sandbox")
AGENT = Path(__file__).with_name("agent.py")
DOCKERFILE = Path(__file__).resolve().parent.parent / "docker" / "sandbox-runtime.Dockerfile"
SECRET_ENV = re.compile(r"(TOKEN|SECRET|PASSW|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|AUTH|COOKIE|SESSION)", re.I)
UNCONTAINED_CAPS = {"CODE_EXECUTION", "INFRASTRUCTURE_CONTROL", "DATA_TRANSFER", "EXTERNAL_LOOKUP"}
WRITE_CAPS = {"WRITE", "CODE_EXECUTION", "INFRASTRUCTURE_CONTROL", "DATA_TRANSFER"}
CONTAINER_HOME = "/home/sandbox"
SHIM = """#!/usr/bin/env python3
import json, os, sys, time
name = os.path.basename(sys.argv[0])
cmd = " ".join(sys.argv)[:300]
try:
    with open(os.environ.get("SENTINEL_EVENTS", "/sentinel/out/events.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": "exec", "name": name, "cmd": cmd, "blocked": True,
                             "canary": "%s" in cmd, "t": time.time()}) + "\\n")
except OSError:
    pass
sys.stderr.write(name + ": blocked by the MCP-Sentinel sandbox\\n")
sys.exit(126)
""" % CANARY_PREFIX


# --------------------------------------------------------------------------------------------
@dataclass
class RunDirs:
    base: Path
    home: Path
    out: Path
    ws: dict[int, Path]  # root index -> directory that holds the root's copy

    @classmethod
    def create(cls, base: Path) -> RunDirs:
        dirs = cls(base=base, home=base / "home", out=base / "out", ws={})
        for p in (dirs.home, dirs.out, base / "ws", base / "tmp"):
            p.mkdir(parents=True, exist_ok=True)
        return dirs

    def root_path(self, root: Root) -> Path:
        """Host path of the root's copy (a directory, or the file inside its holder dir)."""
        if root.home:
            return self.home
        holder = self.ws[root.index]
        return holder / root.name if root.is_file else holder


class ShadowRun:
    """A launched sandbox copy of the server."""

    def __init__(self, client: StdioClient, dirs: RunDirs, pathmap: PathMap, backend: str, *, container: str | None = None,
                 recorder: EgressRecorder | None = None) -> None:
        self.client = client
        self.dirs = dirs
        self.pathmap = pathmap
        self.backend = backend
        self.container = container
        self.recorder = recorder
        self.events_file = dirs.out / "events.jsonl"
        self._sampled: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._sampler: threading.Thread | None = None
        if backend == "process":
            self._sampler = threading.Thread(target=self._sample, daemon=True)
            self._sampler.start()

    def _sample(self) -> None:
        seen: set[int] = set()
        endpoints: set[str] = set()
        opened: set[str] = set()
        while not self._stop.is_set():
            snap = procmon.snapshot(self.client.pid, include_files=True) if self.client.pid else None
            now = time.time()
            if snap is not None:
                for child in snap.children:
                    if child["pid"] not in seen:
                        seen.add(child["pid"])
                        self._sampled.append({"kind": "proc", "pid": child["pid"], "name": child.get("name", ""),
                                              "cmd": " ".join(child.get("cmdline") or [])[:300], "t": now})
                for ep in snap.remote_endpoints:
                    if ep not in endpoints:
                        endpoints.add(ep)
                        self._sampled.append({"kind": "connect", "host": ep.rsplit(":", 1)[0], "direct": True, "t": now})
                for path in snap.open_files:
                    if path not in opened:
                        opened.add(path)
                        self._sampled.append({"kind": "fs", "op": "open", "path": path, "t": now})
            self._stop.wait(0.1)

    def events(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            for line in self.events_file.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        except OSError:
            pass
        out.extend(self._sampled)
        if self.recorder is not None:
            for a in self.recorder.attempts:
                if a.get("allowed"):
                    continue  # package-registry tunnels needed to launch npx/uvx servers
                out.append({"kind": "proxy", "host": a.get("host", ""), "t": a.get("at", 0),
                            "canary": a.get("carried_canary", False) and not a.get("carried_env_canary", False),
                            "env_canary": a.get("carried_env_canary", False)})
        return sorted(out, key=lambda e: e.get("t", 0))

    def close(self) -> None:
        self._stop.set()
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            pass
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, timeout=20)
        if self.recorder is not None:
            self.recorder.close()


# --------------------------------------------------------------------------------------------
class DockerBackend:
    name = "docker"

    def __init__(self, settings: Any, base: Path) -> None:
        self.settings = settings
        self.base = base
        self._probe: tuple[float, bool, str] = (0.0, False, "")
        self._image: tuple[float, bool] = (0.0, False)
        self._mounts: dict[str, bool] = {}
        self.sysctl_ok = True

    def available(self) -> tuple[bool, str]:
        at, ok, why = self._probe
        if time.time() - at < 30:
            return ok, why
        if not shutil.which("docker"):
            ok, why = False, "Docker is not installed (install Docker Desktop for full containment)"
        else:
            try:
                res = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=10)
                ok = res.returncode == 0 and bool(res.stdout.strip())
                why = f"Docker {res.stdout.strip()}" if ok else "Docker is installed but the daemon is not running (start Docker Desktop)"
            except (OSError, subprocess.TimeoutExpired) as exc:
                ok, why = False, f"Docker did not respond: {exc}"
        self._probe = (time.time(), ok, why)
        return ok, why

    def image_ready(self, *, refresh: bool = False) -> bool:
        at, ok = self._image
        if not refresh and time.time() - at < 30:
            return ok
        try:
            ok = subprocess.run(["docker", "image", "inspect", self.settings.sandbox_image], capture_output=True, timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        self._image = (time.time(), ok)
        return ok

    def build_image(self, progress: list[str]) -> tuple[bool, str]:
        context = Path(tempfile.mkdtemp(prefix="sentinel-sandbox-build-"))
        try:
            shutil.copy2(DOCKERFILE, context / "Dockerfile")
            (context / "sandbox-ca").mkdir()
            ca = _ca_bundle()
            if ca:
                shutil.copy2(ca, context / "sandbox-ca" / "ca.crt")
            cmd = ["docker", "build", "-t", self.settings.sandbox_image,
                   "--build-arg", f"NODE_IMAGE={self.settings.sandbox_node_image}",
                   "--build-arg", f"PYTHON_IMAGE={self.settings.sandbox_python_image}"]
            for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
                if os.environ.get(var):
                    cmd += ["--build-arg", f"{var}={os.environ[var]}"]
            if _loopback_proxy():
                cmd += ["--network", "host"]
            cmd.append(str(context))
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            assert proc.stdout is not None
            for line in proc.stdout:
                progress.append(line.rstrip()[:300])
                del progress[:-60]
            code = proc.wait(timeout=1800)
            self.image_ready(refresh=True)
            return code == 0, "\n".join(progress[-8:])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        finally:
            shutil.rmtree(context, ignore_errors=True)

    def mountable(self, path: str | Path) -> bool:
        """Can the daemon bind-mount this host path? Docker Desktop only sees the folders listed under
        Settings -> Resources -> File sharing (on Linux just the home folder by default), so a path
        such as /tmp or /opt fails with "mounts denied". Probed once per folder, then cached."""
        key = str(Path(path).expanduser().resolve())
        for known, ok in self._mounts.items():
            if ok and (key == known or key.startswith(known.rstrip("/") + "/")):
                return True
        if key in self._mounts:
            return self._mounts[key]
        try:
            res = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{key}:/probe:ro", self.settings.sandbox_image, "true"],
                                 capture_output=True, text=True, timeout=60, env=_docker_cli_env())
        except (OSError, subprocess.TimeoutExpired):
            return True  # cannot tell: let the real launch report the problem
        err = (res.stderr or "").lower()
        ok = res.returncode == 0 or not any(m in err for m in ("mounts denied", "not shared", "is not known to docker"))
        self._mounts[key] = ok
        return ok

    def require_mountable(self, path: str | Path, what: str) -> None:
        if not self.mountable(path):
            raise RuntimeError(f"Docker cannot see {path} ({what}). Add it under Docker Desktop -> Settings -> Resources -> "
                               "File sharing, or move it below your home folder")

    def runtime_file(self, src: str | Path, name: str) -> Path:
        """A copy of a host file inside the sandbox folder, which Docker can always mount."""
        dst = self.base / "runtime" / name
        data = Path(src).read_bytes()
        if not dst.exists() or dst.read_bytes() != data:
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_suffix(dst.suffix + f".{secrets.token_hex(3)}")
            tmp.write_bytes(data)
            os.replace(tmp, dst)
        return dst

    def app_mount(self, plan: launch.LaunchPlan) -> str:
        """Host folder to mount read-only as the server's code (a staged copy if Docker cannot see it)."""
        if not plan.mount or self.mountable(plan.mount):
            return plan.mount
        src = Path(plan.mount)
        stats = [f.stat() for f in src.rglob("*") if f.is_file() and not f.is_symlink()]
        size = sum(st.st_size for st in stats)
        if size > 300 * 1024 * 1024:
            self.require_mountable(plan.mount, "the server's code")
        newest = max((st.st_mtime_ns for st in stats), default=0)
        stamp = hashlib.sha256(f"{src.resolve()}:{size}:{newest}".encode()).hexdigest()[:16]
        dst = self.base / "apps" / stamp
        if not (dst / ".sentinel-staged").exists():
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", ".git"))
            (dst / ".sentinel-staged").write_text(str(src), encoding="utf-8")
        return str(dst)

    def _user(self) -> str:
        if hasattr(os, "getuid") and os.getuid() != 0:
            return f"{os.getuid()}:{os.getgid()}"
        return "10001:10001"

    def prepare(self, plan: launch.LaunchPlan) -> tuple[list[str], Path | None]:
        """Install the package (network on, no install scripts) and resolve the entry point."""
        pkg_dir: Path | None = None
        if plan.needs_install:
            pkg_dir = self.base / "pkgs" / plan.install_key
            marker = pkg_dir / ".sentinel-installed"
            if not marker.exists():
                shutil.rmtree(pkg_dir, ignore_errors=True)
                pkg_dir.mkdir(parents=True, exist_ok=True)
                make_writable(pkg_dir)
                # -w /tmp: uv looks for uv.toml in the working directory, and the image's /home/sandbox
                # belongs to uid 10001, so running as the host user from there fails with EACCES
                cmd = ["docker", "run", "--rm", "--name", f"sentinel-install-{plan.install_key[:12]}-{secrets.token_hex(3)}",
                       "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-u", self._user(), "-w", "/tmp",
                       "-e", "HOME=/tmp/home", "-e", "npm_config_cache=/tmp/npm-cache", "-e", "UV_CACHE_DIR=/tmp/uv-cache",
                       "-e", "UV_NO_CONFIG=1", "-e", "npm_config_update_notifier=false", "-v", f"{pkg_dir}:{launch.PKG}"]
                for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
                    if os.environ.get(var):
                        cmd += ["-e", f"{var}={os.environ[var]}"]
                ca = _ca_bundle()
                if ca:
                    ca = str(self.runtime_file(ca, "host-ca.crt"))
                    cmd += ["-v", f"{ca}:/opt/sentinel/host-ca.crt:ro", "-e", "NODE_EXTRA_CA_CERTS=/opt/sentinel/host-ca.crt",
                            "-e", "SSL_CERT_FILE=/opt/sentinel/host-ca.crt", "-e", "PIP_CERT=/opt/sentinel/host-ca.crt",
                            "-e", "REQUESTS_CA_BUNDLE=/opt/sentinel/host-ca.crt"]
                if _loopback_proxy():
                    cmd += ["--network", "host"]
                cmd += [self.settings.sandbox_image, *launch.install_command(plan)]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.settings.sandbox_install_timeout_seconds)
                if res.returncode != 0:
                    raise RuntimeError(f"sandbox install of {plan.package} failed: {(res.stderr or res.stdout).strip()[-400:]}")
                marker.write_text(json.dumps({"package": plan.package, "at": time.time()}), encoding="utf-8")
        entry = launch.resolve_entry(plan, pkg_dir or Path("/nonexistent"))
        return entry, pkg_dir

    def launch(self, plan: launch.LaunchPlan, entry: list[str], pkg_dir: Path | None, dirs: RunDirs, roots: list[Root],
               args: list[str], env: dict[str, str], cwd: str, timeout: float) -> ShadowRun:
        name = f"sentinel-shadow-{dirs.base.name[:12]}"
        user = self._user()
        if user.startswith("10001"):
            for path in (dirs.home, dirs.out, *dirs.ws.values()):
                make_writable(path)
        shims = _shim_dir(self.base)
        agent = self.runtime_file(AGENT, "agent.py")
        app = self.app_mount(plan)
        cmd = ["docker", "run", "-i", "--rm", "--name", name, "--label", "mcp-sentinel.sandbox=1",
               "--network", "none", "--dns", "127.0.0.1", "--read-only", "--tmpfs", "/tmp:rw,size=64m",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
               "--memory", self.settings.sandbox_memory, "--cpus", str(self.settings.sandbox_cpus),
               "-u", user, "-w", cwd,
               "-v", f"{agent}:/opt/sentinel/agent.py:ro", "-v", f"{shims}:/opt/sentinel/shims:ro",
               "-v", f"{dirs.out}:/sentinel/out", "-v", f"{dirs.home}:{CONTAINER_HOME}"]
        if self.sysctl_ok:
            cmd += ["--sysctl", "net.ipv4.ip_unprivileged_port_start=0"]
        if pkg_dir is not None:
            cmd += ["-v", f"{pkg_dir}:{launch.PKG}:ro"]
        if app:
            cmd += ["-v", f"{app}:{launch.APP}:ro"]
        for root in roots:
            if not root.home:
                cmd += ["-v", f"{dirs.ws[root.index]}:/workspace/{root.index}"]
        for key, value in env.items():
            cmd += ["-e", f"{key}={value}"]
        cmd += [self.settings.sandbox_image, "python3", "/opt/sentinel/agent.py", "--out", "/sentinel/out/events.jsonl",
                "--watch", CONTAINER_HOME, "--shims", "/opt/sentinel/shims", "--", *entry, *args]
        client = StdioClient(f"shadow-{dirs.base.name[:8]}", command="docker", args=cmd[1:], env=_docker_cli_env(), inherit_env=False)
        run = ShadowRun(client, dirs, PathMap([]), "docker", container=name)
        try:
            client.initialize(timeout=timeout)
        except Exception as exc:
            tail = " ".join(client.stderr_tail(6))
            run.close()
            if self.sysctl_ok and "sysctl" in tail.lower():
                self.sysctl_ok = False  # older engines: retry without the DNS-sinkhole sysctl
                return self.launch(plan, entry, pkg_dir, dirs, roots, args, env, cwd, timeout)
            raise RuntimeError(f"sandbox container failed to start: {exc}; {tail[-300:]}") from exc
        return run


class ProcessBackend:
    name = "process"

    def __init__(self, settings: Any, base: Path) -> None:
        self.settings = settings
        self.base = base

    def launch(self, config: dict[str, Any], dirs: RunDirs, args: list[str], env: dict[str, str], cwd: str, canary: str,
               env_canary: str, timeout: float) -> ShadowRun:
        recorder = EgressRecorder(f"{CANARY_PREFIX}{canary}", f"{CANARY_PREFIX}{env_canary}")
        proxy = f"http://127.0.0.1:{recorder.port}"
        child = default_child_env()
        for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMP", "TEMP", "TMPDIR",
                    "HOMEDRIVE", "HOMEPATH", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
            child.pop(key, None)
        tmp = dirs.base / "tmp"
        child.update({
            "HOME": str(dirs.home), "USERPROFILE": str(dirs.home), "APPDATA": str(dirs.home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(dirs.home / "AppData" / "Local"), "XDG_CONFIG_HOME": str(dirs.home / ".config"),
            "TMPDIR": str(tmp), "TMP": str(tmp), "TEMP": str(tmp),
            "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy, "ALL_PROXY": proxy,
            "NO_PROXY": "", "no_proxy": "", "NODE_USE_ENV_PROXY": "1", "SENTINEL_EVENTS": str(dirs.out / "events.jsonl"),
        })
        ca = _ca_bundle()
        if ca:
            child["NODE_EXTRA_CA_CERTS"] = ca
        child.update(_real_caches())
        if sys.platform != "win32":
            child["PATH"] = str(_shim_dir(self.base)) + os.pathsep + child.get("PATH", "")
        child.update(env)
        client = StdioClient(f"shadow-{dirs.base.name[:8]}", command=str(config.get("command") or ""), args=args, env=child,
                             cwd=cwd, inherit_env=False)
        run = ShadowRun(client, dirs, PathMap([]), "process", recorder=recorder)
        try:
            client.initialize(timeout=timeout)
        except Exception as exc:
            tail = " ".join(client.stderr_tail(6))
            run.close()
            raise RuntimeError(f"sandbox process failed to start: {exc}; {tail[-300:]}") from exc
        return run


# --------------------------------------------------------------------------------------------
@dataclass
class ServerState:
    fingerprint: str
    config: dict[str, Any]
    plan: launch.LaunchPlan
    roots: list[Root]
    mirror: Path
    manifests: dict[int, Manifest] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    entry: list[str] | None = None
    pkg_dir: Path | None = None
    docker_error: str = ""


@dataclass
class CallContext:
    server_id: str
    tool: str
    state: ServerState
    preflight: dict[str, Any] | None = None
    skipped: str = ""
    pre: dict[int, Manifest] = field(default_factory=dict)
    predicted: set[str] = field(default_factory=set)
    reliable: bool = False
    _released: bool = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self.state.lock.release()


class SandboxManager:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self.base = Path(settings.sandbox_dir).expanduser()
        self.docker = DockerBackend(settings, self.base)
        self.process = ProcessBackend(settings, self.base)
        self.inject = InjectionGuard()
        self._servers: dict[str, ServerState] = {}
        self._lock = threading.Lock()
        self.build: dict[str, Any] = {"status": "idle", "log": [], "started_at": None, "finished_at": None, "message": ""}

    # -- status / backends ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self.settings.sandbox_mode != "off" and self.settings.sandbox_preflight != "off"

    def status(self) -> dict[str, Any]:
        docker_ok, docker_why = self.docker.available() if self.settings.sandbox_mode in {"auto", "docker"} else (False, "not used")
        image = docker_ok and self.docker.image_ready()
        if image and not self.docker.mountable(self.base):
            docker_ok, docker_why = False, _sharing_hint(self.base)
        active = "off" if not self.enabled else "docker" if docker_ok and image else (
            "unavailable" if self.settings.sandbox_mode == "docker" else "process")
        return {
            "mode": self.settings.sandbox_mode,
            "preflight": self.settings.sandbox_preflight,
            "active_backend": active,
            "docker": {"available": docker_ok, "detail": docker_why, "image": self.settings.sandbox_image, "image_ready": image},
            "build": {k: v for k, v in self.build.items() if k != "log"} | {"log": self.build["log"][-12:]},
            "containment": {
                "docker": "full: no network, read-only image, all capabilities dropped, decoy home, copy of your files",
                "process": "observation only: decoy home, canary credentials, recording proxy; code-executing and data-sending tools are not pre-flighted",
                "off": "no pre-flight",
                "unavailable": "Docker required but not available: calls the sandbox cannot verify are escalated",
            }[active],
            "limits": {"max_deletes": self.settings.sandbox_max_deletes, "max_modifications": self.settings.sandbox_max_modifications,
                       "max_files": self.settings.sandbox_max_files},
        }

    def start_build(self) -> bool:
        with self._lock:
            if self.build["status"] == "building":
                return False
            self.build.update(status="building", log=[], started_at=time.time(), finished_at=None, message="")

        def run() -> None:
            ok, message = self.docker.build_image(self.build["log"])
            self.build.update(status="ready" if ok else "failed", finished_at=time.time(), message=message[-600:])

        threading.Thread(target=run, name="sentinel-sandbox-build", daemon=True).start()
        return True

    def _backend(self, state: ServerState) -> tuple[str, str]:
        """('docker' | 'process' | '', reason)."""
        mode = self.settings.sandbox_mode
        if mode == "off":
            return "", "sandbox disabled"
        if mode in {"auto", "docker"}:
            ok, why = self.docker.available()
            if ok and not self.docker.image_ready():
                if self.build["status"] != "building" and self.build["status"] != "failed":
                    self.start_build()
                why = "the sandbox image is being built"
                ok = False
            if ok and not self.docker.mountable(self.base):
                ok, why = False, _sharing_hint(self.base)
            if ok and state.plan.supported and not state.docker_error:
                return "docker", ""
            if ok and not state.plan.supported:
                why = state.plan.reason
            elif ok and state.docker_error:
                why = state.docker_error
            if mode == "docker":
                return "", why
            return "process", why
        return "process", ""

    def state(self, server_id: str, config: dict[str, Any]) -> ServerState:
        fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True, default=str).encode()).hexdigest()[:16]
        with self._lock:
            st = self._servers.get(server_id)
            if st is None or st.fingerprint != fingerprint:
                plan = launch.plan_for(config)
                roots = discover_roots(config, exclude=plan.own_paths() + [str(self.base)])
                st = ServerState(fingerprint, config, plan, roots, self.base / "mirrors" / server_id)
                self._servers[server_id] = st
            return st

    def forget(self, server_id: str) -> None:
        with self._lock:
            self._servers.pop(server_id, None)
        shutil.rmtree(self.base / "mirrors" / server_id, ignore_errors=True)

    def _limits(self) -> WorkspaceLimits:
        return WorkspaceLimits(self.settings.sandbox_max_files, self.settings.sandbox_max_bytes)

    def _sync(self, st: ServerState) -> dict[int, Manifest]:
        for root in st.roots:
            if root.home:
                continue
            st.manifests[root.index] = sync_mirror(Path(root.real), st.mirror / str(root.index), st.manifests.get(root.index), self._limits())
        return {k: v for k, v in st.manifests.items()}

    # -- per-call API ---------------------------------------------------------------------------
    def begin(self, server_id: str, config: dict[str, Any], tool: dict[str, Any], arguments: dict[str, Any], *,
              preflight: bool, contract: dict[str, Any] | None = None, learned_hosts: set[str] | None = None) -> CallContext:
        st = self.state(server_id, config)
        if not st.lock.acquire(timeout=max(30.0, self.settings.upstream_timeout_seconds * 2)):
            raise TimeoutError("another call to this server is still being verified")
        ctx = CallContext(server_id, tool["name"], st)
        try:
            ctx.pre = self._sync(st)
            if not preflight:
                ctx.skipped = "not in pre-flight scope"
                return ctx
            if self.settings.sandbox_preflight == "writes" and not set(tool.get("capabilities") or []) & WRITE_CAPS:
                ctx.skipped = "read-only tools are not pre-flighted (SENTINEL_SANDBOX_PREFLIGHT=writes)"
                return ctx
            ctx.preflight = self._preflight(st, tool, arguments, contract or {}, learned_hosts or set())
            pv = ctx.preflight.get("preview") or {}
            ctx.predicted = {f["path"] for f in pv.get("files", [])}
            ctx.reliable = (ctx.preflight.get("verdict") not in {"INCONCLUSIVE"} and not pv.get("tool_error")
                            and not pv.get("partial") and not pv.get("more_files"))
        except Exception:
            ctx.release()
            raise
        return ctx

    def finish(self, ctx: CallContext, *, executed: bool, journal_dir: Path | None = None) -> dict[str, Any]:
        """Measure the real call's effects, journal them for undo, catch sandbox evasion."""
        try:
            if not executed or not ctx.state.roots:
                return {}
            changes: list[Change] = []
            for root in ctx.state.roots:
                if root.home or root.index not in ctx.pre:
                    continue
                after = scan(Path(root.real), self._limits())
                for c in diff(ctx.pre[root.index], after, root.index):
                    c.real = join_real(root, c.rel)
                    changes.append(c)
            if not changes:
                return {"changes": []}
            journal = _journal(ctx, changes, journal_dir) if journal_dir is not None else []
            result: dict[str, Any] = {"changes": [c.as_dict() for c in changes[:200]], "journal": journal}
            if ctx.reliable and ctx.preflight is not None:
                surprise = [c for c in changes if c.kind in {"deleted", "modified"} and c.real not in ctx.predicted]
                if surprise:
                    reverted = restore([e for e in journal if e["path"] in {c.real for c in surprise}], journal_dir) if journal_dir else {}
                    result["evasion"] = {
                        "unpredicted": [c.as_dict() for c in surprise[:50]],
                        "reverted": reverted,
                        "message": f"the real server changed {len(surprise)} file(s) the sandbox run did not touch",
                    }
            return result
        finally:
            ctx.release()

    # -- shadow runs ----------------------------------------------------------------------------
    def _prepare_run(self, st: ServerState, backend: str, *, synthetic: bool = False) -> tuple[RunDirs, PathMap, str, str]:
        run_id = uuid.uuid4().hex
        dirs = RunDirs.create(self.base / "runs" / run_id)
        canary = secrets.token_hex(10)
        build_decoy_home(dirs.home, canary)
        pairs: list[tuple[str, str]] = []
        for root in st.roots:
            if root.home:
                pairs.append((root.real, CONTAINER_HOME if backend == "docker" else str(dirs.home)))
                continue
            holder = dirs.base / "ws" / str(root.index)
            dirs.ws[root.index] = holder
            if synthetic:
                _synthetic_workspace(holder, root)
            else:
                copy_tree(st.mirror / str(root.index), holder)
            shadow = f"/workspace/{root.index}" if backend == "docker" else str(holder)
            if root.is_file:
                shadow = f"{shadow}/{root.name}" if backend == "docker" else str(holder / root.name)
            pairs.append((root.real, shadow))
        return dirs, PathMap(pairs), canary, run_id

    def _launch(self, st: ServerState, backend: str, dirs: RunDirs, pathmap: PathMap, canary: str) -> ShadowRun:
        token = f"{CANARY_PREFIX}{canary}"
        env_canary = _env_canary(canary)
        env_token = f"{CANARY_PREFIX}{env_canary}"
        env: dict[str, str] = {}
        for key, value in (st.config.get("env") or {}).items():
            value = str(value)
            # the server's real secrets never enter the sandbox: they are replaced by a traceable stand-in
            env[str(key)] = env_token if SECRET_ENV.search(str(key)) and value else str(pathmap.to_shadow(value))
        for key in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            env.setdefault(key, token)
        args = [str(a) for a in pathmap.to_shadow([str(a) for a in st.config.get("args") or []])]
        timeout = min(90.0, float(self.settings.upstream_connect_timeout_seconds))
        first = next((r for r in st.roots if not r.home), None)
        if backend == "docker":
            if st.entry is None:
                st.entry, st.pkg_dir = self.docker.prepare(st.plan)
            env.update({"HOME": CONTAINER_HOME, "SENTINEL_CANARY": canary, "SENTINEL_ENV_CANARY": env_canary})
            server_args = [str(a) for a in pathmap.to_shadow(st.plan.args)]
            cwd = f"/workspace/{first.index}" if first else "/tmp"  # never the decoy home (dotenv would load ~/.env)
            return self.docker.launch(st.plan, st.entry, st.pkg_dir, dirs, st.roots, server_args, env, cwd, timeout)
        cwd = str(dirs.ws[first.index]) if first else str(dirs.base / "tmp")
        return self.process.launch(st.config, dirs, args, env, cwd, canary, env_canary, timeout)

    def _preflight(self, st: ServerState, tool: dict[str, Any], arguments: dict[str, Any], contract: dict[str, Any],
                   learned: set[str]) -> dict[str, Any]:
        backend, why = self._backend(st)
        caps = set(tool.get("capabilities") or [])
        if not backend:
            return _inconclusive(why or "no sandbox backend available", backend)
        if backend == "process":
            uncontained = caps & UNCONTAINED_CAPS
            if uncontained:
                return _skipped(f"the process sandbox cannot contain {', '.join(sorted(uncontained))} tools"
                                + (f" ({why})" if why else "; install Docker for full containment"), backend)
        started = time.time()
        dirs, pathmap, canary, _ = self._prepare_run(st, backend)
        run: ShadowRun | None = None
        try:
            try:
                run = self._launch(st, backend, dirs, pathmap, canary)
            except Exception as exc:
                if backend == "docker" and self.settings.sandbox_mode == "auto":
                    st.docker_error = str(exc)[:300]  # this server cannot run in the container: fall back
                    log.warning("docker sandbox failed for %s, using the process backend: %s", st.plan.package or st.plan.kind, exc)
                    shutil.rmtree(dirs.base, ignore_errors=True)
                    return self._preflight(st, tool, arguments, contract, learned)
                return _inconclusive(f"sandbox launch failed: {exc}", backend)
            return self._exercise(st, run, dirs, pathmap, canary, tool, arguments, contract, learned, started)
        finally:
            if run is not None:
                run.close()
            shutil.rmtree(dirs.base, ignore_errors=True)

    def _exercise(self, st: ServerState, run: ShadowRun, dirs: RunDirs, pathmap: PathMap, canary: str, tool: dict[str, Any],
                  arguments: dict[str, Any], contract: dict[str, Any], learned: set[str], started: float) -> dict[str, Any]:
        before = {r.index: scan(dirs.root_path(r), self._limits()) for r in st.roots if not r.home}
        home_before = scan(dirs.home, self._limits())
        t0 = time.time()
        error, timed_out, result = "", False, {}
        try:
            result = run.client.call_tool(tool["name"], pathmap.to_shadow(arguments), timeout=self.settings.sandbox_call_timeout_seconds)
        except TimeoutError as exc:
            timed_out, error = True, f"timed out: {exc}"
        except Exception as exc:  # noqa: BLE001 - a JSON-RPC error is still an observation
            error = str(exc)[:300]
            timed_out = "timed out" in error.lower()
            if "code" in error.lower() and "server process exited" not in error.lower():
                error = ""  # the tool answered with an MCP error: its effects are still valid evidence
        time.sleep(0.4)  # delayed side effects (background exfiltration) land in the window
        obs = self._observe(st, run, dirs, pathmap, canary, tool, arguments, before, home_before, t0, result, error, timed_out)
        obs.duration_ms = (time.time() - started) * 1000
        allowed = hosts_in(st.config) | learned | set(contract.get("startup_hosts") or [])
        tool_contract = (contract.get("tools") or {}).get(tool["name"]) or {}
        allowed |= set(tool_contract.get("hosts") or [])
        known = set(tool_contract.get("processes") or []) | set(contract.get("startup_processes") or [])
        limits = Limits(self.settings.sandbox_max_deletes, self.settings.sandbox_max_modifications)
        verdict = judge(obs, allowed_hosts=allowed, known_processes=known, limits=limits)
        verdict["backend"] = run.backend
        verdict["observed"] = {"hosts": sorted({str(n.get("host")) for n in obs.network if n.get("host")}),
                               "processes": sorted({str(p.get("name")) for p in obs.processes if p.get("name")}),
                               "writes": any(c.kind != "deleted" for c in obs.changes),
                               "deletes": any(c.kind == "deleted" for c in obs.changes)}
        return verdict

    def _observe(self, st: ServerState, run: ShadowRun, dirs: RunDirs, pathmap: PathMap, canary: str, tool: dict[str, Any],
                 arguments: dict[str, Any], before: dict[int, Manifest], home_before: Manifest, t0: float, result: dict[str, Any],
                 error: str, timed_out: bool) -> Observation:
        caps = set(tool.get("capabilities") or ["READ"])
        annotations = tool.get("annotations") or {}
        read_only = bool(annotations.get("readOnlyHint")) or caps <= {"READ"}
        changes: list[Change] = []
        partial = False
        for root in st.roots:
            if root.home:
                continue
            after = scan(dirs.root_path(root), self._limits())
            partial = partial or after.partial or bool(st.manifests.get(root.index) and st.manifests[root.index].partial)
            for c in diff(before[root.index], after, root.index):
                c.real = join_real(root, c.rel)
                if c.kind != "deleted" and len(changes) < 10:
                    src = (st.mirror / str(root.index) / (root.name if root.is_file else c.rel)) if c.kind == "modified" else None
                    dst = dirs.root_path(root) if root.is_file else dirs.root_path(root) / c.rel
                    c.diff = text_diff(src, dst, c.rel)
                changes.append(c)
        home_after = scan(dirs.home, self._limits())
        home_writes = [c.rel for c in diff(home_before, home_after, -1) if c.kind != "deleted"]
        events = run.events()
        window = [e for e in events if e.get("t", 0) >= t0 - 0.05]
        decoy_reads: set[str] = set()
        home_prefixes = [CONTAINER_HOME + "/", str(dirs.home) + os.sep]
        for e in events:  # planted credentials are off limits at any time, start-up included
            if e.get("kind") == "fs" and e.get("op") in {"open", "read"}:
                path = str(e.get("path") or "")
                for prefix in home_prefixes:
                    if path.startswith(prefix):
                        rel = path[len(prefix):].replace("\\", "/")
                        if _is_decoy(rel):
                            decoy_reads.add(rel)
        if run.backend == "process":  # no inotify: access times of the planted files
            for rel in _decoy_files(dirs.home):
                p = dirs.home / rel
                try:
                    st_ = p.stat()
                    if st_.st_atime > st_.st_mtime - 86400 + 1:
                        decoy_reads.add(rel)
                except OSError:
                    pass
        network = [{"host": e.get("host", ""), "via": e.get("kind"), "canary": bool(e.get("canary")), "env_canary": bool(e.get("env_canary")),
                    **({"port": e.get("port")} if e.get("port") else {})}
                   for e in events if e.get("kind") in {"dns", "connect", "proxy"}
                   and (e.get("t", 0) >= t0 - 0.05 or e.get("canary") or e.get("env_canary"))]
        network = [n for n in network if not any(n["host"] == r or n["host"].endswith("." + r) for r in REGISTRY_ALLOWLIST)]
        seen_hosts: set[tuple[str, bool]] = set()
        deduped = []
        for n in network:
            key = (n["host"], n["canary"] or n["env_canary"])
            if key not in seen_hosts:
                seen_hosts.add(key)
                deduped.append(n)
        own = {e.get("pid") for e in events if e.get("kind") == "proc" and e.get("t", 0) < t0}
        processes = [{"name": e.get("name", ""), "cmd": e.get("cmd", ""), "blocked": e.get("kind") == "exec"}
                     for e in window if (e.get("kind") == "proc" and e.get("pid") not in own) or e.get("kind") == "exec"]
        output = json.dumps(result, default=str)[:400_000]  # what would reach the model
        injection = self.inject.scan(output[:200_000], field_name="tool_output")
        return Observation(
            tool=tool["name"], capabilities=caps, read_only=read_only, arguments=arguments,
            referenced=pathmap.referenced(arguments),
            changes=changes, workspace_files=sum(len(m.files) for m in before.values()),
            home_writes=home_writes, decoy_reads=sorted(decoy_reads),
            canary_in_output=canary in output, env_canary_in_output=_env_canary(canary) in output,
            network=deduped, processes=[p for p in processes if p["name"] or p["cmd"]],
            output_injection=injection.detected and injection.severity in {"HIGH", "CRITICAL"},
            error=error, timed_out=timed_out, partial=partial, tool_error=bool(result.get("isError")) or bool(error),
            backend=run.backend,
        )

    # -- registration-time behaviour audit ---------------------------------------------------------
    def audit(self, server_id: str, config: dict[str, Any], tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Exercise every tool once in the sandbox on a synthetic workspace and record a behaviour contract."""
        st = self.state(server_id, config)
        backend, why = self._backend(st)
        report: dict[str, Any] = {"status": "DONE", "backend": backend or "none", "started_at": time.time(), "tools": {},
                                  "startup_hosts": [], "startup_processes": [], "note": why}
        if not backend:
            report.update(status="SKIPPED", note=why or "no sandbox backend")
            return report
        dirs, pathmap, canary, _ = self._prepare_run(st, backend, synthetic=True)
        run: ShadowRun | None = None
        try:
            try:
                run = self._launch(st, backend, dirs, pathmap, canary)
            except Exception as exc:
                if backend == "docker" and self.settings.sandbox_mode == "auto":
                    st.docker_error = str(exc)[:300]
                    shutil.rmtree(dirs.base, ignore_errors=True)
                    return self.audit(server_id, config, tools)
                report.update(status="FAILED", note=f"sandbox launch failed: {exc}"[:400])
                return report
            startup = run.events()
            report["startup_hosts"] = sorted({str(e.get("host")) for e in startup if e.get("kind") in {"dns", "connect", "proxy"} and e.get("host")}
                                             - set(REGISTRY_ALLOWLIST) - LOCAL_HOSTS)[:20]
            report["startup_processes"] = sorted({str(e.get("name")) for e in startup if e.get("kind") == "proc" and e.get("name")})[:20]
            try:
                sandbox_names = {t.get("name") for t in run.client.list_tools(timeout=30)}
                missing = sorted({t["name"] for t in tools} - sandbox_names)
                if missing:
                    report["tool_list_mismatch"] = missing[:20]
            except Exception:  # noqa: BLE001
                pass
            ordered = sorted(tools, key=lambda t: (_rank(t), t["name"]))[:30]
            for tool in ordered:
                if backend == "process" and set(tool.get("capabilities") or []) & UNCONTAINED_CAPS:
                    report["tools"][tool["name"]] = {"verdict": "SKIPPED", "reasons": ["the process sandbox cannot contain this tool"]}
                    continue
                if not run.client.alive:
                    run.close()
                    run = self._launch(st, backend, dirs, pathmap, canary)
                args = synthetic_arguments(tool.get("inputSchema") or {}, pathmap, st.roots)
                started = time.time()
                verdict = self._exercise(st, run, dirs, pathmap, canary, tool, args, {}, set(), started)
                observed = verdict.get("observed") or {}
                report["tools"][tool["name"]] = {
                    "verdict": verdict["verdict"], "reasons": verdict["reasons"], "findings": verdict["findings"][:8],
                    "hosts": observed.get("hosts", []) if verdict["verdict"] != "MALICIOUS" else [],
                    "processes": observed.get("processes", []) if verdict["verdict"] != "MALICIOUS" else [],
                    "writes": observed.get("writes", False), "deletes": observed.get("deletes", False),
                    "duration_ms": verdict["preview"].get("duration_ms"), "error": verdict["preview"].get("error", ""),
                }
        finally:
            if run is not None:
                run.close()
            shutil.rmtree(dirs.base, ignore_errors=True)
        verdicts = [t["verdict"] for t in report["tools"].values()]
        report["finished_at"] = time.time()
        report["summary"] = {v: verdicts.count(v) for v in sorted(set(verdicts))}
        return report


# --------------------------------------------------------------------------------------------
def _inconclusive(why: str, backend: str) -> dict[str, Any]:
    return {"verdict": "INCONCLUSIVE", "findings": [], "reasons": [why], "backend": backend or "none",
            "preview": {"headline": "Not verified in the sandbox", "files": [], "error": why, "backend": backend}}


def _skipped(why: str, backend: str) -> dict[str, Any]:
    out = _inconclusive(why, backend)
    out["skipped"] = True
    return out


def _env_canary(canary: str) -> str:
    return "env" + hashlib.sha256(canary.encode()).hexdigest()[:17]


def _is_decoy(rel: str) -> bool:
    return rel in DECOY_RELS


DECOY_RELS = {".ssh/id_rsa", ".aws/credentials", ".env", ".config/Claude/claude_desktop_config.json",
              "Library/Application Support/Claude/claude_desktop_config.json", ".cursor/mcp.json", ".git-credentials"}


def _decoy_files(home: Path) -> list[str]:
    return [rel for rel in DECOY_RELS if (home / rel).exists()]


def _rank(tool: dict[str, Any]) -> int:
    caps = set(tool.get("capabilities") or [])
    if (tool.get("annotations") or {}).get("destructiveHint") or caps & {"CODE_EXECUTION", "INFRASTRUCTURE_CONTROL"}:
        return 2
    return 1 if caps & {"WRITE", "DATA_TRANSFER"} else 0


SAMPLE_FILES = {
    "README.md": "# Sample project\n\nSynthetic workspace used by the MCP-Sentinel behaviour audit.\n",
    "notes.txt": "Meeting notes (synthetic).\n- item one\n- item two\n",
    "data.csv": "id,name,amount\n1,alpha,10\n2,beta,20\n",
    "src/app.py": "def main():\n    print('hello')\n",
    "docs/guide.md": "# Guide\n\nSynthetic documentation.\n",
}


def _synthetic_workspace(holder: Path, root: Root) -> None:
    holder.mkdir(parents=True, exist_ok=True)
    if root.is_file:
        (holder / root.name).write_text("" if root.name.endswith((".json", ".jsonl")) else "sample\n", encoding="utf-8")
        return
    for rel, content in SAMPLE_FILES.items():
        p = holder / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


PATHY = re.compile(r"(path|file|dir|folder|root|repo|source|destination|target|cwd|location)", re.I)
DIRISH = re.compile(r"(dir|folder|root|repo|cwd|directory|location)", re.I)


def synthetic_arguments(schema: dict[str, Any], pathmap: PathMap, roots: list[Root], depth: int = 0) -> dict[str, Any]:
    """Plausible arguments derived from a tool's input schema; paths point into the synthetic workspace."""
    dir_root = next((r for r in roots if not r.is_file and not r.home), None)
    base = dir_root.real if dir_root else None
    file_root = next((r for r in roots if r.is_file), None)
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    args: dict[str, Any] = {}
    for name, spec in props.items():
        if not isinstance(spec, dict) or (name not in required and len(args) >= 3):
            continue
        args[name] = _value(name, spec, base, file_root, depth)
    return args


def _value(name: str, spec: dict[str, Any], base: str | None, file_root: Root | None, depth: int) -> Any:
    typ = spec.get("type")
    if isinstance(typ, list):
        typ = next((t for t in typ if t != "null"), "string")
    if spec.get("enum"):
        return spec["enum"][0]
    if "default" in spec:
        return spec["default"]
    if typ in {"integer", "number"}:
        return spec.get("minimum", 1)
    if typ == "boolean":
        return False
    if typ == "array":
        items = spec.get("items") if isinstance(spec.get("items"), dict) else {}
        if spec.get("minItems") or PATHY.search(name):
            return [_value(name.rstrip("s"), items or {"type": "string"}, base, file_root, depth + 1)]
        return []
    if typ == "object" or spec.get("properties"):
        if depth > 2:
            return {}
        props = spec.get("properties") or {}
        required = set(spec.get("required") or [])
        return {k: _value(k, v, base, file_root, depth + 1) for k, v in props.items()
                if isinstance(v, dict) and (k in required or len(props) <= 3)}
    lowered = name.lower()
    if PATHY.search(lowered):
        if file_root is not None and not base:
            return file_root.real
        if base:
            if DIRISH.search(lowered):
                return base
            if "dest" in lowered or "target" in lowered:
                return f"{base}/notes-copy.txt"
            return f"{base}/notes.txt"
        return "notes.txt"
    if spec.get("format") in {"uri", "url"} or any(k in lowered for k in ("url", "uri", "endpoint", "link")):
        return "https://example.com/"
    if "email" in lowered:
        return "audit@example.com"
    if spec.get("format") == "date-time":
        return "2026-01-01T00:00:00Z"
    if any(k in lowered for k in ("query", "search", "pattern", "term", "keyword")):
        return "sample"
    return "Sentinel audit sample text"


def _journal(ctx: CallContext, changes: list[Change], journal_dir: Path) -> list[dict[str, Any]]:
    """Copy the pre-call version of every modified / deleted file out of the mirror."""
    entries: list[dict[str, Any]] = []
    roots = {r.index: r for r in ctx.state.roots}
    for i, c in enumerate(changes):
        entry: dict[str, Any] = {"path": c.real, "change": c.kind}
        if c.kind in {"modified", "deleted"}:
            root = roots[c.root]
            src = ctx.state.mirror / str(c.root) / (root.name if root.is_file else c.rel)
            if src.exists():
                dst = journal_dir / "files" / f"{i:05d}"
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                entry["backup"] = dst.name
                entry["mode"] = stat.S_IMODE(src.stat().st_mode)
        if c.kind in {"created", "modified"}:
            try:
                st_ = Path(c.real).stat()
                entry["after"] = [st_.st_size, st_.st_mtime_ns]
            except OSError:
                pass
        entries.append(entry)
    return entries


def restore(entries: list[dict[str, Any]], journal_dir: Path | None) -> dict[str, Any]:
    """Undo journalled changes: restore backups, remove created files that were not changed since."""
    report: dict[str, Any] = {"restored": [], "removed": [], "conflicts": []}
    for entry in entries:
        path = Path(entry["path"])
        try:
            if entry.get("after") and path.exists():
                st_ = path.stat()
                if [st_.st_size, st_.st_mtime_ns] != entry["after"]:
                    report["conflicts"].append({"path": str(path), "why": "changed again after this call"})
                    continue
            if entry["change"] == "created":
                if path.exists():
                    path.unlink()
                    report["removed"].append(str(path))
            elif entry.get("backup") and journal_dir is not None:
                src = journal_dir / "files" / entry["backup"]
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, path)
                report["restored"].append(str(path))
            else:
                report["conflicts"].append({"path": str(path), "why": "no backup (file was not mirrored)"})
        except OSError as exc:
            report["conflicts"].append({"path": str(path), "why": str(exc)})
    return report


def _shim_dir(base: Path) -> Path:
    shims = base / "shims"
    marker = shims / ".v1"
    if not marker.exists():
        shims.mkdir(parents=True, exist_ok=True)
        for name in sorted(NETWORK_TOOLS - {"powershell", "pwsh", "certutil", "bitsadmin"}):
            p = shims / name
            p.write_text(SHIM, encoding="utf-8")
            p.chmod(0o755)
        marker.write_text("1", encoding="utf-8")
    return shims


def _sharing_hint(path: Path) -> str:
    return (f"Docker cannot mount the sandbox folder {path}: add it under Docker Desktop -> Settings -> Resources -> "
            "File sharing, or set SENTINEL_SANDBOX_DIR to a folder below your home directory")


def _ca_bundle() -> str:
    for var in ("SENTINEL_SANDBOX_CA_FILE", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        value = os.environ.get(var)
        if value and os.path.isfile(value):
            return value
    return ""


def _loopback_proxy() -> bool:
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    return any(h in proxy for h in ("127.0.0.1", "localhost", "[::1]"))


def _docker_cli_env() -> dict[str, str]:
    env = default_child_env()
    for var in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"):
        if os.environ.get(var):
            env[var] = os.environ[var]
    return env


def _real_caches() -> dict[str, str]:
    home = Path.home()
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home))
        return {"npm_config_cache": os.environ.get("npm_config_cache") or str(local / "npm-cache"),
                "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR") or str(local / "uv" / "cache")}
    return {"npm_config_cache": os.environ.get("npm_config_cache") or str(home / ".npm"),
            "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR") or str(home / ".cache" / "uv")}


_manager: SandboxManager | None = None
_manager_lock = threading.Lock()


def get_sandbox(settings: Any | None = None) -> SandboxManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            from sentinel.config import get_settings

            _manager = SandboxManager(settings or get_settings())
        return _manager


def reset_sandbox() -> None:
    global _manager
    with _manager_lock:
        _manager = None
