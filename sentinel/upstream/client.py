"""Minimal, dependency-light MCP client used by Sentinel to talk to upstream servers.

Transports
* ``stdio``  – Sentinel launches the server as a subprocess (newline-delimited JSON-RPC).
* ``http``   – Streamable HTTP (POST with ``Accept: application/json, text/event-stream``),
               with the spec'd fallback to the legacy HTTP+SSE transport on 400/404/405.
* ``sse``    – legacy HTTP+SSE (protocol 2024-11-05): GET stream + ``endpoint`` event.

Sentinel declares **no** client capabilities (no sampling, roots or elicitation), so an
upstream server cannot use the user's LLM or read the user's filesystem roots through it.
Server→client requests other than ``ping`` are refused.
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import Future, TimeoutError as FutureTimeout
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import urljoin

import httpx
from sentinel import __version__

log = logging.getLogger("sentinel.upstream")

CLIENT_INFO = {"name": "mcp-sentinel", "title": "MCP-Sentinel security gateway", "version": __version__}
REQUESTED_PROTOCOL = "2025-06-18"
KNOWN_PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MAX_TOOL_PAGES = 50

NotificationHandler = Callable[[str, dict[str, Any]], None]


class UpstreamError(Exception):
    """Transport-level failure (process died, HTTP error, timeout)."""


class McpError(Exception):
    """JSON-RPC error returned by the upstream server."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class _SessionExpired(UpstreamError):
    pass


class _FallbackToSse(UpstreamError):
    pass


def _loopback_url(url: str) -> bool:
    """Loopback upstreams must never be routed through an HTTP(S)_PROXY from the environment."""
    from urllib.parse import urlsplit

    from sentinel.netutil import HostClass, classify_host

    try:
        return classify_host(urlsplit(url).hostname or "") == HostClass.LOOPBACK
    except ValueError:
        return False


def default_child_env() -> dict[str, str]:
    """Environment inherited by stdio servers.

    Mirrors the MCP SDK's default inheritance list: upstream servers never see Sentinel's own
    configuration (JWT secrets, database URLs, keys) - only what they need to run.
    """
    if sys.platform == "win32":
        keys = [
            "APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PATHEXT", "PROCESSOR_ARCHITECTURE",
            "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERNAME", "USERPROFILE", "PROGRAMFILES",
            "PROGRAMFILES(X86)", "PROGRAMDATA", "COMSPEC", "WINDIR", "NUMBER_OF_PROCESSORS",
        ]
    else:
        keys = ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER", "LANG", "LC_ALL", "TMPDIR", "XDG_RUNTIME_DIR"]
    env = {k: v for k, v in os.environ.items() if k.upper() in {x.upper() for x in keys} and not v.startswith("()")}
    for proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
                      "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"):
        if proxy_var in os.environ:
            env[proxy_var] = os.environ[proxy_var]
    return env


def resolve_command(command: str, env: dict[str, str]) -> str:
    """Resolve ``npx`` → ``npx.cmd`` etc. on Windows; CreateProcess does not consult PATHEXT."""
    if os.path.isabs(command) and os.path.exists(command):
        return command
    found = shutil.which(command, path=env.get("PATH") or env.get("Path") or os.environ.get("PATH"))
    if not found:
        raise UpstreamError(f"command not found on PATH: {command!r}")
    return found


def _parse_messages(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [m for m in raw if isinstance(m, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


def iter_sse(lines: Iterable[str]) -> Iterator[tuple[str, str, str | None]]:
    """Yield (event, data, id) from an SSE line stream."""
    event, data_lines, event_id = "message", [], None
    for raw in lines:
        line = raw.rstrip("\r")
        if line == "":
            if data_lines:
                yield event, "\n".join(data_lines), event_id
            event, data_lines = "message", []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            event = value or "message"
        elif field == "data":
            data_lines.append(value)
        elif field == "id":
            event_id = value
    if data_lines:
        yield event, "\n".join(data_lines), event_id


class BaseClient:
    transport = "base"

    def __init__(self, server_id: str, on_notification: NotificationHandler | None = None) -> None:
        self.server_id = server_id
        self.on_notification = on_notification
        self._ids = itertools.count(1)
        self._pending: dict[Any, Future] = {}
        self._pending_lock = threading.Lock()
        self.server_info: dict[str, Any] = {}
        self.server_capabilities: dict[str, Any] = {}
        self.protocol_version: str = ""
        self.instructions: str = ""
        self.initialized = False
        self.connected_at: float = 0.0
        self.last_activity: float = 0.0
        self.notices: deque[str] = deque(maxlen=50)

    # -- transport hooks -------------------------------------------------------------------
    def _send(self, message: dict[str, Any], *, expect_id: Any = None, timeout: float = 30.0) -> dict[str, Any] | None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    @property
    def alive(self) -> bool:
        return self.initialized

    @property
    def pid(self) -> int | None:
        return None

    def stderr_tail(self, n: int = 50) -> list[str]:
        return list(self.notices)[-n:]

    # -- JSON-RPC ----------------------------------------------------------------------------
    def _register(self) -> tuple[int, Future]:
        rid = next(self._ids)
        fut: Future = Future()
        with self._pending_lock:
            self._pending[rid] = fut
        return rid, fut

    def _resolve(self, message: dict[str, Any]) -> None:
        with self._pending_lock:
            fut = self._pending.pop(message.get("id"), None)
        if fut is not None and not fut.done():
            fut.set_result(message)

    def _fail_all(self, error: Exception) -> None:
        with self._pending_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for fut in pending:
            if not fut.done():
                fut.set_exception(error)

    def _dispatch(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle an inbound message. Returns a JSON-RPC response to send back for server requests."""
        self.last_activity = time.time()
        if "method" not in message and "id" in message:
            self._resolve(message)
            return None
        method = str(message.get("method") or "")
        if "id" in message:  # server -> client request
            if method == "ping":
                return {"jsonrpc": "2.0", "id": message["id"], "result": {}}
            self.notices.append(f"refused server request {method!r} (Sentinel grants upstream servers no client capabilities)")
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"MCP-Sentinel does not allow upstream servers to call {method}"},
            }
        if method == "notifications/message":
            params = message.get("params") or {}
            self.notices.append(f"[{params.get('level', 'info')}] {str(params.get('data'))[:400]}")
        if self.on_notification is not None:
            try:
                self.on_notification(method, message.get("params") or {})
            except Exception:  # never let a handler kill the reader thread
                log.exception("notification handler failed")
        return None

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0) -> dict[str, Any]:
        rid, fut = self._register()
        message = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            message["params"] = params
        try:
            direct = self._send(message, expect_id=rid, timeout=timeout)
            if direct is not None:
                self._resolve(direct)
            response = fut.result(timeout=timeout)
        except FutureTimeout as exc:
            with self._pending_lock:
                self._pending.pop(rid, None)
            self.notify("notifications/cancelled", {"requestId": rid, "reason": "timeout in MCP-Sentinel"})
            raise UpstreamError(f"{method} timed out after {timeout:.0f}s") from exc
        except Exception:
            with self._pending_lock:
                self._pending.pop(rid, None)
            raise
        if "error" in response:
            err = response.get("error") or {}
            raise McpError(int(err.get("code", -32603)), str(err.get("message", "error")), err.get("data"))
        result = response.get("result")
        return result if isinstance(result, dict) else {}

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        try:
            self._send(message, timeout=10.0)
        except Exception as exc:  # notifications are best-effort
            self.notices.append(f"notification {method} failed: {exc}")

    # -- MCP ---------------------------------------------------------------------------------
    def initialize(self, timeout: float = 60.0) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {"protocolVersion": REQUESTED_PROTOCOL, "capabilities": {}, "clientInfo": CLIENT_INFO},
            timeout=timeout,
        )
        self.protocol_version = str(result.get("protocolVersion") or "")
        if self.protocol_version and self.protocol_version not in KNOWN_PROTOCOLS:
            self.notices.append(f"server negotiated unknown protocol version {self.protocol_version}")
        self.server_info = dict(result.get("serverInfo") or {})
        self.server_capabilities = dict(result.get("capabilities") or {})
        self.instructions = str(result.get("instructions") or "")
        self.initialized = True
        self.connected_at = time.time()
        self.notify("notifications/initialized")
        return result

    def list_tools(self, timeout: float = 30.0) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor = None
        for _ in range(MAX_TOOL_PAGES):
            params = {"cursor": cursor} if cursor else {}
            result = self.request("tools/list", params, timeout=timeout)
            tools.extend(t for t in (result.get("tools") or []) if isinstance(t, dict) and t.get("name"))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any], timeout: float = 45.0) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)

    def ping(self, timeout: float = 10.0) -> bool:
        try:
            self.request("ping", {}, timeout=timeout)
            return True
        except Exception:
            return False


class StdioClient(BaseClient):
    transport = "stdio"

    def __init__(
        self,
        server_id: str,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        on_notification: NotificationHandler | None = None,
        inherit_env: bool = True,
    ) -> None:
        super().__init__(server_id, on_notification)
        child_env = default_child_env() if inherit_env else {}
        child_env.update({str(k): str(v) for k, v in (env or {}).items()})
        self.argv = [resolve_command(command, child_env), *[str(a) for a in (args or [])]]
        self.cwd = cwd or None
        self._write_lock = threading.Lock()
        self._stderr: deque[str] = deque(maxlen=300)
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = 0x08000000 | 0x00000200  # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True  # own process group so we can terminate npx -> node trees
        try:
            self.proc = subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_env,
                cwd=self.cwd,
                **kwargs,
            )
        except OSError as exc:
            raise UpstreamError(f"failed to launch {self.argv[0]}: {exc}") from exc
        self._reader = threading.Thread(target=self._read_stdout, name=f"mcp-stdout-{server_id}", daemon=True)
        self._err_reader = threading.Thread(target=self._read_stderr, name=f"mcp-stderr-{server_id}", daemon=True)
        self._reader.start()
        self._err_reader.start()

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    @property
    def alive(self) -> bool:
        return self.initialized and self.proc.poll() is None

    def stderr_tail(self, n: int = 50) -> list[str]:
        return (list(self._stderr) + list(self.notices))[-n:]

    def _write(self, message: dict[str, Any]) -> None:
        data = (json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        with self._write_lock:
            if self.proc.poll() is not None or self.proc.stdin is None:
                raise UpstreamError(f"server process exited with code {self.proc.returncode}")
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise UpstreamError(f"server stdin closed: {exc}") from exc

    def _send(self, message: dict[str, Any], *, expect_id: Any = None, timeout: float = 30.0) -> None:
        self._write(message)
        return None

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for raw in iter(self.proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                # Protocol violation: stdout must only carry MCP messages. Keep it as evidence.
                self._stderr.append(f"[non-protocol stdout] {line[:300]}")
                continue
            for message in _parse_messages(parsed):
                reply = self._dispatch(message)
                if reply is not None:
                    try:
                        self._write(reply)
                    except UpstreamError:
                        break
        code = self.proc.wait()
        self.initialized = False
        self._fail_all(UpstreamError(f"server process exited with code {code}"))

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for raw in iter(self.proc.stderr.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                self._stderr.append(line[:500])

    def close(self) -> None:
        self.initialized = False
        proc = self.proc
        if proc.poll() is not None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()  # spec: close stdin first, then SIGTERM, then SIGKILL
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
        _terminate_tree(proc)


def _terminate_tree(proc: subprocess.Popen) -> None:
    try:
        import psutil

        try:
            parent = psutil.Process(proc.pid)
            children = parent.children(recursive=True)
        except psutil.Error:
            children = []
        for child in children:
            try:
                child.terminate()
            except psutil.Error:
                pass
        proc.terminate()
        _, alive = psutil.wait_procs(children, timeout=3)
        for child in alive:
            try:
                child.kill()
            except psutil.Error:
                pass
    except ImportError:
        proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()


class StreamableHttpClient(BaseClient):
    transport = "http"

    def __init__(
        self,
        server_id: str,
        url: str,
        headers: dict[str, str] | None = None,
        on_notification: NotificationHandler | None = None,
        verify_tls: bool = True,
    ) -> None:
        super().__init__(server_id, on_notification)
        self.url = url
        self.session_id: str | None = None
        self._headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self._http = httpx.Client(
            follow_redirects=True, verify=verify_tls, timeout=httpx.Timeout(60.0, connect=10.0), trust_env=not _loopback_url(url)
        )

    def _request_headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **self._headers}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            h["MCP-Protocol-Version"] = self.protocol_version
        return h

    def _send(self, message: dict[str, Any], *, expect_id: Any = None, timeout: float = 30.0) -> dict[str, Any] | None:
        is_init = message.get("method") == "initialize"
        try:
            with self._http.stream(
                "POST", self.url, json=message, headers=self._request_headers(), timeout=httpx.Timeout(timeout, connect=10.0)
            ) as resp:
                if is_init and resp.status_code in (400, 404, 405):
                    raise _FallbackToSse(f"Streamable HTTP initialize returned {resp.status_code}")
                if resp.status_code == 404 and self.session_id and not is_init:
                    raise _SessionExpired("upstream session expired")
                if resp.status_code == 202:
                    return None
                if resp.status_code >= 400:
                    body = resp.read().decode("utf-8", errors="replace")[:300]
                    raise UpstreamError(f"HTTP {resp.status_code} from upstream: {body}")
                if is_init:
                    sid = resp.headers.get("mcp-session-id")
                    if sid:
                        self.session_id = sid
                ctype = resp.headers.get("content-type", "").lower()
                if "text/event-stream" in ctype:
                    return self._consume_sse(resp, expect_id)
                body = resp.read()
                if not body.strip():
                    return None
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError as exc:
                    raise UpstreamError(f"upstream returned invalid JSON ({ctype})") from exc
                found = None
                for msg in _parse_messages(parsed):
                    if expect_id is not None and msg.get("id") == expect_id and "method" not in msg:
                        found = msg
                    else:
                        self._handle_side_message(msg)
                return found
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream HTTP error: {exc}") from exc

    def _handle_side_message(self, msg: dict[str, Any]) -> None:
        reply = self._dispatch(msg)
        if reply is not None:
            try:
                self._http.post(self.url, json=reply, headers=self._request_headers(), timeout=10.0)
            except httpx.HTTPError:
                pass

    def _consume_sse(self, resp: httpx.Response, expect_id: Any) -> dict[str, Any] | None:
        for _event, data, _eid in iter_sse(resp.iter_lines()):
            if not data.strip():
                continue  # priming event (id + empty data)
            try:
                parsed = json.loads(data)
            except json.JSONDecodeError:
                continue
            for msg in _parse_messages(parsed):
                if expect_id is not None and msg.get("id") == expect_id and "method" not in msg:
                    return msg
                self._handle_side_message(msg)
        if expect_id is not None:
            raise UpstreamError("upstream closed the SSE stream before responding")
        return None

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0) -> dict[str, Any]:
        try:
            return super().request(method, params, timeout)
        except _SessionExpired:
            # Spec: on 404 the client MUST start a new session with a fresh InitializeRequest.
            self.session_id = None
            self.protocol_version = ""
            self.initialize(timeout=timeout)
            return super().request(method, params, timeout)

    def close(self) -> None:
        self.initialized = False
        if self.session_id:
            try:
                self._http.delete(self.url, headers=self._request_headers(), timeout=5.0)
            except httpx.HTTPError:
                pass
        self._http.close()


class LegacySseClient(BaseClient):
    transport = "sse"

    def __init__(
        self,
        server_id: str,
        url: str,
        headers: dict[str, str] | None = None,
        on_notification: NotificationHandler | None = None,
        verify_tls: bool = True,
        connect_timeout: float = 30.0,
    ) -> None:
        super().__init__(server_id, on_notification)
        self.url = url
        self._headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self._http = httpx.Client(
            follow_redirects=True, verify=verify_tls, timeout=httpx.Timeout(None, connect=10.0), trust_env=not _loopback_url(url)
        )
        self.endpoint: str | None = None
        self._endpoint_ready = threading.Event()
        self._closed = False
        self._stream_error: str = ""
        self._thread = threading.Thread(target=self._listen, name=f"mcp-sse-{server_id}", daemon=True)
        self._thread.start()
        if not self._endpoint_ready.wait(connect_timeout):
            self.close()
            raise UpstreamError(self._stream_error or "legacy SSE server did not send an 'endpoint' event")
        if not self.endpoint:
            raise UpstreamError(self._stream_error or "legacy SSE connection failed")

    def _listen(self) -> None:
        try:
            with self._http.stream("GET", self.url, headers={"Accept": "text/event-stream", **self._headers}) as resp:
                if resp.status_code >= 400:
                    self._stream_error = f"SSE GET returned HTTP {resp.status_code}"
                    self._endpoint_ready.set()
                    return
                for event, data, _eid in iter_sse(resp.iter_lines()):
                    if self._closed:
                        break
                    if event == "endpoint":
                        self.endpoint = urljoin(self.url, data.strip())
                        self._endpoint_ready.set()
                        continue
                    try:
                        parsed = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    for msg in _parse_messages(parsed):
                        reply = self._dispatch(msg)
                        if reply is not None and self.endpoint:
                            try:
                                self._http.post(self.endpoint, json=reply, headers=self._headers, timeout=10.0)
                            except httpx.HTTPError:
                                pass
        except Exception as exc:  # includes errors raised when close() tears the client down mid-stream
            if not self._closed:
                self._stream_error = f"SSE stream error: {exc}"
        finally:
            self._endpoint_ready.set()
            self.initialized = False
            self._fail_all(UpstreamError(self._stream_error or "SSE stream closed"))

    def _send(self, message: dict[str, Any], *, expect_id: Any = None, timeout: float = 30.0) -> None:
        if not self.endpoint:
            raise UpstreamError("legacy SSE endpoint unknown")
        try:
            resp = self._http.post(
                self.endpoint,
                json=message,
                headers={"Content-Type": "application/json", **self._headers},
                timeout=httpx.Timeout(timeout, connect=10.0),
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream HTTP error: {exc}") from exc
        if resp.status_code >= 400:
            raise UpstreamError(f"HTTP {resp.status_code} from legacy SSE endpoint: {resp.text[:200]}")
        return None

    @property
    def alive(self) -> bool:
        return self.initialized and self._thread.is_alive()

    def close(self) -> None:
        self._closed = True
        self.initialized = False
        try:
            self._http.close()
        except Exception:
            pass


def _launch_hint(stderr: str) -> str:
    """Turn common launcher failures into an actionable message."""
    if "_npx" in stderr and ("ENOTEMPTY" in stderr or "ERR_MODULE_NOT_FOUND" in stderr):
        return " — hint: npx's package cache looks corrupted (an interrupted install); delete the ~/.npm/_npx folder and retry"
    if "command not found" in stderr or "not recognized as an internal or external command" in stderr:
        return " — hint: the launcher is not on Sentinel's PATH; use an absolute path to npx/uvx/node/python"
    return ""


def connect(
    server_id: str,
    transport: str,
    config: dict[str, Any],
    on_notification: NotificationHandler | None = None,
    timeout: float = 60.0,
) -> BaseClient:
    """Create a client for the given transport and perform the MCP initialize handshake."""
    transport = (transport or "http").lower()
    if transport == "stdio":
        client: BaseClient = StdioClient(
            server_id,
            command=str(config.get("command") or ""),
            args=list(config.get("args") or []),
            env=dict(config.get("env") or {}),
            cwd=config.get("cwd") or None,
            on_notification=on_notification,
        )
        try:
            client.initialize(timeout=timeout)
        except Exception as exc:
            tail = " | ".join(client.stderr_tail(5))
            client.close()
            raise UpstreamError(f"{exc}{' — stderr: ' + tail if tail else ''}{_launch_hint(tail)}") from exc
        return client
    url = str(config.get("url") or "")
    if not url.startswith(("http://", "https://")):
        raise UpstreamError("HTTP transports require an http(s):// URL")
    headers = dict(config.get("headers") or {})
    verify_tls = bool(config.get("verify_tls", True))
    if transport in {"http", "streamable-http", "streamable_http"}:
        client = StreamableHttpClient(server_id, url, headers, on_notification, verify_tls)
        try:
            client.initialize(timeout=timeout)
            return client
        except _FallbackToSse:
            client.close()
        except Exception:
            client.close()
            raise
    sse = LegacySseClient(server_id, url, headers, on_notification, verify_tls, connect_timeout=min(timeout, 30.0))
    try:
        sse.initialize(timeout=timeout)
    except Exception:
        sse.close()
        raise
    return sse
