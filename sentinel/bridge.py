"""stdio MCP server for Claude Desktop (and any stdio MCP client).

    claude_desktop_config.json
    {"mcpServers": {"mcp-sentinel": {"command": "<python>", "args": ["-m", "sentinel.bridge"],
                                     "env": {"SENTINEL_API_URL": "http://127.0.0.1:8443"}}}}

The bridge is deliberately thin: every decision is made by the Sentinel API. It
* exposes every Sentinel-protected tool (namespaced ``<server>__<tool>``) plus the meta-tools
* forwards calls to ``POST /v1/mcp/tools/call`` with the user's identity
* when a call needs step-up MFA / human approval, opens the approval page in the browser,
  keeps the call open (progress notifications) and retries the identical call once approved
* polls the catalog and emits ``notifications/tools/list_changed`` when servers change

Environment
  SENTINEL_API_URL            API base URL (default http://127.0.0.1:8443)
  SENTINEL_TOKEN              user access token (OIDC mode). In demo mode it is minted automatically:
  SENTINEL_SUBJECT / SENTINEL_ROLE   identity used for demo tokens (default local-user / SECURITY_ADMIN)
  SENTINEL_OPEN_BROWSER       open approval pages automatically (default 1)
  SENTINEL_WAIT_SECONDS       how long to hold a call open for approval (default from the API, 50s)
  SENTINEL_WORKFLOW_ID        fixed workflow id (default: per session, rotated after 30 min idle)
  SENTINEL_AUTOSTART          start the local API if it is not running (default 1; loopback URLs only)

stdout carries only MCP messages; diagnostics go to stderr.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import Future
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from sentinel.mcp_frontend import CallContext, McpFrontend, text_result, wait_for_stepup

API_URL = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8443").rstrip("/")
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path.home() / ".mcp-sentinel"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def log(message: str) -> None:
    print(f"[mcp-sentinel bridge] {message}", file=sys.stderr, flush=True)


def open_url(url: str) -> None:
    """Open a URL without letting the launcher inherit our stdout (which carries MCP traffic)."""
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        elif sys.platform == "win32":
            os.startfile(url)  # type: ignore[attr-defined]  # ShellExecute; no stdio inheritance
        else:
            subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    except Exception as exc:  # opening a browser is a convenience only
        log(f"could not open browser: {exc}")


def api_healthy(base: str) -> bool:
    try:
        resp = httpx.get(f"{base}/health", timeout=1.5, trust_env=False)
        return resp.status_code == 200 and resp.json().get("component") == "mcp-sentinel"
    except (httpx.HTTPError, ValueError):
        return False


def ensure_api(base: str, wait: float = 30.0) -> bool:
    """Start the local control plane when Claude launches the bridge before anyone ran ``mcp-sentinel serve``.

    Claude Desktop starts the chat and agent-mode bridges at the same moment, so a file lock makes
    sure only one of them launches the API; the other waits for it to come up.
    """
    if api_healthy(base):
        return True
    parts = urlsplit(base)
    if os.environ.get("SENTINEL_AUTOSTART", "1").lower() in {"0", "false", "no"} or (parts.hostname or "").lower() not in LOOPBACK:
        return False
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATA_DIR / "autostart.lock", "w") as lock:
        try:
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX)
        except ImportError:  # Windows: no advisory locks; a duplicate start just fails to bind the port
            pass
        if not api_healthy(base):
            log(f"API not running at {base}; starting it (log: {DATA_DIR / 'sentinel.log'})")
            detach: dict[str, Any] = (
                {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}  # type: ignore[attr-defined]
                if sys.platform == "win32" else {"start_new_session": True}
            )
            with open(DATA_DIR / "sentinel.log", "ab") as out:
                subprocess.Popen(
                    [sys.executable, "-m", "sentinel.cli", "serve", "--host", parts.hostname or "127.0.0.1", "--port", str(parts.port or 8443)],
                    cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, **detach,
                )
        deadline = time.time() + wait
        while time.time() < deadline:
            if api_healthy(base):
                return True
            time.sleep(0.4)
    log(f"API did not come up within {wait:.0f}s; see {DATA_DIR / 'sentinel.log'}")
    return False


class ApiClient:
    def __init__(self, base: str) -> None:
        self.base = base
        host = (urlsplit(base).hostname or "").lower()
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        # a corporate HTTP(S)_PROXY must never intercept the local control plane
        # tool calls may include a first-time `npx`/`uvx` install plus a slow upstream tool
        self.http = httpx.Client(timeout=httpx.Timeout(300.0, connect=5.0), trust_env=not loopback)
        self._token = os.environ.get("SENTINEL_TOKEN", "").strip()
        self._static = bool(self._token)
        self._exp = 0.0
        self._lock = threading.Lock()
        self.agent_id = "mcp-client"

    def token(self) -> str:
        if self._static:
            return self._token
        with self._lock:
            if self._token and time.time() < self._exp - 60:
                return self._token
            params = {
                "role": os.environ.get("SENTINEL_ROLE", "SECURITY_ADMIN"),
                "subject": os.environ.get("SENTINEL_SUBJECT", "local-user"),
                "agent_id": self.agent_id,
            }
            resp = self.http.post(f"{self.base}/v1/demo/token", params=params)
            if resp.status_code != 200:
                raise RuntimeError(f"could not obtain a demo token ({resp.status_code}); set SENTINEL_TOKEN for OIDC mode")
            data = resp.json()
            self._token = data["access_token"]
            self._exp = time.time() + float(data.get("expires_in", 3600))
            return self._token

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}
        try:
            resp = self.http.request(method, f"{self.base}{path}", headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"MCP-Sentinel API unreachable at {self.base}: {exc}") from exc
        if resp.status_code == 401 and not self._static:
            self._exp = 0.0  # token rejected (e.g. API restarted with a new secret): mint again once
            headers["Authorization"] = f"Bearer {self.token()}"
            resp = self.http.request(method, f"{self.base}{path}", headers=headers, **kwargs)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = resp.text[:300]
            raise RuntimeError(f"MCP-Sentinel API error {resp.status_code}: {detail}")
        return resp.json()


class RemoteBackend:
    def __init__(self, api: ApiClient, workflow: "WorkflowClock") -> None:
        self.api = api
        self.workflow = workflow
        self._catalog: list[dict[str, Any]] = []
        self.version = ""
        info = {}
        try:
            info = self.api.http.get(f"{self.api.base}/v1/integrations/info").json()
        except Exception:
            pass
        self.wait_seconds = int(os.environ.get("SENTINEL_WAIT_SECONDS", info.get("approval_wait_seconds", 50)))
        self.open_browser = os.environ.get("SENTINEL_OPEN_BROWSER", "1") not in {"0", "false", "no"}

    def list_tools(self) -> list[dict[str, Any]]:
        try:
            data = self.api.request("GET", "/v1/mcp/tools/list")
            self._catalog = list(data.get("tools") or [])
            self.version = str(data.get("version") or "")
        except RuntimeError as exc:
            log(str(exc))
        return self._catalog

    def _call(self, name: str, arguments: dict[str, Any], ctx: CallContext | None = None) -> dict[str, Any]:
        """Forward one call; while it runs, keep the client informed with progress notifications."""
        done = threading.Event()

        def heartbeat() -> None:
            started = time.time()
            while not done.wait(5.0):
                ctx.progress(f"MCP-Sentinel: '{name}' is still running ({int(time.time() - started)}s)…")

        if ctx is not None and ctx.progress_token is not None:
            threading.Thread(target=heartbeat, name="call-heartbeat", daemon=True).start()
        try:
            return self.api.request(
                "POST",
                "/v1/mcp/tools/call",
                json={"workflow_id": self.workflow.current(), "exposed_name": name, "arguments": arguments, "user_intent": ""},
            )
        finally:
            done.set()

    def _poll(self, kind: str, ident: str) -> str:
        try:
            path = f"/v1/mfa/challenges/{quote(ident)}" if kind == "mfa" else f"/v1/approvals/{quote(ident)}"
            return str(self.api.request("GET", path).get("status") or "PENDING")
        except RuntimeError:
            return "PENDING"

    def call_tool(self, name: str, arguments: dict[str, Any], ctx: CallContext) -> dict[str, Any]:
        try:
            data = self._call(name, arguments, ctx)
        except RuntimeError as exc:
            return text_result(str(exc), True)
        pending = None
        if data.get("decision") == "MFA_REQUIRED" and data.get("mfa_challenge_id"):
            pending = ("mfa", data["mfa_challenge_id"])
        elif data.get("decision") == "HUMAN_APPROVAL" and data.get("approval_id"):
            pending = ("approval", data["approval_id"])
        if pending and self.wait_seconds > 0:
            status = wait_for_stepup(
                kind=pending[0], ident=pending[1], url=data.get("approval_url"), poll=self._poll, ctx=ctx,
                wait_seconds=self.wait_seconds, open_url=open_url if self.open_browser else None,
            )
            if status in {"SATISFIED", "APPROVED"}:
                try:
                    data = self._call(name, arguments, ctx)  # identical call: action-bound leases match exactly
                except RuntimeError as exc:
                    return text_result(str(exc), True)
            elif status in {"DENIED", "REJECTED"}:
                return text_result(f"The user declined the {'step-up' if pending[0] == 'mfa' else 'approval'} request; '{name}' was not run.", True)
        result = data.get("mcp_result")
        if isinstance(result, dict):
            return result
        return text_result(json.dumps(data, ensure_ascii=False)[:4000], data.get("decision") not in {"ALLOW", "MONITOR", "RESTRICT"})

    def status(self, ctx: CallContext) -> dict[str, Any]:
        try:
            return self.api.request("GET", "/v1/session/status", params={"workflow_id": self.workflow.current()})
        except RuntimeError as exc:
            return {"error": str(exc)}

    def explain(self, receipt_id: str, ctx: CallContext) -> dict[str, Any]:
        try:
            return self.api.request("GET", f"/v1/receipts/{quote(receipt_id)}/explain")
        except RuntimeError as exc:
            return {"error": str(exc)}


class WorkflowClock:
    """One workflow per conversation-ish session; rotates after an idle gap."""

    def __init__(self) -> None:
        self.fixed = os.environ.get("SENTINEL_WORKFLOW_ID", "").strip()
        self.idle = int(os.environ.get("SENTINEL_WORKFLOW_IDLE_SECONDS", "1800"))
        self._id = self.fixed or self._new()
        self._last = time.time()
        self._lock = threading.Lock()

    def _new(self) -> str:
        return f"claude-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    def current(self) -> str:
        with self._lock:
            if not self.fixed and time.time() - self._last > self.idle:
                self._id = self._new()
            self._last = time.time()
            return self._id


class Bridge:
    def __init__(self) -> None:
        self.api = ApiClient(API_URL)
        self.workflow = WorkflowClock()
        self.backend = RemoteBackend(self.api, self.workflow)
        self.frontend = McpFrontend(self.backend, expose_meta_tools=True)
        self.session: dict[str, Any] = {}
        self._out = threading.Lock()
        self._pending: dict[str, Future] = {}
        self._stop = threading.Event()

    def write(self, message: dict[str, Any]) -> None:
        data = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        with self._out:
            sys.stdout.write(data + "\n")
            sys.stdout.flush()

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self.write({"jsonrpc": "2.0", "method": method, "params": params})

    def elicit_url(self, url: str, ident: str, message: str) -> str | None:
        """URL-mode elicitation (MCP 2025-11-25): ask the client to show the approval page out of band."""
        rid = f"sentinel-{uuid.uuid4().hex[:10]}"
        fut: Future = Future()
        self._pending[rid] = fut
        self.write({"jsonrpc": "2.0", "id": rid, "method": "elicitation/create",
                    "params": {"mode": "url", "message": message, "url": url, "elicitationId": ident}})
        try:
            answer = fut.result(timeout=20)
        except Exception:
            return None
        finally:
            self._pending.pop(rid, None)
        return str((answer or {}).get("action") or "") or None

    def _context(self, token: Any) -> CallContext:
        return CallContext(self.session, token, self.notify, self.elicit_url)

    def _handle(self, message: dict[str, Any]) -> None:
        if message.get("method") == "initialize":
            client_name = str(((message.get("params") or {}).get("clientInfo") or {}).get("name") or "mcp-client")
            self.api.agent_id = client_name[:64]
        response = self.frontend.handle(message, self.session, self._context)
        if response is not None:
            self.write(response)
        if message.get("method") == "tools/list":
            self.session["listed_version"] = self.backend.version

    def _watch_catalog(self) -> None:
        while not self._stop.wait(5.0):
            if not self.session.get("initialized"):
                continue
            try:
                version = self.api.request("GET", "/v1/mcp/catalog/version").get("version", "")
            except RuntimeError:
                continue
            listed = self.session.get("listed_version")
            if listed is not None and version and version != listed:
                self.session["listed_version"] = version
                self.notify("notifications/tools/list_changed", {})
                log("tool catalog changed; sent notifications/tools/list_changed")

    def run(self) -> int:
        log(f"starting (API {API_URL}); stdout is reserved for MCP traffic")
        threading.Thread(target=self._watch_catalog, name="catalog-watch", daemon=True).start()
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self.write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue
            if not isinstance(message, dict):
                self.write({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "batching is not supported"}})
                continue
            if "method" not in message and "id" in message:  # response to our elicitation request
                fut = self._pending.get(str(message.get("id")))
                if fut is not None and not fut.done():
                    fut.set_result(message.get("result") or {})
                continue
            if message.get("method") == "initialize" or "id" not in message:
                self._handle(message)  # keep ordering for the handshake and notifications
            else:
                threading.Thread(target=self._safe_handle, args=(message,), daemon=True).start()
        self._stop.set()
        return 0

    def _safe_handle(self, message: dict[str, Any]) -> None:
        try:
            self._handle(message)
        except Exception as exc:
            log(f"error handling {message.get('method')}: {exc}")
            if "id" in message:
                self.write({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32603, "message": "MCP-Sentinel bridge error"}})


def main() -> int:
    # Windows defaults stdin/stdout to the ANSI code page and \r\n; MCP stdio is UTF-8, newline-delimited.
    for stream, kwargs in ((sys.stdin, {"encoding": "utf-8", "errors": "replace"}), (sys.stdout, {"encoding": "utf-8", "newline": "\n"})):
        try:
            stream.reconfigure(**kwargs)  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    ensure_api(API_URL)
    return Bridge().run()


if __name__ == "__main__":
    raise SystemExit(main())
