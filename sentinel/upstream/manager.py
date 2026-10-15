"""Lifecycle of upstream MCP connections plus Sentinel's background security jobs.

* one live client per registered server (launched / connected lazily, reconnected on death
  or configuration change)
* ``notifications/tools/list_changed`` from an upstream server triggers an immediate
  integrity re-scan (that is the moment a rug pull happens)
* periodic re-discovery of every enabled server (rug-pull detection even when the server
  stays silent about its change)
* periodic process-tree sampling of stdio servers (runtime behaviour monitor)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from integrity.crypto import canonical_hash
from monitoring import process as procmon
from sentinel.config import get_settings
from sentinel.secrets_box import decrypt_json
from sentinel.upstream.client import BaseClient, UpstreamError, connect

log = logging.getLogger("sentinel.upstream.manager")

DiscoveryCallback = Callable[[str, str], None]  # (server_id, reason)
MonitorCallback = Callable[[str, dict[str, Any]], None]  # (server_id, snapshot dict)


def server_connection_config(row: Any) -> tuple[str, dict[str, Any]]:
    """(transport, config) for a ServerRow. Secrets are decrypted only in memory."""
    transport = (row.transport or "http").lower()
    config = decrypt_json(getattr(row, "config_encrypted", "") or "", default={}) or {}
    if transport in {"http", "sse", "streamable-http"} and not config.get("url"):
        config["url"] = row.endpoint
    return transport, config


class _Conn:
    def __init__(self, client: BaseClient, fingerprint: str) -> None:
        self.client = client
        self.fingerprint = fingerprint
        self.lock = threading.Lock()
        self.calls = 0
        self.errors = 0
        self.last_error = ""


class UpstreamManager:
    def __init__(self) -> None:
        self._conns: dict[str, _Conn] = {}
        self._connect_locks: dict[str, threading.Lock] = {}
        self._global = threading.Lock()
        self._dirty: dict[str, str] = {}
        self._dirty_event = threading.Event()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._last_discovery: dict[str, float] = {}
        self._last_errors: dict[str, str] = {}
        self._snapshots: dict[str, dict[str, Any]] = {}
        self.discovery_callback: DiscoveryCallback | None = None
        self.monitor_callback: MonitorCallback | None = None
        self.server_lister: Callable[[], list[tuple[str, bool]]] | None = None

    # -- connections -------------------------------------------------------------------------
    def _lock_for(self, server_id: str) -> threading.Lock:
        with self._global:
            lock = self._connect_locks.get(server_id)
            if lock is None:
                lock = threading.Lock()
                self._connect_locks[server_id] = lock
            return lock

    def _on_notification(self, server_id: str) -> Callable[[str, dict[str, Any]], None]:
        def handler(method: str, params: dict[str, Any]) -> None:
            if method in {"notifications/tools/list_changed", "notifications/resources/list_changed",
                          "notifications/prompts/list_changed"}:
                self.mark_dirty(server_id, f"upstream sent {method}")

        return handler

    def get_client(self, row: Any) -> BaseClient:
        settings = get_settings()
        transport, config = server_connection_config(row)
        fingerprint = canonical_hash({"transport": transport, "config": config})
        with self._lock_for(row.server_id):
            conn = self._conns.get(row.server_id)
            if conn and conn.client.alive and conn.fingerprint == fingerprint:
                return conn.client
            if conn:
                self._safe_close(conn.client)
                self._conns.pop(row.server_id, None)
            if transport == "stdio" and not settings.allow_stdio_servers:
                raise UpstreamError("stdio servers are disabled (SENTINEL_ALLOW_STDIO_SERVERS=false)")
            try:
                client = connect(
                    row.server_id,
                    transport,
                    config,
                    on_notification=self._on_notification(row.server_id),
                    timeout=settings.upstream_connect_timeout_seconds,
                )
            except Exception as exc:
                self._last_errors[row.server_id] = str(exc)
                raise
            self._conns[row.server_id] = _Conn(client, fingerprint)
            self._last_errors.pop(row.server_id, None)
            return client

    def _safe_close(self, client: BaseClient) -> None:
        try:
            client.close()
        except Exception:
            log.debug("close failed", exc_info=True)

    def disconnect(self, server_id: str) -> None:
        with self._lock_for(server_id):
            conn = self._conns.pop(server_id, None)
        if conn:
            self._safe_close(conn.client)

    def list_tools(self, row: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        client = self.get_client(row)
        try:
            tools = client.list_tools(timeout=get_settings().upstream_timeout_seconds)
        except UpstreamError:
            # one reconnect for read-only discovery (safe to repeat)
            self.disconnect(row.server_id)
            client = self.get_client(row)
            tools = client.list_tools(timeout=get_settings().upstream_timeout_seconds)
        info = {
            "serverInfo": client.server_info,
            "protocolVersion": client.protocol_version,
            "capabilities": client.server_capabilities,
            "instructions": client.instructions,
            "transport": client.transport,
        }
        return tools, info

    def call_tool(self, row: Any, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool and return the raw result plus independently observed telemetry.

        Tool calls are never retried after they were sent (they may not be idempotent).
        """
        client = self.get_client(row)
        conn = self._conns.get(row.server_id)
        before = procmon.snapshot(client.pid)
        started = time.perf_counter()
        telemetry: dict[str, Any] = {}
        result: dict[str, Any] | None = None
        try:
            result = client.call_tool(tool_name, arguments, timeout=get_settings().upstream_timeout_seconds)
        except Exception as exc:
            if conn:
                conn.errors += 1
                conn.last_error = str(exc)
            telemetry["error"] = str(exc)
            setattr(exc, "telemetry", telemetry)
            raise
        finally:
            after = procmon.snapshot(client.pid)
            if conn:
                conn.calls += 1
            telemetry["latency_ms"] = round((time.perf_counter() - started) * 1000.0, 1)
            telemetry["process"] = procmon.diff(before, after)
        return {"result": result or {}, "telemetry": telemetry}

    def status(self, server_id: str) -> dict[str, Any]:
        conn = self._conns.get(server_id)
        if not conn:
            return {
                "connected": False,
                "last_error": self._last_errors.get(server_id, ""),
                "process": self._snapshots.get(server_id),
            }
        c = conn.client
        return {
            "connected": c.alive,
            "transport": c.transport,
            "pid": c.pid,
            "protocol_version": c.protocol_version,
            "server_info": c.server_info,
            "connected_at": c.connected_at,
            "last_activity": c.last_activity,
            "calls": conn.calls,
            "errors": conn.errors,
            "last_error": conn.last_error or self._last_errors.get(server_id, ""),
            "logs": c.stderr_tail(40),
            "process": self._snapshots.get(server_id),
        }

    # -- background jobs ---------------------------------------------------------------------
    def mark_dirty(self, server_id: str, reason: str) -> None:
        self._dirty[server_id] = reason
        self._dirty_event.set()

    def note_discovered(self, server_id: str) -> None:
        self._last_discovery[server_id] = time.time()

    def start(self) -> None:
        if self._threads:
            return
        self._stop.clear()
        for target, name in ((self._discovery_loop, "sentinel-discovery"), (self._monitor_loop, "sentinel-monitor")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def _discovery_loop(self) -> None:
        settings = get_settings()
        time.sleep(1.0)
        while not self._stop.is_set():
            due: dict[str, str] = {}
            while self._dirty:
                sid, reason = self._dirty.popitem()
                due[sid] = reason
            if self.server_lister is not None:
                try:
                    for sid, enabled in self.server_lister():
                        last = self._last_discovery.get(sid, 0.0)
                        if enabled and time.time() - last >= settings.discovery_interval_seconds and sid not in due:
                            due[sid] = "scheduled integrity re-scan"
                except Exception:
                    log.exception("server listing failed")
            for sid, reason in due.items():
                if self._stop.is_set():
                    break
                self._last_discovery[sid] = time.time()
                if self.discovery_callback is not None:
                    try:
                        self.discovery_callback(sid, reason)
                    except Exception:
                        log.exception("discovery for %s failed", sid)
            self._dirty_event.wait(timeout=2.0)
            self._dirty_event.clear()

    def _monitor_loop(self) -> None:
        settings = get_settings()
        while not self._stop.wait(timeout=max(1.0, settings.process_monitor_interval_seconds)):
            if not settings.process_monitor_enabled:
                continue
            for sid, conn in list(self._conns.items()):
                pid = conn.client.pid
                if not pid:
                    continue
                snap = procmon.snapshot(pid)
                if snap is None:
                    continue
                data = snap.as_dict()
                self._snapshots[sid] = data
                if self.monitor_callback is not None:
                    try:
                        self.monitor_callback(sid, data)
                    except Exception:
                        log.exception("monitor callback failed for %s", sid)

    def shutdown(self) -> None:
        self._stop.set()
        self._dirty_event.set()
        for sid in list(self._conns):
            self.disconnect(sid)
        self._threads.clear()


_manager: UpstreamManager | None = None
_manager_lock = threading.Lock()


def get_manager() -> UpstreamManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = UpstreamManager()
        return _manager


def reset_manager() -> None:
    global _manager
    with _manager_lock:
        if _manager is not None:
            _manager.shutdown()
        _manager = None
