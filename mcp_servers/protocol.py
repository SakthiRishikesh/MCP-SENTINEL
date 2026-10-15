"""Small stdio MCP server transport shared by the project operations tools."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

PROTOCOLS = {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}


class ToolServer:
    def __init__(self, name: str, tools: list[dict[str, Any]], handlers: dict[str, Callable[[dict[str, Any]], Any]]) -> None:
        self.name = name
        self.tools = tools
        self.handlers = handlers

    def _handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if "id" not in message:
            return None
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}

        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in PROTOCOLS else "2025-06-18"
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": "1.0.0"},
            }
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": self.tools}}
        if method == "tools/call":
            name = str(params.get("name") or "")
            arguments = params.get("arguments") or {}
            handler = self.handlers.get(name)
            if handler is None:
                return self._error(request_id, -32602, f"Unknown tool: {name}")
            if not isinstance(arguments, dict):
                return self._error(request_id, -32602, "Tool arguments must be an object")
            try:
                value = handler(arguments)
                text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
                structured = value if isinstance(value, dict) else {"value": value}
                result = {"content": [{"type": "text", "text": text}], "structuredContent": structured, "isError": False}
            except Exception as exc:  # MCP clients receive a useful tool error; details stay off stdout.
                print(f"[{self.name}] {name} failed: {exc}", file=sys.stderr, flush=True)
                result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        return self._error(request_id, -32601, f"Method not found: {method}")

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    def run(self) -> None:
        for line in sys.stdin:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                response = self._error(None, -32700, "Parse error")
            else:
                if not isinstance(message, dict):
                    response = self._error(None, -32600, "Request must be an object")
                else:
                    response = self._handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=True, separators=(",", ":")) + "\n")
                sys.stdout.flush()
