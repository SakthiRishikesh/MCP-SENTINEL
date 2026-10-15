"""Connections from MCP-Sentinel to upstream MCP servers (stdio, Streamable HTTP, legacy SSE)."""

from sentinel.upstream.client import McpError, UpstreamError
from sentinel.upstream.manager import UpstreamManager, get_manager, server_connection_config

__all__ = ["McpError", "UpstreamError", "UpstreamManager", "get_manager", "server_connection_config"]
