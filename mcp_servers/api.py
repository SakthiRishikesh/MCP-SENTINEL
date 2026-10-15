"""Authenticated HTTP access to the running MCP-Sentinel API."""

from __future__ import annotations

import os
from typing import Any

import httpx


class SentinelApi:
    def __init__(self) -> None:
        self.base_url = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8443").rstrip("/")
        self.token = os.environ.get("SENTINEL_TOKEN", "").strip()
        self.client = httpx.Client(timeout=20.0, trust_env=False)

    def get(self, route: str, params: dict[str, Any] | None = None) -> Any:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            response = self.client.get(f"{self.base_url}{route}", params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:500]
            if exc.response.status_code in {401, 403}:
                raise RuntimeError(
                    f"Sentinel API rejected access ({exc.response.status_code}); configure a valid SENTINEL_TOKEN "
                    "for this server, or use the API's local demo mode."
                ) from exc
            raise RuntimeError(f"Sentinel API returned HTTP {exc.response.status_code}: {detail}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"Could not read live Sentinel data from {self.base_url}: {exc}") from exc

