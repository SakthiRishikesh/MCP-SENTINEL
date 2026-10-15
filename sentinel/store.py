from __future__ import annotations

import json
import threading
import time
from typing import Any


class MemoryTTLStore:
    """In-process TTL store used when Redis is unavailable (tests / single-node demo)."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def setex(self, key: str, ttl: int, value: Any) -> None:
        payload = json.dumps(value) if not isinstance(value, str) else value
        with self._lock:
            self._data[key] = (time.time() + ttl, payload)

    def get(self, key: str) -> str | None:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, val = item
            if exp < time.time():
                self._data.pop(key, None)
                return None
            return val

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def keys(self, prefix: str) -> list[str]:
        now = time.time()
        with self._lock:
            out = []
            for k, (exp, _) in list(self._data.items()):
                if exp < now:
                    self._data.pop(k, None)
                    continue
                if k.startswith(prefix):
                    out.append(k)
            return out


class StateStore:
    def __init__(self, redis_url: str | None = None) -> None:
        self._memory = MemoryTTLStore()
        self._redis = None
        if redis_url:
            try:
                import redis

                client = redis.Redis.from_url(
                    redis_url, decode_responses=True, socket_connect_timeout=1.0, socket_timeout=2.0
                )
                client.ping()
                self._redis = client
            except Exception:
                self._redis = None

    def setex(self, key: str, ttl: int, value: Any) -> None:
        payload = json.dumps(value) if not isinstance(value, (str, bytes)) else value
        if self._redis is not None:
            self._redis.setex(key, ttl, payload)
            return
        self._memory.setex(key, ttl, payload)

    def get_json(self, key: str) -> Any | None:
        raw = self._redis.get(key) if self._redis is not None else self._memory.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return raw

    def delete(self, key: str) -> None:
        if self._redis is not None:
            self._redis.delete(key)
            return
        self._memory.delete(key)

    def keys(self, prefix: str) -> list[str]:
        if self._redis is not None:
            return [k for k in self._redis.scan_iter(f"{prefix}*")]
        return self._memory.keys(prefix)

    @property
    def backend(self) -> str:
        return "redis" if self._redis is not None else "memory"
