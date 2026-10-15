"""Workflow risk memory: suspicion carries over between calls and decays over time.

Zero trust means re-evaluating continuously, not judging each call in isolation. Anomalies
observed earlier in a workflow (a suspicious transition, an injection in a tool output, a
blocked exfiltration attempt) raise the likelihood for the following calls. Memory is keyed by
anomaly *kind* and excludes kinds already present in the current call, so honest retries of
the same action do not ratchet risk upward; it decays with a configurable half-life.
"""

from __future__ import annotations

import time

from risk.engine import Evidence
from sentinel.config import Settings
from sentinel.store import StateStore

MIN_REMEMBERED = 0.15
DAMPING = 0.6
CAP = 0.6


class RiskMemory:
    def __init__(self, store: StateStore, settings: Settings) -> None:
        self.store = store
        self.settings = settings

    def _key(self, workflow_id: str) -> str:
        return f"riskmem:{workflow_id}"

    def _decayed(self, workflow_id: str) -> dict[str, dict]:
        data = self.store.get_json(self._key(workflow_id))
        if not isinstance(data, dict):
            return {}
        now = time.time()
        half_life = max(30.0, float(self.settings.risk_memory_half_life_seconds))
        out = {}
        for name, item in data.items():
            try:
                p = float(item["p"]) * 0.5 ** ((now - float(item["t"])) / half_life)
            except (KeyError, TypeError, ValueError):
                continue
            if p >= 0.02:
                out[name] = {"p": p, "t": now, "reason": item.get("reason", name)}
        return out

    def evidence(self, workflow_id: str, exclude: set[str]) -> Evidence | None:
        items = {k: v for k, v in self._decayed(workflow_id).items() if k not in exclude}
        if not items:
            return None
        remaining = 1.0
        for item in items.values():
            remaining *= 1.0 - item["p"]
        p = min(CAP, (1.0 - remaining) * DAMPING)
        if p < 0.03:
            return None
        top = sorted(items.items(), key=lambda kv: -kv[1]["p"])[:3]
        reason = "earlier in this workflow: " + "; ".join(v["reason"] for _, v in top)
        return Evidence("workflow_memory", p, reason, "memory", memorable=False)

    def remember(self, workflow_id: str, evidence: list[Evidence]) -> None:
        current = self._decayed(workflow_id)
        changed = False
        for e in evidence:
            if not e.memorable or e.category not in {"anomaly", "dataflow", "runtime"} or e.likelihood < MIN_REMEMBERED:
                continue
            prev = current.get(e.name, {}).get("p", 0.0)
            if e.likelihood > prev:
                current[e.name] = {"p": e.likelihood, "t": time.time(), "reason": e.reason[:160]}
                changed = True
        if changed:
            self.store.setex(self._key(workflow_id), self.settings.workflow_ttl_seconds, current)

    def snapshot(self, workflow_id: str) -> dict[str, dict]:
        return self._decayed(workflow_id)
