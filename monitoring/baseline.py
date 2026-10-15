"""Statistical behavioural baseline per tool (behavioural rug-pull detection).

Definition pinning cannot see a server that keeps its description and changes its code. The
baseline learns, per tool, what normal execution looks like - latency, output size, output
structure, domains referenced in outputs, whether outputs ever contained instructions or
secrets, which child processes / remote hosts appear during calls (stdio servers) - and flags
drift once it has enough samples. Anomalies are never learned into the baseline, so a
compromised tool keeps alerting instead of becoming the new normal.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from monitoring.process import classify_children

MIN_SAMPLES = 5
MAX_SET = 40


@dataclass
class Observation:
    latency_ms: float = 0.0
    output_bytes: int = 0
    is_error: bool = False
    domains: list[str] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)
    injection: bool = False
    secrets: int = 0
    new_child_names: list[str] = field(default_factory=list)
    new_remote_hosts: list[str] = field(default_factory=list)


def _welford(stats: dict[str, Any], name: str, value: float) -> tuple[float, float]:
    n = int(stats.get(f"{name}_n", 0)) + 1
    mean = float(stats.get(f"{name}_mean", 0.0))
    m2 = float(stats.get(f"{name}_m2", 0.0))
    delta = value - mean
    mean += delta / n
    m2 += delta * (value - mean)
    stats[f"{name}_n"], stats[f"{name}_mean"], stats[f"{name}_m2"] = n, mean, m2
    std = math.sqrt(m2 / (n - 1)) if n > 1 else 0.0
    return mean, std


def _zscore(stats: dict[str, Any], name: str, value: float) -> float:
    n = int(stats.get(f"{name}_n", 0))
    if n < 2:
        return 0.0
    mean = float(stats.get(f"{name}_mean", 0.0))
    std = math.sqrt(float(stats.get(f"{name}_m2", 0.0)) / (n - 1))
    return abs(value - mean) / max(std, 0.1 * abs(mean), 1.0)


def update(baseline: dict[str, Any] | None, obs: Observation) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Return (new baseline, anomalies[(severity, message)])."""
    b = dict(baseline or {})
    n = int(b.get("n", 0))
    learning = n < MIN_SAMPLES
    anomalies: list[tuple[str, str]] = []
    domains = set(b.get("domains") or [])
    keys = set(b.get("keys") or [])
    children = set(b.get("children") or [])
    hosts = set(b.get("hosts") or [])

    if not learning and not obs.is_error:
        z_lat = _zscore(b, "lat", obs.latency_ms)
        if z_lat > 6 and obs.latency_ms > 3 * float(b.get("lat_mean", 0)) + 500:
            anomalies.append(("LOW", f"latency drift ({obs.latency_ms:.0f} ms vs ~{float(b.get('lat_mean', 0)):.0f} ms)"))
        z_size = _zscore(b, "size", obs.output_bytes)
        if z_size > 6 and obs.output_bytes > 4 * float(b.get("size_mean", 0)) + 2048:
            anomalies.append(("MEDIUM", f"output size anomaly ({obs.output_bytes} bytes vs ~{float(b.get('size_mean', 0)):.0f})"))
        new_domains = sorted(set(obs.domains) - domains)
        if new_domains and len(domains) <= 3:
            anomalies.append(("MEDIUM", f"output references new external domain(s): {', '.join(new_domains[:3])}"))
        new_keys = sorted(set(obs.keys) - keys)
        if new_keys and keys and len(new_keys) >= 2:
            anomalies.append(("LOW", f"output structure changed (new fields: {', '.join(new_keys[:4])})"))
        if obs.injection and not b.get("injection_seen"):
            anomalies.append(("HIGH", "tool output now contains prompt-injection content (never seen in its baseline)"))
        if obs.secrets and not b.get("secrets_seen"):
            anomalies.append(("MEDIUM", "tool output now contains secret-like values (never seen in its baseline)"))
    if obs.injection and learning:
        anomalies.append(("HIGH", "tool output contains prompt-injection content"))

    suspicious_children, unusual_children = classify_children(obs.new_child_names)
    if suspicious_children:
        anomalies.append(("HIGH", f"spawned suspicious process(es): {', '.join(sorted(set(suspicious_children)))}"))
    new_unusual = sorted(set(unusual_children) - children)
    if new_unusual and not learning:
        anomalies.append(("MEDIUM", f"spawned new process(es): {', '.join(new_unusual[:4])}"))
    new_hosts = sorted(set(obs.new_remote_hosts) - hosts)
    if new_hosts and not learning:
        anomalies.append(("MEDIUM", f"connected to new remote host(s): {', '.join(new_hosts[:4])}"))

    # learn (never learn behaviour that raised a MEDIUM+ anomaly)
    flagged = any(sev in {"MEDIUM", "HIGH", "CRITICAL"} for sev, _ in anomalies)
    b["n"] = n + 1
    if not obs.is_error:
        _welford(b, "lat", obs.latency_ms)
        _welford(b, "size", float(obs.output_bytes))
    b["errors"] = int(b.get("errors", 0)) + (1 if obs.is_error else 0)
    if learning or not flagged:
        b["domains"] = sorted((domains | set(obs.domains)))[:MAX_SET]
        b["keys"] = sorted((keys | set(obs.keys)))[:MAX_SET]
        b["children"] = sorted((children | set(unusual_children)))[:MAX_SET]
        b["hosts"] = sorted((hosts | set(obs.new_remote_hosts)))[:MAX_SET]
        if obs.secrets:
            b["secrets_seen"] = True
    # anomaly score decays (half-life 30 min) and feeds the risk engine for later calls
    now = time.time()
    prev = float(b.get("anomaly_score", 0.0)) * 0.5 ** ((now - float(b.get("anomaly_at", now))) / 1800.0)
    weight = {"LOW": 0.05, "MEDIUM": 0.2, "HIGH": 0.45, "CRITICAL": 0.8}
    for sev, _ in anomalies:
        prev = 1 - (1 - prev) * (1 - weight.get(sev, 0.05))
    b["anomaly_score"] = round(prev, 4)
    b["anomaly_at"] = now
    if anomalies:
        recent = list(b.get("recent_anomalies") or [])
        recent.extend({"severity": s, "message": m, "at": now} for s, m in anomalies)
        b["recent_anomalies"] = recent[-20:]
    b["learning"] = b["n"] < MIN_SAMPLES
    return b, anomalies


def drift_likelihood(baseline: dict[str, Any] | None) -> float:
    b = baseline or {}
    score = float(b.get("anomaly_score", 0.0))
    at = float(b.get("anomaly_at", time.time()))
    return round(score * 0.5 ** ((time.time() - at) / 1800.0), 4)
