"""Entity behaviour analytics (UEBA) for the people and agents calling tools.

Sentinel profiles upstream *servers* in depth; this does the same for the *caller*. Every
executed call updates a per-subject baseline — which tools, servers and capabilities it uses,
at which hours, how often, through which agents, and how much of that is sensitive. Once a
subject has enough history, calls that deviate from its baseline become risk evidence:

* a sensitive capability the subject has never used before
* a server the subject has never reached before
* a known subject suddenly acting through a new agent (possible token theft / impersonation)
* a sensitive action at an hour the subject is never active
* a burst of calls far above the subject's normal rate (automation / runaway agent)
* continued sensitive attempts after repeated denials (probing / confused-deputy abuse)

This is evidence about the *caller*, independent of whether the server is malicious. It feeds
the same noisy-OR risk engine as the server-side detectors. During the learning window a new
subject is never penalised for doing things for the first time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.types import SENSITIVE_CAPABILITIES, Capability, Sensitivity, utcnow

# Calls observed before deviations are treated as anomalies (everything is new at the start).
LEARN_MIN = 8
# Keep the per-subject maps bounded so one noisy subject cannot grow the row without limit.
MAX_KEYS = 200


def _blank(subject: str) -> dict[str, Any]:
    now = utcnow().isoformat()
    return {
        "subject": subject,
        "first_seen": now,
        "last_seen": now,
        "calls": 0,          # executed (allowed) calls counted into the baseline
        "denied": 0,         # calls blocked / denied for this subject (lifetime)
        "denied_at": [],     # Unix timestamps of each denial (for time-decayed scoring)
        "sensitive_calls": 0,
        "tools": {},         # exposed_name -> count
        "servers": {},       # server_id -> count
        "capabilities": {},  # capability value -> count
        "agents": {},        # agent_id -> count
        "hours": [0] * 24,   # UTC hour-of-day histogram of executed calls
        "peak_minute_rate": 0,
    }


def _bump(mapping: dict[str, int], key: str, cap: int = MAX_KEYS) -> None:
    if not key:
        return
    if key in mapping or len(mapping) < cap:
        mapping[key] = int(mapping.get(key, 0)) + 1


def normalize(profile: dict[str, Any] | None, subject: str) -> dict[str, Any]:
    """A profile dict with every field present (older / partial rows are healed)."""
    base = _blank(subject)
    if isinstance(profile, dict):
        for key, value in profile.items():
            if key in base:
                base[key] = value
    hours = base.get("hours") or []
    base["hours"] = ([int(h) for h in hours] + [0] * 24)[:24]
    for field_name in ("tools", "servers", "capabilities", "agents"):
        base[field_name] = {str(k): int(v) for k, v in (base.get(field_name) or {}).items()}
    base["subject"] = subject
    return base


@dataclass
class EntityAssessment:
    evidence: list[tuple[str, float, str]] = field(default_factory=list)  # (name, likelihood, reason)
    anomalies: list[str] = field(default_factory=list)
    learning: bool = False
    novelty: dict[str, bool] = field(default_factory=dict)


def assess(
    profile: dict[str, Any],
    *,
    agent_id: str,
    server_id: str,
    exposed_name: str,
    capability: Capability,
    sensitivity: Sensitivity,
    recent_calls_last_minute: int = 0,
) -> EntityAssessment:
    """Evidence about *this caller* making *this call*, given its learned baseline."""
    calls = int(profile.get("calls") or 0)
    sensitive = capability in SENSITIVE_CAPABILITIES or sensitivity in {Sensitivity.HIGH, Sensitivity.CRITICAL}
    novelty = {
        "server": bool(server_id) and server_id not in (profile.get("servers") or {}),
        "tool": bool(exposed_name) and exposed_name not in (profile.get("tools") or {}),
        "capability": capability.value not in (profile.get("capabilities") or {}),
        "agent": bool(agent_id) and agent_id not in (profile.get("agents") or {}) and agent_id not in {"", "unknown-agent"},
    }
    res = EntityAssessment(learning=calls < LEARN_MIN, novelty=novelty)
    if res.learning:
        return res  # still learning this subject: first-time behaviour is expected, not anomalous

    def ev(name: str, p: float, reason: str) -> None:
        res.evidence.append((name, p, reason))
        res.anomalies.append(reason)

    if novelty["capability"] and sensitive:
        ev("entity_new_sensitive_capability", 0.3,
           f"first use of the {capability.value} capability by {profile['subject']} in {calls} prior calls")
    elif novelty["capability"] and capability not in {Capability.READ}:
        ev("entity_new_capability", 0.12, f"{profile['subject']} has not used the {capability.value} capability before")
    if novelty["agent"]:
        known = ", ".join(sorted((profile.get("agents") or {}))[:3]) or "none"
        ev("entity_new_agent", 0.3,
           f"{profile['subject']} is acting through a new agent '{agent_id}' (previously: {known}) — possible token reuse")
    if novelty["server"] and sensitive:
        ev("entity_new_server_sensitive", 0.2, f"{profile['subject']} has never used this server, and this is a {capability.value} call")
    elif novelty["server"]:
        ev("entity_new_server", 0.08, f"{profile['subject']} has not used this server before")
    hours = profile.get("hours") or [0] * 24
    hour = utcnow().hour
    active_hours = sum(1 for h in hours if h)
    if sensitive and active_hours >= 3 and hours[hour] == 0:
        ev("entity_off_hours", 0.15, f"sensitive call at an hour ({hour:02d}:00 UTC) when {profile['subject']} is normally inactive")
    peak = int(profile.get("peak_minute_rate") or 0)
    if recent_calls_last_minute >= max(12, peak * 3):
        ev("entity_volume_spike", 0.25,
           f"{recent_calls_last_minute} calls in the last minute — well above {profile['subject']}'s usual peak of {peak}/min")
    # Denial history: use a decayed weight so early misconfiguration doesn't penalise forever.
    # Each denial contributes 1.0 at the time it happened, decaying with a 7-day half-life.
    denied_timestamps = list(profile.get("denied_at") or [])
    if denied_timestamps and sensitive:
        import time as _time
        now_ts = _time.time()
        half_life = 7 * 86400  # 7 days
        decayed_weight = sum(
            0.5 ** ((now_ts - float(ts)) / half_life)
            for ts in denied_timestamps
            if isinstance(ts, (int, float))
        )
        if decayed_weight >= 2.0:  # equivalent to ~2+ recent denials
            p = min(0.4, 0.08 + 0.06 * decayed_weight)
            total_denied = int(profile.get("denied") or 0)
            ev("entity_denial_history", p,
               f"{profile['subject']} has {total_denied} denied calls on record "
               f"(recent-weighted: {decayed_weight:.1f}) and is attempting a sensitive action")
    return res


def record(
    profile: dict[str, Any],
    *,
    allowed: bool,
    agent_id: str,
    server_id: str,
    exposed_name: str,
    capability: Capability,
    sensitivity: Sensitivity,
    recent_calls_last_minute: int = 0,
) -> dict[str, Any]:
    """Fold one observed call into the subject's baseline. Returns the updated profile."""
    now = utcnow()
    profile["last_seen"] = now.isoformat()
    if not allowed:
        profile["denied"] = int(profile.get("denied") or 0) + 1
        # Record timestamp for time-decayed denial scoring (keep last 50 denial times)
        import time as _time
        denied_at = list(profile.get("denied_at") or [])
        denied_at.append(_time.time())
        profile["denied_at"] = denied_at[-50:]
        return profile
    profile["calls"] = int(profile.get("calls") or 0) + 1
    _bump(profile["servers"], server_id)
    _bump(profile["tools"], exposed_name)
    _bump(profile["capabilities"], capability.value, cap=len(Capability) + 2)
    _bump(profile["agents"], agent_id if agent_id and agent_id != "unknown-agent" else "")
    profile["agents"].pop("", None)
    profile["hours"][now.hour] = int(profile["hours"][now.hour]) + 1
    if capability in SENSITIVE_CAPABILITIES or sensitivity in {Sensitivity.HIGH, Sensitivity.CRITICAL}:
        profile["sensitive_calls"] = int(profile.get("sensitive_calls") or 0) + 1
    if recent_calls_last_minute > int(profile.get("peak_minute_rate") or 0):
        profile["peak_minute_rate"] = int(recent_calls_last_minute)
    return profile


def summary(profile: dict[str, Any]) -> dict[str, Any]:
    """Compact view for the dashboard's entity list."""
    p = normalize(profile, profile.get("subject", ""))
    calls = p["calls"]
    top_tools = sorted(p["tools"].items(), key=lambda kv: -kv[1])[:5]
    return {
        "subject": p["subject"],
        "first_seen": p["first_seen"],
        "last_seen": p["last_seen"],
        "calls": calls,
        "denied": p["denied"],
        "sensitive_calls": p["sensitive_calls"],
        "sensitive_rate": round(p["sensitive_calls"] / calls, 3) if calls else 0.0,
        "servers": len(p["servers"]),
        "capabilities": sorted(p["capabilities"], key=lambda c: -p["capabilities"][c]),
        "agents": sorted(p["agents"], key=lambda a: -p["agents"][a]),
        "top_tools": [{"tool": t, "count": c} for t, c in top_tools],
        "hours": p["hours"],
        "peak_minute_rate": p["peak_minute_rate"],
        "established": calls >= LEARN_MIN,
    }
