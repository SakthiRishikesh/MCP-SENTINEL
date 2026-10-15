"""Toolset-level toxic-flow analysis ("lethal trifecta" / Agents Rule of Two).

Per-tool checks cannot see this risk: an agent that can (A) read private data, (B) ingest
attacker-controlled content and (C) communicate externally can be prompt-injected through B
into moving A out through C - even if every individual tool is benign. This module maps the
exposed toolset onto those three roles, enumerates reachable toxic paths and suggests the
smallest set of servers whose removal breaks every path. The per-workflow runtime guard in
``dataflow.guard`` enforces the same idea call by call.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any

from sentinel.types import FlowRole


@dataclass
class ToolNode:
    exposed_name: str
    server_id: str
    roles: set[str]
    capabilities: set[str]


def analyze(tools: list[ToolNode], max_paths: int = 12) -> dict[str, Any]:
    private = [t for t in tools if FlowRole.PRIVATE_SOURCE.value in t.roles]
    untrusted = [t for t in tools if FlowRole.UNTRUSTED_SOURCE.value in t.roles]
    egress = [t for t in tools if FlowRole.EGRESS_SINK.value in t.roles]
    exec_tools = [t for t in tools if "CODE_EXECUTION" in t.capabilities]
    secret_tools = [t for t in tools if "SECRET_ACCESS" in t.capabilities]

    paths: list[dict[str, Any]] = []
    for p, u, e in product(private, untrusted, egress):
        if len(paths) >= max_paths:
            break
        if p.exposed_name == e.exposed_name and p.exposed_name == u.exposed_name and len(tools) > 1:
            continue
        servers = {p.server_id, u.server_id, e.server_id}
        paths.append({
            "private_source": p.exposed_name,
            "untrusted_source": u.exposed_name,
            "egress_sink": e.exposed_name,
            "servers": sorted(servers),
            "single_server": len(servers) == 1,
        })

    trifecta = bool(private and untrusted and egress)
    if trifecta and (exec_tools or secret_tools):
        level = "CRITICAL"
    elif trifecta:
        level = "HIGH"
    elif sum(bool(x) for x in (private, untrusted, egress)) == 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Greedy hitting set: fewest servers whose removal leaves at least one leg empty.
    remediation: list[str] = []
    if trifecta:
        legs = {
            "private": {t.server_id for t in private},
            "untrusted": {t.server_id for t in untrusted},
            "egress": {t.server_id for t in egress},
        }
        best_leg = min(legs, key=lambda k: len(legs[k]))
        remediation = sorted(legs[best_leg])

    return {
        "level": level,
        "lethal_trifecta": trifecta,
        "counts": {
            "private_sources": len(private),
            "untrusted_sources": len(untrusted),
            "egress_sinks": len(egress),
            "code_execution": len(exec_tools),
            "secret_access": len(secret_tools),
        },
        "legs": {
            "private_sources": [t.exposed_name for t in private][:30],
            "untrusted_sources": [t.exposed_name for t in untrusted][:30],
            "egress_sinks": [t.exposed_name for t in egress][:30],
        },
        "injection_to_rce": bool(untrusted and exec_tools),
        "example_paths": paths,
        "remediation": {
            "remove_or_restrict_servers": remediation,
            "explanation": (
                "Restricting these servers removes an entire leg of every toxic path; Sentinel additionally "
                "enforces the trifecta per workflow at call time."
                if remediation else "No complete toxic path in the current toolset."
            ),
        },
    }
