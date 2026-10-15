"""Plain-language safety verdict for a newly added MCP server.

Everything Sentinel learns while adding a server (supply-chain checks, honeypot run, sandbox
behaviour audit, vulnerability scan) is condensed into one verdict a non-specialist can act on:

* SAFE    - nothing above LOW severity
* CAUTION - medium-severity issues; usable, with the listed fixes recommended
* UNSAFE  - a HIGH/CRITICAL finding, a misbehaving tool or a compromised honeypot run.
            The server is still added (as requested) but its sensitive tools stay restricted
            until an administrator fixes the issues or explicitly accepts the risk.

Design risks that Sentinel contains at runtime on every call (toxic tool combinations such as
the lethal trifecta, code-execution capability) are listed under ``contained`` and count as
CAUTION, not UNSAFE: taint tracking, step-up approval and the pre-flight sandbox handle them.
"""

from __future__ import annotations

from typing import Any

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SUPPLY_CHAIN_FIXES = {
    "unpinned_package": "Pin the package to an exact version (pkg@1.2.3 / pkg==1.2.3) so an update cannot silently change the code.",
    "typosquat": "Double-check the package name: it is one or two letters away from a well-known MCP server.",
    "shell_wrapper": "Launch the server binary directly instead of through a shell command.",
    "secret_in_args": "Move credentials out of the command line into the server's environment settings.",
    "plaintext_transport": "Use the server's https:// URL.",
    "credentials_in_url": "Remove credentials from the URL and use a bearer token instead.",
    "container_privileged": "Remove --privileged from the docker command.",
    "container_docker_socket": "Do not mount the Docker socket into the server container.",
    "container_host_root": "Mount only the folders the server needs.",
    "unpinned_image": "Pin the container image to a version tag or digest.",
}
HONEYPOT_LEVEL = {"MALICIOUS_OR_COMPROMISED": "CRITICAL", "HIGH_RISK": "HIGH", "SUSPICIOUS": "MEDIUM"}
# scan categories describing what the toolset *can* do rather than a defect in the server
CONTAINED_CATEGORIES = {"toxic_flow", "capability"}
CONTAINED_NOTE = {
    "toxic_flow": "Sentinel tracks tainted data across calls and blocks the dangerous combination at runtime.",
    "capability": "Sentinel requires step-up approval and a sandbox pre-flight before these tools run.",
}


def assess(
    *,
    scan: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None = None,
    honeypot: dict[str, Any] | None = None,
    audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    issues: list[tuple[str, str, str]] = []  # (severity, title, fix)
    contained: list[str] = []
    for v in (scan or {}).get("vulnerabilities") or []:
        if v.get("category") in CONTAINED_CATEGORIES and SEVERITY_RANK.get(v["severity"], 0) >= SEVERITY_RANK["HIGH"]:
            contained.append(f"{v['title']}: {CONTAINED_NOTE[v['category']]}")
            issues.append(("MEDIUM", v["title"], v.get("remediation") or ""))
            continue
        issues.append((v["severity"], v["title"], v.get("remediation") or ""))
    for f in findings or []:
        if f.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}:
            issues.append((f["severity"], f.get("title", f.get("category", "finding")), SUPPLY_CHAIN_FIXES.get(f.get("category", ""), "")))
    cls = (honeypot or {}).get("classification")
    if cls in HONEYPOT_LEVEL:
        issues.append((HONEYPOT_LEVEL[cls], f"misbehaved in the honeypot sandbox ({cls.replace('_', ' ').lower()})",
                       "Do not give this server real credentials or data until the honeypot findings are explained."))
    for tool, result in ((audit or {}).get("tools") or {}).items():
        verdict = result.get("verdict")
        if verdict == "MALICIOUS":
            issues.append(("CRITICAL", f"tool '{tool}' behaved maliciously in the sandbox audit: {'; '.join(result.get('reasons', [])[:2])}",
                           "Remove this server, or disable the tool, and report it to its publisher."))
        elif verdict in {"SUSPICIOUS", "DANGEROUS"}:
            # a synthetic run is a hint, not proof: each real call is pre-flighted and escalated anyway
            issues.append(("MEDIUM", f"tool '{tool}' showed unexpected behaviour in the sandbox audit: {'; '.join(result.get('reasons', [])[:2])}",
                           "Review what the tool does before allowing it; Sentinel asks for approval whenever a call repeats it."))

    worst = max((SEVERITY_RANK.get(s, 0) for s, _, _ in issues), default=0)
    verdict = "UNSAFE" if worst >= SEVERITY_RANK["HIGH"] else "CAUTION" if worst == SEVERITY_RANK["MEDIUM"] else "SAFE"
    ordered = sorted(issues, key=lambda i: -SEVERITY_RANK.get(i[0], 0))
    fixes: list[str] = []
    for _, _, fix in ordered:
        if fix and fix not in fixes:
            fixes.append(fix)
    reasons = [f"{s}: {t}" for s, t, _ in ordered if SEVERITY_RANK.get(s, 0) >= SEVERITY_RANK["MEDIUM"]]
    if verdict == "UNSAFE":
        headline = ("This MCP server is NOT SAFE to use as it is. It was added, but Sentinel keeps its sensitive tools "
                    "restricted until the issues below are fixed or an administrator accepts the risk.")
    elif verdict == "CAUTION":
        headline = "This MCP server can be used, but it has weaknesses. Apply the recommended fixes when you can."
    else:
        headline = "No significant problems found. Sentinel keeps checking every call and every update."
    return {"verdict": verdict, "headline": headline, "reasons": reasons[:12], "recommendations": fixes[:12],
            "contained": contained[:6], "grade": ((scan or {}).get("summary") or {}).get("grade")}


def blocking_reasons(verdict: dict[str, Any]) -> list[str]:
    """The HIGH/CRITICAL reasons that make a server UNSAFE (what an administrator accepts)."""
    return [r for r in verdict.get("reasons", []) if r.startswith(("HIGH:", "CRITICAL:"))]
