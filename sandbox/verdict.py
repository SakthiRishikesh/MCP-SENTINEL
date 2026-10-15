"""Verdict rules for a shadow (pre-flight) run.

The sandbox observes what a tool call *does* - files created / modified / deleted, planted
credentials opened or leaked, network destinations, processes - independently of what the
tool claims. These rules turn the observation into one verdict:

* MALICIOUS    - the tool did something no honest tool does (reads or leaks the planted
                 credentials, contacts the network with them, a read-only tool changing files,
                 deleting files it was not asked to touch, installing persistence, spawning
                 network utilities). The call is blocked even if a user approves it, and the
                 tool is quarantined.
* DANGEROUS    - an honest-looking call whose effect is out of proportion (mass deletion,
                 wiping most of a folder). The call is blocked; the tool is not quarantined.
* SUSPICIOUS   - needs a human: a local tool contacting an unknown host, editing CI or editor
                 automation, returning credential material that was explicitly requested.
* INCONCLUSIVE - the sandbox could not run the call (timeout, launch failure).
* SAFE         - nothing above; NOTICE findings are informational.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sandbox.workspace import Change, within

LEVELS = ["SAFE", "INCONCLUSIVE", "SUSPICIOUS", "DANGEROUS", "MALICIOUS"]
EGRESS_CAPS = {"EXTERNAL_LOOKUP", "DATA_TRANSFER"}
READ_ONLY_CAPS = {"READ", "EXTERNAL_LOOKUP"}
SHELLS = {"sh", "bash", "dash", "zsh", "ash", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "telnet", "ftp", "tftp", "nslookup",
                 "dig", "host", "openssl", "base64", "certutil", "bitsadmin", "powershell", "pwsh", "rsync"}
# credential stores and autostart locations (relative to HOME)
HOME_PERSISTENCE = (
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".config/fish/",
    ".ssh/", ".aws/", ".gnupg/", ".config/autostart/", "Library/LaunchAgents/", ".config/systemd/", ".gitconfig",
    ".npmrc", ".pypirc", ".docker/", ".kube/", ".netrc", ".git-credentials", ".config/gh/", ".config/Claude/",
    "Library/Application Support/Claude/", ".cursor/", ".claude.json", ".claude/", "AppData/Roaming/Claude/",
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/", ".config/Code/User/", ".vscode/",
)
HOME_BENIGN = (".cache/", ".npm/", ".local/state/", ".local/share/", ".config/", "tmp/", ".node_repl_history", ".python_history")
# repository automation that runs code later
WORKSPACE_HOOKS = re.compile(r"(^|/)\.git/hooks/[^/]+$")
WORKSPACE_AUTOMATION = re.compile(r"(^|/)(\.github/workflows/|\.gitlab-ci\.yml$|\.vscode/(tasks|settings|launch)\.json$|\.husky/|"
                                  r"\.envrc$|\.pre-commit-config\.yaml$|Makefile$|package\.json$)")
HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}


@dataclass
class Limits:
    max_deletes: int = 25
    max_modifications: int = 100
    max_bytes_written: int = 100 * 1024 * 1024


@dataclass
class Finding:
    level: str  # MALICIOUS | DANGEROUS | SUSPICIOUS | NOTICE
    rule: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"level": self.level, "rule": self.rule, "message": self.message}


@dataclass
class Observation:
    tool: str
    capabilities: set[str]
    read_only: bool
    arguments: dict[str, Any]
    referenced: list[str] = field(default_factory=list)  # real paths named in the arguments
    changes: list[Change] = field(default_factory=list)  # real-path workspace changes
    workspace_files: int = 0
    home_writes: list[str] = field(default_factory=list)  # relative to HOME
    decoy_reads: list[str] = field(default_factory=list)  # planted credential files that were opened
    canary_in_output: bool = False  # planted-file credentials in what would reach the model
    env_canary_in_output: bool = False  # the server's own (stand-in) credentials in its output
    network: list[dict[str, Any]] = field(default_factory=list)  # {host, via, canary}
    processes: list[dict[str, Any]] = field(default_factory=list)  # {name, cmd, blocked}
    output_injection: bool = False
    error: str = ""
    timed_out: bool = False
    partial: bool = False
    tool_error: bool = False
    backend: str = ""
    duration_ms: float = 0.0


def hosts_in(value: Any) -> set[str]:
    found: set[str] = set()

    def visit(v: Any) -> None:
        if isinstance(v, str):
            for m in HOST_RE.finditer(v[:20000]):
                found.add(m.group(1).lower())
        elif isinstance(v, dict):
            for item in v.values():
                visit(item)
        elif isinstance(v, list):
            for item in v:
                visit(item)

    visit(value)
    return found


def _host_allowed(host: str, allowed: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return host in LOCAL_HOSTS or any(host == a or host.endswith("." + a) for a in allowed)


def _explicit(path_fragment: str, obs: Observation) -> bool:
    """Was this HOME-relative path explicitly named in the arguments?"""
    flat = str(obs.arguments)
    return path_fragment.split("/")[-1] in flat or path_fragment in flat


def judge(obs: Observation, *, allowed_hosts: set[str] | None = None, known_processes: set[str] | None = None,
          limits: Limits | None = None) -> dict[str, Any]:
    limits = limits or Limits()
    allowed = {h.lower() for h in (allowed_hosts or set())} | hosts_in(obs.arguments)
    known = {p.lower() for p in (known_processes or set())}
    egress = bool(obs.capabilities & EGRESS_CAPS)
    executes = "CODE_EXECUTION" in obs.capabilities or "INFRASTRUCTURE_CONTROL" in obs.capabilities
    f: list[Finding] = []

    # planted credentials -------------------------------------------------------------------
    for item in obs.network:
        if item.get("canary"):
            f.append(Finding("MALICIOUS", "credential_exfiltration",
                             f"tried to send planted credentials to {item.get('host') or 'the network'}"))
            break
    for item in obs.network:
        if item.get("env_canary") and not _host_allowed(str(item.get("host") or ""), allowed):
            f.append(Finding("MALICIOUS", "credential_exfiltration",
                             f"tried to send its configured credentials to {item.get('host') or 'an unknown host'}"))
            break
    if obs.env_canary_in_output:
        f.append(Finding("SUSPICIOUS", "credential_output", "returns its own API credentials to the AI model"))
    for decoy in sorted(set(obs.decoy_reads)):
        if _explicit(decoy, obs):
            f.append(Finding("SUSPICIOUS", "credential_read_requested", f"reads your credential file ~/{decoy} (it was named in the request)"))
        else:
            f.append(Finding("MALICIOUS", "credential_read", f"opened ~/{decoy} although nothing in the request asked for it"))
    if obs.canary_in_output:
        if obs.decoy_reads and all(_explicit(d, obs) for d in obs.decoy_reads):
            f.append(Finding("SUSPICIOUS", "credential_output", "returns credential material to the AI model"))
        else:
            f.append(Finding("MALICIOUS", "credential_leak", "returned planted credentials it should never have read"))

    # persistence -----------------------------------------------------------------------------
    for rel in sorted(set(obs.home_writes)):
        if any(rel == p.rstrip("/") or rel.startswith(p) for p in HOME_PERSISTENCE):
            level = "SUSPICIOUS" if _explicit(rel, obs) else "MALICIOUS"
            f.append(Finding(level, "persistence", f"writes ~/{rel} (a startup script or credential store)"))
        elif not any(rel.startswith(p) or rel == p.rstrip("/") for p in HOME_BENIGN):
            f.append(Finding("NOTICE", "home_write", f"writes ~/{rel} outside your workspace"))
    for c in obs.changes:
        path = c.real.replace("\\", "/")
        if c.kind == "deleted":
            continue
        if WORKSPACE_HOOKS.search(path) and not path.endswith(".sample"):
            level = "SUSPICIOUS" if c.real in obs.referenced else "MALICIOUS"
            f.append(Finding(level, "git_hook", f"installs a git hook ({path.split('/.git/')[-1]}) that would run code on your next git command"))
        elif WORKSPACE_AUTOMATION.search(path) and not within(c.real, obs.referenced):
            f.append(Finding("SUSPICIOUS", "automation_edit", f"edits {path.rsplit('/', 1)[-1]} (build or CI automation) although it was not asked to"))

    # effects vs. declared behaviour ------------------------------------------------------
    deleted = [c for c in obs.changes if c.kind == "deleted"]
    modified = [c for c in obs.changes if c.kind == "modified"]
    created = [c for c in obs.changes if c.kind == "created"]
    moved = _moves(deleted, created)  # a move/rename is not a deletion
    deleted = [c for c in deleted if c.real not in moved]
    if obs.read_only and (deleted or modified):
        what = ", ".join(c.real for c in (deleted + modified)[:3])
        f.append(Finding("MALICIOUS", "read_only_mutation",
                         f"is declared read-only but {'deleted' if deleted else 'modified'} {len(deleted) + len(modified)} file(s): {what}"))
    elif obs.read_only and created:
        f.append(Finding("SUSPICIOUS", "read_only_write", f"is declared read-only but created {len(created)} file(s)"))
    if obs.referenced:
        collateral_del = [c for c in deleted if not within(c.real, obs.referenced)]
        collateral_mod = [c for c in modified if not within(c.real, obs.referenced)]
        if collateral_del:
            f.append(Finding("MALICIOUS", "collateral_delete",
                             f"deletes {len(collateral_del)} file(s) it was not asked to touch: {', '.join(c.real for c in collateral_del[:3])}"))
        if collateral_mod:
            f.append(Finding("SUSPICIOUS", "collateral_modify",
                             f"modifies {len(collateral_mod)} file(s) beyond the ones named in the request: {', '.join(c.real for c in collateral_mod[:3])}"))

    # blast radius ----------------------------------------------------------------------------
    written = sum(c.size_after or 0 for c in created + modified)
    share = len(deleted) / obs.workspace_files if obs.workspace_files else 0.0
    if len(deleted) > limits.max_deletes:
        f.append(Finding("DANGEROUS", "blast_radius", f"would delete {len(deleted)} files (limit {limits.max_deletes} per call)"))
    elif obs.workspace_files >= 8 and share >= 0.5:
        f.append(Finding("DANGEROUS", "blast_radius", f"would delete {len(deleted)} of {obs.workspace_files} files ({share:.0%} of the folder)"))
    if len(modified) > limits.max_modifications:
        f.append(Finding("DANGEROUS", "blast_radius", f"would modify {len(modified)} files (limit {limits.max_modifications} per call)"))
    if written > limits.max_bytes_written:
        f.append(Finding("DANGEROUS", "blast_radius", f"would write {written // (1024 * 1024)} MB"))

    # network ---------------------------------------------------------------------------------
    unknown = sorted({str(n.get("host") or "").lower() for n in obs.network if not _host_allowed(str(n.get("host") or ""), allowed)} - {""})
    if unknown:
        listed = ", ".join(unknown[:4])
        if egress:
            f.append(Finding("NOTICE", "new_destination", f"contacts {listed}"))
        else:
            f.append(Finding("SUSPICIOUS", "unexpected_network", f"is a local tool but tried to contact {listed}"))

    # processes -------------------------------------------------------------------------------
    for proc in obs.processes:
        name = str(proc.get("name") or "").lower()
        if name in known:
            continue
        if name in NETWORK_TOOLS:
            level = "NOTICE" if executes else "MALICIOUS"
            f.append(Finding(level, "network_utility", f"ran '{name}'{' (blocked by the sandbox)' if proc.get('blocked') else ''}"))
        elif name in SHELLS and not executes:
            f.append(Finding("SUSPICIOUS", "shell", f"started a shell ({proc.get('cmd') or name})"[:200]))
    if obs.output_injection:
        f.append(Finding("NOTICE", "output_injection", "its output contains instructions aimed at the AI model (Sentinel will withhold them)"))

    # verdict -----------------------------------------------------------------------------------
    order = {"MALICIOUS": 4, "DANGEROUS": 3, "SUSPICIOUS": 2}
    worst = max((order.get(x.level, 0) for x in f), default=0)
    if worst:
        verdict = LEVELS[worst]
    elif obs.error or obs.timed_out:
        verdict = "INCONCLUSIVE"
    else:
        verdict = "SAFE"
    return {
        "verdict": verdict,
        "findings": [x.as_dict() for x in f],
        "reasons": [x.message for x in f if x.level != "NOTICE"][:8],
        "preview": preview(obs),
        "unknown_hosts": unknown,
    }


def _moves(deleted: list[Change], created: list[Change]) -> set[str]:
    """Deleted paths that reappear elsewhere with the same name and size (move / rename)."""
    pool: dict[tuple[str, int | None], int] = {}
    for c in created:
        key = (c.real.replace("\\", "/").rsplit("/", 1)[-1], c.size_after)
        pool[key] = pool.get(key, 0) + 1
    moved: set[str] = set()
    for c in deleted:
        key = (c.real.replace("\\", "/").rsplit("/", 1)[-1], c.size_before)
        if pool.get(key):
            pool[key] -= 1
            moved.add(c.real)
    return moved


def preview(obs: Observation) -> dict[str, Any]:
    counts = {k: sum(1 for c in obs.changes if c.kind == k) for k in ("created", "modified", "deleted")}
    parts = [f"{verb} {n} file{'s' if n != 1 else ''}" for verb, n in
             (("create", counts["created"]), ("modify", counts["modified"]), ("delete", counts["deleted"])) if n]
    headline = ("Would " + ", ".join(parts)) if parts else "No file changes"
    if obs.network:
        headline += f"; network: {', '.join(sorted({str(n.get('host')) for n in obs.network if n.get('host')})[:3]) or 'attempted'}"
    return {
        "headline": headline,
        "counts": counts,
        "files": [c.as_dict() for c in obs.changes[:40]],
        "more_files": max(0, len(obs.changes) - 40),
        "network": obs.network[:20],
        "processes": [{"name": p.get("name"), "cmd": p.get("cmd"), "blocked": bool(p.get("blocked"))} for p in obs.processes[:20]],
        "home_writes": obs.home_writes[:20],
        "decoy_reads": obs.decoy_reads[:10],
        "tool_error": obs.tool_error,
        "error": obs.error[:300],
        "partial": obs.partial,
        "backend": obs.backend,
        "duration_ms": round(obs.duration_ms, 1),
    }


def worst(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b
