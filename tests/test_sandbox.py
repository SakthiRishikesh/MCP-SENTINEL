"""Sandbox pre-flight: launch plans, workspace mirrors / undo, verdict rules, backends.

Credential-theft rules are tested on synthetic observations only (no stealing fixtures).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sandbox import launch
from sandbox.shadow import SandboxManager, restore, synthetic_arguments
from sandbox.verdict import Limits, Observation, judge
from sandbox.workspace import Change, PathMap, discover_roots
from sentinel.config import Settings

FIXTURE = str(Path(__file__).parent / "fixtures" / "mcp_test_server.py")


def _settings(tmp_path: Path, **overrides) -> Settings:
    return Settings(sandbox_dir=str(tmp_path / "sbx"), **overrides)


def _obs(**kw) -> Observation:
    base = {"tool": "t", "capabilities": {"WRITE"}, "read_only": False, "arguments": {}}
    base.update(kw)
    return Observation(**base)


def _chg(kind: str, path: str, before: int | None = 5, after: int | None = 5) -> Change:
    return Change(0, path.rsplit("/", 1)[-1], kind, before if kind != "created" else None, after if kind != "deleted" else None, real=path)


# -- launch plans -----------------------------------------------------------------------------
def test_launch_plans():
    p = launch.plan_for({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "/data"]})
    assert (p.kind, p.package, p.args) == ("npm", "@modelcontextprotocol/server-filesystem@2026.8.31", ["/data"])
    assert launch.npm_name(p.package) == "@modelcontextprotocol/server-filesystem"
    p = launch.plan_for({"command": "C:\\Program Files\\nodejs\\npx.cmd", "args": ["--package=pkg@1", "pkg-bin", "--flag"]})
    assert (p.kind, p.package, p.bin, p.args) == ("npm", "pkg@1", "pkg-bin", ["--flag"])
    assert launch.plan_for({"command": "uvx", "args": ["mcp-server-time==2026.8.18"]}).package == "mcp-server-time==2026.8.18"
    p = launch.plan_for({"command": "uvx", "args": ["mcp-server-git@2026.8.18", "--repository", "/r"]})
    assert (p.package, p.bin, p.args) == ("mcp-server-git==2026.8.18", "mcp-server-git", ["--repository", "/r"])
    assert launch.plan_for({"command": "uv", "args": ["tool", "run", "--from", "pkg[x]==1", "cmd"]}).package == "pkg[x]==1"
    p = launch.plan_for({"command": sys.executable, "args": ["-u", FIXTURE]})
    assert p.kind == "python-script" and p.interpreter_flags == ["-u"] and FIXTURE in p.own_paths()
    assert not launch.plan_for({"command": "npx", "args": ["./local"]}).supported
    assert not launch.plan_for({"command": "python", "args": ["-m", "pkg"]}).supported
    assert not launch.plan_for({"command": "docker", "args": ["run", "img"]}).supported


# -- workspace ------------------------------------------------------------------------------
def test_roots_and_path_map(tmp_path):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "sub").mkdir()
    db = tmp_path / "memory.json"
    db.write_text("{}")
    roots = discover_roots({"args": [str(tmp_path / "proj"), str(tmp_path / "proj" / "sub"), "/usr", "relative"],
                            "env": {"MEMORY_FILE_PATH": str(db)}}, home=str(tmp_path / "home"))
    assert [(r.real, r.is_file) for r in roots] == [(str(tmp_path / "proj"), False), (str(db), True)]  # nested + system dropped
    pm = PathMap([(str(tmp_path / "proj"), "/workspace/0")])
    args = {"path": str(tmp_path / "proj" / "a.txt"), "list": [str(tmp_path / "proj")], "other": str(tmp_path / "projX")}
    shadow = pm.to_shadow(args)
    assert shadow == {"path": "/workspace/0/a.txt", "list": ["/workspace/0"], "other": str(tmp_path / "projX")}
    assert pm.to_real(shadow) == args
    assert pm.referenced(args) == [str(tmp_path / "proj" / "a.txt"), str(tmp_path / "proj")]
    win = PathMap([("C:\\Users\\a\\proj", "/workspace/0")])
    assert win.to_shadow("c:\\users\\a\\proj\\src\\x.py") == "/workspace/0/src/x.py"


def test_mirror_journal_and_undo(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "keep.txt").write_text("keep")
    (ws / "edit.txt").write_text("v1")
    (ws / "gone.txt").write_text("bye")
    mgr = SandboxManager(_settings(tmp_path))
    cfg = {"command": sys.executable, "args": [FIXTURE, str(ws)]}
    ctx = mgr.begin("s1", cfg, {"name": "t", "capabilities": ["WRITE"]}, {}, preflight=False)
    assert ctx.skipped and len(ctx.pre[0].files) == 3
    (ws / "edit.txt").write_text("v2 changed")  # the "real call"
    (ws / "gone.txt").unlink()
    (ws / "new.txt").write_text("created")
    journal = tmp_path / "journal"
    out = mgr.finish(ctx, executed=True, journal_dir=journal)
    assert {(c["path"].rsplit("/", 1)[-1], c["change"]) for c in out["changes"]} == {("edit.txt", "modified"), ("gone.txt", "deleted"), ("new.txt", "created")}
    assert "evasion" not in out  # no pre-flight prediction to compare with
    report = restore(out["journal"], journal)
    assert (ws / "edit.txt").read_text() == "v1" and (ws / "gone.txt").read_text() == "bye" and not (ws / "new.txt").exists()
    assert len(report["restored"]) == 2 and len(report["removed"]) == 1 and not report["conflicts"]
    # the per-server lock was released: a second begin does not block
    mgr.finish(mgr.begin("s1", cfg, {"name": "t"}, {}, preflight=False), executed=False)


# -- verdict rules (synthetic observations) -------------------------------------------------
def test_verdict_rules_on_synthetic_observations():
    v = judge(_obs(changes=[_chg("created", "/p/a.txt")], referenced=["/p/a.txt"]))
    assert v["verdict"] == "SAFE" and v["preview"]["counts"]["created"] == 1
    v = judge(_obs(decoy_reads=[".ssh/id_rsa"], capabilities={"READ"}, read_only=True))
    assert v["verdict"] == "MALICIOUS" and "credential_read" in {f["rule"] for f in v["findings"]}
    v = judge(_obs(decoy_reads=[".ssh/id_rsa"], arguments={"path": "~/.ssh/id_rsa"}, capabilities={"READ"}))
    assert v["verdict"] == "SUSPICIOUS"  # explicitly requested: a human decides
    assert judge(_obs(network=[{"host": "x.example", "canary": True}]))["verdict"] == "MALICIOUS"
    assert judge(_obs(network=[{"host": "api.example.com", "env_canary": True}]), allowed_hosts={"example.com"})["verdict"] == "SAFE"
    assert judge(_obs(network=[{"host": "other.example", "env_canary": True}]), allowed_hosts={"example.com"})["verdict"] == "MALICIOUS"
    v = judge(_obs(read_only=True, capabilities={"READ"}, changes=[_chg("modified", "/p/a.txt")]))
    assert v["verdict"] == "MALICIOUS" and v["findings"][0]["rule"] == "read_only_mutation"
    v = judge(_obs(referenced=["/p/a.txt"], changes=[_chg("modified", "/p/a.txt"), _chg("deleted", "/p/b.txt")]))
    assert v["verdict"] == "MALICIOUS" and any(f["rule"] == "collateral_delete" for f in v["findings"])
    many = [_chg("deleted", f"/p/f{i}.txt") for i in range(30)]
    assert judge(_obs(changes=many, workspace_files=200))["verdict"] == "DANGEROUS"
    half = [_chg("deleted", f"/p/f{i}.txt") for i in range(6)]
    assert judge(_obs(changes=half, workspace_files=10), limits=Limits(max_deletes=25))["verdict"] == "DANGEROUS"
    moved = [_chg("deleted", f"/p/docs/f{i}.txt") for i in range(12)] + [_chg("created", f"/p/archive/f{i}.txt") for i in range(12)]
    assert judge(_obs(changes=moved, workspace_files=13, referenced=["/p/docs", "/p/archive"]))["verdict"] == "SAFE"
    assert judge(_obs(capabilities={"READ"}, network=[{"host": "telemetry.example"}]))["verdict"] == "SUSPICIOUS"
    assert judge(_obs(capabilities={"EXTERNAL_LOOKUP"}, network=[{"host": "telemetry.example"}]))["verdict"] == "SAFE"
    assert judge(_obs(network=[{"host": "docs.example.org"}], arguments={"url": "https://docs.example.org/x"}, capabilities={"READ"}))["verdict"] == "SAFE"
    v = judge(_obs(changes=[_chg("created", "/p/.git/hooks/pre-commit")], referenced=["/p/README.md"]))
    assert v["verdict"] == "MALICIOUS" and v["findings"][0]["rule"] == "git_hook"
    assert judge(_obs(changes=[_chg("created", "/p/.git/hooks/pre-commit.sample")], referenced=["/p"]))["verdict"] == "SAFE"
    assert judge(_obs(home_writes=[".bashrc"]))["verdict"] == "MALICIOUS"
    assert judge(_obs(home_writes=[".cache/x/y"]))["verdict"] == "SAFE"
    assert judge(_obs(processes=[{"name": "curl", "blocked": True}]))["verdict"] == "MALICIOUS"
    assert judge(_obs(capabilities={"CODE_EXECUTION"}, processes=[{"name": "curl"}, {"name": "sh"}]))["verdict"] == "SAFE"
    assert judge(_obs(processes=[{"name": "git"}]), known_processes={"git"})["verdict"] == "SAFE"
    assert judge(_obs(error="launch failed"))["verdict"] == "INCONCLUSIVE"


def test_synthetic_arguments_point_into_the_workspace(tmp_path):
    (tmp_path / "proj").mkdir()
    roots = discover_roots({"args": [str(tmp_path / "proj")]})
    schema = {"type": "object", "required": ["path", "edits"], "properties": {
        "path": {"type": "string"}, "directory": {"type": "string"}, "dryRun": {"type": "boolean"},
        "edits": {"type": "array", "minItems": 1, "items": {"type": "object", "required": ["oldText"], "properties": {"oldText": {"type": "string"}}}}}}
    args = synthetic_arguments(schema, PathMap([]), roots)
    assert args["path"] == f"{tmp_path / 'proj'}/notes.txt" and args["directory"] == str(tmp_path / "proj")
    assert args["edits"] == [{"oldText": "Sentinel audit sample text"}] and args["dryRun"] is False


# -- backends ------------------------------------------------------------------------------
def test_process_backend_preflight_and_audit(tmp_path):
    mgr = SandboxManager(_settings(tmp_path, sandbox_mode="process"))
    cfg = {"command": sys.executable, "args": [FIXTURE], "env": {"API_TOKEN": "real-secret"}}
    ctx = mgr.begin("fx", cfg, {"name": "search_logs", "capabilities": ["READ"], "annotations": {"readOnlyHint": True}},
                    {"query": "10.0.0.1"}, preflight=True)
    mgr.finish(ctx, executed=False)
    assert ctx.preflight["verdict"] == "SAFE" and ctx.preflight["backend"] == "process" and ctx.reliable
    # egress / code-executing tools are never pre-flighted without real containment
    ctx = mgr.begin("fx", cfg, {"name": "send_data", "capabilities": ["DATA_TRANSFER"]}, {}, preflight=True)
    mgr.finish(ctx, executed=False)
    assert ctx.preflight["verdict"] == "INCONCLUSIVE" and ctx.preflight.get("skipped")
    tools = [{"name": "search_logs", "capabilities": ["READ"], "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
             {"name": "create_ticket", "capabilities": ["WRITE"], "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}}}},
             {"name": "send_data", "capabilities": ["DATA_TRANSFER"], "inputSchema": {"type": "object"}}]
    report = mgr.audit("fx", cfg, tools)
    assert report["status"] == "DONE" and report["tools"]["search_logs"]["verdict"] == "SAFE"
    assert report["tools"]["create_ticket"]["verdict"] == "SAFE" and report["tools"]["send_data"]["verdict"] == "SKIPPED"


def _docker_image() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", Settings().sandbox_image], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.fixture
def docker_dir():
    """A scratch folder Docker can bind-mount: Docker Desktop only shares the home folder by default, not /tmp."""
    root = Path.home() / ".cache" / "mcp-sentinel-tests"
    root.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=root))
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.mark.skipif(not _docker_image(), reason="Docker and the sandbox image are not available")
def test_docker_backend_contains_a_real_call(tmp_path, docker_dir):
    ws = tmp_path / "ws"  # the real workspace may live anywhere: only Sentinel's copy is mounted
    ws.mkdir()
    (ws / "a.txt").write_text("v1")
    mgr = SandboxManager(_settings(docker_dir, sandbox_mode="docker"))
    cfg = {"command": sys.executable, "args": [FIXTURE, str(ws)]}
    ctx = mgr.begin("fxd", cfg, {"name": "search_logs", "capabilities": ["READ"]}, {"query": "x"}, preflight=True)
    mgr.finish(ctx, executed=False)
    assert ctx.preflight["backend"] == "docker" and ctx.preflight["verdict"] == "SAFE", ctx.preflight
    assert (ws / "a.txt").read_text() == "v1"


@pytest.mark.skipif(not _docker_image(), reason="Docker and the sandbox image are not available")
def test_docker_backend_reports_unshared_sandbox_folder(tmp_path):
    mgr = SandboxManager(_settings(tmp_path, sandbox_mode="docker"))
    if mgr.docker.mountable(tmp_path):
        pytest.skip("this Docker engine can mount the temp folder")
    status = mgr.status()
    assert status["active_backend"] == "unavailable" and "File sharing" in status["docker"]["detail"]
