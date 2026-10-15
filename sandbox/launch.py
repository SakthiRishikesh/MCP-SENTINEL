"""Launch plans: how to run a local MCP server inside the sandbox container.

The user's launch command is turned into a two-phase plan:

* **install** (network on, server code never runs): ``npm install --ignore-scripts`` or
  ``uv pip install`` into a package directory on the host, keyed by the package spec;
* **run** (``--network none``): the package directory is mounted read-only and the server's
  entry point is started directly, with its arguments rewritten to the sandbox paths.

Supported launchers: ``npx`` (incl. ``-p``/``--package``), ``uvx`` / ``uv tool run``,
``python script.py`` and ``node script.js``. Anything else uses the process backend.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PKG = "/opt/mcp/pkg"
APP = "/opt/mcp/app"
NPX_SWITCHES = {"-y", "--yes", "-q", "--quiet", "--no", "--no-install", "--prefer-offline", "--prefer-online", "--silent"}
UVX_VALUE_FLAGS = {"--python", "-p", "--index-url", "--extra-index-url", "--index", "--default-index", "-i", "--find-links", "-f",
                   "--cache-dir", "--python-preference", "--constraints", "-c", "--overrides", "--env-file"}


@dataclass
class LaunchPlan:
    kind: str  # npm | pypi | python-script | node-script | unsupported
    package: str = ""
    bin: str = ""
    args: list[str] = field(default_factory=list)
    with_packages: list[str] = field(default_factory=list)
    script: str = ""  # host path of the entry script
    mount: str = ""  # host directory mounted read-only at APP
    interpreter_flags: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def supported(self) -> bool:
        return self.kind != "unsupported"

    @property
    def needs_install(self) -> bool:
        return self.kind in {"npm", "pypi"}

    @property
    def install_key(self) -> str:
        raw = json.dumps([self.kind, self.package, sorted(self.with_packages)])
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    def own_paths(self) -> list[str]:
        """Host paths that are the server's own code (never treated as a workspace root)."""
        return [p for p in (self.script, self.mount) if p]

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "package": self.package, "bin": self.bin, "script": self.script, "reason": self.reason}


def _base(command: str) -> str:
    name = os.path.basename(command.replace("\\", "/")).lower()
    for suffix in (".cmd", ".exe", ".bat", ".ps1"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def npm_name(spec: str) -> str:
    """``@scope/pkg@1.2.3`` -> ``@scope/pkg``; ``pkg@latest`` -> ``pkg``."""
    if spec.startswith("@"):
        at = spec.find("@", 1)
        return spec if at == -1 else spec[:at]
    return spec.split("@", 1)[0]


def _npx(args: list[str]) -> LaunchPlan:
    packages: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in NPX_SWITCHES:
            i += 1
        elif a in {"-p", "--package"} and i + 1 < len(args):
            packages.append(args[i + 1])
            i += 2
        elif a.startswith("--package="):
            packages.append(a.split("=", 1)[1])
            i += 1
        elif a in {"-c", "--call"}:
            return LaunchPlan("unsupported", reason="npx --call runs a shell command")
        elif a == "--":
            i += 1
            break
        elif a.startswith("-"):
            i += 1
        else:
            break
    rest = args[i:]
    if not rest:
        return LaunchPlan("unsupported", reason="npx without a package")
    if packages:
        spec, binary, server_args = packages[0], rest[0], rest[1:]
        extra = packages[1:]
    else:
        spec, binary, server_args, extra = rest[0], "", rest[1:], []
    if spec.startswith((".", "/", "file:", "git", "http")) or "\\" in spec:
        return LaunchPlan("unsupported", reason=f"npx package source {spec!r} is not a registry package")
    return LaunchPlan("npm", package=spec, bin=binary, args=server_args, with_packages=extra)


def _uvx(args: list[str]) -> LaunchPlan:
    source = ""
    withs: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--from" and i + 1 < len(args):
            source = args[i + 1]
            i += 2
        elif a == "--with" and i + 1 < len(args):
            withs.append(args[i + 1])
            i += 2
        elif a.startswith("--from="):
            source = a.split("=", 1)[1]
            i += 1
        elif a.startswith("--with="):
            withs.append(a.split("=", 1)[1])
            i += 1
        elif a in UVX_VALUE_FLAGS and i + 1 < len(args):
            i += 2
        elif a == "--":
            i += 1
            break
        elif a.startswith("-"):
            i += 1
        else:
            break
    rest = args[i:]
    if not rest:
        return LaunchPlan("unsupported", reason="uvx without a command")
    command = rest[0]
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(.*)$", command)
    if not m:
        return LaunchPlan("unsupported", reason=f"cannot parse uvx command {command!r}")
    binary, extras, spec = m.group(1), m.group(2) or "", m.group(3)
    if spec.startswith("@"):
        version = spec[1:]
        requirement = f"{binary}{extras}" + (f"=={version}" if version and version != "latest" else "")
    else:
        requirement = command  # pkg, pkg==1.2, pkg>=1.0, pkg[extra]==1.2
    package = source or requirement
    if package.startswith((".", "/", "git+", "http")) or "\\" in package:
        return LaunchPlan("unsupported", reason=f"uvx source {package!r} is not a PyPI package")
    return LaunchPlan("pypi", package=package, bin=binary, args=rest[1:], with_packages=withs)


def _package_root(script: Path) -> Path:
    for parent in [script.parent, *script.parents]:
        if (parent / "package.json").exists():
            return parent
        if parent == parent.parent or parent == Path.home():
            break
    return script.parent


def plan_for(config: dict[str, Any]) -> LaunchPlan:
    command = str(config.get("command") or "")
    args = [str(a) for a in config.get("args") or []]
    base = _base(command)
    if base == "npx":
        return _npx(args)
    if base == "uvx":
        return _uvx(args)
    if base == "uv" and args[:2] == ["tool", "run"]:
        return _uvx(args[2:])
    if base.startswith("python") or base == "py":
        flags = []
        i = 0
        while i < len(args) and args[i].startswith("-") and args[i] not in {"-m", "-c"}:
            flags.append(args[i])
            i += 1
        if i < len(args) and args[i].endswith(".py") and os.path.isfile(os.path.expanduser(args[i])):
            script = Path(os.path.expanduser(args[i])).resolve()
            return LaunchPlan("python-script", script=str(script), mount=str(script.parent), args=args[i + 1:],
                              interpreter_flags=[f for f in flags if f in {"-u", "-B", "-E", "-s", "-I", "-O"}])
        return LaunchPlan("unsupported", reason="python launcher without a script file (-m modules need their environment)")
    if base == "node":
        if args and args[0].endswith((".js", ".mjs", ".cjs")) and os.path.isfile(os.path.expanduser(args[0])):
            script = Path(os.path.expanduser(args[0])).resolve()
            return LaunchPlan("node-script", script=str(script), mount=str(_package_root(script)), args=args[1:])
        return LaunchPlan("unsupported", reason="node launcher without a script file")
    if base == "docker":
        return LaunchPlan("unsupported", reason="container-launched servers keep their own container isolation")
    return LaunchPlan("unsupported", reason=f"launcher {base!r} has no sandbox recipe")


def install_command(plan: LaunchPlan) -> list[str]:
    if plan.kind == "npm":
        return ["npm", "install", "--prefix", PKG, "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error",
                plan.package, *plan.with_packages]
    if plan.kind == "pypi":
        quoted = " ".join(_sh_quote(p) for p in [plan.package, *plan.with_packages])
        return ["sh", "-c", f"uv venv --quiet {PKG}/venv && uv pip install --quiet --python {PKG}/venv/bin/python {quoted}"]
    return []


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def resolve_entry(plan: LaunchPlan, pkg_dir: Path) -> list[str]:
    """Container command that starts the server (before its arguments)."""
    if plan.kind == "npm":
        name = npm_name(plan.package)
        manifest = pkg_dir / "node_modules" / name / "package.json"
        data = json.loads(manifest.read_text(encoding="utf-8"))
        bins = data.get("bin")
        if isinstance(bins, str):
            target = bins
        elif isinstance(bins, dict) and bins:
            short = name.split("/")[-1]
            target = bins.get(plan.bin) or (next(iter(bins.values())) if len(bins) == 1 else bins.get(short) or next(iter(bins.values())))
        else:
            raise FileNotFoundError(f"{name} declares no executable (package.json 'bin')")
        if plan.bin and isinstance(bins, dict) and plan.bin not in bins:
            # npx -p pkg other-bin: the binary may come from a dependency
            dep = pkg_dir / "node_modules" / ".bin" / plan.bin
            if dep.exists():
                return ["node", f"{PKG}/node_modules/.bin/{plan.bin}"]
        return ["node", f"{PKG}/node_modules/{name}/{target.lstrip('./')}"]
    if plan.kind == "pypi":
        if not (pkg_dir / "venv" / "bin" / plan.bin).exists():
            raise FileNotFoundError(f"console script {plan.bin!r} not found after installing {plan.package}")
        return [f"{PKG}/venv/bin/{plan.bin}"]
    if plan.kind == "python-script":
        return ["python3", *plan.interpreter_flags, f"{APP}/{Path(plan.script).name}"]
    if plan.kind == "node-script":
        rel = Path(plan.script).relative_to(Path(plan.mount)).as_posix()
        return ["node", f"{APP}/{rel}"]
    raise ValueError(f"no entry point for plan kind {plan.kind}")
