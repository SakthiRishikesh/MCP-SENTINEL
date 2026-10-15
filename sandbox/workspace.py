"""Workspace roots, mirrors, manifests and diffs for shadow execution.

A *root* is a directory (or a single file) a local MCP server is configured to work on: the
absolute paths in its launch arguments, its environment and its working directory. Sentinel
keeps a private *mirror* of every root that is re-synchronised incrementally right before each
tool call. The sandbox runs the call against a throw-away *run copy* of the mirror and the
manifests before/after tell exactly what the call would create, modify or delete.

The mirror holds the pre-call state, so it is also the source of the undo journal and the
baseline for detecting a server that behaves differently outside the sandbox.
"""

from __future__ import annotations

import difflib
import ntpath
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

# heavyweight caches that no MCP tool should need: skipped (and reported as not mirrored)
SKIP_DIR_NAMES = {"node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
                  ".gradle", ".terraform", ".DS_Store"}
SYSTEM_ROOTS = {"/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/var", "/opt", "/boot",
                "/run", "/srv", "/tmp", "/home", "/Users", "/root", "/System", "/Library", "/private", "/Volumes", "/mnt", "/media"}
SYSTEM_PREFIXES = ("/proc/", "/sys/", "/dev/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/etc/", "/boot/", "/System/",
                   "/Library/", "/Applications/")
WINDOWS_SYSTEM = re.compile(r"^[a-z]:\\(windows|program files|program files \(x86\)|programdata)(\\|$)", re.I)
PREVIEW_BYTES = 256 * 1024


@dataclass
class Limits:
    max_files: int = 5000
    max_bytes: int = 200 * 1024 * 1024


@dataclass
class Root:
    index: int
    real: str  # absolute path as the server sees it
    is_file: bool = False
    home: bool = False  # the user's home directory: mapped onto the decoy home, never copied

    @property
    def name(self) -> str:
        return ntpath.basename(self.real) if "\\" in self.real else os.path.basename(self.real.rstrip("/"))


@dataclass
class Manifest:
    files: dict[str, tuple[int, int]] = field(default_factory=dict)  # rel posix path -> (size, mtime_ns)
    dirs: set[str] = field(default_factory=set)
    partial: bool = False
    skipped: list[str] = field(default_factory=list)
    total_bytes: int = 0


@dataclass
class Change:
    root: int
    rel: str
    kind: str  # created | modified | deleted
    size_before: int | None = None
    size_after: int | None = None
    real: str = ""
    diff: str = ""

    def as_dict(self) -> dict[str, Any]:
        out = {"path": self.real or self.rel, "change": self.kind, "size_before": self.size_before, "size_after": self.size_after}
        if self.diff:
            out["diff"] = self.diff
        return out


def _is_system(path: str) -> bool:
    p = path.rstrip("/") or "/"
    if p in SYSTEM_ROOTS or any(p.startswith(prefix) for prefix in SYSTEM_PREFIXES):
        return True
    return bool(WINDOWS_SYSTEM.match(path))


def _candidates(config: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for arg in config.get("args") or []:
        arg = str(arg)
        if "=" in arg and arg.startswith("-"):
            arg = arg.split("=", 1)[1]
        values.append(arg)
    for value in (config.get("env") or {}).values():
        values.extend(str(value).split(os.pathsep))
    if config.get("cwd"):
        values.append(str(config["cwd"]))
    return values


def discover_roots(config: dict[str, Any], *, exclude: list[str] | None = None, home: str | None = None) -> list[Root]:
    """Absolute, existing paths the server is configured with (minus system dirs and its own code)."""
    home = os.path.normcase(os.path.abspath(home or str(Path.home())))
    excluded = {os.path.normcase(os.path.abspath(e)) for e in exclude or []}
    found: list[tuple[str, bool, bool]] = []
    for raw in _candidates(config):
        raw = raw.strip()
        if not raw or not (os.path.isabs(raw) or raw.startswith("~")):
            continue
        path = os.path.abspath(os.path.expanduser(raw))
        norm = os.path.normcase(path)
        if norm in excluded or _is_system(path) or not os.path.exists(path):
            continue
        if norm == home:
            found.append((path, False, True))
            continue
        if home.startswith(norm + os.sep):  # an ancestor of the home directory (e.g. /Users): far too broad
            continue
        found.append((path, os.path.isfile(path), False))
    roots: list[Root] = []
    for path, is_file, is_home in sorted(set(found), key=lambda f: len(f[0])):
        norm = os.path.normcase(path)
        if any(not r.is_file and (norm == os.path.normcase(r.real) or norm.startswith(os.path.normcase(r.real).rstrip(os.sep) + os.sep))
               for r in roots if not r.home):
            continue  # nested inside a root we already mirror
        roots.append(Root(index=len(roots), real=path, is_file=is_file, home=is_home))
    return roots


def scan(path: Path, limits: Limits) -> Manifest:
    """Files (size, mtime_ns) and directories under ``path``; symlinks are not followed."""
    m = Manifest()
    if not path.exists():
        return m
    if path.is_file():
        st = path.stat()
        m.files[path.name] = (st.st_size, st.st_mtime_ns)
        m.total_bytes = st.st_size
        return m
    stack = [(path, "")]
    while stack:
        current, rel = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            child_rel = f"{rel}/{entry.name}" if rel else entry.name
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in SKIP_DIR_NAMES:
                        m.skipped.append(child_rel)
                        continue
                    m.dirs.add(child_rel)
                    stack.append((Path(entry.path), child_rel))
                elif entry.is_file(follow_symlinks=False):
                    st = entry.stat(follow_symlinks=False)
                    if len(m.files) >= limits.max_files or m.total_bytes + st.st_size > limits.max_bytes:
                        m.partial = True
                        continue
                    m.files[child_rel] = (st.st_size, st.st_mtime_ns)
                    m.total_bytes += st.st_size
            except OSError:
                continue
    return m


def sync_mirror(real: Path, mirror: Path, previous: Manifest | None, limits: Limits) -> Manifest:
    """Bring ``mirror`` up to date with ``real`` copying only what changed. Returns the real manifest."""
    current = scan(real, limits)
    if real.is_file():
        mirror.mkdir(parents=True, exist_ok=True)
        target = mirror / real.name
        if previous is None or previous.files.get(real.name) != current.files.get(real.name) or not target.exists():
            shutil.copy2(real, target)
        return current
    if previous is None:
        shutil.rmtree(mirror, ignore_errors=True)
        previous = Manifest()
    mirror.mkdir(parents=True, exist_ok=True)
    for rel in sorted(current.dirs):
        (mirror / rel).mkdir(parents=True, exist_ok=True)
    for rel, sig in current.files.items():
        target = mirror / rel
        if previous.files.get(rel) != sig or not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(real / rel, target)
            except OSError:
                current.partial = True
    for rel in set(previous.files) - set(current.files):
        try:
            (mirror / rel).unlink()
        except OSError:
            pass
    for rel in sorted(previous.dirs - current.dirs, key=len, reverse=True):
        shutil.rmtree(mirror / rel, ignore_errors=True)
    return current


def copy_tree(src: Path, dst: Path) -> None:
    shutil.rmtree(dst, ignore_errors=True)
    if src.exists():
        shutil.copytree(src, dst, symlinks=True, copy_function=shutil.copy2)
    else:
        dst.mkdir(parents=True, exist_ok=True)


def make_writable(path: Path) -> None:
    """World-writable throw-away copies, so an unprivileged sandbox user can work on them."""
    if sys.platform == "win32":
        return
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames:
            try:
                os.chmod(os.path.join(dirpath, name), 0o777)
            except OSError:
                pass
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                if not os.path.islink(p):
                    os.chmod(p, os.stat(p).st_mode | 0o666)
            except OSError:
                pass
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass


def diff(before: Manifest, after: Manifest, root: int) -> list[Change]:
    changes: list[Change] = []
    for rel, sig in after.files.items():
        old = before.files.get(rel)
        if old is None:
            changes.append(Change(root, rel, "created", None, sig[0]))
        elif old != sig:
            changes.append(Change(root, rel, "modified", old[0], sig[0]))
    for rel, sig in before.files.items():
        if rel not in after.files:
            changes.append(Change(root, rel, "deleted", sig[0], None))
    changes.sort(key=lambda c: (c.kind, c.rel))
    return changes


def text_diff(before: Path | None, after: Path | None, label: str, max_lines: int = 60) -> str:
    def read(p: Path | None) -> list[str] | None:
        if p is None or not p.exists():
            return []
        try:
            if p.stat().st_size > PREVIEW_BYTES:
                return None
            return p.read_text(encoding="utf-8").splitlines(keepends=True)
        except (UnicodeDecodeError, OSError):
            return None

    a, b = read(before), read(after)
    if a is None or b is None:
        return ""
    lines = list(difflib.unified_diff(a, b, fromfile=f"a/{label}", tofile=f"b/{label}", n=2))
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(lines) - max_lines} more diff lines)\n"]
    return "".join(lines)


class PathMap:
    """Rewrites real paths to their sandbox counterparts (and back) inside arbitrary JSON values."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self.pairs = sorted(((r.rstrip("/\\") or r, s.rstrip("/") or s) for r, s in pairs), key=lambda p: len(p[0]), reverse=True)

    @staticmethod
    def _match(value: str, prefix: str) -> str | None:
        windows = "\\" in prefix or (len(prefix) > 1 and prefix[1] == ":")
        v, p = (value.lower(), prefix.lower()) if windows else (value, prefix)
        if v == p:
            return ""
        for sep in ("/", "\\") if windows else ("/",):
            if v.startswith(p + sep):
                return value[len(prefix) + 1:]
        return None

    def _swap(self, value: str, reverse: bool) -> str:
        for real, shadow in self.pairs:
            src, dst = (shadow, real) if reverse else (real, shadow)
            rest = self._match(value, src)
            if rest is None:
                continue
            if not rest:
                return dst
            if reverse and ("\\" in dst):
                return dst + "\\" + rest.replace("/", "\\")
            return dst + "/" + rest.replace("\\", "/") if dst.startswith("/") else str(Path(dst) / rest)
        return value

    def to_shadow(self, value: Any) -> Any:
        return self._walk(value, reverse=False)

    def to_real(self, value: Any) -> Any:
        return self._walk(value, reverse=True)

    def _walk(self, value: Any, *, reverse: bool) -> Any:
        if isinstance(value, str):
            expanded = os.path.expanduser(value) if value.startswith("~") and not reverse else value
            swapped = self._swap(expanded, reverse)
            return swapped if swapped != expanded else value
        if isinstance(value, list):
            return [self._walk(v, reverse=reverse) for v in value]
        if isinstance(value, dict):
            return {k: self._walk(v, reverse=reverse) for k, v in value.items()}
        return value

    def referenced(self, value: Any) -> list[str]:
        """Real paths (inside a root) that appear in ``value``."""
        out: list[str] = []

        def visit(v: Any) -> None:
            if isinstance(v, str):
                expanded = os.path.expanduser(v) if v.startswith("~") else v
                if any(self._match(expanded, real) is not None for real, _ in self.pairs):
                    out.append(expanded)
            elif isinstance(v, list):
                for item in v:
                    visit(item)
            elif isinstance(v, dict):
                for item in v.values():
                    visit(item)

        visit(value)
        return out


def within(path: str, referenced: list[str]) -> bool:
    """True when ``path`` equals or is inside one of the referenced paths."""
    p = path.replace("\\", "/").rstrip("/")
    for ref in referenced:
        r = ref.replace("\\", "/").rstrip("/")
        if p == r or p.startswith(r + "/"):
            return True
    return False


def join_real(root: Root, rel: str) -> str:
    if root.is_file:
        return root.real
    if "\\" in root.real:
        return root.real.rstrip("\\") + "\\" + rel.replace("/", "\\")
    return str(PurePosixPath(root.real) / rel) if root.real.startswith("/") else str(Path(root.real) / rel)
