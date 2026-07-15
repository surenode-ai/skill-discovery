"""Zero-config discovery of in-repo (project-level) skill locations.

The user-level scan already knows the global skill roots. Project skills, though,
live in arbitrary repos scattered under the developer's home, so requiring a
``--project`` path defeats the point. This walks for them instead: a fast
``os.scandir`` traversal that prunes heavy build/cache trees and the AI tools'
own home directories, and whenever a directory contains a registered agent's
project marker (``.claude/skills``, ``.cursor/rules``, ...), records that
directory as a project root.

Only directory structure is read here — never file contents — and symlinks are
not followed, so the walk cannot be steered out of the tree or into a loop. It
is bounded by a denylist, a depth cap, and a wall-clock budget so it stays cheap
enough to run on every launch and on a fleet of developer machines.
"""

from __future__ import annotations

import glob as _glob
import os
import time
from pathlib import Path

from discovery.agents import AGENTS


def _confirm_map() -> dict[str, list[str]]:
    """marker dotdir -> the concrete registry subpaths that must actually exist
    for it to count. ``.github`` is in every repo (CI); only ``.github/skills``
    and the like are real project skill locations."""
    out: dict[str, list[str]] = {}
    for spec in AGENTS.values():
        for rel in spec.project_roots + spec.project_rule_globs:
            rel = rel.replace("\\", "/")
            out.setdefault(rel.split("/")[0], []).append(rel)
    return out


_CONFIRM = _confirm_map()
_MARKERS = frozenset(_CONFIRM)

# Directory names never worth descending into. Heavy build/dependency/cache
# trees and VCS internals (speed), OS app-support, and the AI tools' own home
# and cache dirs (whose skill folders are already covered by the user-level
# scan). Agent *project markers* like ``.claude`` are probed before this list
# is consulted, so their home-dir twins here only stop us recursing into
# ``~/.codex``, ``~/.vscode``, etc. Non-tool hidden dirs are still traversed,
# so a project hidden on an unusual path is not a discovery blind spot.
DEFAULT_DENY = frozenset({
    # build / dependency / cache
    "node_modules", ".venv", "venv", "env", "site-packages", ".cache", ".cargo",
    ".rustup", ".npm", ".pnpm-store", ".yarn", "dist", "build", "target",
    ".next", ".nuxt", ".gradle", "Pods", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".tox", "DerivedData", ".m2", "vendor", ".bundle",
    ".terraform", ".idea",
    # vcs internals
    ".git", ".svn", ".hg",
    # OS / editor / agent homes and caches (their skills are user-level already)
    "Library", "AppData", "Application Data", ".vscode", ".vscode-server",
    ".cursor-server", ".antigravity", ".codex", ".gemini", ".codeium",
    ".copilot", ".config", ".local", ".docker", ".ollama",
    # sensitive, never a skill root
    ".ssh", ".aws", ".gnupg", ".kube", ".Trash",
})
MAX_DEPTH = 8
DEFAULT_TIME_BUDGET = 20.0


def _confirms(parent: str, marker: str) -> bool:
    for sub in _CONFIRM[marker]:
        full = os.path.join(parent, *sub.split("/"))
        if "*" in sub:
            if _glob.glob(full):
                return True
        elif sub.endswith(".md"):
            if os.path.isfile(full):
                return True
        elif os.path.isdir(full):
            return True
    return False


def discover_project_roots(
    base: str | Path,
    *,
    deny: frozenset[str] = DEFAULT_DENY,
    max_depth: int = MAX_DEPTH,
    time_budget: float | None = DEFAULT_TIME_BUDGET,
    clock=time.monotonic,
) -> tuple[list[str], bool]:
    """Walk ``base`` and return ``(roots, truncated)``: directories that hold a
    registered agent's project marker, and whether the time budget cut the walk
    short. Robust to permission errors and unreadable directories (skipped)."""
    base = str(Path(base).expanduser())
    roots: set[str] = set()
    truncated = False
    start = clock()
    stack: list[tuple[str, int]] = [(base, 0)]
    while stack:
        if time_budget is not None and clock() - start > time_budget:
            truncated = True
            break
        path, depth = stack.pop()
        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, OSError):
            continue  # unreadable dir on a fleet machine — skip, don't crash
        for e in entries:
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            name = e.name
            if name in _MARKERS:
                if _confirms(path, name):
                    roots.add(path)
                continue  # never recurse into a marker/config dir
            if name in deny or depth + 1 >= max_depth:
                continue
            stack.append((e.path, depth + 1))
    return sorted(roots), truncated


def project_label(root: str, base: str) -> str:
    """A stable, privacy-safe provenance label for a discovered project: its
    path relative to the discovery base, with the base (which contains the
    username) stripped. Falls back to the basename if it is not under base."""
    try:
        rel = os.path.relpath(root, base)
    except ValueError:  # different drive on Windows
        rel = os.path.basename(root)
    rel = rel.replace("\\", "/")
    if rel == "..":
        return os.path.basename(root.rstrip("/\\"))
    if rel == ".":
        return ""  # the base itself (e.g. ~ with ~/.claude/skills): leave
        # unlabeled so it dedups against the user-level scan and never emits the
        # home directory's basename (the username) as a label.
    return rel
