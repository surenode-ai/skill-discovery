"""Walk a local skill root for SKILL.md folders and assemble each skill.

For each SKILL.md found under a root, the skill's folder is assembled (SKILL.md
plus the text files beside it, minus any nested skill), identity is read from
the frontmatter, and the folder is checked for PII and secrets. The root is
only read, never executed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from discovery.sanitize import SanitizationReport, sanitize_folder
from discovery.skillmd import SkillParseError, parse_skill_md

# Safety bounds. The walker is read-only, but we still cap how much it ingests.
MAX_FILE_BYTES = 100_000
MAX_FILES_PER_SKILL = 50
MAX_SKILLS = 500

_PRUNE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
               "build", ".tox", ".mypy_cache", ".pytest_cache", ".idea"}
# Text files we will read into a skill folder. Anything else (binaries, images)
# is skipped and noted.
_TEXT_EXTS = {".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml", ".toml",
              ".cfg", ".ini", ".rst", ".js", ".ts", ".sql", ".html", ".csv"}


@dataclass
class DiscoveredSkill:
    rel_dir: str                 # root-relative directory; the external_id base
    external_id: str             # stable identity within the chosen source
    name: str                    # from SKILL.md frontmatter
    description: str
    files: dict[str, str]        # skill folder contents, keyed by relative path
    file_count: int
    valid: bool
    findings: SanitizationReport
    error: str | None = None
    skipped_files: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return not self.findings.clean


def _repo_label(location: str) -> str:
    # Normalize Windows separators so the label is the directory basename on
    # every OS, never a full native path.
    base = location.replace("\\", "/").rstrip("/").split("/")[-1]
    return base[:-4] if base.endswith(".git") else base or "repo"


def _read_text(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def _assemble_folder(skill_dir: str) -> tuple[dict[str, str], list[str]]:
    """Collect SKILL.md plus the text files beside it into a skill folder.
    Subdirectories that contain their own SKILL.md are pruned (nested skills)."""
    folder: dict[str, str] = {}
    skipped: list[str] = []
    for root, dirs, files in os.walk(skill_dir):
        # Prune noise and nested skills (a subdir with its own SKILL.md).
        if root != skill_dir and "SKILL.md" in files:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _PRUNE_DIRS and not os.path.islink(os.path.join(root, d))]
        for fname in files:
            full = os.path.join(root, fname)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, skill_dir).replace(os.sep, "/")
            if fname != "SKILL.md" and os.path.splitext(fname)[1].lower() not in _TEXT_EXTS:
                skipped.append(rel)
                continue
            content = _read_text(full)
            if content is None:
                skipped.append(rel)
                continue
            folder[rel] = content
            if len(folder) >= MAX_FILES_PER_SKILL:
                return folder, skipped
    return folder, skipped


def _discover(root: str, location: str) -> tuple[list[DiscoveredSkill], list[str]]:
    repo_label = _repo_label(location)
    skills: list[DiscoveredSkill] = []
    errors: list[str] = []
    skill_dirs: list[str] = []
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _PRUNE_DIRS and not os.path.islink(os.path.join(cur, d))]
        if "SKILL.md" in files:
            skill_dirs.append(cur)
    skill_dirs.sort()

    for skill_dir in skill_dirs:
        if len(skills) >= MAX_SKILLS:
            errors.append(f"Stopped at {MAX_SKILLS} skills; the root has more.")
            break
        rel_dir = os.path.relpath(skill_dir, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        external_id = rel_dir or repo_label

        folder, skipped = _assemble_folder(skill_dir)
        skill_md = folder.get("SKILL.md", "")
        name, description, valid, err = external_id, "", True, None
        try:
            parsed = parse_skill_md(skill_md)
            name, description = parsed.name, parsed.description
        except SkillParseError as exc:
            valid, err = False, f"SKILL.md does not parse: {exc}"

        _, report = sanitize_folder(folder)  # findings only; content kept as-is here
        skills.append(DiscoveredSkill(
            rel_dir=rel_dir, external_id=external_id, name=name, description=description,
            files=folder, file_count=len(folder), valid=valid, findings=report,
            error=err, skipped_files=skipped,
        ))
    return skills, errors


# Public alias for the walker entry point.
discover_skills = _discover
