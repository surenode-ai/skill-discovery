"""Parse and fingerprint SKILL.md documents.

A SKILL.md is YAML frontmatter delimited by ``---`` followed by a markdown
body. We extract ``name`` and ``description`` from the frontmatter and treat
the whole document as the canonical content.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

import yaml

_FRONTMATTER_RE = re.compile(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)


class SkillParseError(ValueError):
    """Raised when a SKILL.md document cannot be parsed."""


@dataclass(frozen=True)
class ParsedSkill:
    name: str
    description: str
    body: str
    content: str  # the full normalized document
    frontmatter: dict


_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


def strip_code_fences(text: str) -> str:
    """Remove fenced code blocks so downstream text analysis keys on prose."""
    return _FENCE_RE.sub(" ", text or "")


def content_hash(content: str) -> str:
    """Stable hash over normalized content; identical text -> identical hash."""
    normalized = content.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def parse_skill_md(
    content: str,
    *,
    name_override: str | None = None,
    description_override: str | None = None,
) -> ParsedSkill:
    if not content or not content.strip():
        raise SkillParseError("Skill content is empty.")

    normalized = content.replace("\r\n", "\n").strip() + "\n"
    match = _FRONTMATTER_RE.match(normalized)
    frontmatter: dict = {}
    body = normalized
    if match:
        raw_fm, body = match.group(1), match.group(2)
        try:
            loaded = yaml.safe_load(raw_fm) or {}
        except yaml.YAMLError as exc:
            raise SkillParseError(f"Invalid YAML frontmatter: {exc}") from exc
        if not isinstance(loaded, dict):
            raise SkillParseError("Frontmatter must be a mapping.")
        frontmatter = loaded

    name = name_override or _str(frontmatter.get("name"))
    description = description_override or _str(frontmatter.get("description"))

    if not name:
        raise SkillParseError(
            "Skill has no 'name' (provide it in frontmatter or as name_override)."
        )

    return ParsedSkill(
        name=name.strip(),
        description=description.strip(),
        body=body.strip(),
        content=normalized.strip(),
        frontmatter=frontmatter,
    )


def _str(value) -> str:
    return "" if value is None else str(value)
