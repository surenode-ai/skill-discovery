"""Sanitize a skill folder before anything leaves the machine.

Runs locally, so neither the sensitive value nor its detection ever reaches the
server. Two kinds of finding:

- Redactions (applied automatically): clear PII and secrets in the skill prose
  are replaced with ``[redacted:...]`` markers. Skills are meant to capture
  process details, so we target only unambiguous credentials and personal
  identifiers, never commands, ports, IPs, or tool names.
- Path flags (reported, never auto-removed): a personal home directory path,
  e.g. a tool stored under ``/Users/<name>/...``. A tool may legitimately need
  that path, so we surface it to the operator rather than silently rewriting it.

Only Markdown files are scanned (SKILL.md, references/*.md, and markdown rule
files such as Cursor's *.mdc). Script and asset contents are out of scope: what
happens inside a bundled tool is the tool's concern, not ours.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- Redactors: (kind, pattern, replacement). Order matters; broad PII last. ---
_REDACTORS: list[tuple[str, re.Pattern, str]] = [
    ("private-key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[redacted:private-key]"),
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     "[redacted:jwt]"),
    ("aws-access-key",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "[redacted:aws-access-key]"),
    ("api-key",
     re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
     "[redacted:api-key]"),
    ("api-key",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "[redacted:api-key]"),
    ("token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
     "[redacted:token]"),
    ("token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "[redacted:token]"),
    ("token",
     re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._/+=-]{20,}"),
     "Bearer [redacted:token]"),
    ("secret",  # password embedded in a URL: scheme://user:secret@host
     re.compile(r"://([^:@/\s]+):([^@/\s]+)@"),
     r"://\1:[redacted:secret]@"),
    ("ssn",
     re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "[redacted:ssn]"),
    ("email",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "[redacted:email]"),
]

# Personal home directory paths. Flagged, never auto-removed.
_PERSONAL_PATHS: list[re.Pattern] = [
    re.compile(r"(?:/Users/|/home/)[^/\s'\"`)]+(?:/[^\s'\"`)]*)?"),
    re.compile(r"[A-Za-z]:[\\/]Users[\\/][^\\/\s'\"`)]+(?:[\\/][^\s'\"`)]*)?"),
]


@dataclass
class Redaction:
    kind: str
    count: int


@dataclass
class PathFlag:
    path: str   # the personal path found
    file: str   # the skill file it appears in
    line: str   # the surrounding line, trimmed, for context


@dataclass
class SanitizationReport:
    redactions: list[Redaction] = field(default_factory=list)
    path_flags: list[PathFlag] = field(default_factory=list)

    @property
    def redaction_total(self) -> int:
        return sum(r.count for r in self.redactions)

    @property
    def has_flags(self) -> bool:
        return bool(self.path_flags)

    @property
    def clean(self) -> bool:
        return not self.redactions and not self.path_flags

    def render(self) -> str:
        lines: list[str] = []
        if self.redactions:
            lines.append("Removed sensitive data before upload:")
            for r in self.redactions:
                lines.append(f"  - {r.kind}: {r.count}")
        if self.path_flags:
            lines.append("Personal file paths found (a tool path may need these; "
                         "they are NOT removed and need your approval):")
            for f in self.path_flags:
                lines.append(f"  - {f.path}   (in {f.file})")
        if not lines:
            lines.append("No PII, secrets, or personal paths found.")
        return "\n".join(lines)


def _line_of(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start: end if end != -1 else len(text)].strip()


def sanitize_text(text: str, filename: str = "SKILL.md") -> tuple[str, SanitizationReport]:
    """Redact a single blob of skill prose, reusing the folder sanitizer so the
    exact same rules apply. Redactions are applied to the returned text; personal
    paths are reported, not removed."""
    out, report = sanitize_folder({filename: text or ""})
    return out[filename], report


def sanitize_folder(folder: dict[str, str]) -> tuple[dict[str, str], SanitizationReport]:
    """Return a sanitized copy of the folder plus a report. Redactions are
    applied to the returned folder; path flags are reported, not applied."""
    out = dict(folder)
    counts: dict[str, int] = {}
    flags: list[PathFlag] = []
    seen_paths: set[tuple[str, str]] = set()

    for path, content in folder.items():
        if not path.endswith((".md", ".mdc")):
            continue  # tool/script/asset internals are out of scope
        new = content
        for kind, rx, repl in _REDACTORS:
            new, n = rx.subn(repl, new)
            if n:
                counts[kind] = counts.get(kind, 0) + n
        out[path] = new
        # Flag personal paths on the post-redaction text.
        for rx in _PERSONAL_PATHS:
            for m in rx.finditer(new):
                found = m.group(0)
                key = (path, found)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                flags.append(PathFlag(path=found, file=path, line=_line_of(new, m.start())))

    redactions = [Redaction(kind, counts[kind]) for kind in sorted(counts)]
    return out, SanitizationReport(redactions=redactions, path_flags=flags)
