"""Local endpoint discovery for administrator-deployed agents.

This code runs on the developer machine. It reads only configured skill roots,
scans each skill locally, and prepares the JSON report sent to
``POST /discovery/reports``.
"""

from __future__ import annotations

import hashlib
import os
import socket
from dataclasses import dataclass
from pathlib import Path

from discovery.sanitize import SanitizationReport, sanitize_folder, sanitize_text
from discovery.scanning import (
    Finding, ScannerError, Severity, configure_scanner,
    findings_for_skipped_files, get_scanner,
)
from discovery.skillmd import SkillParseError, parse_skill_md
from discovery.walker import MAX_SKILLS, _discover, _read_text


@dataclass(frozen=True)
class DiscoveryLocation:
    root: Path
    source: str
    location_kind: str
    # When set, this location inventories standalone instruction/rule files
    # matching the glob under root (e.g. ".cursor/rules/*.mdc") instead of
    # walking root for SKILL.md folders.
    pattern: str | None = None


def default_locations(home: Path | None = None) -> list[DiscoveryLocation]:
    home = home or Path.home()
    return [
        DiscoveryLocation(home / ".agents" / "skills", "codex", "user_codex"),
        DiscoveryLocation(home / ".claude" / "skills", "claude", "user_claude"),
    ]


def _posix(path: str) -> str:
    """Normalize a relative path to forward slashes so report identity and
    fingerprints are identical across Windows, macOS, and Linux."""
    return path.replace("\\", "/")


def _normalize_eol(text: str) -> str:
    """Collapse CRLF and lone CR to LF so a skill fingerprints identically
    whether it was checked out on Windows (git autocrlf) or Unix. Line-ending
    style is not a meaningful difference between two copies of the same skill."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _fingerprint(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for path in sorted(files, key=_posix):
        h.update(_posix(path).encode())
        h.update(b"\0")
        h.update(_normalize_eol(files[path]).encode())
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def _redact_meta(text: str) -> str:
    """Redact secrets out of a report field lifted verbatim from untrusted skill
    content (name, description) or from a path segment (a skill directory or a
    file named like a credential). Without this a secret would ride to the
    server in the clear even in ``metadata_only`` mode, which uploads no file
    bodies, through the description, the external_id, or the relative_path.
    Deterministic, so an external_id built from it stays a stable upsert key;
    reuses the same redactors as file sanitization and keeps only the cleaned
    text (the finding was already counted when the source file was scanned)."""
    return sanitize_text(text or "")[0]


def _redact_candidate(folder: dict[str, str]) -> dict[str, str]:
    """Redact secrets from candidate map keys as well as values: a file named
    like a credential would otherwise leak through the key in ``full_skill``
    even though ``sanitize_folder`` already cleaned its contents."""
    return {_redact_meta(path): content for path, content in folder.items()}


def _finding_json(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity.name,
        "title": finding.title,
        "path": finding.path,
    }


def _scanner_error_finding(message: str) -> Finding:
    return Finding(
        rule_id="local.discovery_scan_failed",
        category="scanner_error",
        severity=Severity.medium,
        title=message,
    )


def _invalid_skill_finding(error: str | None) -> Finding:
    """The skill's SKILL.md did not parse. Surface it as a finding so a broken
    or malformed manifest is visible in the report instead of silently
    appearing as a normal item with an empty name/description."""
    return Finding(
        rule_id="local.invalid_skill_md",
        category="invalid_manifest",
        severity=Severity.low,
        title=error or "SKILL.md did not parse.",
        path="SKILL.md",
    )


def _sanitization_findings(report: SanitizationReport) -> list[Finding]:
    findings: list[Finding] = []
    for redaction in report.redactions:
        findings.append(Finding(
            rule_id=f"sanitize.redacted.{redaction.kind}",
            category="sensitive_data",
            severity=Severity.medium,
            title=f"Sanitized {redaction.count} {redaction.kind} value(s) before upload.",
        ))
    for flag in report.path_flags:
        findings.append(Finding(
            rule_id="sanitize.personal_path",
            category="sensitive_path",
            severity=Severity.medium,
            title="Personal filesystem path found in local skill content.",
            path=flag.file,
        ))
    return findings


_HEADING_RE_TEXT = r"^\s*#+\s*(.+)$"


def _rule_description(content: str) -> str:
    """Cheap one-line description for a standalone instruction file: the
    frontmatter ``description:`` if present, else the first heading, else the
    first non-empty line."""
    import re

    body = content
    fm_match = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)$", content, re.DOTALL)
    if fm_match:
        desc = re.search(r"^description:\s*(.+)$", fm_match.group(1), re.MULTILINE)
        if desc:
            return desc.group(1).strip().strip("\"'")[:255]
        body = fm_match.group(2)
    for line in body.splitlines():
        line = line.strip()
        if line:
            heading = re.match(_HEADING_RE_TEXT, line)
            return (heading.group(1) if heading else line).strip()[:255]
    return ""


def _privacy_text(text: str, home: Path | None = None) -> str:
    """Redact common personal path shapes before reporting discovery errors."""
    import re

    home_text = str((home or Path.home()).expanduser())
    if home_text and home_text != ".":
        text = text.replace(home_text, "~")
    text = re.sub(r"(/Users|/home)/[^/\s'\"`)]+", r"\1/[redacted-user]", text)
    text = re.sub(r"[A-Za-z]:[\\/]Users[\\/][^\\/\s'\"`)]+", r"C:\\Users\\[redacted-user]", text)
    return text


def build_discovery_report(
    *,
    locations: list[DiscoveryLocation] | None = None,
    upload_mode: str = "metadata_only",
    device_id: str | None = None,
    device_name: str | None = None,
    user_id: str | None = None,
    agent_version: str = "skill-discovery",
    scanner_backend: str = "auto",
) -> dict:
    """Build a privacy-aware discovery report from local skill roots."""

    scanner_name = "local"
    try:
        scanner_name = configure_scanner(scanner_backend)
    except ScannerError:
        # The report still goes through with an explicit scanner finding per
        # item rather than silently claiming a clean local scan.
        pass

    device_name = device_name or socket.gethostname()
    device_id = device_id or device_name
    user_id = user_id or os.environ.get("USER") or os.environ.get("USERNAME")
    items: list[dict] = []

    include_candidate = upload_mode in {"full_skill", "full_skill_after_local_scan"}

    for loc in locations or default_locations():
        root = loc.root.expanduser()
        if not root.is_dir():
            continue
        if loc.pattern:
            # Standalone instruction/rule files (Cursor rules, Kiro steering,
            # Copilot instructions, ...): one report item per matching file,
            # fingerprinted, sanitized, and scanned exactly like a skill folder.
            root_real = os.path.realpath(root)
            for match in sorted(root.glob(loc.pattern))[:MAX_SKILLS]:
                # Skip symlinks, and anything that resolves outside the root via
                # a symlinked path component: the skill-folder walker refuses to
                # follow symlinks, and a rule file must not be the hole that
                # reads (and uploads) an arbitrary target like ~/.ssh/id_rsa.
                if match.is_symlink() or not match.is_file():
                    continue
                match_real = os.path.realpath(match)
                if match_real != root_real and not match_real.startswith(root_real + os.sep):
                    continue
                content = _read_text(str(match))
                if content is None:
                    continue  # non-UTF-8 or oversized; rule files are text
                rel = _posix(str(match.relative_to(root)))
                files = {rel: content}
                try:
                    findings = get_scanner().scan(files)
                except ScannerError as exc:
                    findings = [_scanner_error_finding(str(exc))]
                sanitized, sanitization = sanitize_folder(files)
                findings = findings + _sanitization_findings(sanitization)
                safe_rel = _redact_meta(rel)  # the filename itself may be a secret
                items.append({
                    "external_id": f"{loc.source}:{loc.location_kind}:{safe_rel}",
                    "source": loc.source,
                    "location_kind": loc.location_kind,
                    "relative_path": safe_rel,
                    "name": _redact_meta(match.stem or match.name),
                    "description": _redact_meta(_rule_description(content)),
                    "fingerprint": _fingerprint(files),
                    "scanner": scanner_name,
                    "scanner_version": agent_version,
                    "local_findings": [_finding_json(f) for f in findings],
                    **({"candidate": _redact_candidate(sanitized)} if include_candidate else {}),
                })
            continue
        skills, errors = _discover(str(root), str(root))
        for skill in skills:
            findings: list[Finding]
            try:
                findings = get_scanner().scan(skill.files)
            except ScannerError as exc:
                findings = [_scanner_error_finding(str(exc))]
            sanitized, sanitization = sanitize_folder(skill.files)
            findings = findings + _sanitization_findings(sanitization)
            if not skill.valid:
                findings.append(_invalid_skill_finding(skill.error))
            # An executable/archive the walker had to skip (non-UTF-8 or
            # oversized) is a hidden-payload tell; surface it in the report.
            findings.extend(findings_for_skipped_files(skill.skipped_files))
            name = skill.name
            description = skill.description
            if not skill.valid:
                try:
                    parsed = parse_skill_md(skill.files.get("SKILL.md", ""))
                    name = parsed.name
                    description = parsed.description
                except SkillParseError:
                    pass
            rel_dir = _posix(skill.rel_dir)
            safe_rel_dir = _redact_meta(rel_dir)  # a skill dir may be named like a secret
            items.append({
                "external_id": f"{loc.source}:{loc.location_kind}:{safe_rel_dir}",
                "source": loc.source,
                "location_kind": loc.location_kind,
                "relative_path": f"{safe_rel_dir}/SKILL.md" if safe_rel_dir else "SKILL.md",
                "name": _redact_meta(name) or "unknown",
                "description": _redact_meta(description),
                "fingerprint": _fingerprint(skill.files),
                "scanner": scanner_name,
                "scanner_version": agent_version,
                "local_findings": [_finding_json(f) for f in findings],
                **({"candidate": _redact_candidate(sanitized)} if include_candidate else {}),
            })
        for err in errors:
            safe_err = _privacy_text(err, root)
            items.append({
                "external_id": f"{loc.source}:{loc.location_kind}:error:{hashlib.sha256(err.encode()).hexdigest()[:16]}",
                "source": loc.source,
                "location_kind": loc.location_kind,
                "relative_path": "",
                "name": "discovery error",
                "description": safe_err,
                "fingerprint": "sha256:" + hashlib.sha256(err.encode()).hexdigest(),
                "scanner": scanner_name,
                "scanner_version": agent_version,
                "local_findings": [_finding_json(_scanner_error_finding(err))],
            })

    return {
        "device_id": device_id,
        "device_name": device_name,
        "user_id": user_id,
        "agent_version": agent_version,
        "upload_mode": upload_mode,
        "items": items,
        "meta": {
            "scanner": scanner_name,
            "locations": [
                {"source": loc.source, "location_kind": loc.location_kind}
                for loc in (locations or default_locations())
            ],
        },
    }
