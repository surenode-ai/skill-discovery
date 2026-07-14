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

from discovery.sanitize import SanitizationReport, sanitize_folder
from discovery.scanning import Finding, ScannerError, Severity, configure_scanner, get_scanner
from discovery.skillmd import SkillParseError, parse_skill_md
from discovery.walker import _discover


@dataclass(frozen=True)
class DiscoveryLocation:
    root: Path
    source: str
    location_kind: str


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


def _fingerprint(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for path in sorted(files, key=_posix):
        h.update(_posix(path).encode())
        h.update(b"\0")
        h.update(files[path].encode())
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


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

    for loc in locations or default_locations():
        root = loc.root.expanduser()
        if not root.is_dir():
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
            name = skill.name
            description = skill.description
            if not skill.valid:
                try:
                    parsed = parse_skill_md(skill.files.get("SKILL.md", ""))
                    name = parsed.name
                    description = parsed.description
                except SkillParseError:
                    pass
            include_candidate = upload_mode in {"full_skill", "full_skill_after_local_scan"}
            rel_dir = _posix(skill.rel_dir)
            items.append({
                "external_id": f"{loc.source}:{loc.location_kind}:{rel_dir}",
                "source": loc.source,
                "location_kind": loc.location_kind,
                "relative_path": f"{rel_dir}/SKILL.md" if rel_dir else "SKILL.md",
                "name": name or "unknown",
                "description": description or "",
                "fingerprint": _fingerprint(skill.files),
                "scanner": scanner_name,
                "scanner_version": agent_version,
                "local_findings": [_finding_json(f) for f in findings],
                **({"candidate": sanitized} if include_candidate else {}),
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
                {"source": l.source, "location_kind": l.location_kind}
                for l in (locations or default_locations())
            ],
        },
    }
