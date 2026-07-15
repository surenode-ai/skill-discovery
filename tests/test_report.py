"""Report building: metadata-only shape, sanitized full-skill candidates, and
fingerprint stability."""

from __future__ import annotations

import json
import os

from discovery import scanning
from discovery.local import DiscoveryLocation, _fingerprint, build_discovery_report
from discovery.scanning import Finding, Severity

from tests.conftest import skill_md


class _FakeScanner:
    def __init__(self, findings):
        self._findings = findings

    def scan(self, files):
        return self._findings


def test_local_discovery_builds_metadata_only_report(tmp_path, monkeypatch):
    root = tmp_path / "skills"
    (root / "deploy").mkdir(parents=True)
    (root / "deploy" / "SKILL.md").write_text(
        skill_md("deploy", "Roll out with checks.", "Run rollout checks."),
        encoding="utf-8",
    )
    scanning.set_scanner(_FakeScanner([Finding("LOW1", "output_handling", Severity.low)]))
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")

    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "codex", "user_codex")],
        upload_mode="metadata_only",
        device_id="dev1",
        user_id="dev@example.com",
    )
    assert report["device_id"] == "dev1"
    assert len(report["items"]) == 1
    item = report["items"][0]
    assert item["external_id"] == "codex:user_codex:deploy"
    assert item["name"] == "deploy"
    assert item["scanner"] == "fake"
    assert item["local_findings"][0]["rule_id"] == "LOW1"
    assert "candidate" not in item

    # The report is JSON serializable for the CLI POST path.
    json.dumps(report)


def test_local_discovery_full_skill_sanitizes_candidate(tmp_path, monkeypatch):
    secret = "sk-ant-" + ("b" * 24)
    root = tmp_path / "skills"
    (root / "leaky").mkdir(parents=True)
    (root / "leaky" / "SKILL.md").write_text(
        skill_md("leaky", "Has a key.", f"Use {secret}."),
        encoding="utf-8",
    )
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")

    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "codex", "user_codex")],
        upload_mode="full_skill",
        device_id="dev2",
    )
    item = report["items"][0]
    assert secret not in item["candidate"]["SKILL.md"]
    assert "[redacted:api-key]" in item["candidate"]["SKILL.md"]
    assert any(f["rule_id"].startswith("sanitize.redacted") for f in item["local_findings"])


def test_fingerprint_is_stable_and_content_sensitive():
    files = {"SKILL.md": "---\nname: a\n---\n\nbody\n", "references/x.md": "notes\n"}
    fp1 = _fingerprint(files)
    fp2 = _fingerprint(dict(reversed(list(files.items()))))  # order-independent
    assert fp1 == fp2
    assert fp1.startswith("sha256:")
    changed = dict(files)
    changed["references/x.md"] = "notes v2\n"
    assert _fingerprint(changed) != fp1


def test_metadata_only_redacts_secret_in_description(tmp_path, monkeypatch):
    """metadata_only uploads no file bodies, only fields like description. A
    secret placed in SKILL.md frontmatter must not ride along in the clear."""
    secret = "sk-ant-" + ("a" * 28)
    root = tmp_path / "skills"
    (root / "leaky").mkdir(parents=True)
    (root / "leaky" / "SKILL.md").write_text(
        skill_md("leaky", f"Use token {secret}", "body"), encoding="utf-8")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "codex", "user_codex")], device_id="m")
    item = report["items"][0]
    assert "candidate" not in item          # metadata_only
    assert secret not in item["description"]
    assert "[redacted:api-key]" in item["description"]


def test_full_skill_redacts_secret_in_bundled_script(tmp_path, monkeypatch):
    """full_skill uploads scripts alongside SKILL.md; a secret in a .py file
    must be redacted in the candidate, not just secrets in markdown."""
    secret = "sk-ant-" + ("b" * 28)
    root = tmp_path / "skills"
    (root / "tool").mkdir(parents=True)
    (root / "tool" / "SKILL.md").write_text(
        skill_md("tool", "A tool.", "Run it."), encoding="utf-8")
    (root / "tool" / "run.py").write_text(f"KEY = {secret!r}\n", encoding="utf-8")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "codex", "user_codex")],
        upload_mode="full_skill", device_id="m")
    candidate = report["items"][0]["candidate"]
    assert secret not in candidate["run.py"]
    assert "[redacted:api-key]" in candidate["run.py"]


def test_rule_file_symlink_is_not_followed(tmp_path, monkeypatch):
    """A rule-file glob must not follow a symlink to an arbitrary target the
    way an unguarded read would (e.g. .cursor/rules/x.mdc -> ~/.ssh/id_rsa)."""
    secret_target = tmp_path / "outside_secret"
    secret_target.write_text("sk-ant-" + ("c" * 28) + "\n", encoding="utf-8")
    rules = tmp_path / ".cursor" / "rules"
    rules.mkdir(parents=True)
    os.symlink(secret_target, rules / "linked.mdc")
    (rules / "real.mdc").write_text("# real rule\n\nDo the thing.\n", encoding="utf-8")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    report = build_discovery_report(
        locations=[DiscoveryLocation(rules, "cursor", "project_cursor_rules", pattern="*.mdc")],
        upload_mode="full_skill", device_id="m")
    rels = {i["relative_path"] for i in report["items"]}
    assert rels == {"real.mdc"}  # the symlink is skipped, the real file is kept
    blob = json.dumps(report)
    assert "sk-ant-" not in blob


def test_fingerprint_ignores_line_endings(tmp_path):
    """A skill checked out with CRLF (Windows/git autocrlf) must fingerprint
    identically to the LF copy — line-ending style is not a real difference."""
    lf = {"SKILL.md": "---\nname: a\n---\n\nline one\nline two\n"}
    crlf = {"SKILL.md": lf["SKILL.md"].replace("\n", "\r\n")}
    assert _fingerprint(lf) == _fingerprint(crlf)
    # Real content changes still change the fingerprint.
    assert _fingerprint({"SKILL.md": lf["SKILL.md"] + "extra\n"}) != _fingerprint(lf)


def test_broken_frontmatter_is_flagged_in_report(tmp_path, monkeypatch):
    root = tmp_path / "skills"
    (root / "broken").mkdir(parents=True)
    (root / "broken" / "SKILL.md").write_text("no frontmatter at all\n", encoding="utf-8")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "custom", "custom")], device_id="m")
    rule_ids = {f["rule_id"] for f in report["items"][0]["local_findings"]}
    assert "local.invalid_skill_md" in rule_ids


def test_unscannable_script_becomes_a_report_finding(tmp_path, monkeypatch):
    """A non-UTF-8 script is skipped by the walker; report assembly must turn
    that skip into a finding, not drop it silently."""
    root = tmp_path / "skills"
    (root / "tool").mkdir(parents=True)
    (root / "tool" / "SKILL.md").write_text(
        skill_md("tool", "A tool.", "Run it."), encoding="utf-8")
    (root / "tool" / "payload.py").write_bytes(b"print('x')\n\xff\xfe\x00bad")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "custom", "custom")], device_id="m")
    rule_ids = {f["rule_id"] for f in report["items"][0]["local_findings"]}
    assert "unscannable-executable" in rule_ids


def test_symlinked_skill_md_produces_no_phantom_item(tmp_path, monkeypatch):
    root = tmp_path / "skills"
    (root / "ghost").mkdir(parents=True)
    target = tmp_path / "elsewhere.md"
    target.write_text("---\nname: ghost\n---\n\nbody\n", encoding="utf-8")
    os.symlink(target, root / "ghost" / "SKILL.md")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "custom", "custom")], device_id="m")
    assert report["items"] == []  # a symlinked SKILL.md is not a real local skill


def test_missing_root_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    report = build_discovery_report(
        locations=[DiscoveryLocation(tmp_path / "nope", "claude", "user_claude")],
        device_id="dev3",
    )
    assert report["items"] == []
    assert report["meta"]["locations"] == [{"source": "claude", "location_kind": "user_claude"}]


def test_heuristic_floor_flags_unsafe_skill_without_skillspector(tmp_path):
    """No SkillSpector on the machine -> the report still carries heuristic
    findings and says which backend ran."""
    root = tmp_path / "skills"
    (root / "envdump").mkdir(parents=True)
    (root / "envdump" / "SKILL.md").write_text(
        skill_md("envdump", "Demo.", "Run this:\n\n```bash\nprintenv | base64\n```\n"),
        encoding="utf-8",
    )
    report = build_discovery_report(
        locations=[DiscoveryLocation(root, "custom", "custom")],
        device_id="dev4",
        scanner_backend="heuristics",
    )
    item = report["items"][0]
    assert item["scanner"] == "heuristics"
    assert report["meta"]["scanner"] == "heuristics"
    cats = {f["category"] for f in item["local_findings"]}
    assert "data_exfiltration" in cats
