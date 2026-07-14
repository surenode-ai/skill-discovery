"""Agent registry resolution, the --agent/--project CLI surface, and
OS-agnostic report identity (posix separators everywhere)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from discovery.agents import AGENTS, agent_keys, project_locations, user_locations
from discovery.cli import main
from discovery.local import DiscoveryLocation, _fingerprint, build_discovery_report
from discovery.sanitize import SanitizationReport
from discovery.walker import DiscoveredSkill

from tests.conftest import skill_md


# ---- registry resolution ----

def test_registry_user_locations(tmp_path):
    locs = user_locations(["claude"], tmp_path)
    assert locs == [DiscoveryLocation(tmp_path / ".claude" / "skills", "claude", "user_claude")]


def test_registry_project_locations(tmp_path):
    locs = project_locations(["codex", "opencode"], tmp_path)
    assert (tmp_path / ".agents" / "skills", "codex", "project_codex") == (
        locs[0].root, locs[0].source, locs[0].location_kind)
    assert (tmp_path / ".opencode" / "skills", "opencode", "project_opencode") == (
        locs[1].root, locs[1].source, locs[1].location_kind)


def test_registry_covers_documented_agents():
    assert set(agent_keys()) == {"codex", "claude", "opencode", "cursor",
                                 "antigravity", "windsurf", "copilot", "kiro"}
    for spec in AGENTS.values():
        assert spec.user_roots  # every agent has at least a user-level root
    # Rule globs shipped where the vendor documents instruction files.
    assert AGENTS["cursor"].project_rule_globs == (".cursor/rules/*.mdc",)
    assert ".kiro/steering/*.md" in AGENTS["kiro"].project_rule_globs
    assert ".kiro/steering/*.md" in AGENTS["kiro"].user_rule_globs
    assert ".github/copilot-instructions.md" in AGENTS["copilot"].project_rule_globs
    assert ".github/instructions/*.instructions.md" in AGENTS["copilot"].project_rule_globs
    assert ".codeium/windsurf/memories/global_rules.md" in AGENTS["windsurf"].user_rule_globs
    # Antigravity documents no on-disk rules path; the registry must not invent one.
    assert AGENTS["antigravity"].project_rule_globs == ()
    assert AGENTS["antigravity"].user_rule_globs == ()


# ---- CLI: --agent all is the zero-config default ----

def test_cli_agent_all_is_default(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--home", str(home), "--device-id", "dev", "--dry-run"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    kinds = {loc["location_kind"] for loc in out["meta"]["locations"]}
    # Every agent's user skill root is checked; rule-glob locations appear
    # under their own ..._rules kinds.
    assert {f"user_{k}" for k in agent_keys()} <= kinds
    assert all(k.startswith("user_") for k in kinds)


def test_cli_agent_flag_scopes_scan(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    (home / ".config" / "opencode" / "skills" / "fmt").mkdir(parents=True)
    (home / ".config" / "opencode" / "skills" / "fmt" / "SKILL.md").write_text(
        skill_md("fmt", "Format.", "Run it."), encoding="utf-8")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--agent", "opencode", "--home", str(home), "--device-id", "dev", "--dry-run"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["meta"]["locations"] == [{"source": "opencode", "location_kind": "user_opencode"}]
    assert out["items"][0]["external_id"] == "opencode:user_opencode:fmt"


def test_cli_rejects_unknown_agent(tmp_path, capsys):
    with pytest.raises(SystemExit):
        main(["--agent", "nonesuch", "--home", str(tmp_path), "--dry-run"])
    assert "unknown agent" in capsys.readouterr().err


# ---- CLI: deprecated aliases keep working ----

def test_cli_claude_codex_aliases(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--claude", "--codex", "--home", str(home), "--device-id", "dev", "--dry-run"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    kinds = {loc["location_kind"] for loc in out["meta"]["locations"]}
    assert kinds == {"user_claude", "user_codex"}  # opencode not implied by aliases


# ---- CLI: project-level scanning ----

def test_cli_project_scanning(tmp_path, capsys, monkeypatch):
    proj = tmp_path / "repo"
    (proj / ".claude" / "skills" / "review").mkdir(parents=True)
    (proj / ".claude" / "skills" / "review" / "SKILL.md").write_text(
        skill_md("review", "Review the diff.", "Steps."), encoding="utf-8")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--project", str(proj), "--device-id", "dev", "--dry-run"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    item = out["items"][0]
    assert item["location_kind"] == "project_claude"
    assert item["external_id"] == "claude:project_claude:review"
    # No user-level roots were scanned: --project alone means project-only.
    kinds = {loc["location_kind"] for loc in out["meta"]["locations"]}
    assert all(k.startswith("project_") for k in kinds)


def test_cli_dry_run_lists_checked_roots_on_stderr(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--home", str(home), "--device-id", "dev", "--dry-run"])
    assert rc == 0
    captured = capsys.readouterr()
    json.loads(captured.out)  # stdout stays pure JSON
    assert "Checked locations:" in captured.err
    assert "[      found] skills" in captured.err  # ~/.claude/skills exists
    assert "[not present]" in captured.err         # the other roots do not
    assert "rules " in captured.err                # rule globs listed and labeled


# ---- OS-agnostic identity: posix separators no matter what the walker returns ----

def _fake_windows_discover(root, location):
    files = {"SKILL.md": skill_md("deep", "Nested.", "Body."),
             "references\\notes.md": "notes\n"}
    skill = DiscoveredSkill(
        rel_dir="nested\\deploy", external_id="nested\\deploy", name="deep",
        description="Nested.", files=files, file_count=len(files), valid=True,
        findings=SanitizationReport(),
    )
    return [skill], []


def test_windows_style_paths_normalize_to_posix_in_report(tmp_path, monkeypatch):
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    monkeypatch.setattr("discovery.local._discover", _fake_windows_discover)
    report = build_discovery_report(
        locations=[DiscoveryLocation(tmp_path, "claude", "user_claude")],
        device_id="win-dev",
    )
    item = report["items"][0]
    assert item["relative_path"] == "nested/deploy/SKILL.md"
    assert item["external_id"] == "claude:user_claude:nested/deploy"
    assert "\\" not in item["relative_path"] and "\\" not in item["external_id"]


def test_fingerprint_identical_across_path_separators():
    posix = {"SKILL.md": "body", "references/x.md": "notes"}
    windows = {"SKILL.md": "body", "references\\x.md": "notes"}
    assert _fingerprint(posix) == _fingerprint(windows)
