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
    # The skill root plus the ~/.claude/CLAUDE.md memory rule glob.
    assert DiscoveryLocation(tmp_path / ".claude" / "skills", "claude", "user_claude") in locs
    assert any(l.location_kind == "user_claude_rules" and l.pattern == ".claude/CLAUDE.md"
               for l in locs)


def test_registry_project_locations(tmp_path):
    locs = project_locations(["codex", "opencode"], tmp_path)
    assert any(l.location_kind == "project_codex" and l.pattern is None
               and l.root == tmp_path / ".agents" / "skills" for l in locs)
    assert any(l.location_kind == "project_codex_rules" and l.pattern == "AGENTS.md"
               for l in locs)
    assert any(l.location_kind == "project_opencode"
               and l.root == tmp_path / ".opencode" / "skills" for l in locs)


def test_registry_covers_documented_agents():
    assert set(agent_keys()) == {"codex", "claude", "opencode", "cursor",
                                 "antigravity", "windsurf", "copilot", "kiro",
                                 "gemini", "cline", "roo"}
    for spec in AGENTS.values():
        # Every agent contributes at least one location (skills or instructions).
        assert (spec.user_roots or spec.project_roots
                or spec.user_rule_globs or spec.project_rule_globs)
    # Rule globs shipped where the vendor documents instruction files.
    assert ".cursor/rules/**/*.mdc" in AGENTS["cursor"].project_rule_globs  # recursive
    assert "AGENTS.md" in AGENTS["codex"].project_rule_globs
    assert "CLAUDE.md" in AGENTS["claude"].project_rule_globs
    assert ".claude/CLAUDE.md" in AGENTS["claude"].user_rule_globs
    assert "GEMINI.md" in AGENTS["gemini"].project_rule_globs
    assert ".kiro/steering/**/*.md" in AGENTS["kiro"].project_rule_globs
    assert ".github/copilot-instructions.md" in AGENTS["copilot"].project_rule_globs
    assert ".codeium/windsurf/memories/global_rules.md" in AGENTS["windsurf"].user_rule_globs
    # Instruction-only agents document no SKILL.md roots; the registry must not invent any.
    assert AGENTS["gemini"].user_roots == () and AGENTS["gemini"].project_roots == ()
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
    # Every agent is checked, as a user skill root (user_<k>) and/or, for
    # instruction-only agents, a rule-glob location (user_<k>_rules).
    for k in agent_keys():
        assert f"user_{k}" in kinds or f"user_{k}_rules" in kinds
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
    # claude also contributes its ~/.claude/CLAUDE.md rule glob; codex has no
    # user-level rule glob. opencode is not implied by the aliases.
    assert kinds == {"user_claude", "user_claude_rules", "user_codex"}


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


def _skill_home(tmp_path, name="deploy", desc="Roll out with checks.", body="Steps."):
    home = tmp_path / "home"
    (home / ".claude" / "skills" / name).mkdir(parents=True)
    (home / ".claude" / "skills" / name / "SKILL.md").write_text(
        skill_md(name, desc, body), encoding="utf-8")
    return home


def test_cli_dry_run_defaults_to_json_when_piped(tmp_path, capsys, monkeypatch):
    # capsys' stdout is not a TTY, so the default format is json.
    home = _skill_home(tmp_path)
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    assert main(["--home", str(home), "--dry-run"]) == 0
    doc = json.loads(capsys.readouterr().out)  # pure JSON on stdout
    item = doc["items"][0]
    assert item["name"] == "deploy"
    assert "_path" not in item and "_where" not in item  # wire report has no local fields


def test_cli_human_view_renders_labeled_tables(tmp_path, capsys, monkeypatch):
    home = _skill_home(tmp_path)
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    assert main(["--home", str(home), "--dry-run", "--format", "human"]) == 0
    out = capsys.readouterr().out
    assert "skill-discovery" in out                              # headline
    assert "Skills (1)" in out                                   # section title + count
    for header in ("name", "agent", "where", "description"):     # column headers present
        assert header in out
    assert "deploy" in out and "Roll out" in out
    assert "global" in out                                       # where column, user-level
    assert "✓ No findings" in out                                # clean-state signal
    assert "\033" not in out                                     # no ANSI when not a TTY


def test_cli_human_view_verbose_shows_paths_and_locations(tmp_path, capsys, monkeypatch):
    home = _skill_home(tmp_path)
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    assert main(["--home", str(home), "--dry-run", "--format", "human", "-v"]) == 0
    out = capsys.readouterr().out
    assert "deploy/SKILL.md" in out          # the item's full path sub-line
    assert "Locations checked:" in out
    assert "[not present]" in out            # empties shown with --verbose


def test_cli_human_view_wraps_by_default(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude" / "skills" / "big").mkdir(parents=True)
    (home / ".claude" / "skills" / "big" / "SKILL.md").write_text(
        skill_md("big", "alpha " * 50, "b"), encoding="utf-8")  # long description
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    main(["--home", str(home), "--dry-run", "--format", "human"])
    wrapped = capsys.readouterr().out
    assert "…" not in wrapped                              # wrapped by default, nothing cut
    main(["--home", str(home), "--dry-run", "--format", "human", "--no-wrap"])
    dense = capsys.readouterr().out
    assert "…" in dense                                   # --no-wrap truncates for density
    assert wrapped.count("alpha") > dense.count("alpha")  # default shows more


def test_cli_no_server_shows_inventory_without_submitting(tmp_path, capsys, monkeypatch):
    # No --dry-run and no server configured: show the inventory locally, never POST.
    home = _skill_home(tmp_path)
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    monkeypatch.setattr("discovery.cli._post",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not submit")))
    rc = main(["--home", str(home), "--json"])   # no --dry-run, no --url
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["items"][0]["name"] == "deploy"


def test_cli_submit_error_is_reported_not_fatal(tmp_path, capsys, monkeypatch):
    import urllib.error
    home = _skill_home(tmp_path)
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")

    def fail(url, body, token=None):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr("discovery.cli._post", fail)
    rc = main(["--home", str(home), "--url", "https://reports.example.com"])
    assert rc == 1                                   # clean failure, not a traceback
    assert "could not submit" in capsys.readouterr().err


def test_cli_fail_on_findings_sets_exit_code(tmp_path, capsys):
    # A skill that trips the heuristic floor (env dump) produces a finding.
    home = tmp_path / "home"
    (home / ".claude" / "skills" / "bad").mkdir(parents=True)
    (home / ".claude" / "skills" / "bad" / "SKILL.md").write_text(
        skill_md("bad", "Demo", "Run:\n\n```bash\nprintenv | base64\n```\n"), encoding="utf-8")
    base = ["--home", str(home), "--dry-run", "--json", "--scanner-backend", "heuristics"]
    assert main(base) == 0                                   # findings are not errors by default
    capsys.readouterr()
    assert main(base + ["--fail-on", "findings"]) == 1       # opt-in CI gate trips


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
