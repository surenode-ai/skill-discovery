"""Zero-config project discovery: the marker-anchored walk and its CLI wiring
(auto-discovery on by default, provenance labels, fleet-distinct identities)."""

from __future__ import annotations

import json
import os

import pytest

from discovery.cli import main
from discovery.projects import discover_project_roots, project_label

from tests.conftest import skill_md


def _skill(root, name="deploy"):
    d = root / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(skill_md(name, "d", "b"), encoding="utf-8")


# --- the collector ---------------------------------------------------------

def test_discovers_repo_with_a_marker(tmp_path):
    repo = tmp_path / "dev" / "myrepo"
    _skill(repo / ".claude" / "skills")
    roots, truncated = discover_project_roots(tmp_path)
    assert not truncated
    assert str(repo) in roots


def test_prunes_heavy_dirs(tmp_path):
    _skill(tmp_path / "proj" / "node_modules" / "pkg" / ".claude" / "skills")
    roots, _ = discover_project_roots(tmp_path)
    assert all("node_modules" not in r for r in roots)


def test_bare_github_is_not_a_hit_but_github_skills_is(tmp_path):
    ci = tmp_path / "repo_a" / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "ci.yml").write_text("on: push\n", encoding="utf-8")
    _skill(tmp_path / "repo_b" / ".github" / "skills")
    roots, _ = discover_project_roots(tmp_path)
    assert str(tmp_path / "repo_a") not in roots      # only CI, no skills
    assert str(tmp_path / "repo_b") in roots           # confirmed .github/skills


def test_respects_depth_cap(tmp_path):
    deep = tmp_path
    for i in range(10):
        deep = deep / f"d{i}"
    _skill(deep / ".claude" / "skills")
    roots, _ = discover_project_roots(tmp_path, max_depth=3)
    assert roots == []


def test_permission_error_is_skipped_not_fatal(tmp_path, monkeypatch):
    _skill(tmp_path / "ok" / ".claude" / "skills")
    (tmp_path / "locked").mkdir()
    real = os.scandir

    def flaky(path):
        if str(path).endswith("locked"):
            raise PermissionError(str(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", flaky)
    roots, _ = discover_project_roots(tmp_path)
    assert any(r.endswith("ok") for r in roots)   # didn't crash; found the good one


def test_time_budget_truncates(tmp_path):
    _skill(tmp_path / "a" / ".claude" / "skills")
    ticks = iter([0.0, 100.0, 200.0])   # start=0, first check=100 > budget
    roots, truncated = discover_project_roots(
        tmp_path, time_budget=1.0, clock=lambda: next(ticks))
    assert truncated is True


def test_symlinked_dir_is_not_followed(tmp_path):
    _skill(tmp_path / "real" / ".claude" / "skills")
    os.symlink(tmp_path / "real", tmp_path / "link")
    roots, _ = discover_project_roots(tmp_path)
    assert str(tmp_path / "real") in roots
    assert str(tmp_path / "link") not in roots        # symlink not traversed


def test_project_label():
    base = os.path.join(os.sep, "home", "u")
    assert project_label(os.path.join(base, "dev", "klin"), base) == "dev/klin"
    assert project_label(base, base) == ""            # base itself -> unlabeled
    # Not under base at all: basename fallback, never a ".." traversal in the id.
    outside = project_label(os.path.join(os.sep, "tmp", "other"), base)
    assert outside == "other"
    assert ".." not in outside


# --- CLI integration -------------------------------------------------------

def _run(argv, monkeypatch, capsys):
    monkeypatch.setattr("discovery.local.configure_scanner", lambda b: "fake")
    assert main(argv) == 0
    return json.loads(capsys.readouterr().out)


def test_cli_auto_discovers_in_repo_skills(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    _skill(home / "dev" / "app" / ".claude" / "skills")
    out = _run(["--home", str(home), "--dry-run", "--device-id", "d"], monkeypatch, capsys)
    ids = [i["external_id"] for i in out["items"]]
    assert "claude:project_claude:dev/app:deploy" in ids


def test_cli_fleet_two_repos_same_skill_stay_distinct(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    _skill(home / "dev" / "app1" / ".claude" / "skills")
    _skill(home / "dev" / "app2" / ".claude" / "skills")
    out = _run(["--home", str(home), "--dry-run"], monkeypatch, capsys)
    ids = {i["external_id"] for i in out["items"] if i["name"] == "deploy"}
    assert "claude:project_claude:dev/app1:deploy" in ids
    assert "claude:project_claude:dev/app2:deploy" in ids
    assert len(ids) == 2   # same skill name, distinct identities across the fleet


def test_cli_no_discover_projects_disables_it(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    _skill(home / "dev" / "app" / ".claude" / "skills")
    out = _run(["--home", str(home), "--no-discover-projects", "--dry-run"],
               monkeypatch, capsys)
    assert out["items"] == []


def test_cli_discover_root_reaches_outside_home(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    workspace = tmp_path / "workspace"
    _skill(workspace / "svc" / ".agents" / "skills", name="fmt")
    out = _run(["--home", str(home), "--discover-root", str(workspace), "--dry-run"],
               monkeypatch, capsys)
    ids = [i["external_id"] for i in out["items"]]
    assert "codex:project_codex:svc:fmt" in ids


def test_cli_discover_roots_env_var(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    workspace = tmp_path / "ws"
    _skill(workspace / "svc" / ".agents" / "skills", name="fmt")
    monkeypatch.setenv("SKILL_DISCOVERY_ROOTS", str(workspace))
    out = _run(["--home", str(home), "--dry-run"], monkeypatch, capsys)
    assert any("svc:fmt" in i["external_id"] for i in out["items"])
