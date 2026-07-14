"""CLI-level behavior: --dry-run prints a well-formed JSON report and needs no
server."""

from __future__ import annotations

import json

from discovery.cli import main

from tests.conftest import skill_md


def test_cli_discover_dry_run(tmp_path, capsys, monkeypatch):
    root = tmp_path / "skills"
    (root / "deploy").mkdir(parents=True)
    (root / "deploy" / "SKILL.md").write_text(
        skill_md("deploy", "Roll out with checks.", "Run rollout checks."),
        encoding="utf-8",
    )
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main([
        "--path", str(root),
        "--device-id", "cli-dev",
        "--dry-run",
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["device_id"] == "cli-dev"
    assert out["items"][0]["name"] == "deploy"


def test_cli_dry_run_report_shape(tmp_path, capsys):
    root = tmp_path / "skills"
    (root / "fmt").mkdir(parents=True)
    (root / "fmt" / "SKILL.md").write_text(
        skill_md("fmt", "Format things.", "Run the formatter."),
        encoding="utf-8",
    )
    rc = main([
        "--path", str(root),
        "--source", "demo",
        "--device-id", "shape-dev",
        "--scanner-backend", "heuristics",
        "--dry-run",
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    # Top-level payload shape for POST /discovery/reports.
    assert set(out) == {"device_id", "device_name", "user_id", "agent_version",
                        "upload_mode", "items", "meta"}
    assert out["upload_mode"] == "metadata_only"
    item = out["items"][0]
    for key in ("external_id", "source", "location_kind", "relative_path", "name",
                "description", "fingerprint", "scanner", "scanner_version",
                "local_findings"):
        assert key in item, key
    assert item["source"] == "demo"
    assert item["location_kind"] == "custom"
    assert item["fingerprint"].startswith("sha256:")
    assert item["scanner"] == "heuristics"
    assert "candidate" not in item  # metadata_only never carries content


def test_cli_defaults_to_user_roots_when_no_flags(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude" / "skills" / "notes").mkdir(parents=True)
    (home / ".claude" / "skills" / "notes" / "SKILL.md").write_text(
        skill_md("notes", "Take notes.", "Write them down."),
        encoding="utf-8",
    )
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--home", str(home), "--device-id", "home-dev", "--dry-run"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    kinds = {loc["location_kind"] for loc in out["meta"]["locations"]}
    assert kinds == {"user_codex", "user_claude"}
    assert out["items"][0]["external_id"] == "claude:user_claude:notes"
