"""CLI-level behavior: --dry-run prints a well-formed JSON report and needs no
server; submissions refuse plaintext HTTP off-loopback and always time out."""

from __future__ import annotations

import json

import pytest

from discovery.cli import REQUEST_TIMEOUT_SECONDS, _dw, _pad, _post, main

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
    assert {"user_codex", "user_claude"} <= kinds  # all registered agents, incl. these two
    assert out["items"][0]["external_id"] == "claude:user_claude:notes"


def _skill_root(tmp_path):
    root = tmp_path / "skills"
    (root / "deploy").mkdir(parents=True)
    (root / "deploy" / "SKILL.md").write_text(
        skill_md("deploy", "Roll out with checks.", "Run rollout checks."),
        encoding="utf-8",
    )
    return root


def _fake_post(posted):
    def post(url, body, token=None):
        posted["url"] = url
        return {"accepted": len(body["items"]), "flagged": 0, "blocked": 0}
    return post


def test_cli_refuses_plaintext_http_off_loopback(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--path", str(_skill_root(tmp_path)),
              "--url", "http://reports.example.com"])
    assert exc.value.code == 2  # argparse error, before any scan or network I/O
    assert "--allow-http" in capsys.readouterr().err


def test_cli_allow_http_overrides_for_remote_host(tmp_path, monkeypatch):
    posted = {}
    monkeypatch.setattr("discovery.cli._post", _fake_post(posted))
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--path", str(_skill_root(tmp_path)),
               "--url", "http://reports.example.com", "--allow-http"])
    assert rc == 0
    assert posted["url"] == "http://reports.example.com/discovery/reports"


def test_cli_loopback_http_needs_no_flag(tmp_path, monkeypatch):
    posted = {}
    monkeypatch.setattr("discovery.cli._post", _fake_post(posted))
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--path", str(_skill_root(tmp_path)), "--url", "http://127.0.0.1:8000"])
    assert rc == 0
    assert posted["url"] == "http://127.0.0.1:8000/discovery/reports"


@pytest.mark.parametrize("host", ["127.0.0.1.evil.com", "127.evil.com", "notlocalhost"])
def test_cli_rejects_hostnames_that_only_look_like_loopback(tmp_path, capsys, host):
    """A DNS name that merely starts with '127.' or contains 'localhost' is not
    loopback and must be refused over plaintext http."""
    with pytest.raises(SystemExit) as exc:
        main(["--path", str(_skill_root(tmp_path)), "--url", f"http://{host}"])
    assert exc.value.code == 2
    assert "--allow-http" in capsys.readouterr().err


def test_cli_accepts_ipv6_loopback(tmp_path, monkeypatch):
    posted = {}
    monkeypatch.setattr("discovery.cli._post", _fake_post(posted))
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--path", str(_skill_root(tmp_path)), "--url", "http://[::1]:8000"])
    assert rc == 0
    assert posted["url"] == "http://[::1]:8000/discovery/reports"


@pytest.mark.parametrize("bad", [{}, [], None, {"unexpected": 1}])
def test_cli_malformed_server_response_is_a_failed_submission(tmp_path, monkeypatch, capsys, bad):
    """A 2xx without the documented shape ({}, [], None, contract-less) is a
    failed submission (exit 1 + message), not a fabricated success."""
    monkeypatch.setattr("discovery.cli._post", lambda url, body, token=None, _v=bad: _v)
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--path", str(_skill_root(tmp_path)), "--url", "http://127.0.0.1:8000"])
    assert rc == 1
    assert "did not return the expected response" in capsys.readouterr().err


def test_cli_valid_server_response_reports_success(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("discovery.cli._post", lambda url, body, token=None:
                        {"report_id": "r1", "accepted": 3, "flagged": 1, "blocked": 0})
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--path", str(_skill_root(tmp_path)), "--url", "http://127.0.0.1:8000"])
    assert rc == 0
    assert "Reported 3 discovered skill(s): 1 flagged, 0 blocked" in capsys.readouterr().out


class _FakeResp:
    """Minimal context-manager stand-in for an http response with a fixed body."""
    def __init__(self, body):
        self._body = body.encode()
    def read(self):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def test_post_sets_a_timeout(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["timeout"] = timeout
        return _FakeResp('{"accepted": 0, "flagged": 0, "blocked": 0}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    _post("https://reports.example.com/discovery/reports", {"items": []})
    assert seen["timeout"] == REQUEST_TIMEOUT_SECONDS


@pytest.mark.parametrize("body", ["", "   ", "not json at all", "<html>oops</html>"])
def test_post_returns_none_on_empty_or_nonjson_body(monkeypatch, body):
    """A 2xx with an empty or non-JSON body returns None (never raises); the
    caller treats a malformed response as a failed submission."""
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: _FakeResp(body))
    assert _post("https://reports.example.com/discovery/reports", {"items": []}) is None


def test_display_width_handles_wide_and_combining_chars():
    assert _dw("ascii") == 5
    assert _dw("部署") == 4          # two wide (CJK) columns
    assert _dw("🚀") == 2            # emoji renders wide
    assert _dw("é") == 1       # e + combining acute = one column
    # _pad reaches the target display width regardless of char widths
    assert _dw(_pad("部署", 10)) == 10
    assert _dw(_pad("🚀x", 6)) == 6
    assert _pad("ascii", 8) == "ascii   "
