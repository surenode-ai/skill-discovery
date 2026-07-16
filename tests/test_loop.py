"""Continuous mode: digest stability, report-on-change, heartbeat, retry after
failed submission, and the CLI floor on --loop."""

from __future__ import annotations

import json

import pytest

from discovery.cli import main
from discovery.loop import inventory_digest, run_loop

from tests.conftest import skill_md


def _report(items):
    return {
        "device_id": "dev", "device_name": "Dev Box", "user_id": "dev",
        "agent_version": "skill-discovery/test", "upload_mode": "metadata_only",
        "items": items, "meta": {"scanner": "heuristics", "locations": []},
    }


def _item(external_id="claude:user_claude:deploy", fingerprint="sha256:aaa", findings=()):
    return {
        "external_id": external_id, "source": "claude", "location_kind": "user_claude",
        "relative_path": "deploy/SKILL.md", "name": "deploy", "description": "",
        "fingerprint": fingerprint, "scanner": "heuristics",
        "scanner_version": "skill-discovery/test", "local_findings": list(findings),
    }


class _Clock:
    """Fake monotonic clock; the fake sleep advances it like real time would."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _driver(clock, max_passes):
    """A fake sleep that advances the clock and stops the loop after N passes
    (each pass ends in exactly one sleep call)."""
    state = {"n": 0}

    def sleep(seconds):
        clock.t += seconds
        state["n"] += 1
        if state["n"] >= max_passes:
            raise KeyboardInterrupt

    return sleep


class _Submits:
    def __init__(self, fail_first=0):
        self.attempts = 0
        self.successes = []
        self._fail_first = fail_first

    def __call__(self, report):
        self.attempts += 1
        if self.attempts <= self._fail_first:
            raise OSError("connection refused")
        self.successes.append(report)
        return {"accepted": len(report["items"]), "flagged": 0, "blocked": 0}


# ---- digest ----

def test_digest_ignores_run_noise_but_sees_content_change():
    a = _report([_item(), _item("codex:user_codex:fmt", "sha256:bbb")])
    # Same inventory: different device/meta/item order must not matter.
    b = _report(list(reversed(a["items"])))
    b["device_name"] = "Another Box"
    b["agent_version"] = "skill-discovery/other"
    b["meta"] = {"scanner": "skillspector+heuristics", "locations": [{"x": 1}]}
    assert inventory_digest(a) == inventory_digest(b)

    changed = _report([_item(), _item("codex:user_codex:fmt", "sha256:CHANGED")])
    assert inventory_digest(changed) != inventory_digest(a)


def test_digest_sees_findings_change_regardless_of_order():
    f1 = {"rule_id": "r1", "category": "c", "severity": "high", "title": "t", "path": None}
    f2 = {"rule_id": "r2", "category": "c", "severity": "low", "title": "t", "path": "x"}
    a = _report([_item(findings=[f1, f2])])
    b = _report([_item(findings=[f2, f1])])   # order-insensitive
    assert inventory_digest(a) == inventory_digest(b)
    c = _report([_item(findings=[f1])])       # a finding disappeared: content change
    assert inventory_digest(c) != inventory_digest(a)


# ---- loop behavior ----

def test_first_pass_submits_then_quiet_passes_do_not():
    clock = _Clock()
    submits = _Submits()
    rc = run_loop(lambda: _report([_item()]), submits,
                  interval=60, sleep=_driver(clock, max_passes=3), clock=clock)
    assert rc == 0
    assert submits.attempts == 1          # first pass only; passes 2-3 were quiet
    assert len(submits.successes) == 1


def test_change_triggers_submission():
    clock = _Clock()
    submits = _Submits()
    reports = iter([
        _report([_item()]),
        _report([_item()]),                                  # unchanged
        _report([_item(fingerprint="sha256:NEW")]),          # changed
    ])
    rc = run_loop(lambda: next(reports), submits,
                  interval=60, sleep=_driver(clock, max_passes=3), clock=clock)
    assert rc == 0
    assert submits.attempts == 2  # pass 1 (first) and pass 3 (change)


def test_heartbeat_forces_submission_without_change():
    clock = _Clock()
    submits = _Submits()
    rc = run_loop(lambda: _report([_item()]), submits,
                  interval=200, heartbeat=100,
                  sleep=_driver(clock, max_passes=2), clock=clock)
    assert rc == 0
    assert submits.attempts == 2  # unchanged, but 200s elapsed >= 100s heartbeat


def test_heartbeat_zero_submits_every_pass():
    clock = _Clock()
    submits = _Submits()
    rc = run_loop(lambda: _report([_item()]), submits,
                  interval=60, heartbeat=0,
                  sleep=_driver(clock, max_passes=3), clock=clock)
    assert rc == 0
    assert submits.attempts == 3


def test_failed_submission_retries_next_pass():
    clock = _Clock()
    submits = _Submits(fail_first=1)
    rc = run_loop(lambda: _report([_item()]), submits,
                  interval=60, sleep=_driver(clock, max_passes=3), clock=clock)
    assert rc == 0
    # Pass 1 fails; the digest is NOT recorded, so pass 2 retries and succeeds;
    # pass 3 is then quiet.
    assert submits.attempts == 2
    assert len(submits.successes) == 1


def test_malformed_submit_response_does_not_crash_and_retries():
    clock = _Clock()

    class _Malformed:
        attempts = 0

        def __call__(self, report):
            self.attempts += 1
            return None if self.attempts == 1 else {"accepted": 1}  # None must not crash

    submits = _Malformed()
    rc = run_loop(lambda: _report([_item()]), submits,
                  interval=60, sleep=_driver(clock, max_passes=3), clock=clock)
    assert rc == 0
    # Pass 1's None is unconfirmed -> digest not recorded -> pass 2 retries and
    # succeeds -> pass 3 quiet.
    assert submits.attempts == 2


def test_dry_run_loop_prints_once_then_notes_no_change(capsys):
    clock = _Clock()
    rc = run_loop(lambda: _report([_item()]), lambda r: (_ for _ in ()).throw(AssertionError),
                  interval=60, dry_run=True,
                  sleep=_driver(clock, max_passes=3), clock=clock)
    assert rc == 0
    captured = capsys.readouterr()
    # stdout: exactly one JSON report (first pass), parseable as a single doc.
    assert json.loads(captured.out)["device_id"] == "dev"
    assert captured.out.count('"device_id"') == 1
    # stderr: quiet passes are narrated.
    assert "no change, 1 skill(s)" in captured.err


# ---- CLI wiring ----

def test_cli_loop_floor_validation(tmp_path, capsys):
    with pytest.raises(SystemExit):
        main(["--path", str(tmp_path), "--dry-run", "--loop", "10"])
    assert "at least 60" in capsys.readouterr().err


def test_cli_negative_heartbeat_rejected(tmp_path, capsys):
    with pytest.raises(SystemExit):
        main(["--path", str(tmp_path), "--dry-run", "--loop", "60", "--heartbeat", "-1"])
    assert "--heartbeat" in capsys.readouterr().err


def test_cli_without_loop_is_one_shot(tmp_path, capsys, monkeypatch):
    root = tmp_path / "skills"
    (root / "deploy").mkdir(parents=True)
    (root / "deploy" / "SKILL.md").write_text(
        skill_md("deploy", "Roll out with checks.", "Steps."), encoding="utf-8")
    monkeypatch.setattr("discovery.local.configure_scanner", lambda backend: "fake")
    rc = main(["--path", str(root), "--device-id", "dev", "--dry-run"])
    assert rc == 0  # returns (would loop forever if --loop leaked into one-shot)
    assert json.loads(capsys.readouterr().out)["items"][0]["name"] == "deploy"
