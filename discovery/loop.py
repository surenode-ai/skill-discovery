"""Continuous mode: rescan on an interval, report only when the inventory
changes, heartbeat so the server's last-seen stays current.

Modeled on running a small agent under any supervisor (launchd, systemd,
Task Scheduler): the loop itself is dumb and durable. State is in memory only;
after a restart the first pass submits once and the server upserts, which is
the intended behavior.

Testable by construction: ``run_loop`` takes injectable ``sleep`` and ``clock``
callables so tests can drive passes without real time.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from typing import Callable

DEFAULT_HEARTBEAT_SECONDS = 86400.0
MIN_LOOP_SECONDS = 60.0


def _log(message: str) -> None:
    """Loop narration goes to stderr; stdout carries only report JSON."""
    print(f"skill-discovery: {message}", file=sys.stderr)


def inventory_digest(report: dict) -> str:
    """A stable digest of what the inventory *is*, ignoring per-run noise.

    Covers each item's external_id, fingerprint, and a canonical serialization
    of its findings, in sorted order. Device metadata, agent version, upload
    mode, and ``meta`` are excluded, so two passes over an unchanged set of
    skills digest identically."""
    entries = []
    for item in report.get("items", []):
        findings = sorted(
            (json.dumps(f, sort_keys=True) for f in item.get("local_findings", [])),
        )
        entries.append((
            str(item.get("external_id", "")),
            str(item.get("fingerprint", "")),
            json.dumps(findings),
        ))
    h = hashlib.sha256()
    for external_id, fingerprint, findings_blob in sorted(entries):
        h.update(external_id.encode())
        h.update(b"\0")
        h.update(fingerprint.encode())
        h.update(b"\0")
        h.update(findings_blob.encode())
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def run_loop(
    build_report: Callable[[], dict],
    submit: Callable[[dict], dict],
    *,
    interval: float,
    heartbeat: float = DEFAULT_HEARTBEAT_SECONDS,
    dry_run: bool = False,
    print_json: bool = False,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Scan, report on change (or heartbeat), sleep, repeat until interrupted.

    - The first pass always submits (or prints, in dry-run).
    - Later passes submit only when the inventory digest changed, or when
      ``heartbeat`` seconds have passed since the last successful submission
      (``heartbeat=0`` submits every pass).
    - A failed submission logs one line and does NOT update the last-submitted
      digest, so the next pass retries.
    - KeyboardInterrupt (Ctrl-C, supervisor stop) exits cleanly with 0. No
      POSIX signal handlers are installed, so this works on Windows too.
    """
    last_digest: str | None = None
    last_submit_at: float | None = None
    try:
        while True:
            report = build_report()
            digest = inventory_digest(report)
            count = len(report.get("items", []))
            changed = digest != last_digest
            heartbeat_due = (
                last_submit_at is None
                or heartbeat == 0
                or clock() - last_submit_at >= heartbeat
            )
            if changed or heartbeat_due:
                reason = "inventory changed" if changed else "heartbeat"
                if dry_run:
                    # Flush per report: under a supervisor, stdout is often a
                    # pipe/file and block-buffered.
                    print(json.dumps(report, indent=2), flush=True)
                    last_digest = digest
                    last_submit_at = clock()
                    _log(f"{reason}: printed report with {count} skill(s) (dry run)")
                else:
                    if print_json:
                        print(json.dumps(report, indent=2), flush=True)
                    try:
                        res = submit(report)
                    except Exception as exc:  # noqa: BLE001 - keep looping overnight
                        _log(f"submit failed, will retry next pass: {exc}")
                    else:
                        if not isinstance(res, dict):
                            # Empty/garbage/non-object 2xx body: unconfirmed, so
                            # don't advance state — retry on the next pass.
                            _log("submit got an unexpected response, will retry next pass")
                        else:
                            last_digest = digest
                            last_submit_at = clock()
                            _log(f"{reason}: reported {res.get('accepted', count)} skill(s), "
                                 f"{res.get('flagged', 0)} flagged, {res.get('blocked', 0)} blocked")
            else:
                _log(f"no change, {count} skill(s)")
            sleep(interval)
    except KeyboardInterrupt:
        _log("interrupted, exiting")
        return 0
