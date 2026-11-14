"""SkillSpector adapter: the CLI must not use --output (refused on Windows), the
JSON is read from stdout, and a failed backend is reported, never silently dropped."""

from __future__ import annotations

import json
import subprocess

from discovery.scanning import CompositeScanner, HeuristicScanner, ScannerError
from discovery.scanning import skillspector as ss_mod
from discovery.scanning.skillspector import SkillSpectorScanner


class _Boom:
    def scan(self, files):
        raise ScannerError("skillspector exited 2: Safe file output is unsupported")


def test_adapter_runs_without_output_flag_and_reads_stdout(monkeypatch):
    seen = {}
    report = {"issues": [{"id": "E2", "category": "Data Exfiltration", "severity": "HIGH",
                          "explanation": "env harvesting", "location": {"file": "dump.py"}}]}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(ss_mod.shutil, "which", lambda name: "/fake/skillspector")
    monkeypatch.setattr(ss_mod.subprocess, "run", fake_run)
    findings = SkillSpectorScanner().scan({"dump.py": "import os\n"})

    assert "--output" not in seen["cmd"]
    assert [f.rule_id for f in findings] == ["E2"]


def test_composite_reports_failed_backend_instead_of_hiding_it():
    findings = CompositeScanner([HeuristicScanner(), _Boom()]).scan(
        {"x.py": "import os\nprint(dict(os.environ))\n"})
    rule_ids = {f.rule_id for f in findings}
    assert "env-var-exfiltration" in rule_ids           # the heuristic floor still ran
    assert "local.scanner_backend_failed" in rule_ids   # and the failure is visible
