"""Optional detection backend: embed NVIDIA SkillSpector via its CLI.

SkillSpector scans a folder on disk, so this adapter writes the in-memory skill
folder to a temp directory, runs `skillspector scan <dir> --format json`, parses
the report with ``parse_skillspector_report``, and cleans up. SkillSpector is
not vendored; install it with
``uv tool install git+https://github.com/NVIDIA/skillspector.git``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from discovery.scanning.models import Finding
from discovery.scanning.scanner import ScannerError, parse_skillspector_report

__all__ = ["ScannerError", "SkillSpectorScanner"]


class SkillSpectorScanner:
    def __init__(self, command: str = "skillspector", *, use_llm: bool = False,
                 extra_args=None, timeout: int = 120) -> None:
        self._command = command
        # Static-only by default: no LLM key needed, offline, zero inference cost.
        # Opt into deep semantic analysis with use_llm=True.
        self._extra = (["--no-llm"] if not use_llm else []) + list(extra_args or [])
        self._timeout = timeout

    def available(self) -> bool:
        return shutil.which(self._command) is not None

    def _write_folder(self, files: dict[str, str], root: str) -> None:
        """Write {path: content} under root, refusing any path that escapes it."""
        root_real = os.path.realpath(root)
        for path, content in files.items():
            full = os.path.realpath(os.path.join(root, path))
            if full != root_real and not full.startswith(root_real + os.sep):
                continue  # path traversal attempt — skip, never write outside the sandbox
            os.makedirs(os.path.dirname(full) or root, exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(content)

    def scan(self, files: dict[str, str]) -> list[Finding]:
        if not self.available():
            raise ScannerError(
                f"'{self._command}' is not installed. Install it with: "
                "uv tool install git+https://github.com/NVIDIA/skillspector.git"
            )
        workdir = tempfile.mkdtemp(prefix="skill-discovery-scan-")
        report_path = os.path.join(workdir, "_report.json")
        skill_dir = os.path.join(workdir, "skill")
        os.makedirs(skill_dir, exist_ok=True)
        try:
            self._write_folder(files, skill_dir)
            cmd = [self._command, "scan", skill_dir, "--format", "json",
                   "--output", report_path, *self._extra]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self._timeout)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ScannerError(f"skillspector failed to run: {exc}") from exc

            # Findings are read from the report; a non-zero exit just signals
            # "findings present", which is expected, not an error.
            raw = ""
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8") as fh:
                    raw = fh.read().strip()
            if not raw:
                raw = (proc.stdout or "").strip()
            if not raw:
                if proc.returncode not in (0, 1):  # 0/1 are clean/findings; else a real failure
                    # Collapse newlines from untrusted scanner output (log-injection safety).
                    err = " ".join((proc.stderr or "").split())[:300]
                    raise ScannerError(f"skillspector exited {proc.returncode}: {err}")
                return []
            try:
                report = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ScannerError(f"could not parse skillspector output: {exc}") from exc
            return parse_skillspector_report(report)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
