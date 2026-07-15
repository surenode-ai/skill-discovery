"""Tests for pre-upload sanitization: redact PII and secrets, flag personal
paths, and never touch process details or tool internals."""

from __future__ import annotations

from discovery.sanitize import sanitize_folder


def test_redacts_secrets_and_pii():
    folder = {"SKILL.md": (
        "Contact alice@example.com for access.\n"
        "Use key sk-ant-abcdefghijklmnopqrstuvwxyz0123 to authenticate.\n"
        "AWS key AKIAIOSFODNN7EXAMPLE must be rotated.\n"
        "Header: Bearer abcdefghijklmnopqrstuvwxyz123456\n"
        "Connect to postgres://user:hunter2@db.internal/app\n"
        "SSN 123-45-6789 on file.\n"
    )}
    clean, report = sanitize_folder(folder)
    md = clean["SKILL.md"]
    assert "alice@example.com" not in md and "[redacted:email]" in md
    assert "sk-ant-" not in md and "[redacted:api-key]" in md
    assert "AKIAIOSFODNN7EXAMPLE" not in md and "[redacted:aws-access-key]" in md
    assert "[redacted:token]" in md  # bearer
    assert "hunter2" not in md and "[redacted:secret]" in md
    assert "123-45-6789" not in md and "[redacted:ssn]" in md
    assert report.redaction_total >= 6
    assert not report.has_flags


def test_keeps_process_details():
    # Commands, ports, localhost bindings, tool names are process detail, kept.
    folder = {"SKILL.md": (
        "# proc\n\nRun `uvicorn app:main --host 127.0.0.1 --port 8000`.\n"
        "Check 0.0.0.0 vs 127.0.0.1 and use `lsof -nP -iTCP -sTCP:LISTEN`.\n"
    )}
    clean, report = sanitize_folder(folder)
    assert clean["SKILL.md"] == folder["SKILL.md"]  # unchanged
    assert report.clean


def test_flags_personal_paths_without_removing():
    folder = {"SKILL.md": (
        "# tool\n\nRun the helper at /Users/alex/tools/recalc.py before deploy.\n"
        "Also see C:\\Users\\dana\\tools\\fix.ps1 on Windows.\n"
    )}
    clean, report = sanitize_folder(folder)
    # Not removed: the tool may need the path.
    assert "/Users/alex/tools/recalc.py" in clean["SKILL.md"]
    assert report.has_flags
    found = {f.path for f in report.path_flags}
    assert "/Users/alex/tools/recalc.py" in found
    assert any("Users" in p and "dana" in p for p in found)


def test_scripts_are_redacted_not_just_markdown():
    # full_skill uploads bundled scripts too, so a secret in a script must be
    # redacted just like one in prose. (Regression: previously non-markdown
    # files were skipped and their secrets shipped in the clear.)
    folder = {
        "SKILL.md": "# s\n\nSee [tool](scripts/run.py).\n",
        "scripts/run.py": "API_KEY = 'sk-ant-abcdefghijklmnopqrstuvwxyz0123'\n",
    }
    clean, report = sanitize_folder(folder)
    assert "sk-ant-abcdefghijklmnopqrstuvwxyz0123" not in clean["scripts/run.py"]
    assert "[redacted:api-key]" in clean["scripts/run.py"]
    assert not report.clean


def test_clean_folder_reports_clean():
    folder = {"SKILL.md": "# ok\n\nA plain process description with no secrets.\n"}
    clean, report = sanitize_folder(folder)
    assert report.clean and clean == folder
