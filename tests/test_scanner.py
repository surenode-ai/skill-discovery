"""The SkillSpector report parser: shape handling and neutralizing hostile
scanner-supplied text before it reaches the report JSON / downstream logs."""

from __future__ import annotations

from discovery.scanning.scanner import parse_skillspector_report


def test_parser_scrubs_control_chars_and_caps_length():
    report = {"issues": [{
        "id": "evil\x1b[31m\nrule",
        "category": "Data\nExfiltration",
        "severity": "high",
        "explanation": "line one\nline two\x1b[0m" + ("A" * 500),
        "location": {"file": "a\nb.py"},
    }]}
    (finding,) = parse_skillspector_report(report)
    for field in (finding.title, finding.rule_id, finding.category, finding.path):
        assert "\n" not in field and "\x1b" not in field
    assert len(finding.title) <= 300
    assert finding.category == "data_exfiltration"  # normalized, control-free


def test_parser_is_defensive_about_shape():
    assert parse_skillspector_report({}) == []
    assert parse_skillspector_report({"issues": ["not-a-dict", 3]}) == []
    assert parse_skillspector_report([]) == []  # non-dict input
