"""The local SKILL.md folder walker: assembly, nested-skill pruning, and
skipping of unreadable files."""

from __future__ import annotations

from discovery.scanning import findings_for_skipped_files
from discovery.walker import _assemble_folder, _discover

from tests.conftest import skill_md


def test_walker_finds_and_assembles_skills(tmp_path):
    root = tmp_path / "skills"
    (root / "deploy").mkdir(parents=True)
    (root / "deploy" / "SKILL.md").write_text(skill_md("deploy", "Deploy.", "Steps."))
    (root / "deploy" / "references").mkdir()
    (root / "deploy" / "references" / "notes.md").write_text("extra notes\n")
    (root / "review").mkdir()
    (root / "review" / "SKILL.md").write_text(skill_md("review", "Review.", "Steps."))

    skills, errors = _discover(str(root), str(root))
    assert errors == []
    assert [s.rel_dir for s in skills] == ["deploy", "review"]
    deploy = skills[0]
    assert deploy.name == "deploy"
    assert deploy.valid
    assert set(deploy.files) == {"SKILL.md", "references/notes.md"}


def test_walker_prunes_nested_skills_and_noise_dirs(tmp_path):
    root = tmp_path / "skills"
    outer = root / "outer"
    (outer / "inner").mkdir(parents=True)
    outer.joinpath("SKILL.md").write_text(skill_md("outer", "Outer.", "Body."))
    outer.joinpath("inner", "SKILL.md").write_text(skill_md("inner", "Inner.", "Body."))
    (outer / "node_modules").mkdir()
    (outer / "node_modules" / "junk.md").write_text("junk")

    skills, _ = _discover(str(root), str(root))
    by_dir = {s.rel_dir: s for s in skills}
    assert set(by_dir) == {"outer", "outer/inner"}
    # The nested skill's files are not folded into the outer skill.
    assert "inner/SKILL.md" not in by_dir["outer"].files
    assert "node_modules/junk.md" not in by_dir["outer"].files


def test_invalid_frontmatter_is_reported_not_fatal(tmp_path):
    root = tmp_path / "skills"
    (root / "broken").mkdir(parents=True)
    (root / "broken" / "SKILL.md").write_text("no frontmatter at all\n")

    skills, errors = _discover(str(root), str(root))
    assert errors == []
    assert len(skills) == 1
    assert not skills[0].valid
    assert "does not parse" in (skills[0].error or "")


def test_non_utf8_script_is_skipped_then_flagged(tmp_path):
    """A non-UTF-8 script is dropped by the walker's text reader, and
    findings_for_skipped_files turns that skip into a finding."""
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: csv-summarizer\ndescription: counts rows\n---\n")
    # Invalid UTF-8 bytes -> the walker's _read_text returns None -> skipped.
    (skill / "summarize.py").write_bytes(b"import os\nprint(os.environ)\n\xff\xfe\x00bad")

    folder, skipped = _assemble_folder(str(skill))
    assert "summarize.py" in skipped and "summarize.py" not in folder
    assert any(f.rule_id == "unscannable-executable" for f in findings_for_skipped_files(skipped))
