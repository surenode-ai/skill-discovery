"""Registry of known on-disk locations for AI coding agents.

Data-driven so support for a new agent is one entry, not code. Each
``AgentSpec`` names two kinds of location:

- Skill roots (``user_roots`` / ``project_roots``): directories of SKILL.md
  skill folders, walked like any skill root.
- Rule globs (``user_rule_globs`` / ``project_rule_globs``): persistent
  instruction files that are not SKILL.md folders (Cursor rules, Kiro steering,
  Copilot instructions, Windsurf rules). Each matching file is inventoried as
  one report item with a ``..._rules`` location_kind.

The registry is deliberately conservative: every path here comes from the
agent vendor's own documentation. Adding entries for more agents is the single
most wanted community contribution (see CONTRIBUTING.md); cite the vendor doc
for any new path. Several agents also read the shared Agent Skills locations
(``.agents/skills`` / ``~/.agents/skills``) and Claude-compatible locations;
those are listed once, under the entry that owns the convention, and the CLI
de-duplicates any root that two agents share so nothing is double counted.

Sources for the shipped entries:
- codex:    ``~/.agents/skills`` (user) and ``$REPO_ROOT/.agents/skills``
            (project), the cross-agent Agent Skills convention.
            https://developers.openai.com/codex/skills
            Also owns the cross-tool ``AGENTS.md`` standard. https://agents.md/
- claude:   ``~/.claude/skills`` and ``.claude/skills`` (Anthropic docs).
            Memory files: ``~/.claude/CLAUDE.md`` (user), ``CLAUDE.md`` and
            ``CLAUDE.local.md`` (project). https://code.claude.com/docs/en/memory
- opencode: ``~/.config/opencode/skills`` (global) and ``.opencode/skills``
            (project). https://opencode.ai/docs/skills/
- cursor:   skills in ``~/.cursor/skills`` and ``.cursor/skills`` (also reads
            the shared ``.agents/skills`` locations, covered by codex).
            https://cursor.com/docs/skills.md
            Project rules are ``.cursor/rules/*.mdc``.
            https://cursor.com/docs/rules
- antigravity: global skills in ``~/.gemini/config/skills`` (all Antigravity
            surfaces) and ``~/.gemini/antigravity-cli/skills`` (CLI); project
            skills use the shared ``.agents/skills`` convention.
            https://codelabs.developers.google.com/getting-started-with-antigravity-skills
            No on-disk rules path is documented by the vendor.
- windsurf: skills in ``~/.codeium/windsurf/skills`` and ``.windsurf/skills``.
            https://docs.windsurf.com/windsurf/cascade/skills
            Rules: ``.devin/rules/*.md`` (preferred) with legacy
            ``.windsurf/rules/*.md``, and the global rules file
            ``~/.codeium/windsurf/memories/global_rules.md``.
            https://docs.windsurf.com/windsurf/cascade/memories
- copilot:  personal skills in ``~/.copilot/skills`` (also ``~/.agents/skills``,
            covered by codex); repository skills in ``.github/skills`` (also
            ``.claude/skills`` / ``.agents/skills``, covered elsewhere).
            https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills
            Instructions: ``.github/copilot-instructions.md`` and
            ``.github/instructions/*.instructions.md``.
            https://docs.github.com/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot
- kiro:     skills in ``~/.kiro/skills`` and ``.kiro/skills``.
            https://kiro.dev/docs/skills/
            Steering (recursive): ``~/.kiro/steering/**/*.md`` and
            ``.kiro/steering/**/*.md``. https://kiro.dev/docs/steering/
- gemini:   Gemini CLI context files ``~/.gemini/GEMINI.md`` (user) and
            ``GEMINI.md`` (project). No SKILL.md roots documented.
            https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/auto-memory.md
- cline:    project rules ``.clinerules/**/*.md`` and cross-tool ``AGENTS.md``
            (covered by codex); global ``~/Documents/Cline/Rules/**/*.md`` and
            ``~/.agents/AGENTS.md``. https://docs.cline.bot/features/cline-rules
- roo:      project ``.roo/rules/**/*.md`` with legacy ``.roorules``; global
            ``~/.roo/rules/**/*.md``; ``AGENTS.md`` covered by codex.
            https://docs.roocode.com/features/custom-instructions

Rule globs use ``**`` for recursive matching where the vendor documents nested
rule files (Cursor, Windsurf, Kiro, Roo). Legacy single-file forms
(``.cursorrules``, ``.windsurfrules``, ``.roorules``) and the cross-tool
``AGENTS.md`` / ``CLAUDE.md`` / ``GEMINI.md`` instruction files are inventoried
as standalone rule items. Files a second agent also reads (``AGENTS.md``, the
shared roots) are attributed once, to the first agent in registry order.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from discovery.local import DiscoveryLocation


@dataclass(frozen=True)
class AgentSpec:
    key: str                        # registry key; used in source/location_kind
    display_name: str
    user_roots: tuple[str, ...]     # SKILL.md roots relative to the home dir
    project_roots: tuple[str, ...]  # SKILL.md roots relative to a project dir
    user_rule_globs: tuple[str, ...] = ()     # instruction-file globs under home
    project_rule_globs: tuple[str, ...] = ()  # instruction-file globs under a project


# Insertion order is scan/report order. codex stays first so the shared
# .agents/skills convention attributes to it under --agent all (the CLI
# de-duplicates roots, first agent wins).
AGENTS: dict[str, AgentSpec] = {
    spec.key: spec
    for spec in (
        AgentSpec(
            key="codex",
            display_name="OpenAI Codex CLI (Agent Skills convention)",
            user_roots=(".agents/skills",),
            project_roots=(".agents/skills",),
            project_rule_globs=("AGENTS.md",),  # the cross-tool AGENTS.md standard
        ),
        AgentSpec(
            key="claude",
            display_name="Claude Code",
            user_roots=(".claude/skills",),
            project_roots=(".claude/skills",),
            user_rule_globs=(".claude/CLAUDE.md",),
            project_rule_globs=("CLAUDE.md", "CLAUDE.local.md"),
        ),
        AgentSpec(
            key="opencode",
            display_name="opencode",
            user_roots=(".config/opencode/skills",),
            project_roots=(".opencode/skills",),
        ),
        AgentSpec(
            key="cursor",
            display_name="Cursor",
            user_roots=(".cursor/skills",),
            project_roots=(".cursor/skills",),
            project_rule_globs=(".cursor/rules/**/*.mdc", ".cursorrules"),
        ),
        AgentSpec(
            key="antigravity",
            display_name="Google Antigravity",
            user_roots=(".gemini/config/skills", ".gemini/antigravity-cli/skills"),
            project_roots=(".agents/skills",),  # shared convention; deduped vs codex
        ),
        AgentSpec(
            key="windsurf",
            display_name="Windsurf",
            user_roots=(".codeium/windsurf/skills",),
            project_roots=(".windsurf/skills",),
            user_rule_globs=(".codeium/windsurf/memories/global_rules.md",),
            project_rule_globs=(".devin/rules/**/*.md", ".windsurf/rules/**/*.md",
                                ".windsurfrules"),
        ),
        AgentSpec(
            key="copilot",
            display_name="GitHub Copilot",
            user_roots=(".copilot/skills",),
            project_roots=(".github/skills",),
            project_rule_globs=(".github/copilot-instructions.md",
                                ".github/instructions/*.instructions.md"),
        ),
        AgentSpec(
            key="kiro",
            display_name="Kiro (AWS)",
            user_roots=(".kiro/skills",),
            project_roots=(".kiro/skills",),
            user_rule_globs=(".kiro/steering/**/*.md",),
            project_rule_globs=(".kiro/steering/**/*.md",),
        ),
        # Instruction-only agents (no SKILL.md roots documented): their standing
        # instruction files are inventoried through the same rule-glob mechanism.
        AgentSpec(
            key="gemini",
            display_name="Gemini CLI",
            user_roots=(),
            project_roots=(),
            user_rule_globs=(".gemini/GEMINI.md",),
            project_rule_globs=("GEMINI.md",),
        ),
        AgentSpec(
            key="cline",
            display_name="Cline",
            user_roots=(),
            project_roots=(),
            user_rule_globs=("Documents/Cline/Rules/**/*.md", ".agents/AGENTS.md"),
            project_rule_globs=(".clinerules/**/*.md",),
        ),
        AgentSpec(
            key="roo",
            display_name="Roo Code",
            user_roots=(),
            project_roots=(),
            user_rule_globs=(".roo/rules/**/*.md",),
            project_rule_globs=(".roo/rules/**/*.md", ".roorules"),
        ),
    )
}


def agent_keys() -> list[str]:
    return list(AGENTS)


def user_locations(keys: list[str], home: Path) -> list[DiscoveryLocation]:
    """User-level skill roots and rule globs for the given agents, under ``home``."""
    out: list[DiscoveryLocation] = []
    for key in keys:
        spec = AGENTS[key]
        for rel in spec.user_roots:
            out.append(DiscoveryLocation(home.joinpath(*rel.split("/")),
                                         spec.key, f"user_{spec.key}"))
        for glob in spec.user_rule_globs:
            out.append(DiscoveryLocation(home, spec.key, f"user_{spec.key}_rules",
                                         pattern=glob))
    return out


def project_locations(keys: list[str], project_dir: Path) -> list[DiscoveryLocation]:
    """Project-level skill roots and rule globs for the given agents."""
    out: list[DiscoveryLocation] = []
    for key in keys:
        spec = AGENTS[key]
        for rel in spec.project_roots:
            out.append(DiscoveryLocation(project_dir.joinpath(*rel.split("/")),
                                         spec.key, f"project_{spec.key}"))
        for glob in spec.project_rule_globs:
            out.append(DiscoveryLocation(project_dir, spec.key,
                                         f"project_{spec.key}_rules", pattern=glob))
    return out
