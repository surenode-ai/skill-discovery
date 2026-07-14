"""Registry of known on-disk skill locations for AI coding agents.

Data-driven so support for a new agent is one entry, not code: each
``AgentSpec`` names the user-level roots (relative to the home directory) and
project-level roots (relative to a project checkout) where that agent loads
SKILL.md skill folders from. The registry is deliberately conservative — every
path here comes from the agent vendor's own documentation or a convention this
tool's upstream verifies in production. Adding entries for more agents is the
single most wanted community contribution (see CONTRIBUTING.md); please cite
the vendor doc for any new path.

Sources for the shipped entries:
- claude:   Claude Code loads user skills from ``~/.claude/skills`` and
            project skills from ``.claude/skills`` (Anthropic docs).
- codex:    OpenAI Codex CLI follows the cross-agent Agent Skills convention:
            ``~/.agents/skills`` (user) and ``$REPO_ROOT/.agents/skills``
            (project) — https://developers.openai.com/codex/skills
- opencode: opencode's native locations are ``~/.config/opencode/skills``
            (global) and ``.opencode/skills`` (project) —
            https://opencode.ai/docs/skills/ . opencode also reads the claude
            and codex locations above; those are covered by their own entries,
            so they are not repeated here (no double counting).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from discovery.local import DiscoveryLocation


@dataclass(frozen=True)
class AgentSpec:
    key: str                        # registry key; used in source/location_kind
    display_name: str
    user_roots: tuple[str, ...]     # relative to the user's home directory
    project_roots: tuple[str, ...]  # relative to a project directory


# Insertion order is scan/report order (codex then claude mirrors the original
# two-agent default; opencode was added with the registry).
AGENTS: dict[str, AgentSpec] = {
    spec.key: spec
    for spec in (
        AgentSpec(
            key="codex",
            display_name="OpenAI Codex CLI (Agent Skills convention)",
            user_roots=(".agents/skills",),
            project_roots=(".agents/skills",),
        ),
        AgentSpec(
            key="claude",
            display_name="Claude Code",
            user_roots=(".claude/skills",),
            project_roots=(".claude/skills",),
        ),
        AgentSpec(
            key="opencode",
            display_name="opencode",
            user_roots=(".config/opencode/skills",),
            project_roots=(".opencode/skills",),
        ),
    )
}


def agent_keys() -> list[str]:
    return list(AGENTS)


def user_locations(keys: list[str], home: Path) -> list[DiscoveryLocation]:
    """User-level skill roots for the given agents, under ``home``."""
    out: list[DiscoveryLocation] = []
    for key in keys:
        spec = AGENTS[key]
        for rel in spec.user_roots:
            out.append(DiscoveryLocation(home.joinpath(*rel.split("/")),
                                         spec.key, f"user_{spec.key}"))
    return out


def project_locations(keys: list[str], project_dir: Path) -> list[DiscoveryLocation]:
    """Project-level skill roots for the given agents, under ``project_dir``."""
    out: list[DiscoveryLocation] = []
    for key in keys:
        spec = AGENTS[key]
        for rel in spec.project_roots:
            out.append(DiscoveryLocation(project_dir.joinpath(*rel.split("/")),
                                         spec.key, f"project_{spec.key}"))
    return out
