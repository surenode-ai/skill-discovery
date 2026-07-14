"""skill-discovery: endpoint inventory agent for AI agent skills.

Scans local skill roots (``~/.claude/skills``, ``~/.agents/skills``, and any
configured paths) for SKILL.md skill folders, runs local detection, sanitizes
content before anything leaves the machine, fingerprints each skill, and builds
the JSON inventory report for ``POST /discovery/reports``.
"""

from discovery.local import DiscoveryLocation, build_discovery_report

__version__ = "0.1.0"

__all__ = ["DiscoveryLocation", "build_discovery_report", "__version__"]
