"""Command-line entry point: the `skill-discovery` endpoint agent.

Scans local skill roots (``~/.claude/skills``, ``~/.agents/skills``, and any
``--path`` roots) for SKILL.md skill folders, runs local detection, sanitizes
content before anything leaves the machine, fingerprints each skill, and either
prints the JSON inventory report locally (``--dry-run`` / ``--print-json``) or
POSTs it to a governance server implementing ``POST /discovery/reports``.

Server connection resolution (flag > env):
- URL:   ``--url``, else ``SKILL_DISCOVERY_SERVER_URL``, else ``KILN_SERVER_URL``
  (when reporting to a KLIN server), else ``http://127.0.0.1:8000``.
- Token: ``--token``, else ``SKILL_DISCOVERY_TOKEN``, else ``KILN_API_TOKEN``.
  No token means send no auth header (fine when the server has auth off).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

from discovery import __version__
from discovery.local import DiscoveryLocation, build_discovery_report

DEFAULT_URL = "http://127.0.0.1:8000"


def _auth_headers(token: str | None) -> dict:
    """Bearer header for the governance server when auth is enabled; empty when not."""
    return {"Authorization": f"Bearer {token}"} if token else {}


def _post(url: str, body: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", **_auth_headers(token)},
    )
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def _resolve_url(args) -> str:
    """Server base URL: flag > SKILL_DISCOVERY_SERVER_URL > KILN_SERVER_URL >
    the local default."""
    return (
        args.url
        or os.environ.get("SKILL_DISCOVERY_SERVER_URL")
        or os.environ.get("KILN_SERVER_URL")
        or DEFAULT_URL
    )


def _resolve_token(args) -> str | None:
    """Server token: flag > SKILL_DISCOVERY_TOKEN > KILN_API_TOKEN. None means
    send no auth (fine when the server has auth off)."""
    return (
        args.token
        or os.environ.get("SKILL_DISCOVERY_TOKEN")
        or os.environ.get("KILN_API_TOKEN")
        or None
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill-discovery",
        description="Endpoint inventory of AI agent skills: scan local skill "
                    "folders, run local detection, and report the inventory to "
                    "a governance server (or print it with --dry-run).",
    )
    parser.add_argument("--version", action="version", version=f"skill-discovery {__version__}")
    parser.add_argument("--url", default=None,
                        help="Governance server base URL (else SKILL_DISCOVERY_SERVER_URL "
                             "or KILN_SERVER_URL).")
    parser.add_argument("--token",
                        help="Bearer token for the server (or set SKILL_DISCOVERY_TOKEN "
                             "or KILN_API_TOKEN).")
    parser.add_argument("--home", default="~", help="Home directory to scan for user skill roots.")
    parser.add_argument("--codex", action="store_true", help="Scan ~/.agents/skills.")
    parser.add_argument("--claude", action="store_true", help="Scan ~/.claude/skills.")
    parser.add_argument("--path", action="append", help="Additional skill root to scan.")
    parser.add_argument("--source", default="custom", help="Source label for --path roots.")
    parser.add_argument("--device-id", help="Managed endpoint id. Defaults to hostname.")
    parser.add_argument("--device-name", help="Human-readable endpoint name.")
    parser.add_argument("--user-id", help="User identity to attribute the endpoint observation.")
    parser.add_argument("--agent-version", default=f"skill-discovery/{__version__}",
                        help="Discovery agent version string.")
    parser.add_argument("--upload-mode", choices=["metadata_only", "full_skill"],
                        default="metadata_only",
                        help="metadata_only reports names, hashes, and findings. full_skill "
                             "also uploads sanitized skill folders for server-side scanning.")
    parser.add_argument("--scanner-backend", choices=["auto", "heuristics", "skillspector", "none"],
                        default="auto",
                        help="Local detection backend. 'auto' uses SkillSpector when "
                             "installed and always keeps the built-in heuristic floor.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the report but do not submit it (needs no server).")
    parser.add_argument("--print-json", action="store_true",
                        help="Print the report JSON before submitting.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.codex and not args.claude and not args.path:
        args.codex = True
        args.claude = True

    locations = []
    if args.codex:
        locations.append(DiscoveryLocation(
            Path(args.home).expanduser() / ".agents" / "skills",
            "codex",
            "user_codex",
        ))
    if args.claude:
        locations.append(DiscoveryLocation(
            Path(args.home).expanduser() / ".claude" / "skills",
            "claude",
            "user_claude",
        ))
    for raw in args.path or []:
        locations.append(DiscoveryLocation(Path(raw).expanduser(), args.source, "custom"))

    report = build_discovery_report(
        locations=locations or None,
        upload_mode=args.upload_mode,
        device_id=args.device_id,
        device_name=args.device_name,
        user_id=args.user_id,
        agent_version=args.agent_version,
        scanner_backend=args.scanner_backend,
    )
    if args.print_json or args.dry_run:
        print(json.dumps(report, indent=2))
    if args.dry_run:
        return 0

    url = _resolve_url(args)
    res = _post(f"{url.rstrip('/')}/discovery/reports", report, _resolve_token(args))
    print(
        f"Reported {res['accepted']} discovered skill(s): "
        f"{res['flagged']} flagged, {res['blocked']} blocked."
    )
    return 0


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
