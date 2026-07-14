"""Command-line entry point: the `skill-discovery` endpoint agent.

Scans local skill roots (every registered agent's user roots by default — see
``discovery.agents`` — plus ``--project`` and ``--path`` roots) for SKILL.md
skill folders, runs local detection, sanitizes
content before anything leaves the machine, fingerprints each skill, and either
prints the JSON inventory report locally (``--dry-run`` / ``--print-json``) or
POSTs it to a governance server implementing ``POST /discovery/reports``.

Server connection resolution (flag > env):
- URL:   ``--url``, else ``SKILL_DISCOVERY_SERVER_URL``, else ``KILN_SERVER_URL``
  (when reporting to a KLIN server), else ``http://127.0.0.1:8000``. Plain
  ``http://`` to a non-loopback host is refused unless ``--allow-http``: the
  report and bearer token would travel unencrypted.
- Token: ``--token``, else ``SKILL_DISCOVERY_TOKEN``, else ``KILN_API_TOKEN``.
  No token means send no auth header (fine when the server has auth off).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from discovery import __version__
from discovery.agents import AGENTS, agent_keys, project_locations, user_locations
from discovery.local import DiscoveryLocation, build_discovery_report
from discovery.loop import DEFAULT_HEARTBEAT_SECONDS, MIN_LOOP_SECONDS, run_loop

DEFAULT_URL = "http://127.0.0.1:8000"
# A hung server must not stall a submission forever: fail the request and let
# the caller retry (in --loop mode, on the next pass).
REQUEST_TIMEOUT_SECONDS = 30


def _auth_headers(token: str | None) -> dict:
    """Bearer header for the governance server when auth is enabled; empty when not."""
    return {"Authorization": f"Bearer {token}"} if token else {}


def _post(url: str, body: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", **_auth_headers(token)},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as r:
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


def _require_safe_url(parser: argparse.ArgumentParser, args) -> str:
    """Resolve the server URL, refusing plaintext HTTP to a non-loopback host
    unless --allow-http: the report and bearer token would travel unencrypted.
    Loopback (localhost, 127.x, ::1) is always allowed, so the local default
    and dev servers keep working."""
    url = _resolve_url(args)
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return url
    host = (parts.hostname or "").lower()
    loopback = host in {"localhost", "::1"} or host.startswith("127.")
    if parts.scheme == "http" and (loopback or args.allow_http):
        return url
    parser.error(
        f"refusing to report to {url!r}: the report and bearer token would be "
        f"sent unencrypted. Use an https:// URL, or pass --allow-http if you "
        f"accept the risk (loopback is always allowed)."
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
    parser.add_argument("--allow-http", action="store_true",
                        help="Permit plaintext http:// to a non-loopback server "
                             "(otherwise refused: the report and token would go "
                             "unencrypted).")
    parser.add_argument("--home", default="~", help="Home directory to scan for user skill roots.")
    known = ", ".join(agent_keys())
    parser.add_argument("--agent", action="append", metavar="KEY",
                        help=f"Scan a registered agent's user skill roots (repeatable; "
                             f"known: {known}, or 'all'). Default when no location "
                             f"flags are given: all.")
    parser.add_argument("--project", action="append", metavar="DIR",
                        help="Scan every registered agent's project-level skill roots "
                             "under this directory (repeatable).")
    parser.add_argument("--codex", action="store_true",
                        help="(deprecated) Alias for --agent codex.")
    parser.add_argument("--claude", action="store_true",
                        help="(deprecated) Alias for --agent claude.")
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
    parser.add_argument("--loop", type=float, metavar="SECONDS", default=None,
                        help=f"Continuous mode: rescan every SECONDS (minimum "
                             f"{MIN_LOOP_SECONDS:.0f}) and report only when the "
                             f"inventory changes. Run it under any supervisor. "
                             f"Without --loop the command is one-shot, as before.")
    parser.add_argument("--heartbeat", type=float, metavar="SECONDS",
                        default=DEFAULT_HEARTBEAT_SECONDS,
                        help="With --loop: force a report even without change once "
                             "this much time has passed since the last successful "
                             "submission (default 86400 = daily). 0 reports every pass.")
    return parser


def _selected_agent_keys(parser: argparse.ArgumentParser, args) -> list[str]:
    """Resolve --agent values plus the deprecated --claude/--codex aliases to an
    ordered, de-duplicated list of registry keys ('all' expands the registry)."""
    raw = list(args.agent or [])
    if args.codex:
        raw.append("codex")
    if args.claude:
        raw.append("claude")
    if "all" in raw:
        return agent_keys()
    keys: list[str] = []
    for key in raw:
        if key not in AGENTS:
            parser.error(f"unknown agent {key!r}; known: {', '.join(agent_keys())}, all")
        if key not in keys:
            keys.append(key)
    return keys


def _dedupe_locations(locations: list[DiscoveryLocation]) -> list[DiscoveryLocation]:
    """Drop locations whose (root, pattern) another agent already claimed.
    Several agents document the same shared roots (e.g. .agents/skills);
    scanning a root once keeps items from being double counted. The first
    agent in registry order wins the attribution."""
    seen: set = set()
    out: list[DiscoveryLocation] = []
    for loc in locations:
        key = (os.path.normpath(str(loc.root.expanduser())), loc.pattern)
        if key in seen:
            continue
        seen.add(key)
        out.append(loc)
    return out


def _print_root_summary(locations: list[DiscoveryLocation]) -> None:
    """Human summary of which locations were checked vs found, distinguishing
    SKILL.md skill roots from standalone instruction/rule file globs. Goes to
    stderr so stdout stays pure JSON for piping."""
    print("Checked locations:", file=sys.stderr)
    for loc in locations:
        root = loc.root.expanduser()
        if loc.pattern:
            found = root.is_dir() and any(p.is_file() for p in root.glob(loc.pattern))
            status = "found" if found else "not present"
            what = f"{root}{os.sep}{loc.pattern}"
            label = "rules "
        else:
            status = "found" if root.is_dir() else "not present"
            what = str(root)
            label = "skills"
        print(f"  [{status:>11}] {label} {loc.source}:{loc.location_kind}  {what}",
              file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    keys = _selected_agent_keys(parser, args)
    if not keys and not args.path and not args.project:
        keys = agent_keys()  # zero-config default: every registered agent

    home = Path(args.home).expanduser()
    locations = user_locations(keys, home)
    proj_keys = keys or agent_keys()  # explicit --agent scopes --project too
    for raw in args.project or []:
        locations.extend(project_locations(proj_keys, Path(raw).expanduser()))
    for raw in args.path or []:
        locations.append(DiscoveryLocation(Path(raw).expanduser(), args.source, "custom"))
    locations = _dedupe_locations(locations)

    if args.dry_run:
        _print_root_summary(locations)

    def _build() -> dict:
        return build_discovery_report(
            locations=locations or None,
            upload_mode=args.upload_mode,
            device_id=args.device_id,
            device_name=args.device_name,
            user_id=args.user_id,
            agent_version=args.agent_version,
            scanner_backend=args.scanner_backend,
        )

    if args.loop is not None:
        if args.loop < MIN_LOOP_SECONDS:
            parser.error(f"--loop must be at least {MIN_LOOP_SECONDS:.0f} seconds")
        if args.heartbeat < 0:
            parser.error("--heartbeat must be 0 or positive")
        # Dry-run loops never submit, so the URL scheme doesn't matter there.
        url = _resolve_url(args) if args.dry_run else _require_safe_url(parser, args)
        token = _resolve_token(args)

        def _submit(report: dict) -> dict:
            return _post(f"{url.rstrip('/')}/discovery/reports", report, token)

        return run_loop(
            _build, _submit,
            interval=args.loop,
            heartbeat=args.heartbeat,
            dry_run=args.dry_run,
            print_json=args.print_json,
        )

    # Validate the URL before the scan, so a refused scheme fails fast.
    url = None if args.dry_run else _require_safe_url(parser, args)
    report = _build()
    if args.print_json or args.dry_run:
        print(json.dumps(report, indent=2))
    if args.dry_run:
        return 0

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
