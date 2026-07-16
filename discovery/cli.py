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
import dataclasses
import ipaddress
import json
import os
import shutil
import sys
import textwrap
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from discovery import __version__
from discovery.agents import AGENTS, agent_keys, project_locations, user_locations
from discovery.local import DiscoveryLocation, build_discovery_report
from discovery.loop import DEFAULT_HEARTBEAT_SECONDS, MIN_LOOP_SECONDS, run_loop
from discovery.projects import DEFAULT_TIME_BUDGET, discover_project_roots, project_label

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
        raw = r.read().decode("utf-8", "replace").strip()
    # Return the parsed JSON, or None for an empty/non-JSON body. The caller
    # decides what a malformed 2xx means; None must not crash it.
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _resolve_url(args) -> str:
    """Server base URL: flag > SKILL_DISCOVERY_SERVER_URL > KILN_SERVER_URL >
    the local default."""
    return (
        args.url
        or os.environ.get("SKILL_DISCOVERY_SERVER_URL")
        or os.environ.get("KILN_SERVER_URL")
        or DEFAULT_URL
    )


def _server_configured(args) -> bool:
    """Whether a submission destination was actually set (flag or env). If not,
    the tool shows the inventory locally instead of POSTing to the default."""
    return bool(args.url
                or os.environ.get("SKILL_DISCOVERY_SERVER_URL")
                or os.environ.get("KILN_SERVER_URL"))


def _is_loopback(host: str) -> bool:
    """True only for the loopback literal 'localhost' or an address that
    actually parses as loopback (127.0.0.0/8, ::1). String-prefix checks like
    host.startswith('127.') are unsafe: they accept a DNS name such as
    '127.0.0.1.evil.com' that resolves anywhere."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # a hostname, not an IP literal — never treated as loopback


def _require_safe_url(parser: argparse.ArgumentParser, args) -> str:
    """Resolve the server URL, refusing plaintext HTTP to a non-loopback host
    unless --allow-http: the report and bearer token would travel unencrypted.
    Loopback (localhost, 127.0.0.0/8, ::1) is always allowed, so the local
    default and dev servers keep working."""
    url = _resolve_url(args)
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return url
    host = (parts.hostname or "").lower()
    if parts.scheme == "http" and (_is_loopback(host) or args.allow_http):
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
        description="Endpoint inventory of AI agent skills. Run with no "
                    "arguments to scan every known agent's skill and "
                    "instruction locations under your home directory, run local "
                    "detection, and report the inventory to a governance server "
                    "(or print it with --dry-run). The flags below are optional: "
                    "narrow the scan, or reach into repos and extra folders.",
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
                        help=f"(optional) Narrow the scan to specific agents "
                             f"(repeatable; known: {known}, or 'all'). Default "
                             f"when no location flags are given: every agent.")
    parser.add_argument("--project", action="append", metavar="DIR",
                        help="(optional) Also scan a specific repo's in-repo "
                             "(project-level) skill roots under this directory "
                             "(repeatable). Rarely needed: project skills under "
                             "your home directory are auto-discovered by default.")
    parser.add_argument("--no-discover-projects", action="store_true",
                        help="Turn off automatic discovery of in-repo (project-level) "
                             "skills under your home directory (on by default).")
    parser.add_argument("--discover-root", action="append", metavar="DIR",
                        help="Additional base directory to auto-discover project "
                             "skills under, for code outside your home such as "
                             "/workspace (repeatable; also via SKILL_DISCOVERY_ROOTS, "
                             "os-path-separated).")
    parser.add_argument("--discover-timeout", type=float, default=DEFAULT_TIME_BUDGET,
                        metavar="SECONDS",
                        help=f"Wall-clock budget for project discovery per base "
                             f"(default {DEFAULT_TIME_BUDGET:.0f}). If exceeded, "
                             f"discovery stops and reports what it found so far.")
    parser.add_argument("--codex", action="store_true",
                        help="(deprecated) Alias for --agent codex.")
    parser.add_argument("--claude", action="store_true",
                        help="(deprecated) Alias for --agent claude.")
    parser.add_argument("--path", action="append",
                        help="(optional) Also scan an extra skill root, e.g. a "
                             "mounted team share (repeatable).")
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
    parser.add_argument("--format", choices=["human", "json"], default=None,
                        help="Output format for --dry-run. Default: human when stdout "
                             "is a terminal, json when piped or redirected.")
    parser.add_argument("--json", action="store_const", const="json", dest="format",
                        help="Shorthand for --format json.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color (also honored via the NO_COLOR env var).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="In the human view, show each item's full path and list "
                             "every location checked, including the empty ones.")
    parser.add_argument("--findings", action="store_true",
                        help="Human view: show only items that have findings (triage).")
    parser.add_argument("--no-wrap", action="store_true",
                        help="Human view: truncate long descriptions and finding details "
                             "to one line each instead of wrapping them (denser output).")
    parser.add_argument("--fail-on", choices=["none", "findings", "high"], default="none",
                        help="Exit non-zero if findings (or high+ findings) exist, for "
                             "CI gating. Default: none (findings are not errors).")
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


def _discovery_bases(home: Path, args) -> list[Path]:
    """Bases to auto-discover project skills under: the home directory, plus any
    extra roots from --discover-root and the SKILL_DISCOVERY_ROOTS env var (for
    code that lives outside home, e.g. /workspace on a fleet machine)."""
    bases = [home]
    for raw in args.discover_root or []:
        bases.append(Path(raw).expanduser())
    env = os.environ.get("SKILL_DISCOVERY_ROOTS", "")
    for raw in env.split(os.pathsep):
        if raw.strip():
            bases.append(Path(raw.strip()).expanduser())
    return bases


def _discover_project_locations(proj_keys, home: Path, args) -> list[DiscoveryLocation]:
    """Walk each discovery base for in-repo skill markers and turn every found
    project root into project-level locations, tagged with a provenance label so
    two repos' same-named skills stay distinct. Never raises: discovery is a
    best-effort convenience, so a walk error must not fail the whole run."""
    out: list[DiscoveryLocation] = []
    for base in _discovery_bases(home, args):
        try:
            roots, truncated = discover_project_roots(base, time_budget=args.discover_timeout)
        except OSError:
            continue
        if truncated:
            print(f"skill-discovery: project discovery under {base} hit the "
                  f"{args.discover_timeout:.0f}s budget; reporting what was found "
                  f"so far. Narrow with --discover-root or raise --discover-timeout.",
                  file=sys.stderr)
        base_str = str(base)
        for root in roots:
            label = project_label(root, base_str)
            for loc in project_locations(proj_keys, Path(root)):
                out.append(dataclasses.replace(loc, project_label=label))
    return out


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


# ---- output format & color resolution ----

def _resolve_format(args) -> str:
    """human when stdout is a terminal, json when piped/redirected; --format
    (or --json) always overrides."""
    if args.format:
        return args.format
    return "human" if sys.stdout.isatty() else "json"


def _color_enabled(args) -> bool:
    if args.no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


_ANSI = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
         "underline": "\033[4m", "red": "\033[31m", "yellow": "\033[33m",
         "green": "\033[32m"}


def _hyperlink(text: str, path: str, on: bool) -> str:
    """Wrap `text` in an OSC 8 terminal hyperlink to the file, so it is
    click-to-open in supporting terminals (iTerm2, VS Code, WezTerm, kitty, …)
    and plain text everywhere else."""
    if not on:
        return text
    try:
        uri = Path(os.path.abspath(path)).as_uri()  # correct file:// URI, spaces encoded
    except ValueError:
        return text
    return f"\033]8;;{uri}\033\\{text}\033]8;;\033\\"


def _style(text: str, on: bool, *styles: str) -> str:
    if not on or not styles:
        return text
    return "".join(_ANSI[s] for s in styles) + text + _ANSI["reset"]


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(severity: object) -> int:
    return _SEV_RANK.get(str(severity or "").lower(), 2)


def _sev_styles(severity: str) -> tuple[str, ...]:
    s = (severity or "").lower()
    if s in ("critical", "high"):
        return ("red",)
    if s == "medium":
        return ("yellow",)
    return ("dim",)


# ---- human view ----

def _dw(text: object) -> int:
    """Display width in terminal columns: wide East-Asian and most emoji count
    2, combining marks 0, everything else 1. A stdlib approximation (no wcwidth
    dependency) — good for CJK; some emoji ZWJ sequences may still be off."""
    total = 0
    for ch in str(text):
        if unicodedata.combining(ch):
            continue
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def _clip(text: object, width: int) -> str:
    """Collapse whitespace and truncate to `width` *display columns*, ellipsis."""
    text = " ".join(str(text or "").split())
    if _dw(text) <= width:
        return text
    out, w = [], 0
    for ch in text:
        cw = _dw(ch)
        if w + cw > width - 1:  # leave one column for the ellipsis
            break
        out.append(ch)
        w += cw
    return "".join(out) + "…"


def _pad(text: object, width: int) -> str:
    """Clip to `width` display columns, then pad with spaces to that width so
    columns align even when cells contain wide/zero-width characters."""
    clipped = _clip(text, width)
    return clipped + " " * max(0, width - _dw(clipped))


def _col_width(values, header: str, cap: int) -> int:
    return max(len(header), min(max((_dw(v) for v in values), default=len(header)), cap))


def _emit_row(out, prefix: str, indent: int, text: object, width: int, wrap: bool) -> None:
    """Print a table row whose trailing column is `text`. Truncated to one line,
    or (wrap) wrapped to `width` with a hanging indent so continuation lines sit
    under the column. `prefix` may contain ANSI; `indent` is its visible width."""
    text = " ".join(str(text or "—").split())
    if not wrap:
        print(prefix + _clip(text, width), file=out)
        return
    lines = textwrap.wrap(text, width, break_long_words=True, break_on_hyphens=False) or ["—"]
    print(prefix + lines[0], file=out)
    for cont in lines[1:]:
        print(" " * indent + cont, file=out)


def _shorten_home(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if home != "~" and path.startswith(home) else path


def _where_of(item: dict) -> str:
    """Display value for the 'where' column: 'global' for user-level items, or
    the repo's basename for project items (the last path segment — the part that
    actually distinguishes repos; the full path is in -v / the JSON)."""
    w = item.get("_where") or ("global" if item["location_kind"].startswith("user_")
                               else "project")
    if w in ("global", "project"):
        return w
    return w.replace("\\", "/").rstrip("/").split("/")[-1] or w


def _print_findings_table(findings, width, color, out, wrap=True) -> None:
    # Most severe first; wrap the detail by default (a truncated finding is
    # useless, and there are rarely many). A colored dot per severity gives a
    # scannable left rail beyond the color of the label itself.
    findings = sorted(findings, key=lambda p: _sev_rank(p[1]["severity"]), reverse=True)
    sev_w = _col_width([f["severity"] for _, f in findings], "severity", 10)
    item_w = _col_width([it["name"] for it, _ in findings], "item", 22)
    cat_w = _col_width([f["category"] for _, f in findings], "category", 24)
    indent = 2 + 2 + sev_w + 2 + item_w + 2 + cat_w + 2  # 2 extra for the "● " dot slot
    detail_w = max(24, width - indent)
    header = (f"{'severity':<{sev_w}}  {'item':<{item_w}}  "
              f"{'category':<{cat_w}}  detail")
    print("    " + _style(header, color, "underline"), file=out)
    for it, f in findings:
        styles = _sev_styles(f["severity"])
        dot = _style("●", color, *styles)
        sev = _style(_pad(f["severity"], sev_w), color, *styles)
        prefix = (f"  {dot} {sev}  {_pad(it['name'], item_w)}  "
                  f"{_pad(f['category'], cat_w)}  ")
        _emit_row(out, prefix, indent, f["title"], detail_w, wrap=wrap)


def _print_item_table(first: str, items, width, color, verbose, wrap, out) -> None:
    name_w = _col_width([i["name"] for i in items], first, 28)
    agent_w = _col_width([i["source"] for i in items], "agent", 12)
    where_w = _col_width([_where_of(i) for i in items], "where", 22)
    desc_w = max(16, width - name_w - agent_w - where_w - 8)
    indent = 2 + name_w + 2 + agent_w + 2 + where_w + 2
    header = (f"{first:<{name_w}}  {'agent':<{agent_w}}  "
              f"{'where':<{where_w}}  description")
    print("  " + _style(header, color, "underline"), file=out)
    for i in items:
        name = _style(_pad(i["name"], name_w), color, "bold")  # name pops
        prefix = (f"  {name}  {_pad(i['source'], agent_w)}  "
                  f"{_pad(_where_of(i), where_w)}  ")
        _emit_row(out, prefix, indent, i.get("description") or "—", desc_w, wrap=wrap)
        if verbose and i.get("_path"):
            shown = _style(_shorten_home(i["_path"]), color, "dim")
            print("    " + _hyperlink(shown, i["_path"], color), file=out)


def _print_checked_locations(locations, out) -> None:
    """The full checked-vs-not-present location list (``--verbose``); confirms
    the tool looked where you expected."""
    print("Locations checked:", file=out)
    for loc in locations:
        root = loc.root.expanduser()
        if loc.pattern:
            found = root.is_dir() and any(p.is_file() for p in root.glob(loc.pattern))
            what = f"{root}{os.sep}{loc.pattern}"
            label = "rules "
        else:
            found = root.is_dir()
            what = str(root)
            label = "skills"
        print(f"  [{('found' if found else 'not present'):>11}] {label} "
              f"{loc.source}:{loc.location_kind}  {what}", file=out)


def _render_human(report: dict, locations, args, out=None) -> None:
    """The developer-facing view on stdout: a headline, then tables of findings,
    skills, and instruction files. --verbose adds each item's path and the full
    location list; --findings shows only flagged items."""
    out = out or sys.stdout
    color = _color_enabled(args)
    wrap = not args.no_wrap
    width = shutil.get_terminal_size((100, 20)).columns
    items = report.get("items", [])
    findings = [(it, f) for it in items for f in it.get("local_findings", [])]
    skills = [it for it in items if not it["location_kind"].endswith("_rules")]
    rules = [it for it in items if it["location_kind"].endswith("_rules")]
    agents = len({it["source"] for it in items})
    device = report.get("device_name") or "this machine"

    print(_style("skill-discovery", color, "bold") + _style(f" · {device}", color, "dim"),
          file=out)
    counts = (f"{len(skills)} skills · {len(rules)} instruction files · {agents} agents · "
              f"{len(locations):,} locations scanned")
    line = _style(counts, color, "dim")
    if findings:
        worst = max((f["severity"] for _, f in findings), key=_sev_rank)
        line += _style(f" · {len(findings)} findings", color, *_sev_styles(worst))
    print(line, file=out)

    if findings:
        print(f"\n{_style('Findings', color, 'bold')}", file=out)
        _print_findings_table(findings, width, color, out, wrap)
    else:
        print(f"\n{_style('✓ No findings', color, 'green')}", file=out)

    if args.findings:  # triage mode: findings only, skip the inventory
        return

    if skills:
        print(f"\n{_style(f'Skills ({len(skills)})', color, 'bold')}", file=out)
        _print_item_table("name", skills, width, color, args.verbose, wrap, out)
    if rules:
        print(f"\n{_style(f'Instruction files ({len(rules)})', color, 'bold')}", file=out)
        _print_item_table("file", rules, width, color, args.verbose, wrap, out)
    if not items:
        print(_style(f"No skills or instruction files found "
                     f"({len(locations)} locations scanned).", color, "dim"), file=out)

    footer = "run --json for the full report · -v for paths and every location scanned"
    print("\n" + _style(footer, color, "dim"), file=out)
    if args.verbose:
        print(file=out)
        _print_checked_locations(locations, out)


def _exit_code(report: dict, args) -> int:
    """0 by default (findings are not errors); --fail-on gates CI runs."""
    if args.fail_on == "none":
        return 0
    worst = max((_sev_rank(f.get("severity"))
                 for it in report.get("items", []) for f in it.get("local_findings", [])),
                default=-1)
    if args.fail_on == "findings" and worst >= 0:
        return 1
    if args.fail_on == "high" and worst >= _SEV_RANK["high"]:
        return 1
    return 0


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

    if not args.no_discover_projects:
        locations.extend(_discover_project_locations(proj_keys, home, args))

    locations = _dedupe_locations(locations)

    def _build(include_local: bool = False) -> dict:
        return build_discovery_report(
            locations=locations or None,
            upload_mode=args.upload_mode,
            device_id=args.device_id,
            device_name=args.device_name,
            user_id=args.user_id,
            agent_version=args.agent_version,
            scanner_backend=args.scanner_backend,
            include_local=include_local,
        )

    fmt = _resolve_format(args)

    if args.loop is not None:
        if args.loop < MIN_LOOP_SECONDS:
            parser.error(f"--loop must be at least {MIN_LOOP_SECONDS:.0f} seconds")
        if args.heartbeat < 0:
            parser.error("--heartbeat must be 0 or positive")
        if not args.dry_run and not _server_configured(args):
            parser.error("--loop submits continuously and needs a server: set --url or "
                         "SKILL_DISCOVERY_SERVER_URL, or add --dry-run to print instead.")
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

    # Submit only when a server is actually configured; otherwise (and for
    # --dry-run) just show the inventory locally. This makes a bare
    # `skill-discovery` do the useful, safe thing instead of POSTing to a
    # guessed localhost.
    if args.dry_run or not _server_configured(args):
        report = _build(include_local=(fmt == "human"))
        if fmt == "json":
            print(json.dumps(report, indent=2))
        else:
            _render_human(report, locations, args)
        if not args.dry_run:  # ran with no server configured: say why it didn't submit
            print(_style("No server configured, so nothing was submitted. Point --url "
                         "(or SKILL_DISCOVERY_SERVER_URL) at a governance server to report.",
                         _color_enabled(args), "dim"), file=sys.stderr)
        return _exit_code(report, args)

    url = _require_safe_url(parser, args)  # validate scheme before the scan
    report = _build()
    if args.print_json:
        print(json.dumps(report, indent=2))
    try:
        res = _post(f"{url.rstrip('/')}/discovery/reports", report, _resolve_token(args))
    except (urllib.error.URLError, OSError) as exc:
        # Connection refused, timeout, 404/500, TLS error, ...: report cleanly.
        print(f"skill-discovery: could not submit to {url}: "
              f"{getattr(exc, 'reason', exc)}", file=sys.stderr)
        return 1
    # A 2xx alone is not proof the report was processed: require the documented
    # response shape (a JSON object with report_id/accepted). An empty, garbage,
    # non-object, or contract-less body is a failed submission, not a success —
    # otherwise CI/fleet automation records a success the server never gave.
    if not isinstance(res, dict) or not ("report_id" in res or "accepted" in res):
        print(f"skill-discovery: submitted to {url}, but the server did not return the "
              f"expected response (a JSON object with report_id/accepted); treating as a "
              f"failed submission.", file=sys.stderr)
        return 1
    print(
        f"Reported {res.get('accepted', len(report['items']))} discovered skill(s): "
        f"{res.get('flagged', 0)} flagged, {res.get('blocked', 0)} blocked."
    )
    return _exit_code(report, args)


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
