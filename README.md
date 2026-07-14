# skill-discovery

An endpoint inventory agent for AI agent skills.

Coding agents like Claude Code and Codex CLI act on **skills**: folders of
persistent instructions (`SKILL.md` plus references and scripts) that change
what the agent does in every future session. Developers install them from
repos, marketplaces, and chat messages — and today most organizations have no
idea what skills are running on their machines.

`skill-discovery` gives you that visibility. It runs on the endpoint, scans the
standard skill roots (`~/.claude/skills`, `~/.agents/skills`) and any paths you
add, and produces a JSON inventory report:

- **Parses** each `SKILL.md`'s frontmatter (name, description).
- **Fingerprints** each skill folder (order-independent SHA-256 over contents),
  so the same skill is recognizable across your fleet.
- **Runs local detection**: built-in offline heuristic rules for documented
  malicious-skill patterns (environment dumps, hidden Office/zip payloads,
  bytecode smuggling, scanner-directed prompt injection, package-registry
  tampering), plus [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)
  when it is installed.
- **Sanitizes before anything leaves the machine**: secrets and PII are
  redacted, personal home-directory paths are flagged, error text is scrubbed
  of user paths.
- **Reports**: prints the JSON locally (`--dry-run` / `--print-json`) or POSTs
  it to a governance server implementing the open `POST /discovery/reports`
  contract.

This is **observation, not judgment**. The tool inventories what exists and
attaches findings; deciding what to allow, review, or block is the job of the
governance layer that ingests the reports. It does not claim to find
everything, and a clean report is not a verdict about a skill.

## Install

```bash
pip install .            # from a checkout; publishes a `skill-discovery` CLI
```

Python 3.9+. One runtime dependency (PyYAML, for SKILL.md frontmatter).

Optional deeper detection — install SkillSpector on the endpoint and
`skill-discovery` picks it up automatically:

```bash
uv tool install git+https://github.com/NVIDIA/skillspector.git
```

Without it, the built-in heuristic rules still run, and the report's `scanner`
field says which backend produced the findings (`heuristics` vs
`skillspector+heuristics`), so the server always knows what kind of scan it is
looking at.

## Quickstart

Inventory your own machine, nothing leaves it:

```bash
skill-discovery --claude --dry-run --print-json
```

Scan everything (Claude + Codex roots) and report to a server:

```bash
export SKILL_DISCOVERY_SERVER_URL=https://governance.example.com
export SKILL_DISCOVERY_TOKEN=...        # if the server requires auth
skill-discovery --device-id "$(hostname)" --user-id "$USER"
```

Add arbitrary roots (a repo checkout, a shared tools directory):

```bash
skill-discovery --path ~/work/team-skills --source team-repo --dry-run --print-json
```

### Flags

| Flag | Meaning |
|---|---|
| `--claude` / `--codex` | Scan `~/.claude/skills` / `~/.agents/skills` (both by default when no root flags are given) |
| `--path <dir>` (repeatable) | Additional skill root; labeled with `--source` |
| `--home <dir>` | Home directory to resolve the user skill roots under |
| `--device-id`, `--device-name`, `--user-id` | Attribution for the fleet view (default: hostname / `$USER`) |
| `--upload-mode` | `metadata_only` (default) or `full_skill` |
| `--scanner-backend` | `auto` (default), `heuristics`, `skillspector`, `none` |
| `--dry-run` | Print the report; contact no server |
| `--print-json` | Print the report before submitting |
| `--url`, `--token` | Server base URL and bearer token (see environment below) |

Environment: `SKILL_DISCOVERY_SERVER_URL` / `SKILL_DISCOVERY_TOKEN`, with
`KILN_SERVER_URL` / `KILN_API_TOKEN` honored as fallbacks when reporting to a
KLIN server.

## Upload modes and the privacy story

The default mode sends as little as possible:

- **`metadata_only`** (default): names, descriptions, relative paths,
  fingerprints, and findings. No skill content leaves the machine.
- **`full_skill`**: additionally uploads each skill folder for server-side
  scanning — after local sanitization.

Sanitization runs locally in both modes (its findings are part of the report):

- Secrets and PII in skill markdown become `[redacted:...]` markers: private
  keys, JWTs, AWS/API keys, GitHub/Slack tokens, bearer tokens, URL-embedded
  passwords, SSNs, emails. Redaction happens **before** upload, so neither the
  value nor its location reaches the server.
- Personal home-directory paths (`/Users/<name>/...`) are flagged as findings
  but never rewritten — a bundled tool may need them.
- Directory-walk errors are scrubbed of home paths and usernames before they
  are reported.
- `--dry-run` needs no server, no token, no network: use it to see exactly
  what a report would contain before you deploy anything.

Redaction is pattern-based and best-effort, not a guarantee; review a
`--dry-run` report from a representative machine before enabling
`full_skill` fleet-wide.

## Deploying across a fleet (MDM / scheduled)

`skill-discovery` is a single stateless command, so any scheduler works:
run it daily per user session and the server's inventory stays current
(reports upsert by `device_id` + skill identity).

- **Jamf / Intune / any MDM**: ship a policy that runs
  `skill-discovery --device-id "$(hostname)" --user-id "$USER"` on a schedule,
  with `SKILL_DISCOVERY_SERVER_URL` (and token) set from your management
  profile. Run it as the console user — the skill roots live in user homes.
- **launchd (macOS)**: a `LaunchAgent` with a `StartCalendarInterval`.
- **systemd (Linux)**: a user-level timer unit.
- **Ad hoc**: developers can always run it themselves with `--dry-run` to see
  their own inventory first; that transparency is deliberate.

## The server contract

The agent POSTs one JSON document to `POST /discovery/reports` (bearer auth
optional). Payload sketch:

```jsonc
{
  "device_id": "mac-123",             // stable endpoint id (default: hostname)
  "device_name": "Alice MacBook",
  "user_id": "alice@example.com",
  "agent_version": "skill-discovery/0.1.0",
  "upload_mode": "metadata_only",     // or "full_skill"
  "items": [
    {
      "external_id": "claude:user_claude:deploy",   // source:location:rel_dir
      "source": "claude",              // claude | codex | <--source label>
      "location_kind": "user_claude",  // privacy-preserving location bucket
      "relative_path": "deploy/SKILL.md",
      "name": "deploy",
      "description": "Roll out with checks.",
      "fingerprint": "sha256:...",     // over the whole skill folder
      "scanner": "skillspector+heuristics",   // which local backend ran
      "scanner_version": "skill-discovery/0.1.0",
      "local_findings": [
        {"rule_id": "env-var-exfiltration", "category": "data_exfiltration",
         "severity": "high", "title": "...", "path": "SKILL.md"}
      ],
      "candidate": {"SKILL.md": "..."}  // full_skill mode only; sanitized
    }
  ],
  "meta": {"scanner": "skillspector+heuristics",
           "locations": [{"source": "claude", "location_kind": "user_claude"}]}
}
```

Expected response: `{"report_id": ..., "accepted": n, "flagged": n,
"blocked": n, "results": [...]}` — the accepted/flagged/blocked counts are the
server's judgment, not the agent's.

Any server can implement this contract. KLIN (Surenode's governance product)
is the layer this agent was extracted from: it ingests the reports,
applies per-tenant policy to the findings, and gives security teams the fleet
inventory, drift, and review workflow on top.

## What this tool is not

Plainly: this is posture and transparency tooling. It gives you an inventory
of what skills exist on your endpoints and surfaces findings worth a look. It
does not certify skills, it does not claim detection completeness, and a report
with zero findings means "nothing our local rules noticed", nothing more.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off required) and
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). SkillSpector is a
separate NVIDIA project, invoked as an externally installed CLI when present —
it is not vendored or redistributed here.
