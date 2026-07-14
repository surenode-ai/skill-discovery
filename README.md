# skill-discovery

Audit the skills your AI agents have installed — on your own machine, no
server needed.

Coding agents like Claude Code, Codex CLI, and opencode act on **skills**:
folders of persistent instructions (`SKILL.md` plus references and scripts)
that change what the agent does in every future session. They accumulate from
repos, marketplaces, and pasted snippets, and most people could not list what
is installed right now, let alone what is inside it.

```bash
pip install .        # from a checkout; Python 3.9+, one dependency (PyYAML)
skill-discovery --dry-run
```

That one command checks every known agent's skill roots (see the
[support matrix](#agent-support-matrix)), and prints a JSON inventory of what
it found — names, descriptions, per-folder fingerprints, and local detection
findings. `--dry-run` makes **zero network calls**: nothing leaves your
machine, no server or account is involved. Add `--project ~/work/myrepo` to
include a repo's project-level skills, or `--path <dir>` for any other folder.

What each skill gets:

- **Frontmatter parsing** — name and description from `SKILL.md`.
- **Fingerprint** — order-independent SHA-256 over the folder contents,
  identical for the same skill on Windows, macOS, and Linux.
- **Local detection** — built-in offline heuristic rules for documented
  malicious-skill patterns (environment dumps, hidden Office/zip payloads,
  bytecode smuggling, scanner-directed prompt injection, package-registry
  tampering), plus [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)
  automatically when it is installed
  (`uv tool install git+https://github.com/NVIDIA/skillspector.git`). The
  report's `scanner` field always says which backend ran (`heuristics` vs
  `skillspector+heuristics`).
- **Sanitization findings** — secrets/PII that would be redacted before any
  upload, and personal home-directory paths worth knowing about.

This is **observation, not judgment**. The tool inventories what exists and
attaches findings; it does not certify skills, does not claim detection
completeness, and a report with zero findings means "nothing our local rules
noticed", nothing more.

## Agent support matrix

| Agent | User-level root | Project-level root |
|---|---|---|
| Claude Code (`claude`) | `~/.claude/skills` | `.claude/skills` |
| OpenAI Codex CLI (`codex`, [Agent Skills convention](https://developers.openai.com/codex/skills)) | `~/.agents/skills` | `.agents/skills` |
| [opencode](https://opencode.ai/docs/skills/) (`opencode`) | `~/.config/opencode/skills` | `.opencode/skills` |

The registry lives in [`discovery/agents.py`](discovery/agents.py) and is the
single most wanted community contribution: one small, documented entry adds
support for another agent. Every path must be citable to the agent vendor's
docs — see [CONTRIBUTING.md](CONTRIBUTING.md).

## CLI reference

```bash
skill-discovery --dry-run                          # all agents, print, no network
skill-discovery --agent claude --dry-run           # one agent only
skill-discovery --project ~/work/repo --dry-run    # a repo's project-level skills
skill-discovery --path ~/team-skills --source team-repo --dry-run
```

| Flag | Meaning |
|---|---|
| `--agent <key>` (repeatable) | Scan a registered agent's user roots (`claude`, `codex`, `opencode`, or `all`). Default when no location flags are given: `all` |
| `--project <dir>` (repeatable) | Scan project-level skill roots under a directory (scoped by `--agent` if given) |
| `--path <dir>` (repeatable) | Any additional skill root; labeled with `--source` |
| `--claude` / `--codex` | Deprecated aliases for `--agent claude` / `--agent codex` |
| `--home <dir>` | Home directory to resolve user skill roots under |
| `--device-id`, `--device-name`, `--user-id` | Attribution for the fleet view (default: hostname / `$USER`/`$USERNAME`) |
| `--upload-mode` | `metadata_only` (default) or `full_skill` |
| `--scanner-backend` | `auto` (default), `heuristics`, `skillspector`, `none` |
| `--dry-run` | Print the report, list which roots were checked, contact no server |
| `--print-json` | Print the report before submitting |
| `--url`, `--token` | Server base URL and bearer token (see environment below) |

`--dry-run` prints the JSON report on stdout (pipe-friendly) and a
human-readable list of checked vs found roots on stderr.

## Reporting to a governance server (fleet use)

The same command, pointed at a server implementing the open
`POST /discovery/reports` contract, turns local inventory into fleet
visibility:

```bash
export SKILL_DISCOVERY_SERVER_URL=https://governance.example.com
export SKILL_DISCOVERY_TOKEN=...        # if the server requires auth
skill-discovery --device-id "$(hostname)" --user-id "$USER"
```

Environment: `SKILL_DISCOVERY_SERVER_URL` / `SKILL_DISCOVERY_TOKEN`, with
`KILN_SERVER_URL` / `KILN_API_TOKEN` honored as fallbacks when reporting to a
KLIN server.

### Upload modes and the privacy story

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
- Personal home-directory paths (`/Users/<name>/...`, `C:\Users\<name>\...`)
  are flagged as findings but never rewritten — a bundled tool may need them.
- Directory-walk errors are scrubbed of home paths and usernames before they
  are reported.
- `--dry-run` needs no server, no token, no network: use it to see exactly
  what a report would contain before you deploy anything.

Redaction is pattern-based and best-effort, not a guarantee; review a
`--dry-run` report from a representative machine before enabling
`full_skill` fleet-wide.

### Deploying across a fleet (MDM / scheduled)

`skill-discovery` is a single stateless command, so any scheduler works:
run it daily per user session and the server's inventory stays current
(reports upsert by `device_id` + skill identity). Run it as the console
user — the skill roots live in user homes.

- **Jamf / Intune / any MDM**: ship a policy that runs
  `skill-discovery --device-id "$(hostname)" --user-id "$USER"` on a schedule,
  with `SKILL_DISCOVERY_SERVER_URL` (and token) set from your management
  profile.
- **Windows (Task Scheduler)**:

  ```bat
  schtasks /Create /SC DAILY /ST 09:30 /TN "skill-discovery" ^
    /TR "skill-discovery --device-id %COMPUTERNAME% --user-id %USERNAME%"
  ```

- **launchd (macOS)**: a `LaunchAgent` with a `StartCalendarInterval`.
- **systemd (Linux)** or **cron**: a user-level timer unit, or
  `30 9 * * * skill-discovery --device-id "$(hostname)" --user-id "$USER"`.
- **Ad hoc**: developers can always run it themselves with `--dry-run` to see
  their own inventory first; that transparency is deliberate.

### The server contract

The agent POSTs one JSON document to `POST /discovery/reports` (bearer auth
optional). All paths in the payload use forward slashes on every OS. Payload
sketch:

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
      "source": "claude",              // registry key, or the --source label
      "location_kind": "user_claude",  // privacy-preserving bucket: user_* | project_* | custom
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
does not certify skills, and it renders no verdicts — that judgment belongs to
you or to the governance layer you report into.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests/
```

CI runs the suite on Python 3.9 and 3.12 across Linux, macOS, and Windows.
See [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off required) and
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). SkillSpector is a
separate NVIDIA project, invoked as an externally installed CLI when present —
it is not vendored or redistributed here.
