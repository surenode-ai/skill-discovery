# skill-discovery

[![ci](https://github.com/surenode-ai/skill-discovery/actions/workflows/ci.yml/badge.svg)](https://github.com/surenode-ai/skill-discovery/actions/workflows/ci.yml)

Find out what skills your AI coding agents have installed. One command, runs
on your own machine, no server or account needed.

Coding agents like Claude Code, Codex, Cursor, Copilot, Windsurf, Kiro,
Antigravity, and opencode act on **skills** (folders of persistent
instructions: `SKILL.md` plus references and scripts) and on standing
instruction files (rules, steering, custom instructions). Both change what
the agent does in every future session. They accumulate from
repos, marketplaces, and pasted snippets, and they sit there quietly steering
your agent long after you have forgotten where they came from.

## Why I built skill-discovery

Skills fix agent amnesia, and tools like
[skill-extractor](https://github.com/surenode-ai/skill-extractor) make them
cheap to create. That created the next problem: I could not tell you what was
installed on my own laptop. A skill arrives with a cloned repo, an install
script, a teammate's paste, and from then on it is a standing instruction your
agent follows. Research such as NVIDIA's
[SkillSpector](https://github.com/NVIDIA/skillspector) has documented real
malicious-skill patterns (environment dumps, hidden Office and zip payloads,
prompt injection aimed at the scanner itself), so "I probably know what's
installed" stopped being a good enough answer.

skill-discovery is the smallest useful response: a single command that walks
the known skill folders and instruction files on a machine and reports what
is actually there. Run
it yourself out of curiosity. Run it across a fleet on a schedule and your
security team gets an inventory instead of a guess.

## Quick start

```bash
pip install .        # from a checkout; Python 3.9+, one dependency (PyYAML)
skill-discovery --dry-run
```

That checks every known agent's skill roots and instruction-file locations
(see the [support matrix](#agent-support-matrix)) and prints a JSON inventory
of what it found: names, descriptions, per-folder fingerprints, and local
detection findings. `--dry-run` makes **zero network calls**. Nothing leaves your
machine and no server is involved. Add `--project ~/work/myrepo` to include a
repo's project-level skills, or `--path <dir>` for any other folder.

For each skill you get:

- **Frontmatter parsing**: name and description from `SKILL.md`.
- **Fingerprint**: an order-independent SHA-256 over the folder contents,
  identical for the same skill on Windows, macOS, and Linux.
- **Local detection**: built-in offline heuristic rules for documented
  malicious-skill patterns (environment dumps, hidden Office/zip payloads,
  bytecode smuggling, scanner-directed prompt injection, package-registry
  tampering). If [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)
  is installed (`uv tool install git+https://github.com/NVIDIA/skillspector.git`),
  it runs too. The report's `scanner` field always says which backend actually
  ran (`heuristics` vs `skillspector+heuristics`).
- **Sanitization findings**: secrets and PII that would be redacted before any
  upload, plus personal home-directory paths worth knowing about.

Be clear about what this is: **observation, not judgment**. The tool
inventories what exists and attaches findings. It does not certify skills, it
does not claim detection completeness, and a report with zero findings means
"nothing our local rules noticed", nothing more.

## Agent support matrix

Two kinds of location are inventoried. Skill roots hold SKILL.md folders and
are walked like any skill directory. Instruction files (rules, steering,
custom instructions) are standalone files an agent always follows; each one
becomes its own report item with a `..._rules` location kind, fingerprinted,
sanitized, and scanned exactly like a skill.

| Agent | Skill roots (user, project) | Instruction files | Source |
|---|---|---|---|
| Claude Code (`claude`) | `~/.claude/skills`, `.claude/skills` | `CLAUDE.md` memory files exist but are not yet inventoried | Anthropic docs |
| OpenAI Codex CLI (`codex`) | `~/.agents/skills`, `.agents/skills` (shared Agent Skills convention) | `AGENTS.md` exists but is not yet inventoried | [Codex skills](https://developers.openai.com/codex/skills) |
| opencode (`opencode`) | `~/.config/opencode/skills`, `.opencode/skills` | none beyond skills | [opencode skills](https://opencode.ai/docs/skills/) |
| Cursor (`cursor`) | `~/.cursor/skills`, `.cursor/skills` | `.cursor/rules/*.mdc` | [Cursor skills](https://cursor.com/docs/skills.md), [Cursor rules](https://cursor.com/docs/rules) |
| Google Antigravity (`antigravity`) | `~/.gemini/config/skills`, `~/.gemini/antigravity-cli/skills`; project side uses the shared `.agents/skills` | no on-disk rules path documented by the vendor | [Antigravity skills codelab](https://codelabs.developers.google.com/getting-started-with-antigravity-skills) |
| Windsurf (`windsurf`) | `~/.codeium/windsurf/skills`, `.windsurf/skills` | `.devin/rules/*.md`, legacy `.windsurf/rules/*.md`, global `~/.codeium/windsurf/memories/global_rules.md` | [Windsurf skills](https://docs.windsurf.com/windsurf/cascade/skills), [Windsurf rules](https://docs.windsurf.com/windsurf/cascade/memories) |
| GitHub Copilot (`copilot`) | `~/.copilot/skills`, `.github/skills` (also reads the shared and Claude locations) | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` | [Copilot skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills), [Copilot instructions](https://docs.github.com/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot) |
| Kiro, AWS (`kiro`) | `~/.kiro/skills`, `.kiro/skills` | steering: `~/.kiro/steering/*.md`, `.kiro/steering/*.md` | [Kiro skills](https://kiro.dev/docs/skills/), [Kiro steering](https://kiro.dev/docs/steering/) |

Several agents also read the shared `.agents/skills` and Claude-compatible
locations. Those are listed once, under the entry that owns the convention,
and any root two agents share is scanned only once, so nothing is double
counted. The dry-run summary on stderr labels every location as `skills` or
`rules` so you can tell which kind produced each item.

The registry lives in [`discovery/agents.py`](discovery/agents.py) and is the
single most wanted community contribution: one small, documented entry adds
support for another agent. Every path must be citable to the agent vendor's
docs. See [CONTRIBUTING.md](CONTRIBUTING.md).

## CLI reference

```bash
skill-discovery --dry-run                          # all agents, print, no network
skill-discovery --agent claude --dry-run           # one agent only
skill-discovery --project ~/work/repo --dry-run    # a repo's project-level skills
skill-discovery --path ~/team-skills --source team-repo --dry-run
```

| Flag | Meaning |
|---|---|
| `--agent <key>` (repeatable) | Scan a registered agent's locations: `claude`, `codex`, `cursor`, `antigravity`, `windsurf`, `opencode`, `copilot`, `kiro`, or `all`. Default when no location flags are given: `all` |
| `--project <dir>` (repeatable) | Scan project-level skill roots under a directory (scoped by `--agent` if given) |
| `--path <dir>` (repeatable) | Any additional skill root; labeled with `--source` |
| `--claude` / `--codex` | Deprecated aliases for `--agent claude` / `--agent codex` |
| `--home <dir>` | Home directory to resolve user skill roots under |
| `--device-id`, `--device-name`, `--user-id` | Attribution for the fleet view (default: hostname / `$USER`/`$USERNAME`) |
| `--upload-mode` | `metadata_only` (default) or `full_skill` |
| `--scanner-backend` | `auto` (default), `heuristics`, `skillspector`, `none` |
| `--loop <seconds>` | Continuous mode: rescan on this interval (minimum 60) and report only when the inventory changes. Without it, one-shot as always |
| `--heartbeat <seconds>` | With `--loop`: report even without change once this long has passed since the last successful submission (default 86400, i.e. daily; 0 reports every pass) |
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
- **`full_skill`**: additionally uploads each skill folder, after local
  sanitization, for server-side scanning.

Sanitization runs locally in both modes, and its findings are part of the
report:

- Secrets and PII in skill markdown become `[redacted:...]` markers: private
  keys, JWTs, AWS/API keys, GitHub/Slack tokens, bearer tokens, URL-embedded
  passwords, SSNs, emails. Redaction happens **before** upload, so neither the
  value nor its location reaches the server.
- Personal home-directory paths (`/Users/<name>/...`, `C:\Users\<name>\...`)
  are flagged as findings but never rewritten, because a bundled tool may
  legitimately need them.
- Directory-walk errors are scrubbed of home paths and usernames before they
  are reported.
- `--dry-run` needs no server, no token, no network. Use it to see exactly
  what a report would contain before you deploy anything.

Redaction is pattern-based and best-effort, not a guarantee. Review a
`--dry-run` report from a representative machine before enabling
`full_skill` fleet-wide.

### Deploying across a fleet

The simplest deployment is continuous mode: run it as a service and it
reports when the inventory changes, with a daily heartbeat so the server's
last-seen stays current.

```bash
skill-discovery --loop 900 --device-id "$(hostname)" --user-id "$USER"
```

Each pass rescans locally, digests the inventory (skill identities,
fingerprints, findings), and submits only when that digest differs from the
last successful submission. The traffic property matters at fleet scale: a
quiet machine sends one heartbeat a day, not one report per pass. A failed
submission retries on the next pass, Ctrl-C or a supervisor stop exits
cleanly, and state is in memory only, so after a restart it submits once and
the server upserts. Run it as the console user, since the skill roots live in
user homes.

Service recipes:

- **launchd (macOS)**: a `LaunchAgent` with `KeepAlive`:

  ```xml
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/skill-discovery</string>
    <string>--loop</string><string>900</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  ```

- **systemd (Linux)**: a user service, `~/.config/systemd/user/skill-discovery.service`:

  ```ini
  [Service]
  ExecStart=%h/.local/bin/skill-discovery --loop 900
  Restart=on-failure
  [Install]
  WantedBy=default.target
  ```

- **Windows (Task Scheduler)**:

  ```bat
  schtasks /Create /SC ONSTART /TN "skill-discovery" ^
    /TR "skill-discovery --loop 900 --device-id %COMPUTERNAME% --user-id %USERNAME%"
  ```

Prefer an external schedule? The one-shot command still works under any
scheduler (a Jamf or Intune policy, cron
`30 9 * * * skill-discovery --device-id "$(hostname)" --user-id "$USER"`, a
daily `schtasks` trigger, a launchd `StartCalendarInterval`): run it daily per
user session and the server's inventory stays current, since reports upsert
by `device_id` plus skill identity. Either way, set
`SKILL_DISCOVERY_SERVER_URL` (and token) from your management profile.

Developers can always run it themselves with `--dry-run` to see their own
inventory first. That transparency is deliberate, and `--dry-run --loop 900`
works too: it prints the report whenever the inventory changes and notes
quiet passes on stderr. In loop mode each printed report is one complete JSON
document, and when several print over the life of the process, stdout is a
stream of newline-separated JSON documents in order.

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
"blocked": n, "results": [...]}`. The accepted/flagged/blocked counts are the
server's judgment, not the agent's.

## Using this on a team?

skill-discovery reports what exists; it renders no verdicts. If your team
needs those reports to flow into per-tenant policy, drift detection, and a
review workflow before anyone acts on them, that governance layer is what
[Surenode](https://surenode.ai) builds on top of this agent: KLIN ingests the
reports and gives security teams the fleet inventory and the decisions around
it. Any server can implement the contract above; nothing here is tied to ours.

## What this tool is not

Plainly: this is posture and transparency tooling. It gives you an inventory
of what skills exist on your endpoints and surfaces findings worth a look. It
does not certify skills and it does not claim to catch everything. That
judgment belongs to you, or to the governance layer you report into.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests/
```

CI runs the suite on Python 3.9 and 3.12 across Linux, macOS, and Windows.
See [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off required) and
[SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). SkillSpector is a
separate NVIDIA project, invoked as an externally installed CLI when present.
It is not vendored or redistributed here.
