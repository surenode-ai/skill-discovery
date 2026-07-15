# skill-discovery

[![ci](https://github.com/surenode-ai/skill-discovery/actions/workflows/ci.yml/badge.svg)](https://github.com/surenode-ai/skill-discovery/actions/workflows/ci.yml)

Find out what skills your AI coding agents have installed. One command, runs
on your own machine, no server or account needed.

Coding agents like Claude Code, Codex, Cursor, Copilot, Windsurf, Kiro,
Antigravity, and opencode act on **skills** (folders of persistent
instructions: `SKILL.md` plus references and scripts) and on standing
instruction files (rules, steering, custom instructions). Both change what
the agent does in every future session, and they accumulate from repos,
marketplaces, and pasted snippets long after you have forgotten where they
came from.

## Why I built skill-discovery

Skills fix agent amnesia, and tools like
[skill-extractor](https://github.com/surenode-ai/skill-extractor) make them
cheap to create. That created the next problem: I could not tell you what was
installed on my own laptop. Research such as NVIDIA's
[SkillSpector](https://github.com/NVIDIA/skillspector) has documented real
malicious skill patterns in the wild, so "I probably know what's installed"
stopped being a good enough answer.

skill-discovery is the smallest useful response: a single command that walks
the known skill folders and instruction files on a machine and reports what
is actually there. Run it yourself out of curiosity, or across a fleet on a
schedule so your security team gets an inventory instead of a guess.

## Quick start

```bash
pip install .        # from a checkout; Python 3.9+, one dependency (PyYAML)
skill-discovery --dry-run
```

No paths, no config. With no arguments the tool scans where every supported
agent stores skills and instruction files (see the
[support matrix](#agent-support-matrix)) **and** walks your home directory to
auto discover the in repo (project level) skills committed inside your repos,
so both your global skills and your projects' skills are found with no path
given.

Output adapts to who's asking. At a terminal you get a readable summary:
findings first, then tables of skills and instruction files (name, agent,
where, description). Piped or redirected, you get the JSON report instead, so
`skill-discovery --dry-run | jq …` just works. Force either with `--format
human|json` (or `--json`). `-v` adds each item's full path and the complete
list of locations checked; `--fail-on findings` makes it a CI gate.
`--dry-run` makes **zero network calls**: nothing leaves your machine, and it
shows exactly what a report would contain before you deploy anything.

Auto discovery is bounded (it prunes caches and build trees, reads directory
structure not file contents, and has a time budget), so it stays fast enough to
run on every launch. A few knobs:

- `--no-discover-projects` turns it off (falls back to global skills only).
- `--discover-root <dir>` (or the `SKILL_DISCOVERY_ROOTS` env var, os path
  separated) adds a base for code that lives **outside** your home, e.g.
  `/workspace` on a managed machine.
- `--project <dir>` scans one specific repo; `--path <dir>` adds any other
  folder, such as a mounted team share. Both run *in addition to* auto discovery
  (they add locations, they don't replace it). To scan only what you name, pass
  `--no-discover-projects` as well.

For each skill you get:

- **Frontmatter parsing**: name and description from `SKILL.md`.
- **Fingerprint**: an order independent SHA-256 over the folder contents,
  identical for the same skill on Windows, macOS, and Linux (paths and line
  endings are normalized, so a CRLF checkout hashes the same as an LF one).
- **Local detection**: built in offline heuristic rules for documented
  malicious skill patterns (environment dumps, hidden Office/zip payloads,
  bytecode smuggling, scanner directed prompt injection, package registry
  tampering). If [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)
  is installed (`uv tool install git+https://github.com/NVIDIA/skillspector.git`),
  it runs too. The report's `scanner` field always says which backend actually
  ran (`heuristics` vs `skillspector+heuristics`).
- **Sanitization findings**: secrets and PII that would be redacted before any
  upload, plus personal home directory paths worth knowing about.

## Agent support matrix

Two kinds of location are inventoried. Skill roots hold SKILL.md folders and
are walked like any skill directory. Instruction files (rules, steering,
custom instructions) are standalone files an agent always follows; each one
becomes its own report item with a `..._rules` location kind, fingerprinted,
sanitized, and scanned exactly like a skill.

| Agent | Skill roots (user, project) | Instruction files | Source |
|---|---|---|---|
| Claude Code (`claude`) | `~/.claude/skills`, `.claude/skills` | `~/.claude/CLAUDE.md`, `CLAUDE.md`, `CLAUDE.local.md` | [Claude memory](https://code.claude.com/docs/en/memory) |
| OpenAI Codex CLI (`codex`) | `~/.agents/skills`, `.agents/skills` (shared Agent Skills convention) | `AGENTS.md` (cross tool standard) | [Codex skills](https://developers.openai.com/codex/skills), [agents.md](https://agents.md/) |
| opencode (`opencode`) | `~/.config/opencode/skills`, `.opencode/skills` | none beyond skills | [opencode skills](https://opencode.ai/docs/skills/) |
| Cursor (`cursor`) | `~/.cursor/skills`, `.cursor/skills` | `.cursor/rules/**/*.mdc`, legacy `.cursorrules` | [Cursor skills](https://cursor.com/docs/skills.md), [Cursor rules](https://cursor.com/docs/rules) |
| Google Antigravity (`antigravity`) | `~/.gemini/config/skills`, `~/.gemini/antigravity-cli/skills`; project side uses the shared `.agents/skills` | no on disk rules path documented by the vendor | [Antigravity skills codelab](https://codelabs.developers.google.com/getting-started-with-antigravity-skills) |
| Windsurf (`windsurf`) | `~/.codeium/windsurf/skills`, `.windsurf/skills` | `.devin/rules/**/*.md`, `.windsurf/rules/**/*.md`, legacy `.windsurfrules`, global `~/.codeium/windsurf/memories/global_rules.md` | [Windsurf skills](https://docs.windsurf.com/windsurf/cascade/skills), [Windsurf rules](https://docs.windsurf.com/windsurf/cascade/memories) |
| GitHub Copilot (`copilot`) | `~/.copilot/skills`, `.github/skills` (also reads the shared and Claude locations) | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` | [Copilot skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills), [Copilot instructions](https://docs.github.com/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot) |
| Kiro, AWS (`kiro`) | `~/.kiro/skills`, `.kiro/skills` | steering: `~/.kiro/steering/**/*.md`, `.kiro/steering/**/*.md` | [Kiro skills](https://kiro.dev/docs/skills/), [Kiro steering](https://kiro.dev/docs/steering/) |
| Gemini CLI (`gemini`) | none documented | `~/.gemini/GEMINI.md`, `GEMINI.md` | [Gemini CLI memory](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/auto-memory.md) |
| Cline (`cline`) | none documented | `.clinerules/**/*.md`, global `~/Documents/Cline/Rules/**/*.md`, `~/.agents/AGENTS.md` | [Cline rules](https://docs.cline.bot/features/cline-rules) |
| Roo Code (`roo`) | none documented | `.roo/rules/**/*.md`, legacy `.roorules`, global `~/.roo/rules/**/*.md` | [Roo instructions](https://docs.roocode.com/features/custom-instructions) |

Several agents read the shared `.agents/skills` and Claude compatible
locations. Those are listed once, under the entry that owns the convention,
and any root two agents share is scanned only once, so nothing is double
counted.

The registry lives in [`discovery/agents.py`](discovery/agents.py) and is the
single most wanted community contribution: one small, documented entry adds
support for another agent, and every path must be citable to the agent
vendor's docs. See [CONTRIBUTING.md](CONTRIBUTING.md).

## CLI reference

The zero argument run is the normal one; everything else is optional narrowing
or reaching further:

```bash
skill-discovery                                    # global + auto discovered project skills, submit
skill-discovery --dry-run                          # same, but print instead of submit
skill-discovery --loop 900                         # run continuously as a service
skill-discovery --agent claude --dry-run           # narrow to one agent
skill-discovery --discover-root /workspace --dry-run   # also auto discover code outside home
skill-discovery --no-discover-projects --dry-run   # global skills only, no home walk
```

Every flag below is optional; with none of them the tool scans all registered
agents under your home directory and auto discovers in repo project skills.

| Flag | Meaning |
|---|---|
| `--agent <key>` (repeatable) | Narrow to specific agents: `claude`, `codex`, `cursor`, `antigravity`, `windsurf`, `opencode`, `copilot`, `kiro`, or `all`. Default with no location flags: every agent |
| `--no-discover-projects` | Turn off automatic discovery of in repo project skills under your home directory (on by default) |
| `--discover-root <dir>` (repeatable) | Additional base to auto discover project skills under, for code outside home (also via `SKILL_DISCOVERY_ROOTS`, os path separated) |
| `--discover-timeout <seconds>` | Wall clock budget for project discovery per base (default 20); if exceeded, discovery stops and reports what it found |
| `--project <dir>` (repeatable) | Also scan one specific repo's in repo skill roots (rarely needed; project skills under home are auto discovered) |
| `--path <dir>` (repeatable) | Also scan any extra skill root, e.g. a mounted team share; labeled with `--source` |
| `--claude` / `--codex` | Deprecated aliases for `--agent claude` / `--agent codex` |
| `--home <dir>` | Home directory to resolve user skill roots under |
| `--device-id`, `--device-name`, `--user-id` | Attribution for the fleet view (default: hostname / `$USER`/`$USERNAME`) |
| `--upload-mode` | `metadata_only` (default) or `full_skill` |
| `--scanner-backend` | `auto` (default), `heuristics`, `skillspector`, `none` |
| `--loop <seconds>` | Continuous mode: rescan on this interval (minimum 60) and report only when the inventory changes. Without it, one shot as always |
| `--heartbeat <seconds>` | With `--loop`: report even without change once this long has passed since the last successful submission (default 86400, i.e. daily; 0 reports every pass) |
| `--dry-run` | Produce the report locally, contact no server |
| `--format human\|json` | Output format for `--dry-run` (default: human at a terminal, json when piped) |
| `--json` | Shorthand for `--format json` |
| `--no-color` | Disable ANSI color (also honors the `NO_COLOR` env var) |
| `-v`, `--verbose` | Human view: show each item's full path and list every location checked |
| `--findings` | Human view: show only items that have findings |
| `--fail-on none\|findings\|high` | Exit non-zero if findings (or high+ findings) exist, for CI gating (default `none`) |
| `--print-json` | Print the report before submitting |
| `--url`, `--token` | Server base URL and bearer token (see environment below) |
| `--allow-http` | Permit plaintext `http://` to a non-loopback server. Otherwise refused, since the report and token would go unencrypted; loopback is always allowed |

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

The URL must be `https://` unless it points at loopback: plaintext HTTP would
expose the report and the bearer token, so the agent refuses it unless you
pass `--allow-http`. Requests time out after 30 seconds; in continuous mode a
timed out submission simply retries on the next pass.

### Upload modes and the privacy story

The default mode sends as little as possible:

- **`metadata_only`** (default): names, descriptions, relative paths,
  fingerprints, and findings. No file bodies leave the machine, and every
  field derived from skill content is itself redacted (see below), including
  the name, description, and the paths in `relative_path`/`external_id`, so a
  secret pasted into frontmatter or a filename does not ride along.
- **`full_skill`**: additionally uploads each skill folder, after local
  sanitization, for server side scanning.

Sanitization runs locally in both modes, and its findings are part of the
report:

- Secrets and PII are replaced with `[redacted:...]` markers: private keys,
  JWTs, AWS/API keys, GitHub/Slack tokens, bearer tokens, URL embedded
  passwords, SSNs, emails. This covers every text file in the skill (markdown
  and bundled scripts alike, since `full_skill` uploads scripts too), the
  name/description metadata lifted from them, and the file paths themselves (a
  file named like a credential). Redaction happens **before**
  upload, so neither the value nor its location reaches the server.
- Personal home directory paths (`/Users/<name>/...`, `C:\Users\<name>\...`)
  are flagged as findings but never rewritten, because a bundled tool may
  legitimately need them.
- Directory walk errors are scrubbed of home paths and usernames before they
  are reported.

Redaction is pattern based and best effort, not a guarantee. Review a
`--dry-run` report from a representative machine before enabling
`full_skill` fleet wide.

### Deploying across a fleet

The simplest deployment is continuous mode: run it as a service and it
reports when the inventory changes, with a daily heartbeat so the server's
last seen stays current.

```bash
skill-discovery --loop 900 --device-id "$(hostname)" --user-id "$USER"
```

Each pass rescans locally, digests the inventory (skill identities,
fingerprints, findings), and submits only when that digest differs from the
last successful submission. The traffic property matters at fleet scale: a
quiet machine sends one heartbeat a day, not one report per pass. A failed
submission retries on the next pass, Ctrl-C or a supervisor stop exits
cleanly, and state is in memory only, so after a restart it submits once and
the server upserts. `--dry-run --loop` works too, and prints instead of
submitting: each report is one complete JSON document, so stdout becomes a
stream of newline separated JSON documents in order.

Two things matter for a fleet rollout. **Run it as the developer** (a per user
LaunchAgent, systemd `--user` service, or login item), not as a root daemon:
it scans and auto discovers under the running user's home, so a system service
would inventory the service account's empty home instead of the developer's.
And if your developers keep code **outside** their home (a shared `/workspace`,
mounted repos), point discovery there with `SKILL_DISCOVERY_ROOTS` in the
deployment profile. Each project skill is reported with a per repo identity, so
two developers' identically named skills stay distinct on the server.

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

Prefer an external schedule? The one shot command works under any scheduler
(Jamf or Intune policy, cron, a daily `schtasks` trigger, a launchd
`StartCalendarInterval`): run it daily per user session and the server's
inventory stays current, since reports upsert by `device_id` plus skill
identity. Either way, set `SKILL_DISCOVERY_SERVER_URL` (and token) from your
management profile. Developers can always run `--dry-run` themselves to see
their own inventory; that transparency is deliberate.

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

## What this tool is not

Observation, not judgment. skill-discovery inventories what exists and
attaches findings. It does not certify skills, it does not claim detection
completeness, and a report with zero findings means "nothing our local rules
noticed", nothing more. That judgment belongs to you, or to the governance
layer you report into.

Scoped to instructions, not execution. It inventories skills and standing
instruction files, the agent's *influence* surface.

## Using this on a team?

If your team needs these reports to flow into per tenant policy, drift
detection, and a review workflow before anyone acts on them, that governance
layer is what [Surenode](https://surenode.ai) builds on top of this agent:
KLIN ingests the reports and gives security teams the fleet inventory and the
decisions around it. Any server can implement the contract above; nothing
here is tied to ours.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests/
```

CI runs the suite on Python 3.9 and 3.12 across Linux, macOS, and Windows.
See [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign off required) and
[SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). SkillSpector is a
separate NVIDIA project, invoked as an externally installed CLI when present.
It is not vendored or redistributed here.
