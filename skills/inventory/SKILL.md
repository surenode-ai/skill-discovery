---
name: inventory
description: >-
  Inventory the AI-agent skills and standing instruction files installed on this
  machine. Use when the user asks what skills, agents, rules, or custom
  instructions are installed; wants to audit or review what Claude Code, Codex,
  Cursor, Copilot, Windsurf, Kiro, Antigravity, or opencode has loaded; suspects
  an unknown or untrusted skill; or wants a security posture / inventory of agent
  skills on the endpoint.
---

# Skill inventory

`skill-discovery` walks the known skill folders and standing-instruction files
for every supported coding agent on this machine and reports what is actually
installed. It reads directory structure and `SKILL.md` metadata — not the
contents of your source files — and by default makes **zero network calls**.

## Running it

Invoke the bundled launcher, which finds the best available runner
(`skill-discovery` on PATH, else `uvx`/`pipx`, else plain Python):

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/run-skill-discovery.sh" --dry-run --json
```

- `--dry-run` guarantees nothing leaves the machine and shows exactly what a
  report would contain. Keep it on unless the user explicitly wants to upload to
  a governance server.
- `--json` returns a machine-readable report — parse it and summarize for the
  user. Drop it (or pass `--format human`) if the user wants the raw tables.
- Add `-v` to include each item's full path and every location that was checked.

With no path arguments the tool scans where every supported agent stores skills
**and** auto-discovers project-level skills committed inside repos under the home
directory. Useful narrowing flags:

- `--claude` / `--codex` — limit the scan to one agent's locations.
- `--agent <key>` — repeatable; restrict to specific agents.
- `--no-discover-projects` — global skills only (skip the repo walk).
- `--discover-root <dir>` — add a base outside the home directory.
- `--fail-on findings|high` — exit non-zero (useful as a CI gate).

## Reporting back

After running, summarize for the user:

1. **Findings first** — anything the scanner flagged (unknown, suspicious, or
   policy-violating skills), with where it lives.
2. **Skills** — name, agent, location, description.
3. **Instruction files** — rules / steering / custom-instruction files that
   silently change agent behavior every session.

Call out anything the user likely did not install deliberately, and cite the
path so they can inspect it themselves. Do not claim a skill is "safe" — report
what is present and let the user judge. If the launcher reports a missing
Python interpreter, tell the user to install Python 3.9+, `uv`, or `pipx`.
