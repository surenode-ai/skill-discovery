---
description: Scan this machine for installed AI-agent skills and instruction files, then report the inventory.
argument-hint: "[extra skill-discovery flags, e.g. --claude -v]"
---

Run the `skill-discovery` inventory and report what is installed on this machine.

Execute the bundled launcher with the user's arguments appended (default to a
safe, offline, machine-readable run):

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/run-skill-discovery.sh" --dry-run --json $ARGUMENTS
```

Then summarize the report for the user:

1. **Findings** the scanner flagged (unknown / suspicious / policy-violating
   skills), each with its path.
2. **Skills** — name, agent, location, description.
3. **Instruction files** — rules, steering, and custom-instruction files that
   change agent behavior every session.

`--dry-run` makes zero network calls; keep it unless the user explicitly asks to
upload to a governance server (that needs `--url` and `--token`). Do not label
any skill "safe" — report what is present and cite paths so the user can inspect
it. See the `inventory` skill for the full flag reference.
