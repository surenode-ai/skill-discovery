#!/usr/bin/env bash
# Launcher used by the Claude Code plugin. Runs the skill-discovery CLI from the
# bundled source, trying the most convenient runner available on the machine and
# falling back to plain Python. All arguments are passed straight through.
set -euo pipefail

# CLAUDE_PLUGIN_ROOT is set by Claude Code to this plugin's install directory.
# When run outside the plugin (e.g. by hand), fall back to the repo root.
ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# 1. Already installed on PATH (e.g. `pip install skill-discovery`).
if command -v skill-discovery >/dev/null 2>&1; then
  exec skill-discovery "$@"
fi

# 2. uv: builds an ephemeral env from the bundled pyproject. No global install.
if command -v uvx >/dev/null 2>&1; then
  exec uvx --from "$ROOT" skill-discovery "$@"
fi

# 3. pipx: same idea, different tool.
if command -v pipx >/dev/null 2>&1; then
  exec pipx run --spec "$ROOT" skill-discovery "$@"
fi

# 4. Plain Python. Ensure the one runtime dep (PyYAML) is importable, then run
#    the module directly from the bundled source via PYTHONPATH.
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "skill-discovery: no Python interpreter found (need python3, or install uv/pipx)." >&2
  exit 127
fi
if ! "$PY" -c "import yaml" >/dev/null 2>&1; then
  "$PY" -m pip install --quiet --user PyYAML >/dev/null 2>&1 || true
fi
exec env PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PY" -m discovery.cli "$@"
