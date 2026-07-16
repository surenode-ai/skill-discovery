# Contributing

Thanks for helping improve skill-discovery.

## Small enough to audit

This tool runs on employee endpoints, often deployed by an administrator. Its
core promise is a codebase **small enough to actually read** before you deploy
it: one package, one runtime dependency (PyYAML), one outbound network call.
Every merged feature spends some of that. Contributions are weighted
deliberately:

| Contribution | Reception |
|---|---|
| **New agent registry entries** (where another agent platform stores skills) | The most wanted contribution: one `AgentSpec` in `discovery/agents.py` plus a test. Every path must be citable to the agent vendor's documentation (link it in the entry's docstring); we do not merge guessed paths |
| **New detection heuristics** (documented malicious-skill techniques) | Equally welcome. A rule + a realistic test sample, never touches the report pipeline |
| **New redaction patterns** (secret/token formats the sanitizer should catch) | Welcome: tiny diffs, direct privacy value, must come with a test |
| **Bug fixes** | Always |
| **Features** | High bar. Open an issue first. Judgment about findings (allow/review/block policy) deliberately lives in the server, not here |

What we will not merge: skill *content*, allow/deny verdicts baked into the
agent, or additional network calls. This tool observes and reports; it does
not decide, and it talks to exactly one configured server.

## Ground rules

- **Keep the runtime lean.** Python 3.9+, stdlib plus PyYAML only. `pytest` is
  a dev-only convenience.
- **Privacy is a feature.** Sanitization runs before anything leaves the
  machine; `--dry-run` must always work offline. Do not add network calls.
- **Detection heuristics must be pure and offline** and must never raise: a
  heuristic miss must not fail a scan.
- **Language matters.** This is inventory/posture tooling. Findings are
  observations; do not add wording that promises safety or completeness.

## Workflow

1. Fork, branch, make the change.
2. Run the tests (see Testing and CI below); all green before review.
3. Sanity-check the CLI end to end:
   `skill-discovery --path <some-skills-dir> --dry-run --print-json`.
4. Open a PR with a clear description of the behavior change.

## Testing and CI

The suite is plain `pytest`. Against a single interpreter:

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests/
```

Against every supported Python version at once, use
[nox](https://nox.thea.codes/) (each interpreter must be installed, e.g. via
pyenv or uv):

```bash
pip install nox
nox                 # tests on 3.9 through 3.14, plus a ruff lint session
nox -s tests-3.13   # just one version
nox -s lint         # ruff only
```

CI (GitHub Actions, `.github/workflows/ci.yml`) runs on every push and PR:

- **Lint:** `ruff check` with `target-version = py39`, so syntax that is not
  valid on the minimum supported Python is caught before it reaches a test job.
- **Tests:** every supported version (3.9 through 3.14) on Linux, plus the
  endpoints (3.9 and 3.14) on macOS and Windows, then an offline CLI smoke test.

When a new Python version ships, add it in three places: `PYTHON_VERSIONS` in
`noxfile.py`, the matrix in `.github/workflows/ci.yml`, and the classifiers in
`pyproject.toml`.

## Developer Certificate of Origin

Commits must be signed off (`git commit -s`), certifying the
[DCO](https://developercertificate.org/): you wrote the change or otherwise
have the right to submit it under the Apache 2.0 license.
