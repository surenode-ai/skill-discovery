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
| **New detection heuristics** (documented malicious-skill techniques) | The most wanted contribution. A rule + a realistic test sample, never touches the report pipeline |
| **New redaction patterns** (secret/token formats the sanitizer should catch) | Equally welcome: tiny diffs, direct privacy value, must come with a test |
| **New skill-root conventions** (where another agent platform stores skills) | Welcome — usually a one-line `DiscoveryLocation` plus docs |
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
2. Run the tests: `python3 -m pytest tests/` (all green before review; CI runs
   them on Python 3.9/3.12 across Linux and macOS).
3. Sanity-check the CLI end to end:
   `skill-discovery --path <some-skills-dir> --dry-run --print-json`.
4. Open a PR with a clear description of the behavior change.

## Developer Certificate of Origin

Commits must be signed off (`git commit -s`), certifying the
[DCO](https://developercertificate.org/): you wrote the change or otherwise
have the right to submit it under the Apache 2.0 license.
