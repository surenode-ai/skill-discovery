# Security policy

## Reporting a vulnerability

Please do not open public issues for security problems.

Report privately via GitHub's private vulnerability reporting on this
repository (Security tab → "Report a vulnerability"), or email
security@surenode.ai. We aim to acknowledge reports within 3 business days.

## The security model in one paragraph

This tool reads **local skill folders**, runs **local detection**, and sends an
**inventory report** to the one server you configure. The shipped defaults are
privacy-first: `metadata_only` reports carry no skill content; secrets and PII
are pattern-redacted before any content upload; personal home paths are flagged,
and error text is scrubbed of usernames; `--dry-run` makes no network calls at
all. Skill folders are only ever read — nothing in a scanned folder is
executed, and the optional SkillSpector backend runs against a sanitized temp
copy with path-traversal-safe writes.

## Scope notes

- The agent makes exactly one kind of network call: the report POST to the
  configured server URL. Anything that changes that is a vulnerability.
- Anything that causes skill content to bypass sanitization on its way into a
  `full_skill` upload is a vulnerability, as is anything that lets a scanned
  skill folder influence what the agent executes (the walker must stay
  read-only; scanner temp-dir writes must stay inside their sandbox).
- Detection findings are best-effort observations. A rule missing a malicious
  pattern is a detection-quality issue, welcome as a normal issue/PR with a
  test sample; it is not a security vulnerability in this tool.
- Redaction is pattern-based and best-effort. New unambiguous secret formats
  that slip through are welcome as hardening PRs; targeted bypasses of an
  existing pattern are in scope as vulnerabilities.
