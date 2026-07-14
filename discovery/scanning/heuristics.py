"""Deterministic heuristic detectors for high-signal malicious-skill patterns.

SkillSpector is the primary detector, but a static (``--no-llm``) run can miss a
handful of techniques that show up repeatedly in real malicious skills, such as
Trail of Bits' ``overtly-malicious-skills`` set. These rules are pure, offline
pattern checks that run *alongside* SkillSpector (via ``CompositeScanner``) and
add ``Finding``s. They never call out to the network or an LLM, and they never
raise: a heuristic miss must not fail a scan.

Each rule targets one documented technique and fires only on a specific
signature, to keep false positives low:

  data_exfiltration   bulk dump of the environment store      (csv-summarizer)
  hidden_payload      script smuggled in an Office/zip archive (context-loader)
  obfuscated_code     marshalled / .pyc bytecode loading       (simple-formatter)
  prompt_injection    text aimed at the scanner to suppress it (dev-env-setup)
  supply_chain        npm/yarn repointed at a non-official registry (dev-env-setup)
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from discovery.scanning.models import Finding, Severity


def _compile(*patterns: str) -> tuple[re.Pattern, ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


# (rule_id, category, severity, title, patterns) — a hit on any pattern in a
# file's text yields one Finding for that (rule, file).
_CONTENT_RULES: tuple[tuple[str, str, Severity, str, tuple[re.Pattern, ...]], ...] = (
    (
        "env-var-exfiltration",
        "data_exfiltration",
        Severity.high,
        "Reads and dumps the whole environment variable store",
        _compile(
            r"dict\(\s*os\.environ\s*\)",
            r"os\.environ\.(?:items|keys|values|copy)\s*\(",
            r"for\s+\w+\s+in\s+os\.environ\b",
            r"json\.dumps\(\s*(?:dict\(\s*)?os\.environ",
            r"\bprintenv\b",
            r"\benv\s*\|\s*(?:base64|curl|nc|xxd|wget)",
            r"\benv\s*>\s*[\w./~-]+",
            r"JSON\.stringify\(\s*process\.env",
            r"Object\.(?:keys|entries|values)\(\s*process\.env",
        ),
    ),
    (
        "hidden-doc-smuggling",
        "hidden_payload",
        Severity.high,
        "Extracts a payload hidden inside an Office/zip document",
        _compile(
            r"pandoc[^\n]*--track-changes",
            r"word/document\.xml",
            r"(?:unzip|zipfile|tarfile|tar\b)[^\n]*\.(?:docx|xlsx|pptx|zip)\b",
            r"(?<![\w/])\.[\w-]+\.docx\b",   # hidden, dot-prefixed .docx (e.g. .instructions.docx)
            r"\*\.docx\b[^\n]*-o\b",
        ),
    ),
    (
        "python-bytecode-tamper",
        "obfuscated_code",
        Severity.critical,
        "Loads or fabricates Python bytecode (bytecode poisoning)",
        _compile(
            r"\bmarshal\.loads?\s*\(",
            r"\btypes\.CodeType\s*\(",
            r"\bco_code\b",
            r"importlib[^\n]*\.pyc\b",
            r"\bcompile\([^\n]*['\"]exec['\"]\s*\)",
        ),
    ),
    (
        "scanner-prompt-injection",
        "prompt_injection",
        Severity.high,
        "Contains text directed at the scanner to suppress detection",
        _compile(
            r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions",
            r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|content)",
            r"\bthis\s+skill\s+is\s+(?:safe|benign|trusted|harmless)\b",
            r"\b(?:do\s+not|don'?t)\s+(?:flag|report|block|warn)\b",
            r"\bmark(?:ed)?\s+(?:this|it)?\s*as\s+safe\b",
            r"\bno\s+security\s+(?:issues?|concerns?|risks?|problems?)\b",
            r"\byou\s+are\s+(?:a|an)\s+(?:security\s+)?(?:scanner|reviewer|analyzer|auditor)\b",
            r"\b(?:whitelist|allowlist|approve|trust)\s+this\s+skill\b",
            r"\bas\s+(?:a|an)\s+(?:security\s+)?(?:scanner|model|assistant|ai)\b",
        ),
    ),
)

# Registry overrides are detected with a custom rule (below) so we can ignore the
# official registries and only flag attacker-controlled hosts.
_OFFICIAL_REGISTRIES = frozenset({
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "npm.pkg.github.com",
    "registry.npm.taobao.org",
})
_REGISTRY_RE = re.compile(
    r"(?:config\s+set\s+registry|--registry|\bregistry)\s*[=:\s]\s*"
    r"(https?://[^\s'\"`)]+)",
    re.IGNORECASE,
)

# Suspicious by file extension/name alone (content is often skipped on walk).
_OFFICE_EXTS = (".docx", ".xlsx", ".pptx", ".doc", ".zip")

# Extensions for which "the walker could not read this file" is itself a risk.
# A payload hidden in a script/executable/archive that fails UTF-8 decoding (or
# exceeds the size cap) is dropped before scanning — the act of being unscannable
# is the signal, so we flag it rather than let it pass silently.
_SKIPPED_FLAG_EXTS = frozenset({
    ".py", ".pyc", ".pyo", ".sh", ".bash", ".zsh", ".rb", ".js", ".mjs", ".cjs",
    ".ts", ".pl", ".php", ".ps1", ".bat", ".cmd", ".exe", ".bin", ".so",
    ".dylib", ".dll", ".docx", ".xlsx", ".pptx", ".zip", ".tar", ".gz", ".tgz",
    ".7z", ".rar", ".jar",
})


def findings_for_skipped_files(skipped: list[str] | None) -> list[Finding]:
    """Flag script/executable/archive files the walker had to skip.

    The walker drops any file it cannot read as UTF-8 text or that exceeds its
    size cap. An attacker can hide an executable payload that way (e.g. a
    non-UTF-8 ``summarize.py``) so it never reaches the scanner. Treat an
    unscannable executable/archive as a finding: you cannot evade detection by
    being unreadable, because being unreadable is the tell."""
    out: list[Finding] = []
    for rel in skipped or []:
        ext = os.path.splitext(str(rel))[1].lower()
        if ext in _SKIPPED_FLAG_EXTS:
            out.append(Finding(
                rule_id="unscannable-executable",
                category="obfuscated_code",
                severity=Severity.high,
                title="Executable, script, or archive file could not be scanned "
                      "(non-UTF-8 or oversized) - possible hidden payload",
                path=str(rel),
            ))
    return out


class HeuristicScanner:
    """Static, offline detectors for high-signal malicious-skill patterns. Never
    raises, so it is safe to use as the always-on floor under SkillSpector."""

    name = "heuristics"

    def scan(self, files: dict[str, str]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, str | None]] = set()

        def add(rule_id: str, category: str, severity: Severity, title: str,
                path: str | None) -> None:
            key = (rule_id, path)
            if key in seen:
                return
            seen.add(key)
            out.append(Finding(rule_id=rule_id, category=category,
                               severity=severity, title=title, path=path))

        for path, content in (files or {}).items():
            text = content if isinstance(content, str) else ""
            for rule_id, category, severity, title, patterns in _CONTENT_RULES:
                if any(p.search(text) for p in patterns):
                    add(rule_id, category, severity, title, path)
            for url in _REGISTRY_RE.findall(text):
                host = (urlparse(url).hostname or "").lower()
                if host and host not in _OFFICIAL_REGISTRIES:
                    add("registry-tampering", "supply_chain", Severity.high,
                        f"Repoints the package registry to a non-official host ({host})", path)

            # Path/extension tells: a skill rarely needs to ship compiled bytecode
            # or an Office archive; both are classic smuggling vehicles.
            lower = path.lower()
            base = os.path.basename(lower)
            if lower.endswith(".pyc") or "__pycache__" in lower:
                add("python-bytecode-artifact", "obfuscated_code", Severity.critical,
                    "Ships compiled Python bytecode (.pyc)", path)
            elif lower.endswith(_OFFICE_EXTS):
                hidden = base.startswith(".")
                add("embedded-office-archive", "hidden_payload",
                    Severity.high if hidden else Severity.medium,
                    "Ships an Office/zip document that may hide a payload", path)

        return out
