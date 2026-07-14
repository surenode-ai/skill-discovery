"""Scanner abstraction + the SkillSpector output parser.

This tool does not implement deep detection itself. A ``Scanner`` produces
``Finding``s from a skill folder; the optional external backend shells out to
NVIDIA SkillSpector and parses its JSON/SARIF output via
``parse_skillspector_report``. The default ``NullScanner`` finds nothing, so
scanning is inert until a backend is wired in with ``set_scanner`` (normally
via ``discovery.scanning.configure_scanner``).
"""

from __future__ import annotations

from typing import Protocol

from discovery.scanning.models import Finding, Severity


class ScannerError(Exception):
    """The detection backend could not be run or produced unusable output.

    Defined here (rather than in the SkillSpector adapter) so that wrappers like
    ``CompositeScanner`` can reason about backend failures without importing a
    specific backend."""


class Scanner(Protocol):
    def scan(self, files: dict[str, str]) -> list[Finding]:
        """Return findings for a skill folder ({path: content})."""
        ...


class NullScanner:
    """No detection backend configured: finds nothing."""

    def scan(self, files: dict[str, str]) -> list[Finding]:  # noqa: ARG002
        return []


class CompositeScanner:
    """Run several scanners and union their findings.

    Resilient by design: a sub-scanner that raises ``ScannerError`` is skipped as
    long as at least one other scanner ran, so detection degrades to the
    remaining backends instead of failing open. Only if *every* sub-scanner
    errors does ``ScannerError`` propagate. Pair a never-failing
    ``HeuristicScanner`` with SkillSpector and a scan always has at least the
    heuristic floor, even if SkillSpector breaks.
    """

    def __init__(self, scanners: list[Scanner]) -> None:
        self._scanners = list(scanners)

    def scan(self, files: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        errors: list[str] = []
        ran = 0
        for s in self._scanners:
            try:
                findings.extend(s.scan(files) or [])
                ran += 1
            except ScannerError as exc:
                errors.append(str(exc))
        if ran == 0 and errors:
            raise ScannerError("; ".join(errors))
        return findings


_scanner: Scanner = NullScanner()


def get_scanner() -> Scanner:
    return _scanner


def set_scanner(scanner: Scanner | None) -> None:
    """Install the active scanner (a real backend in production, a fake in
    tests). None resets to the no-op NullScanner."""
    global _scanner
    _scanner = scanner or NullScanner()


def _norm_category(value: object) -> str:
    """Canonicalize a category to snake_case so labels match across scanners
    (e.g. 'Data Exfiltration' -> 'data_exfiltration')."""
    return str(value or "unknown").strip().lower().replace(" ", "_").replace("-", "_")


def parse_skillspector_report(report: dict) -> list[Finding]:
    """Parse a SkillSpector report into Findings. Accepts SkillSpector's native
    JSON (an ``issues`` list), a generic ``findings``/``results`` list, and SARIF
    (``runs[].results``). Defensive: unknown severities map to medium, malformed
    entries are skipped."""
    if not isinstance(report, dict):
        return []

    # SkillSpector native JSON: {"issues": [{"id","category","severity","location":{"file"}}]}
    if "issues" in report:
        out: list[Finding] = []
        for it in report.get("issues") or []:
            if not isinstance(it, dict):
                continue
            loc = it.get("location") if isinstance(it.get("location"), dict) else {}
            out.append(Finding(
                rule_id=str(it.get("id") or "unknown"),
                category=_norm_category(it.get("category") or it.get("id")),
                severity=Severity.parse(it.get("severity", "medium")),
                title=str(it.get("explanation") or it.get("finding") or it.get("remediation") or ""),
                path=(loc or {}).get("file"),
            ))
        return out

    # SARIF: {"runs": [{"results": [{"ruleId","level","message":{"text"},"locations":[...]}]}]}
    if "runs" in report:
        out: list[Finding] = []
        for run in report.get("runs") or []:
            for r in (run or {}).get("results") or []:
                if not isinstance(r, dict):
                    continue
                rule_id = str(r.get("ruleId") or r.get("rule", {}).get("id") or "unknown")
                msg = (r.get("message") or {}).get("text") if isinstance(r.get("message"), dict) else r.get("message")
                path = None
                locs = r.get("locations") or []
                if locs and isinstance(locs[0], dict):
                    path = ((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
                out.append(Finding(
                    rule_id=rule_id,
                    category=_norm_category(r.get("category") or rule_id),
                    severity=Severity.parse(r.get("level", "warning")),
                    title=str(msg or ""),
                    path=path,
                ))
        return out

    # Native JSON: {"findings": [...]} or {"results": [...]} or a bare list.
    items = report.get("findings")
    if items is None:
        items = report.get("results")
    if items is None:
        return []
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        rule_id = str(it.get("id") or it.get("rule_id") or it.get("ruleId") or "unknown")
        out.append(Finding(
            rule_id=rule_id,
            category=_norm_category(it.get("category") or it.get("type") or rule_id),
            severity=Severity.parse(it.get("severity", "medium")),
            title=str(it.get("title") or it.get("message") or it.get("description") or ""),
            path=it.get("path") or it.get("location") or it.get("file"),
        ))
    return out
