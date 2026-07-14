"""Local skill-risk detection for the discovery agent.

Detection is pluggable (see ``scanner``). The built-in ``HeuristicScanner``
(high-signal malicious-skill patterns) runs as an always-on floor; NVIDIA
SkillSpector is used in addition when it is installed on the endpoint. The
findings are observations attached to the inventory report — this package
renders no allow/block judgment; that belongs to the governance server that
ingests the reports.
"""

from discovery.scanning.heuristics import HeuristicScanner, findings_for_skipped_files
from discovery.scanning.llm_scanner import LLMScanner
from discovery.scanning.models import Finding, Severity
from discovery.scanning.scanner import (
    CompositeScanner,
    NullScanner,
    Scanner,
    ScannerError,
    get_scanner,
    parse_skillspector_report,
    set_scanner,
)
from discovery.scanning.skillspector import SkillSpectorScanner


def configure_scanner(backend: str = "auto") -> str:
    """Install the detection backend and return its name. The built-in
    ``HeuristicScanner`` runs as an always-on floor unless scanning is
    explicitly disabled:

    - 'none'        -> NullScanner (scanning fully off).
    - 'heuristics'  -> the built-in heuristic rules alone.
    - 'skillspector'-> SkillSpector + heuristics (error if SkillSpector missing).
    - 'auto'        -> SkillSpector + heuristics if installed, else heuristics
                       alone. Scanning is therefore never silently inert: even
                       without SkillSpector installed, the heuristic floor runs.
    """
    if backend == "none":
        set_scanner(None)
        return "none"
    heuristics = HeuristicScanner()
    if backend == "heuristics":
        set_scanner(heuristics)
        return "heuristics"
    ss = SkillSpectorScanner()
    if backend == "skillspector" and not ss.available():
        raise ScannerError("scanning backend 'skillspector' requested but "
                           "skillspector is not installed.")

    scanners = [heuristics]
    name = "heuristics"
    if ss.available():  # both 'skillspector' and 'auto' use it when present
        scanners.append(ss)
        name = "skillspector+heuristics"

    set_scanner(scanners[0] if len(scanners) == 1 else CompositeScanner(scanners))
    return name


__all__ = [
    "Finding",
    "Severity",
    "NullScanner",
    "CompositeScanner",
    "HeuristicScanner",
    "LLMScanner",
    "findings_for_skipped_files",
    "Scanner",
    "get_scanner",
    "parse_skillspector_report",
    "set_scanner",
    "ScannerError",
    "SkillSpectorScanner",
    "configure_scanner",
]
