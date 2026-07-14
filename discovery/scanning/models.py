"""Data model for local skill-risk scanning.

Severity is ordered (IntEnum) so callers can compare findings with simple
comparisons. Categories are free-form strings because the detection taxonomy
belongs to the scanner (SkillSpector defines ~17) and evolves independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    info = 0
    low = 1
    medium = 2
    high = 3
    critical = 4

    @classmethod
    def parse(cls, value: object) -> "Severity":
        """Map scanner severity strings (incl. SARIF levels) to a Severity."""
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value) if value in (0, 1, 2, 3, 4) else cls.medium
        text = str(value or "").strip().lower()
        sarif = {"none": cls.info, "note": cls.low, "warning": cls.medium, "error": cls.high}
        if text in sarif:
            return sarif[text]
        try:
            return cls[text]
        except KeyError:
            return cls.medium  # unknown severity is treated as medium, never ignored


@dataclass(frozen=True)
class Finding:
    """One risk finding from the scanner."""

    rule_id: str
    category: str
    severity: Severity
    title: str = ""
    path: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", Severity.parse(self.severity))
