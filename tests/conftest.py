from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow running the tests without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery import scanning  # noqa: E402


def skill_md(name: str, description: str, body: str) -> str:
    return f"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n"


@pytest.fixture(autouse=True)
def _reset_scanner():
    yield
    scanning.set_scanner(None)
