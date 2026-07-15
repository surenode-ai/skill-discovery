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


@pytest.fixture(autouse=True)
def _isolate_home(monkeypatch, tmp_path_factory):
    """Point $HOME at an empty temp dir for every test, so the default project
    auto-discovery (which walks the home directory) never touches the real one.
    Keeps the suite hermetic and fast; tests that pass --home override this."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Windows
    return home
