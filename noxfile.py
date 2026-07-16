"""Local test automation across every supported Python version.

Run ``nox`` to test on all of them (each interpreter must be installed, e.g. via
pyenv or uv), or ``nox -s tests-3.13`` for one. ``nox -s lint`` runs ruff. CI
mirrors these versions in GitHub Actions; this file is the local convenience and
the single list to update when a new Python ships. See CONTRIBUTING.md.
"""

import nox

# Every version the package claims to support (pyproject requires-python >=3.9).
# When a new Python is released, add it here, to the CI matrix, and to the
# pyproject classifiers.
PYTHON_VERSIONS = ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]

nox.options.reuse_existing_virtualenvs = True


@nox.session(python=PYTHON_VERSIONS)
def tests(session):
    """Install the package and run the test suite on the session's Python."""
    session.install(".", "pytest")
    session.run("python", "-m", "pytest", "tests/", "-q")


@nox.session(python="3.12")
def lint(session):
    """Lint with ruff (targets the minimum supported Python via pyproject)."""
    session.install("ruff")
    session.run("ruff", "check", "discovery", "tests", "noxfile.py")
