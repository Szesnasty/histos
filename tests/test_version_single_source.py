"""The version must have exactly one source of truth.

`gate_version` is stamped into every audit record, and an audit record exists to be
trusted about which build produced a decision. A distribution that says `0.2.0` while
the module still says `0.1.0` makes every record in the trail quietly wrong, and it
would drift on a release without anything failing. So `pyproject.toml` reads the
version from `histos._version` rather than repeating it.
"""

from __future__ import annotations

import tomllib
from importlib import metadata
from pathlib import Path

import histos
from histos._version import __version__

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _pyproject() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def test_pyproject_does_not_repeat_the_version():
    project = _pyproject()["project"]
    assert "version" not in project, "pyproject.toml pins a literal version; it must stay dynamic"
    assert "version" in project.get("dynamic", []), "`version` must be declared dynamic"


def test_pyproject_reads_the_version_from_the_module():
    dynamic = _pyproject()["tool"]["setuptools"]["dynamic"]
    assert dynamic["version"] == {"attr": "histos._version.__version__"}


def test_the_package_exports_the_same_version_it_stamps():
    assert histos.__version__ == __version__


def test_the_installed_distribution_agrees_with_the_module():
    """Catches the drift itself, not just the configuration that prevents it.

    Skipped when histos is not installed at all (a bare `pythonpath = ["src"]` run),
    because then there is no distribution to disagree with.
    """
    try:
        installed = metadata.version("histos")
    except metadata.PackageNotFoundError:  # pragma: no cover - depends on the checkout
        return
    assert installed == __version__, f"distribution is {installed}, module is {__version__}"
