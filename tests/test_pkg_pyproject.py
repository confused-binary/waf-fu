"""PKG-02: pyproject.toml declares the console scripts, build backend, and version."""

import tomllib
from pathlib import Path

import waf_fu

PYPROJECT_PATH = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _load_pyproject() -> dict:
    with PYPROJECT_PATH.open("rb") as f:
        return tomllib.load(f)


def test_console_scripts_point_to_cli_main():
    data = _load_pyproject()
    scripts = data["project"]["scripts"]
    assert scripts["waf-fu"] == "waf_fu.cli:main"
    assert scripts["wfu"] == "waf_fu.cli:main"


def test_build_backend_requires_setuptools_68_or_newer():
    data = _load_pyproject()
    build_system = data["build-system"]
    assert any(
        req.startswith("setuptools>=") and int(req.split(">=")[1].split(".")[0]) >= 68
        for req in build_system["requires"]
    )
    assert build_system["build-backend"] == "setuptools.build_meta"


def test_package_version_is_0_1_1():
    data = _load_pyproject()
    assert data["project"]["version"] == "0.1.1"
    assert waf_fu.__version__ == "0.1.1"
