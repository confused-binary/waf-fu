"""PKG-03: console entry point resolves and executes without error."""

import os
import subprocess
import sys
from pathlib import Path

from waf_fu.cli import main

SRC_DIR = str(Path(__file__).resolve().parents[1] / "src")


def test_main_is_callable():
    assert callable(main)


def test_python_dash_m_waf_fu_help_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "waf_fu", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR},
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout
