"""PKG-04: --help output matches the golden baseline; TUI keybindings survived the cut."""

import inspect
import os
import re
import subprocess
import sys
from pathlib import Path

from waf_fu.tui import WafTUI

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = (
    REPO_ROOT / ".planning/phases/01-package-restructure-tooling/help-baseline.txt"
)
SRC_DIR = str(REPO_ROOT / "src")

# Keys documented in the original module docstring, now rendered by
# WafTUI._show_help's overlay table (each row: leading 2-space indent,
# key column, 2+ space gutter, description).
EXPECTED_KEYS = {
    "Up/Down",
    "PgUp / PgDn",
    "Home / End",
    "[ / ]",
    "Tab",
    "Shift+Tab",
    "Space",
    "a",
    "Enter",
    "e",
    "v",
    "m",
    "t",
    "b",
    "c",
    "w",
    "W",
    "o",
    "O",
    "f",
    "l",
    "r",
    "F",
    "S",
    "F5",
    "F2",
    "F3",
    "h / ?",
    "q",
}

ROW_PATTERN = re.compile(r'"\s{2}(\S.*?)\s{3,}\S')


def test_help_output_matches_golden_baseline():
    result = subprocess.run(
        [sys.executable, "-m", "waf_fu", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "COLUMNS": "100", "PYTHONPATH": SRC_DIR},
    )
    assert result.returncode == 0
    normalized = result.stdout.replace("usage: waf-fu ", "usage: PROG ", 1)
    expected = BASELINE_PATH.read_text()
    assert normalized == expected


def test_tui_keybinding_table_present():
    source = inspect.getsource(WafTUI._show_help)
    found_keys = set(ROW_PATTERN.findall(source))
    missing = EXPECTED_KEYS - found_keys
    assert not missing, f"keybindings missing from _show_help overlay: {missing}"


HEADINGS = ["AWS:", "System:", "Lookup & Filtering:", "Output:"]


def _grouped_help_output():
    result = subprocess.run(
        [sys.executable, "-m", "waf_fu", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "COLUMNS": "100", "PYTHONPATH": SRC_DIR},
    )
    assert result.returncode == 0
    return result.stdout


def test_help_has_five_headings_in_locked_order():
    output = _grouped_help_output()
    positions = [output.index(h) for h in HEADINGS]
    assert positions == sorted(positions), (
        f"headings out of order: {list(zip(HEADINGS, positions, strict=True))}"
    )


def test_help_has_no_bare_options_section():
    output = _grouped_help_output()
    assert not re.search(r"^options:$", output, re.MULTILINE), (
        "found a bare 'options:' section — a flag was added directly to the "
        "parser instead of to one of the five argument groups"
    )


def test_help_flags_land_in_expected_section():
    output = _grouped_help_output()
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        if line in HEADINGS:
            current = line[:-1]
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(line)

    def _section_of(flag: str) -> str | None:
        for name, lines in sections.items():
            if any(flag in line for line in lines):
                return name
        return None

    assert _section_of("--sqlite") == "System"
    assert _section_of("--export") == "Output"
    assert _section_of("--auth-count-sample") == "Lookup & Filtering"
