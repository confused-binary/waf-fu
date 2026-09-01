"""CLI-level coverage for argparse rejection of removed flags."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SRC_DIR = str(Path(__file__).resolve().parents[1] / "src")


def _run_subprocess(args, tmp_path):
    return subprocess.run(
        [sys.executable, "-m", "waf_fu", *args],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )


# ── Removed flags rejected by argparse ───────────────────────────────────


def test_log_counts_flag_rejected(tmp_path):
    result = _run_subprocess(["--log-counts", "x.json"], tmp_path)
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_lc_short_flag_rejected(tmp_path):
    result = _run_subprocess(["-lc", "x.json"], tmp_path)
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_scan_auth_counts_all_regions_flag_rejected(tmp_path):
    result = _run_subprocess(["--scan-auth-counts-all-regions"], tmp_path)
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_scan_auth_counts_flag_rejected(tmp_path):
    result = _run_subprocess(["--scan-auth-counts"], tmp_path)
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_scan_limit_flag_rejected(tmp_path):
    result = _run_subprocess(["--scan-limit", "10"], tmp_path)
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_log_prefix_flag_rejected(tmp_path):
    result = _run_subprocess(["--log-prefix", "/aws/foo"], tmp_path)
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_exclude_flag_rejected(tmp_path):
    result = _run_subprocess(["--exclude", "pattern"], tmp_path)
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


# ── --auth-count-sample / -ac accepted flags ─────────────────────────────


def test_auth_count_sample_flag_accepted(tmp_path):
    """--auth-count-sample is a recognized flag (does not produce 'unrecognized arguments')."""
    result = _run_subprocess(["--auth-count-sample", "--help"], tmp_path)
    # --help exits 0 regardless; the point is that argparse did not reject -ac
    assert result.returncode == 0
    assert "auth-count-sample" in result.stdout


def test_ac_short_flag_accepted(tmp_path):
    result = _run_subprocess(["-ac", "--help"], tmp_path)
    assert result.returncode == 0
