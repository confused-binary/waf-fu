"""A SQLite database created in the repository must be unstageable.

`waf-fu --sqlite ./logs.db` writes real client cookies, JWTs, authorization
headers and client IPs into that file, so losing the ignore rule is a data
handling failure, not a tidiness one.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
@pytest.mark.parametrize(
    "candidate",
    ["logs.db", "nested/dir/logs.db", "logs.db-wal", "logs.db-shm"],
)
def test_sqlite_artifacts_are_git_ignored(candidate):
    result = subprocess.run(
        ["git", "check-ignore", "-v", "--no-index", candidate],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"{candidate} is not ignored"
    assert ".gitignore" in result.stdout
