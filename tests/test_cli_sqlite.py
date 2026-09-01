"""CLI-level coverage for --sqlite/--refresh: argparse truth table plus
cache decisions proven by counting CloudWatch calls through the CLI's load
branch, not by trusting them.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from waf_fu import cli as cli_module
from waf_fu import storage
from waf_fu.cli import main

SRC_DIR = str(Path(__file__).resolve().parents[1] / "src")

WINDOW_START = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
WINDOW_MID = datetime(2026, 1, 1, 1, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 1, 1, 2, 0, tzinfo=UTC)


class RecordingFetch:
    """Stands in for `fetch_logs_from_cloudwatch`. Records the exact
    (start_time, end_time) datetimes it was called with, and synthesizes one
    record per call whose timestamp is derived from the call's own window so
    gap-fill tests can tell which sub-ranges actually produced records."""

    def __init__(self, waf_record):
        self.calls: list[tuple[datetime, datetime]] = []
        self._waf_record = waf_record

    def __call__(
        self,
        *,
        log_group,
        start_time,
        end_time,
        profile=None,
        region=None,
        action_filter=None,
    ):
        self.calls.append((start_time, end_time))
        ts_ms = int(start_time.timestamp() * 1000) + 1
        return [self._waf_record(timestamp=ts_ms)]


class _RecordedOpenDbPath(Exception):
    """Sentinel raised by a fake `open_db` so a test can inspect the path it
    was given without letting execution continue into the TUI/curses."""

    def __init__(self, path):
        super().__init__(path)
        self.path = path


def _run(monkeypatch, argv, fetch):
    monkeypatch.setattr(sys, "argv", ["waf-fu", *argv])
    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", fetch)
    main()


# ── Argument parsing ─────────────────────────────────────────────────────


def test_file_flag_rejected_by_argparse(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "waf_fu", "--file", "x.json"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_sqlite_omitted_resolves_to_default_path(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["waf-fu"])

    def _fake_open_db(path):
        raise _RecordedOpenDbPath(path)

    monkeypatch.setattr("waf_fu.cli.storage.open_db", _fake_open_db)
    with pytest.raises(_RecordedOpenDbPath) as exc_info:
        main()
    assert exc_info.value.path == storage.DEFAULT_DB_PATH


def test_sqlite_explicit_path_resolves_exactly(monkeypatch, tmp_path):
    target = str(tmp_path / "custom" / "y.db")
    monkeypatch.setattr(sys, "argv", ["waf-fu", "--sqlite", target])

    def _fake_open_db(path):
        raise _RecordedOpenDbPath(path)

    monkeypatch.setattr("waf_fu.cli.storage.open_db", _fake_open_db)
    with pytest.raises(_RecordedOpenDbPath) as exc_info:
        main()
    assert exc_info.value.path == target


def test_replay_and_no_auth_filter_rejected_by_argparse(tmp_path):
    for argv in (["--replay", "chrome"], ["--no-auth-filter"]):
        result = subprocess.run(
            [sys.executable, "-m", "waf_fu", *argv],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
        )
        assert result.returncode != 0
        assert "unrecognized arguments" in result.stderr


def test_initial_mode_defaults_to_firefox_when_no_preference(tmp_path, monkeypatch):
    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["waf-fu", "--sqlite", str(tmp_path / "logs.db")])

    main()

    assert captured["tui"].mode == "firefox"


def test_initial_mode_reads_stored_preference(tmp_path, monkeypatch):
    db_path = tmp_path / "logs.db"
    conn = storage.open_db(str(db_path))
    storage.set_preference(conn, "replay_mode", "curl")
    conn.close()

    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["waf-fu", "--sqlite", str(db_path)])

    main()

    assert captured["tui"].mode == "curl"


def test_auth_filter_preference_off_disables_default(tmp_path, monkeypatch):
    db_path = tmp_path / "logs.db"
    conn = storage.open_db(str(db_path))
    storage.set_preference(conn, "auth_filter", "off")
    conn.close()

    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["waf-fu", "--sqlite", str(db_path)])

    main()

    assert captured["tui"].auth_filter is False


def test_auth_filter_preference_on_still_downgrades_with_zero_auth_entries(
    tmp_path, monkeypatch, waf_record, capsys
):
    db_path = tmp_path / "logs.db"
    conn = storage.open_db(str(db_path))
    storage.set_preference(conn, "auth_filter", "on")
    conn.close()

    def fetch(**kwargs):
        return [waf_record(timestamp=int(WINDOW_START.timestamp() * 1000) + 1)]

    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", fetch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "waf-fu",
            "--sqlite",
            str(db_path),
            "--log-group",
            "test-group",
            "--start",
            WINDOW_START.isoformat(),
            "--end",
            WINDOW_MID.isoformat(),
        ],
    )

    main()

    assert captured["tui"].auth_filter is False
    assert "no entries have replayable auth data" in capsys.readouterr().err


def test_refresh_alone_without_sqlite_does_not_error(tmp_path, monkeypatch, waf_record):
    out_file = tmp_path / "out.json"
    db_path = tmp_path / "logs.db"
    fetch = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        [
            "--log-group",
            "test-group",
            "--sqlite",
            str(db_path),
            "--refresh",
            "--mode",
            "batch-json",
            "--output",
            str(out_file),
        ],
        fetch,
    )
    assert out_file.exists()
    assert len(json.loads(out_file.read_text())) == 1


# ── Cache behaviour (DB-03) ──────────────────────────────────────────────


def _batch_argv(db_path, out_path, start, end, refresh=False):
    argv = [
        "--sqlite",
        str(db_path),
        "--log-group",
        "test-group",
        "--start",
        start.isoformat(),
        "--end",
        end.isoformat(),
        "--mode",
        "batch-json",
        "--output",
        str(out_path),
    ]
    if refresh:
        argv.append("--refresh")
    return argv


def test_cache_hit_makes_zero_cloudwatch_calls(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out1 = tmp_path / "out1.json"
    out2 = tmp_path / "out2.json"

    fetch1 = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        _batch_argv(db_path, out1, WINDOW_START, WINDOW_MID),
        fetch1,
    )
    assert len(fetch1.calls) == 1
    first_count = len(json.loads(out1.read_text()))
    assert first_count == 1

    fetch2 = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        _batch_argv(db_path, out2, WINDOW_START, WINDOW_MID),
        fetch2,
    )
    assert fetch2.calls == []
    second_count = len(json.loads(out2.read_text()))
    assert second_count == first_count


def test_gap_fill_requests_only_uncovered_subrange(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out1 = tmp_path / "out1.json"
    out2 = tmp_path / "out2.json"

    fetch1 = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        _batch_argv(db_path, out1, WINDOW_START, WINDOW_MID),
        fetch1,
    )
    assert len(fetch1.calls) == 1

    fetch2 = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        _batch_argv(db_path, out2, WINDOW_START, WINDOW_END),
        fetch2,
    )
    assert fetch2.calls == [(WINDOW_MID, WINDOW_END)]
    second_count = len(json.loads(out2.read_text()))
    assert second_count == 2


def test_refresh_requests_whole_window_dedup_keeps_count(
    tmp_path, monkeypatch, waf_record
):
    db_path = tmp_path / "logs.db"
    out1 = tmp_path / "out1.json"
    out2 = tmp_path / "out2.json"

    fetch1 = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        _batch_argv(db_path, out1, WINDOW_START, WINDOW_MID),
        fetch1,
    )
    assert len(fetch1.calls) == 1
    first_count = len(json.loads(out1.read_text()))
    assert first_count == 1

    fetch2 = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        _batch_argv(db_path, out2, WINDOW_START, WINDOW_MID, refresh=True),
        fetch2,
    )
    assert fetch2.calls == [(WINDOW_START, WINDOW_MID)]
    second_count = len(json.loads(out2.read_text()))
    assert second_count == first_count


# ── TUI handoff and connection lifetime (DB-01) ──────────────────────────


def _capture_tui(monkeypatch):
    """Replace curses.wrapper with a no-op that captures the WafTUI whose
    bound `run` method it was handed, so the TUI paths can be driven without
    a terminal."""
    captured = {}

    def fake_wrapper(func, *args, **kwargs):
        captured["tui"] = func.__self__
        return []

    monkeypatch.setattr("waf_fu.cli.curses.wrapper", fake_wrapper)
    return captured


def test_sqlite_without_log_group_opens_selector_with_db(tmp_path, monkeypatch):
    """The offline-browse entry point: no --log-group means the TUI must open
    its log-group selector, and it can only offer the database's groups if the
    handle actually reached it."""
    db_path = tmp_path / "logs.db"
    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["waf-fu", "--sqlite", str(db_path)])

    main()

    tui = captured["tui"]
    assert tui.db is not None
    assert tui._needs_log_selection is True
    assert db_path.exists()


def test_no_source_tui_path_closes_db_connection(tmp_path, monkeypatch):
    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["waf-fu", "--sqlite", str(tmp_path / "logs.db")])

    main()

    with pytest.raises(sqlite3.ProgrammingError):
        captured["tui"].db.execute("SELECT 1")


def test_tui_path_closes_db_connection(tmp_path, monkeypatch, waf_record):
    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr(
        "waf_fu.cli.fetch_logs_from_cloudwatch", RecordingFetch(waf_record)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "waf-fu",
            "--sqlite",
            str(tmp_path / "logs.db"),
            "--log-group",
            "test-group",
            "--start",
            WINDOW_START.isoformat(),
            "--end",
            WINDOW_MID.isoformat(),
        ],
    )

    main()

    with pytest.raises(sqlite3.ProgrammingError):
        captured["tui"].db.execute("SELECT 1")


def test_batch_mode_closes_db_connection(tmp_path, monkeypatch, waf_record):
    opened = []
    real_open_db = storage.open_db

    def spy_open_db(path):
        conn = real_open_db(path)
        opened.append(conn)
        return conn

    monkeypatch.setattr("waf_fu.cli.storage.open_db", spy_open_db)
    _run(
        monkeypatch,
        _batch_argv(
            tmp_path / "logs.db", tmp_path / "out.json", WINDOW_START, WINDOW_MID
        ),
        RecordingFetch(waf_record),
    )

    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")


# ── Auth-count upsert on load (CLI-02) ───────────────────────────────────


def _mixed_auth_fetch(waf_record, n_auth, n_plain):
    """Returns a fetch_fn producing `n_auth` cookie-bearing records followed
    by `n_plain` auth-free records, each with a unique in-window timestamp."""
    base_ms = int(WINDOW_START.timestamp() * 1000) + 1

    def _fetch(**kwargs):
        records = []
        for i in range(n_auth):
            records.append(
                waf_record(
                    timestamp=base_ms + i, cookies="session=abc", uri=f"/auth{i}"
                )
            )
        for i in range(n_plain):
            records.append(waf_record(timestamp=base_ms + n_auth + i, uri=f"/plain{i}"))
        return records

    return _fetch


def test_load_writes_auth_counts_row(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    _run(
        monkeypatch,
        _batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
        _mixed_auth_fetch(waf_record, 2, 3),
    )

    conn = storage.open_db(str(db_path))
    try:
        assert storage.get_auth_count(conn, None, None, "test-group") == (2, 5)
    finally:
        conn.close()


def test_auth_counts_keyed_by_profile(tmp_path, monkeypatch, waf_record):
    """A second run with a different --profile must not overwrite the first
    profile's row -- both must be independently readable afterwards. (The
    second run's window is fully cache-covered from the first run regardless
    of profile, since fetch_log coverage isn't profile-scoped, so both runs
    see the same 5 cached records and thus the same (2, 5) counts -- what
    this test actually proves is that both profile keys resolve to a row at
    all, i.e. neither run's upsert clobbered the other's key.)"""
    db_path = tmp_path / "logs.db"
    out1 = tmp_path / "out1.json"
    out2 = tmp_path / "out2.json"

    argv1 = _batch_argv(db_path, out1, WINDOW_START, WINDOW_MID)
    _run(monkeypatch, argv1, _mixed_auth_fetch(waf_record, 2, 3))

    argv2 = [
        "--profile",
        "other",
        *_batch_argv(db_path, out2, WINDOW_START, WINDOW_MID),
    ]
    _run(monkeypatch, argv2, _mixed_auth_fetch(waf_record, 1, 0))

    conn = storage.open_db(str(db_path))
    try:
        assert storage.get_auth_count(conn, None, None, "test-group") == (2, 5)
        assert storage.get_auth_count(conn, "other", None, "test-group") == (2, 5)
        row_count = conn.execute(
            "SELECT COUNT(*) FROM auth_counts WHERE log_group = ?", ("test-group",)
        ).fetchone()[0]
        assert row_count == 2
    finally:
        conn.close()


def test_cache_hit_still_refreshes_auth_counts(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out1 = tmp_path / "out1.json"
    out2 = tmp_path / "out2.json"

    _run(
        monkeypatch,
        _batch_argv(db_path, out1, WINDOW_START, WINDOW_MID),
        _mixed_auth_fetch(waf_record, 2, 3),
    )

    fetch2 = RecordingFetch(waf_record)
    _run(
        monkeypatch,
        _batch_argv(db_path, out2, WINDOW_START, WINDOW_MID),
        fetch2,
    )
    assert fetch2.calls == []

    conn = storage.open_db(str(db_path))
    try:
        counts = storage.get_auth_count(conn, None, None, "test-group")
    finally:
        conn.close()
    assert counts == (2, 5)


def test_auth_counts_upserted_in_batch_mode(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    _run(
        monkeypatch,
        _batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
        _mixed_auth_fetch(waf_record, 2, 3),
    )

    conn = storage.open_db(str(db_path))
    try:
        counts = storage.get_auth_count(conn, None, None, "test-group")
    finally:
        conn.close()
    assert counts == (2, 5)


# ── Multi-source flags: --log-location and --inventory (SRC-07, SRC-08) ──

ACL_ARN = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/demo-acl/abc-123"
ACL_SUMMARY = {"Name": "demo-acl", "Id": "abc-123", "ARN": ACL_ARN}
TS_MS = int(WINDOW_START.timestamp() * 1000) + 1


class _Recorder:
    """Stands in for one AWS call, counting invocations and replaying a canned
    result. Counting (rather than raising) is what lets the `--log-location X
    makes no Y calls` tests assert an absence, since `load_source_with_cache`
    swallows anything a fetch_fn raises."""

    def __init__(self, result=None):
        self.calls: list[tuple] = []
        self._result = [] if result is None else result

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return list(self._result)


def _sampled_record(uri="/pay", authorization="Bearer real-token"):
    """A GetSampledRequests record as `waf_api` stores it: API-native
    {Name, Value} header casing, and never a body."""
    return {
        "timestamp": TS_MS,
        "action": "ALLOW",
        "httpRequest": {
            "httpMethod": "GET",
            "uri": uri,
            "args": "",
            "httpVersion": "HTTP/2",
            "clientIp": "203.0.113.7",
            "country": "US",
            "headers": [{"Name": "Authorization", "Value": authorization}],
            "requestBody": "",
            "requestBodySize": 0,
        },
    }


def _redacted_cwl_fetch(waf_record):
    def _fetch(**kwargs):
        return [
            waf_record(
                timestamp=TS_MS,
                uri="/pay",
                headers={"Authorization": "REDACTED"},
                body="amount=1",
            )
        ]

    return _fetch


def _cache_acl_mapping(db_path, log_group="test-group", s3_bucket=None):
    conn = storage.open_db(str(db_path))
    try:
        storage.upsert_acl_mapping(
            conn, ACL_ARN, "demo-acl", "us-east-1", None, log_group, s3_bucket
        )
    finally:
        conn.close()


def _capture_args(monkeypatch, target):
    """Wrap a cli entry point so a test can read the parsed Namespace it got."""
    captured = {}
    original = getattr(cli_module, target)

    def spy(*args, **kwargs):
        captured["args"] = next(a for a in args if isinstance(a, argparse.Namespace))
        return original(*args, **kwargs)

    monkeypatch.setattr(f"waf_fu.cli.{target}", spy)
    return captured


def test_log_location_flag_parsed(tmp_path, monkeypatch, waf_record):
    captured = _capture_args(monkeypatch, "_load_records")
    _run(
        monkeypatch,
        [
            *_batch_argv(
                tmp_path / "logs.db", tmp_path / "out.json", WINDOW_START, WINDOW_MID
            ),
            "--log-location",
            "cwl",
        ],
        RecordingFetch(waf_record),
    )
    assert captured["args"].log_location == "cwl"


def test_log_location_rejects_unknown_choice(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "waf_fu", "--log-location", "firehose"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )
    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_log_location_accepts_every_documented_choice(tmp_path):
    for log_location in ("cwl", "s3", "waf"):
        result = subprocess.run(
            [sys.executable, "-m", "waf_fu", "--log-location", log_location, "--help"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
        )
        assert result.returncode == 0, log_location


def test_inventory_flag_parsed(tmp_path, monkeypatch):
    captured = _capture_args(monkeypatch, "_run_auto_inventory")
    monkeypatch.setattr("waf_fu.cli._all_wafv2_regions", lambda profile: [])
    monkeypatch.setattr("waf_fu.cli.s3_mod.discover_waf_buckets", _Recorder())
    monkeypatch.setattr(
        sys,
        "argv",
        ["waf-fu", "--sqlite", str(tmp_path / "logs.db"), "--inventory"],
    )

    main()

    assert captured["args"].inventory is True


def test_inventory_takes_precedence_over_log_location(tmp_path, monkeypatch):
    """Both flags together is not an argparse error: --inventory is a
    terminal branch that wins, so the --log-location load path never runs."""
    inventory = _Recorder()
    load = _Recorder()
    monkeypatch.setattr("waf_fu.cli._run_auto_inventory", inventory)
    monkeypatch.setattr("waf_fu.cli._load_records", load)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "waf-fu",
            "--sqlite",
            str(tmp_path / "logs.db"),
            "--inventory",
            "--log-location",
            "s3",
        ],
    )

    main()

    assert len(inventory.calls) == 1
    assert load.calls == []


def test_log_location_cwl_makes_no_s3_or_waf_calls(tmp_path, monkeypatch, waf_record):
    """A cached ACL mapping exists, so the default path *would* sample;
    --log-location cwl must suppress that and leave the redacted CloudWatch
    value in place."""
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    _cache_acl_mapping(db_path, s3_bucket="aws-waf-logs-demo")

    samples = _Recorder([_sampled_record()])
    s3_fetch = _Recorder()
    monkeypatch.setattr("waf_fu.cli.waf_api.fetch_all_sampled_for_acl", samples)
    monkeypatch.setattr("waf_fu.cli.s3_mod.fetch_logs_from_s3", s3_fetch)

    _run(
        monkeypatch,
        [
            *_batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
            "--log-location",
            "cwl",
        ],
        _redacted_cwl_fetch(waf_record),
    )

    assert samples.calls == []
    assert s3_fetch.calls == []
    assert json.loads(out_file.read_text())[0]["headers"]["Authorization"] == "REDACTED"


def test_log_location_s3_reads_s3_only_and_parses_bucket_acl(
    tmp_path, monkeypatch, waf_record
):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"

    s3_fetch = _Recorder([waf_record(timestamp=TS_MS, uri="/from-s3")])
    cwl_fetch = _Recorder()
    samples = _Recorder([_sampled_record()])
    monkeypatch.setattr("waf_fu.cli.s3_mod.fetch_logs_from_s3", s3_fetch)
    monkeypatch.setattr("waf_fu.cli.waf_api.fetch_all_sampled_for_acl", samples)

    _run(
        monkeypatch,
        [
            *_batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
            "--log-location",
            "s3",
            "--log-group",
            "aws-waf-logs-demo:demo-acl",
        ],
        cwl_fetch,
    )

    assert cwl_fetch.calls == []
    assert samples.calls == []
    assert s3_fetch.calls[0][1]["bucket"] == "aws-waf-logs-demo"
    assert s3_fetch.calls[0][1]["acl_name"] == "demo-acl"
    assert json.loads(out_file.read_text())[0]["url"].endswith("/from-s3")

    conn = storage.open_db(str(db_path))
    try:
        assert storage.load_source_records(conn, "cwl", "test-group", 0, 2**62) == []
    finally:
        conn.close()


def test_log_location_waf_reads_sampling_api_only(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"

    cwl_fetch = _Recorder()
    samples = _Recorder([_sampled_record()])
    monkeypatch.setattr("waf_fu.cli.waf_api.list_web_acls", _Recorder([ACL_SUMMARY]))
    monkeypatch.setattr(
        "waf_fu.cli.waf_api.get_logging_configuration",
        lambda *a, **k: {"log_group": "test-group", "s3_bucket": None},
    )
    monkeypatch.setattr("waf_fu.cli.waf_api.fetch_all_sampled_for_acl", samples)

    _run(
        monkeypatch,
        [
            *_batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
            "--log-location",
            "waf",
            "--log-group",
            "demo-acl",
        ],
        cwl_fetch,
    )

    assert cwl_fetch.calls == []
    assert len(samples.calls) == 1
    entry = json.loads(out_file.read_text())[0]
    # Proves the API-native {Name, Value} casing was normalized: this path skips
    # the merge, which is where that normalization otherwise happens.
    assert entry["headers"]["Authorization"] == "Bearer real-token"


def test_default_run_merges_unredacted_sample_over_cwl(
    tmp_path, monkeypatch, waf_record
):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    _cache_acl_mapping(db_path)

    samples = _Recorder([_sampled_record()])
    monkeypatch.setattr("waf_fu.cli.waf_api.fetch_all_sampled_for_acl", samples)

    _run(
        monkeypatch,
        _batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
        _redacted_cwl_fetch(waf_record),
    )

    assert len(samples.calls) == 1
    entry = json.loads(out_file.read_text())[0]
    assert entry["headers"]["Authorization"] == "Bearer real-token"
    # Sampled requests carry no body, so the body must still come from CWL.
    assert entry["body"] == "amount=1"

    conn = storage.open_db(str(db_path))
    try:
        merged = storage.load_merged_records(conn, "test-group", 0, 2**62)
    finally:
        conn.close()
    assert merged[0]["_sources"] == "cwl,waf"


def test_default_run_without_acl_mapping_serves_plain_cwl(
    tmp_path, monkeypatch, waf_record
):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"

    samples = _Recorder([_sampled_record()])
    monkeypatch.setattr("waf_fu.cli.waf_api.fetch_all_sampled_for_acl", samples)

    _run(
        monkeypatch,
        _batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
        _redacted_cwl_fetch(waf_record),
    )

    assert samples.calls == []
    assert json.loads(out_file.read_text())[0]["headers"]["Authorization"] == "REDACTED"


def test_default_run_survives_waf_access_denied(tmp_path, monkeypatch, waf_record):
    """A CloudWatch-only operator must still get their logs when wafv2 is denied."""
    from botocore.exceptions import ClientError

    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    _cache_acl_mapping(db_path)

    def _denied(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
            "GetWebACL",
        )

    monkeypatch.setattr("waf_fu.cli.waf_api.fetch_all_sampled_for_acl", _denied)

    _run(
        monkeypatch,
        _batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID),
        _redacted_cwl_fetch(waf_record),
    )

    assert json.loads(out_file.read_text())[0]["headers"]["Authorization"] == "REDACTED"


def test_inventory_discovers_caches_and_merges(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"

    monkeypatch.setattr("waf_fu.cli._all_wafv2_regions", lambda profile: ["us-east-1"])
    monkeypatch.setattr(
        "waf_fu.auth_sample.fetch_waf_log_groups", lambda **kwargs: ["test-group"]
    )
    monkeypatch.setattr(
        "waf_fu.cli.waf_api.list_web_acls", lambda **kwargs: [ACL_SUMMARY]
    )
    monkeypatch.setattr(
        "waf_fu.cli.waf_api.get_logging_configuration",
        lambda *a, **k: {"log_group": "test-group", "s3_bucket": "aws-waf-logs-demo"},
    )
    monkeypatch.setattr(
        "waf_fu.cli.waf_api.fetch_all_sampled_for_acl",
        _Recorder([_sampled_record()]),
    )
    monkeypatch.setattr(
        "waf_fu.cli.s3_mod.discover_waf_buckets", lambda **kw: ["aws-waf-logs-demo"]
    )
    s3_fetch = _Recorder()
    monkeypatch.setattr("waf_fu.cli.s3_mod.fetch_logs_from_s3", s3_fetch)

    _run(
        monkeypatch,
        [
            "--sqlite",
            str(db_path),
            "--inventory",
            "--start",
            WINDOW_START.isoformat(),
            "--end",
            WINDOW_MID.isoformat(),
        ],
        _redacted_cwl_fetch(waf_record),
    )

    conn = storage.open_db(str(db_path))
    try:
        # The ACL mapping cache is refreshed by the scan itself.
        mapping = storage.get_acl_mapping_for_log_group(conn, "test-group")
        assert mapping["acl_arn"] == ACL_ARN
        assert mapping["s3_bucket"] == "aws-waf-logs-demo"

        merged = storage.load_merged_records(conn, "test-group", 0, 2**62)
        assert merged[0]["_sources"] == "cwl,waf"
    finally:
        conn.close()

    # The bucket's rows are filed under the ACL's log group, not the bucket name,
    # so the merge correlates them with that group's CloudWatch rows.
    assert s3_fetch.calls[0][1]["bucket"] == "aws-waf-logs-demo"


def test_inventory_survives_denied_s3_and_waf(tmp_path, monkeypatch, waf_record):
    from botocore.exceptions import ClientError

    db_path = tmp_path / "logs.db"

    def _denied(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListBuckets"
        )

    monkeypatch.setattr("waf_fu.cli._all_wafv2_regions", lambda profile: ["us-east-1"])
    monkeypatch.setattr(
        "waf_fu.auth_sample.fetch_waf_log_groups", lambda **kwargs: ["test-group"]
    )
    monkeypatch.setattr("waf_fu.cli.waf_api.list_web_acls", _denied)
    monkeypatch.setattr("waf_fu.cli.s3_mod.discover_waf_buckets", _denied)

    _run(
        monkeypatch,
        [
            "--sqlite",
            str(db_path),
            "--inventory",
            "--start",
            WINDOW_START.isoformat(),
            "--end",
            WINDOW_MID.isoformat(),
        ],
        _redacted_cwl_fetch(waf_record),
    )

    conn = storage.open_db(str(db_path))
    try:
        assert (
            len(storage.load_source_records(conn, "cwl", "test-group", 0, 2**62)) == 1
        )
    finally:
        conn.close()


# ── --s3-bucket and --db-only (SC 7, SC 8, SC 19) ────────────────────────


def _seed_source_records(db_path, source, log_group, records):
    conn = storage.open_db(str(db_path))
    try:
        storage.save_source_records(conn, source, log_group, records)
    finally:
        conn.close()


def test_s3_bucket_flag_implies_log_location_and_routes_to_s3(
    tmp_path, monkeypatch, waf_record
):
    captured = _capture_args(monkeypatch, "_load_records")
    s3_fetch = _Recorder([waf_record(timestamp=TS_MS, uri="/from-s3")])
    monkeypatch.setattr("waf_fu.cli.s3_mod.fetch_logs_from_s3", s3_fetch)

    out_file = tmp_path / "out.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "waf-fu",
            "--sqlite",
            str(tmp_path / "logs.db"),
            "--s3-bucket",
            "my-bucket",
            "--start",
            WINDOW_START.isoformat(),
            "--end",
            WINDOW_MID.isoformat(),
            "--mode",
            "batch-json",
            "--output",
            str(out_file),
        ],
    )

    main()

    assert captured["args"].s3_bucket == "my-bucket"
    assert captured["args"].log_location == "s3"
    assert captured["args"].log_group == "my-bucket"
    assert s3_fetch.calls[0][1]["bucket"] == "my-bucket"
    assert json.loads(out_file.read_text())[0]["url"].endswith("/from-s3")


def test_s3_bucket_mutual_exclusion_with_log_group(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "waf_fu", "--log-group", "X", "--s3-bucket", "Y"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )
    assert result.returncode != 0
    assert "not allowed with argument -lg/--log-group" in result.stderr


def test_s3_bucket_rejects_conflicting_log_location(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "waf_fu",
            "--s3-bucket",
            "my-bucket",
            "--log-location",
            "cwl",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )
    assert result.returncode != 0
    assert "--s3-bucket implies --log-location s3" in result.stderr


def test_db_only_flag_parsed_and_skips_cloudwatch_fetch(
    tmp_path, monkeypatch, waf_record
):
    db_path = tmp_path / "logs.db"
    _seed_source_records(db_path, "cwl", "test-group", [waf_record(timestamp=TS_MS)])
    captured = _capture_args(monkeypatch, "_load_db_only_records")
    cwl_fetch = _Recorder()
    out_file = tmp_path / "out.json"

    _run(
        monkeypatch,
        [*_batch_argv(db_path, out_file, WINDOW_START, WINDOW_MID), "--db-only"],
        cwl_fetch,
    )

    assert captured["args"].db_only is True
    assert cwl_fetch.calls == []
    assert len(json.loads(out_file.read_text())) == 1


def test_db_only_missing_db_errors(tmp_path):
    missing_db = tmp_path / "does-not-exist" / "logs.db"
    result = subprocess.run(
        [sys.executable, "-m", "waf_fu", "--db-only", "--sqlite", str(missing_db)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )
    assert result.returncode != 0
    assert "database not found" in result.stderr


def test_db_only_with_no_time_range_loads_all_cached_records(tmp_path, waf_record):
    db_path = tmp_path / "logs.db"
    old_ts = int(WINDOW_START.timestamp() * 1000) + 1
    _seed_source_records(db_path, "cwl", "test-group", [waf_record(timestamp=old_ts)])
    out_file = tmp_path / "out.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "waf_fu",
            "--sqlite",
            str(db_path),
            "--log-group",
            "test-group",
            "--db-only",
            "--mode",
            "batch-json",
            "--output",
            str(out_file),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )

    assert result.returncode == 0, result.stderr
    assert len(json.loads(out_file.read_text())) == 1


def test_db_only_with_explicit_time_range_only_loads_that_range(tmp_path, waf_record):
    db_path = tmp_path / "logs.db"
    in_window = int(WINDOW_START.timestamp() * 1000) + 1
    outside_window = int(WINDOW_END.timestamp() * 1000) + 1
    _seed_source_records(
        db_path,
        "cwl",
        "test-group",
        [
            waf_record(timestamp=in_window, uri="/in"),
            waf_record(timestamp=outside_window, uri="/outside"),
        ],
    )
    out_file = tmp_path / "out.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "waf_fu",
            "--sqlite",
            str(db_path),
            "--log-group",
            "test-group",
            "--db-only",
            "--start",
            WINDOW_START.isoformat(),
            "--end",
            WINDOW_MID.isoformat(),
            "--mode",
            "batch-json",
            "--output",
            str(out_file),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )

    assert result.returncode == 0, result.stderr
    entries = json.loads(out_file.read_text())
    assert len(entries) == 1
    assert entries[0]["url"].endswith("/in")


def test_db_only_without_log_group_launches_tui_with_db_only_flag(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "logs.db"
    storage.open_db(str(db_path)).close()
    captured = _capture_tui(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["waf-fu", "--sqlite", str(db_path), "--db-only"])

    main()

    assert captured["tui"].db_only is True


def test_db_only_requires_explicit_target_for_s3_and_waf_log_locations(tmp_path):
    db_path = tmp_path / "logs.db"
    storage.open_db(str(db_path)).close()

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "waf_fu",
            "--sqlite",
            str(db_path),
            "--db-only",
            "--log-location",
            "s3",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC_DIR, "HOME": str(tmp_path)},
    )

    assert result.returncode != 0
    assert "--db-only requires --log-group or --s3-bucket" in result.stderr
