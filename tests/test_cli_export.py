"""CLI-03 coverage for --export: database-to-JSON export path.

--export reads from the SQLite database only (log group, time window, action
filter) and never touches CloudWatch, unlike the normal load path.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

import pytest

from waf_fu import storage
from waf_fu.cli import main

WINDOW_START = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
WINDOW_MID = datetime(2026, 1, 1, 1, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 1, 1, 2, 0, tzinfo=UTC)


def _seed(db_path, log_group, records):
    conn = storage.open_db(str(db_path))
    storage.save_source_records(conn, "cwl", log_group, records)
    conn.close()


def _never_called(*args, **kwargs):
    raise AssertionError("fetch_logs_from_cloudwatch must not be called by --export")


def test_export_writes_matching_records_without_cloudwatch_call(
    tmp_path, monkeypatch, waf_record
):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    ts = int(WINDOW_START.timestamp() * 1000) + 1
    _seed(db_path, "test-group", [waf_record(timestamp=ts, uri="/a")])

    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", _never_called)
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
            "--export",
            str(out_file),
        ],
    )

    main()

    data = json.loads(out_file.read_text())
    assert len(data) == 1
    assert data[0]["url"].endswith("/a")


def test_export_respects_time_window(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    in_window_ts = int(WINDOW_START.timestamp() * 1000) + 1
    out_of_window_ts = int(WINDOW_END.timestamp() * 1000) + 1
    _seed(
        db_path,
        "test-group",
        [
            waf_record(timestamp=in_window_ts, uri="/in"),
            waf_record(timestamp=out_of_window_ts, uri="/out"),
        ],
    )

    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", _never_called)
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
            "--export",
            str(out_file),
        ],
    )

    main()

    data = json.loads(out_file.read_text())
    assert len(data) == 1
    assert data[0]["url"].endswith("/in")


def test_export_respects_action_filter(tmp_path, monkeypatch, waf_record):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    base_ts = int(WINDOW_START.timestamp() * 1000) + 1
    _seed(
        db_path,
        "test-group",
        [
            waf_record(timestamp=base_ts, uri="/blocked", action="BLOCK"),
            waf_record(timestamp=base_ts + 1, uri="/allowed", action="ALLOW"),
        ],
    )

    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", _never_called)
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
            "--action",
            "BLOCK",
            "--export",
            str(out_file),
        ],
    )

    main()

    data = json.loads(out_file.read_text())
    assert len(data) == 1
    assert data[0]["url"].endswith("/blocked")


def test_export_without_log_group_errors(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"

    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", _never_called)
    monkeypatch.setattr(
        sys, "argv", ["waf-fu", "--sqlite", str(db_path), "--export", str(out_file)]
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code != 0
    assert "--log-group" in capsys.readouterr().err
    assert not out_file.exists()


def test_export_empty_log_group_writes_empty_array(tmp_path, monkeypatch):
    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    # DB exists but has no records for this log group.
    conn = storage.open_db(str(db_path))
    conn.close()

    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", _never_called)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "waf-fu",
            "--sqlite",
            str(db_path),
            "--log-group",
            "empty-group",
            "--export",
            str(out_file),
        ],
    )

    main()

    assert json.loads(out_file.read_text()) == []


def test_export_closes_db_connection(tmp_path, monkeypatch, waf_record):
    import sqlite3

    db_path = tmp_path / "logs.db"
    out_file = tmp_path / "out.json"
    ts = int(WINDOW_START.timestamp() * 1000) + 1
    _seed(db_path, "test-group", [waf_record(timestamp=ts)])

    opened = []
    real_open_db = storage.open_db

    def spy_open_db(path):
        conn = real_open_db(path)
        opened.append(conn)
        return conn

    monkeypatch.setattr("waf_fu.cli.storage.open_db", spy_open_db)
    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", _never_called)
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
            "--export",
            str(out_file),
        ],
    )

    main()

    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")
