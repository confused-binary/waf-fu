"""Relative/ISO time-window parsing for --start/--end.

`--start 1h` crashed with "Invalid isoformat string" during phase 3 UAT,
which made the repeat-run cache workflow unusable, so the accepted forms are
pinned here.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta

import pytest

from waf_fu.cli import main
from waf_fu.models import parse_time_arg

REFERENCE = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("value", "expected_delta"),
    [
        ("30m", timedelta(minutes=30)),
        ("30 minutes", timedelta(minutes=30)),
        ("1h", timedelta(hours=1)),
        ("2 hours", timedelta(hours=2)),
        ("3d", timedelta(days=3)),
        ("3 days", timedelta(days=3)),
        ("2w", timedelta(weeks=2)),
        # "m" is minutes and "mo" is months: the one pair a looser pattern
        # would collapse, silently turning a 30-day window into 30 minutes.
        ("1mo", timedelta(days=30)),
        ("1y", timedelta(days=365)),
    ],
)
def test_relative_offset_is_subtracted_from_reference(value, expected_delta):
    assert parse_time_arg(value, reference=REFERENCE) == REFERENCE - expected_delta


def test_iso_timestamp_is_used_verbatim():
    assert parse_time_arg("2026-01-01T06:30:00+00:00", reference=REFERENCE) == datetime(
        2026, 1, 1, 6, 30, tzinfo=UTC
    )


def test_unparseable_value_raises():
    with pytest.raises(ValueError):
        parse_time_arg("last tuesday", reference=REFERENCE)


def test_cli_accepts_relative_start(tmp_path, monkeypatch, waf_record):
    out_file = tmp_path / "out.json"
    calls: list[tuple[datetime, datetime]] = []

    def fake_fetch(
        *,
        log_group,
        start_time,
        end_time,
        profile=None,
        region=None,
        action_filter=None,
    ):
        calls.append((start_time, end_time))
        return [waf_record(timestamp=int(start_time.timestamp() * 1000) + 1)]

    monkeypatch.setattr("waf_fu.cli.fetch_logs_from_cloudwatch", fake_fetch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "waf-fu",
            "--log-group",
            "test-group",
            "--sqlite",
            str(tmp_path / "logs.db"),
            "--start",
            "1h",
            "--mode",
            "batch-json",
            "--output",
            str(out_file),
        ],
    )

    main()

    assert len(json.loads(out_file.read_text())) == 1
    assert len(calls) == 1
    start_time, end_time = calls[0]
    assert end_time - start_time == timedelta(hours=1)
