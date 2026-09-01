"""Coverage for the SQLite-backed auth-count scan subsystem (CLI-01/CLI-02):
count_auth_in_log_group, scan_region_auth_counts, and
scan_all_regions_auth_counts. This subsystem previously had zero tests.
"""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest

from waf_fu import cloudwatch, storage

# ── The six JSON log-counts symbols must be gone ─────────────────────────

_REMOVED_SYMBOLS = [
    "load_log_counts",
    "_write_log_counts",
    "save_log_counts",
    "get_auth_count",
    "set_auth_count",
    "_log_counts_lock",
]


@pytest.mark.parametrize("name", _REMOVED_SYMBOLS)
def test_json_log_counts_symbols_removed(name):
    assert not hasattr(cloudwatch, name)


# ── count_auth_in_log_group ──────────────────────────────────────────────


class _FakeLogsClient:
    """Fakes boto3's CloudWatch Logs client `filter_log_events`, paginating
    over a fixed list of pre-built events, two per page."""

    def __init__(self, events):
        self._events = events

    def filter_log_events(self, **kwargs):
        token = kwargs.get("nextToken")
        page_size = 2
        start = int(token) if token else 0
        page = self._events[start : start + page_size]
        resp = {"events": page}
        next_start = start + page_size
        if next_start < len(self._events):
            resp["nextToken"] = str(next_start)
        return resp


def _stub_session(monkeypatch, client):
    monkeypatch.setattr(
        boto3, "Session", lambda **kwargs: SimpleNamespace(client=lambda svc: client)
    )


def _event(message: str) -> dict:
    return {"message": message}


def test_count_auth_in_log_group_returns_records(monkeypatch, waf_record):
    import json as jsonlib

    auth_record = waf_record(headers={"Cookie": "sid=1"})
    no_auth_record = waf_record(uri="/static/app.js")
    events = [
        _event(jsonlib.dumps(auth_record)),
        _event(jsonlib.dumps(no_auth_record)),
    ]
    client = _FakeLogsClient(events)
    _stub_session(monkeypatch, client)

    auth_count, total_scanned, records = cloudwatch.count_auth_in_log_group(
        "aws-waf-logs-test"
    )

    assert auth_count == 1
    assert total_scanned == 2
    assert len(records) == total_scanned


def test_count_auth_in_log_group_respects_max_events(monkeypatch, waf_record):
    import json as jsonlib

    events = [_event(jsonlib.dumps(waf_record(uri=f"/{i}"))) for i in range(5)]
    client = _FakeLogsClient(events)
    _stub_session(monkeypatch, client)

    _auth_count, total_scanned, records = cloudwatch.count_auth_in_log_group(
        "aws-waf-logs-test", max_events=3
    )

    assert total_scanned == 3
    assert len(records) == 3


# ── scan_region_auth_counts ──────────────────────────────────────────────


def test_scan_region_auth_counts_writes_sqlite_and_no_json(
    tmp_path, monkeypatch, waf_record
):
    conn = storage.open_db(str(tmp_path / "logs.db"))

    monkeypatch.setattr(
        cloudwatch, "fetch_waf_log_groups", lambda **kw: ["group-a", "group-b"]
    )

    def fake_count(log_group, **kwargs):
        record = waf_record(uri=f"/{log_group}", headers={"Cookie": "sid=1"})
        return (1, 1, [record])

    monkeypatch.setattr(cloudwatch, "count_auth_in_log_group", fake_count)

    results = cloudwatch.scan_region_auth_counts(
        profile="p", region="us-east-1", conn=conn
    )

    assert results == {"group-a": 1, "group-b": 1}
    assert storage.get_auth_count(conn, "p", "us-east-1", "group-a") == (1, 1)
    assert storage.get_auth_count(conn, "p", "us-east-1", "group-b") == (1, 1)
    assert len(storage.load_source_records(conn, "cwl", "group-a", 0, 1 << 62)) == 1
    assert len(storage.load_source_records(conn, "cwl", "group-b", 0, 1 << 62)) == 1

    json_files = list(tmp_path.rglob("*.json"))
    assert json_files == []


def test_scan_region_auth_counts_skips_group_that_raises(
    tmp_path, monkeypatch, waf_record
):
    conn = storage.open_db(str(tmp_path / "logs.db"))

    monkeypatch.setattr(
        cloudwatch, "fetch_waf_log_groups", lambda **kw: ["broken", "good"]
    )

    def fake_count(log_group, **kwargs):
        if log_group == "broken":
            raise RuntimeError("boom")
        return (2, 5, [waf_record(uri="/ok")])

    monkeypatch.setattr(cloudwatch, "count_auth_in_log_group", fake_count)

    results = cloudwatch.scan_region_auth_counts(
        profile=None, region="us-east-1", conn=conn
    )

    assert results == {"good": 2}
    assert storage.get_auth_count(conn, None, "us-east-1", "broken") is None
    assert storage.get_auth_count(conn, None, "us-east-1", "good") == (2, 5)


# ── scan_all_regions_auth_counts ─────────────────────────────────────────


def test_scan_all_regions_uses_get_available_regions_not_aws_regions(
    tmp_path, monkeypatch
):
    conn = storage.open_db(str(tmp_path / "logs.db"))

    fake_regions = ["us-east-1", "eu-west-1"]
    assert fake_regions != cloudwatch.AWS_REGIONS

    monkeypatch.setattr(
        boto3,
        "Session",
        lambda **kwargs: SimpleNamespace(
            get_available_regions=lambda service: fake_regions
        ),
    )

    scanned_regions: list[str] = []

    def fake_scan_region(profile, region, conn, **kwargs):
        scanned_regions.append(region)
        return {}

    monkeypatch.setattr(cloudwatch, "scan_region_auth_counts", fake_scan_region)

    cloudwatch.scan_all_regions_auth_counts(profile=None, conn=conn)

    assert sorted(scanned_regions) == sorted(fake_regions)


def test_scan_all_regions_returns_empty_when_no_regions_available(
    tmp_path, monkeypatch
):
    conn = storage.open_db(str(tmp_path / "logs.db"))

    monkeypatch.setattr(
        boto3,
        "Session",
        lambda **kwargs: SimpleNamespace(get_available_regions=lambda service: []),
    )

    called = []
    monkeypatch.setattr(
        cloudwatch,
        "scan_region_auth_counts",
        lambda *a, **k: called.append(1) or {},
    )

    result = cloudwatch.scan_all_regions_auth_counts(profile=None, conn=conn)

    assert result == {}
    assert called == []
