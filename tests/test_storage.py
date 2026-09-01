"""Unit coverage for storage.py: schema, dedup, coercion, round-trip
fidelity, coverage matching, offline group list, and load_with_cache
orchestration.
"""

from __future__ import annotations

import sqlite3
import threading

import pytest

from waf_fu import storage
from waf_fu.models import ReconstructedRequest, parse_all


@pytest.fixture
def db(tmp_path):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    yield conn
    conn.close()


# --- Schema / open_db --------------------------------------------------------


def test_open_db_creates_missing_parents(tmp_path):
    path = tmp_path / "a" / "b" / "logs.db"
    conn = storage.open_db(str(path))
    try:
        assert path.exists()
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == storage.SCHEMA_VERSION
    finally:
        conn.close()


def test_open_db_reopen_is_idempotent(tmp_path):
    path = tmp_path / "logs.db"
    conn1 = storage.open_db(str(path))
    storage.save_records(conn1, "group-a", [{"timestamp": 1, "action": "ALLOW"}])
    conn1.close()

    conn2 = storage.open_db(str(path))
    try:
        version = conn2.execute("PRAGMA user_version").fetchone()[0]
        assert version == storage.SCHEMA_VERSION
        rows = conn2.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
        assert rows == 1
    finally:
        conn2.close()


def test_open_db_expands_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    conn = storage.open_db("~/nested/logs.db")
    try:
        assert (tmp_path / "nested" / "logs.db").exists()
    finally:
        conn.close()


def test_open_db_rejects_newer_schema(tmp_path):
    path = tmp_path / "logs.db"
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {storage.SCHEMA_VERSION + 1}")
    conn.commit()
    conn.close()

    with pytest.raises(RuntimeError):
        storage.open_db(str(path))


def test_open_db_rejects_foreign_database(tmp_path):
    path = tmp_path / "other.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE unrelated_table (id INTEGER)")
    conn.execute("INSERT INTO unrelated_table VALUES (1)")
    conn.commit()
    conn.close()

    with pytest.raises(RuntimeError):
        storage.open_db(str(path))


# --- Schema v2 migration (auth_counts / preferences) -------------------------


def test_fresh_db_is_schema_v2_with_new_tables(tmp_path):
    path = tmp_path / "logs.db"
    conn = storage.open_db(str(path))
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == storage.SCHEMA_VERSION
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"auth_counts", "preferences"} <= tables
    finally:
        conn.close()


def test_v1_database_migrates_to_v2_without_losing_data(tmp_path):
    path = tmp_path / "logs.db"
    # Build a v1 fixture by hand: only the v1 schema, user_version = 1, one
    # pre-existing waf_logs row -- reusing storage._SCHEMA directly rather
    # than hardcoding a copy of the DDL.
    raw = sqlite3.connect(path)
    raw.executescript(storage._SCHEMA)
    raw.execute(
        "INSERT INTO waf_logs(log_group, timestamp, action, record) "
        "VALUES (?, ?, ?, ?)",
        ("group-a", 1000, "ALLOW", '{"timestamp": 1000, "action": "ALLOW"}'),
    )
    raw.execute("PRAGMA user_version = 1")
    raw.commit()
    raw.close()

    conn = storage.open_db(str(path))
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == storage.SCHEMA_VERSION
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"auth_counts", "preferences", "waf_logs", "fetch_log"} <= tables
        loaded = storage.load_records(conn, "group-a", 0, 5000)
        assert len(loaded) == 1
        assert loaded[0]["action"] == "ALLOW"
    finally:
        conn.close()


def test_v1_to_v2_migration_is_idempotent_on_reopen(tmp_path):
    path = tmp_path / "logs.db"
    raw = sqlite3.connect(path)
    raw.executescript(storage._SCHEMA)
    raw.execute("PRAGMA user_version = 1")
    raw.commit()
    raw.close()

    conn1 = storage.open_db(str(path))
    conn1.close()
    conn2 = storage.open_db(str(path))
    try:
        version = conn2.execute("PRAGMA user_version").fetchone()[0]
        assert version == storage.SCHEMA_VERSION
        rows = conn2.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
        assert rows == 0
    finally:
        conn2.close()


def test_background_thread_write_is_visible_after_join(db):
    errors: list[BaseException] = []

    def _write():
        try:
            storage.save_records(db, "group-a", [{"timestamp": 1, "action": "ALLOW"}])
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=_write)
    t.start()
    t.join()

    assert errors == []
    count = db.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
    assert count == 1


# --- Dedup (DB-02) -----------------------------------------------------------


def test_dedup_repeat_batch_is_noop(db, waf_record):
    records = [waf_record(uri=f"/p{i}") for i in range(5)]
    assert storage.save_records(db, "group-a", records) == 5
    assert storage.save_records(db, "group-a", records) == 0
    count = db.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
    assert count == 5


def test_null_key_dedups_to_one_row(db):
    # A record with no httpRequest key at all makes all three dedup-key
    # json_extract expressions NULL. Bare json_extract would treat these
    # as distinct (SQLite NULLs are distinct in unique indexes), producing
    # three rows; the ifnull() wrapper collapses them to one.
    record = {"timestamp": 1000, "action": "ALLOW"}
    storage.save_records(db, "group-a", [record])
    storage.save_records(db, "group-a", [record])
    storage.save_records(db, "group-a", [record])
    count = db.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
    assert count == 1


def test_save_records_empty_batch_inserts_nothing(db):
    assert storage.save_records(db, "group-a", []) == 0
    count = db.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
    assert count == 0


def test_dedup_key_not_over_broad(db, waf_record):
    r1 = waf_record(uri="/one")
    r2 = waf_record(uri="/two")
    inserted = storage.save_records(db, "group-a", [r1, r2])
    assert inserted == 2


# --- NOT NULL coercion (DB-02) -----------------------------------------------


def test_coerce_none_timestamp_and_action(db):
    record = {"timestamp": None, "action": None}
    inserted = storage.save_records(db, "group-a", [record])
    assert inserted == 1
    row = db.execute("SELECT timestamp, action FROM waf_logs").fetchone()
    assert row["timestamp"] == 0
    assert row["action"] == ""


def test_coerced_zero_timestamp_invisible_to_positive_range(db):
    storage.save_records(db, "group-a", [{"timestamp": None, "action": None}])
    loaded = storage.load_records(db, "group-a", 1, 1000)
    assert loaded == []


# --- Round-trip fidelity (DB-04) ---------------------------------------------


def test_roundtrip_fidelity(db, waf_record):
    records = [
        waf_record(
            uri="/a",
            cookies="session=abc",
            body='{"x":1}',
            headers={"X-Custom": "v"},
            timestamp=1000,
            action="ALLOW",
        ),
        waf_record(
            uri="/b",
            args="q=1",
            timestamp=2000,
            action="BLOCK",
        ),
    ]
    storage.save_records(db, "group-a", records)
    loaded = storage.load_records(db, "group-a", 0, 3000)

    original_parsed = parse_all(records)
    loaded_parsed = parse_all(loaded)

    assert len(original_parsed) == len(loaded_parsed)
    for orig, got in zip(original_parsed, loaded_parsed):
        assert orig.full_url == got.full_url
        assert orig.method == got.method
        assert orig.headers == got.headers
        assert orig.cookies == got.cookies
        assert orig.body == got.body
        assert orig.action == got.action
        assert orig.timestamp == got.timestamp


def test_load_records_respects_window_and_action_filter(db, waf_record):
    records = [
        waf_record(uri="/a", timestamp=1000, action="ALLOW"),
        waf_record(uri="/b", timestamp=2000, action="BLOCK"),
        waf_record(uri="/c", timestamp=3000, action="ALLOW"),
    ]
    storage.save_records(db, "group-a", records)

    loaded = storage.load_records(db, "group-a", 1000, 2000)
    assert {r["httpRequest"]["uri"] for r in loaded} == {"/a", "/b"}

    loaded_allow = storage.load_records(db, "group-a", 0, 5000, action_filter="ALLOW")
    assert {r["httpRequest"]["uri"] for r in loaded_allow} == {"/a", "/c"}


# --- Coverage matching (DB-03) -----------------------------------------------


def test_action_filter_null_safe_matching(db):
    storage.record_fetch(db, "group-a", 0, 100, None, None, None, 5)
    assert storage.covered_ranges(db, "group-a", 0, 100, None) == [(0, 100)]
    assert storage.covered_ranges(db, "group-a", 0, 100, "ALLOW") == []

    storage.record_fetch(db, "group-b", 0, 100, "ALLOW", None, None, 5)
    assert storage.covered_ranges(db, "group-b", 0, 100, "ALLOW") == [(0, 100)]
    assert storage.covered_ranges(db, "group-b", 0, 100, None) == []


def test_covered_ranges_excludes_non_overlapping(db):
    storage.record_fetch(db, "group-a", 0, 50, None, None, None, 1)
    storage.record_fetch(db, "group-a", 200, 300, None, None, None, 1)
    assert storage.covered_ranges(db, "group-a", 100, 150, None) == []
    assert storage.covered_ranges(db, "group-a", 40, 60, None) == [(0, 50)]


def test_covered_ranges_scopes_by_log_group(db):
    storage.record_fetch(db, "group-a", 0, 100, None, None, None, 1)
    assert storage.covered_ranges(db, "group-b", 0, 100, None) == []


# --- Offline selector ---------------------------------------------------------


def test_offline_selector_returns_distinct_sorted_groups(db, waf_record):
    storage.save_records(db, "group-c", [waf_record(uri="/1")])
    storage.save_records(db, "group-a", [waf_record(uri="/2")])
    storage.save_records(db, "group-a", [waf_record(uri="/3")])
    assert storage.list_log_groups(db) == ["group-a", "group-c"]


def test_offline_selector_excludes_empty_fetch_only_groups(db):
    storage.record_fetch(db, "group-empty", 0, 100, None, None, None, 0)
    assert storage.list_log_groups(db) == []


# --- load_with_cache orchestration (DB-03) -----------------------------------


class _RecordingFetcher:
    def __init__(self, records_by_call=None, exc=None):
        self.calls: list[tuple[int, int]] = []
        self._records_by_call = records_by_call
        self._exc = exc
        self._call_index = 0

    def __call__(self, log_group, start_time, end_time, action_filter, profile, region):
        self.calls.append((start_time, end_time))
        if self._exc is not None:
            raise self._exc
        if self._records_by_call is not None:
            records = self._records_by_call[self._call_index]
            self._call_index += 1
            return records
        return []


def test_cache_hit_makes_zero_fetch_calls(db, waf_record):
    records = [waf_record(uri="/a", timestamp=50)]
    storage.save_records(db, "group-a", records)
    storage.record_fetch(db, "group-a", 0, 100, None, None, None, 1)

    fetcher = _RecordingFetcher()
    result = storage.load_with_cache(db, "group-a", 0, 100, None, None, None, fetcher)
    assert fetcher.calls == []
    assert len(result) == 1


def test_cache_miss_fetches_full_window(db, waf_record):
    fetched = [waf_record(uri="/a", timestamp=50)]
    fetcher = _RecordingFetcher(records_by_call=[fetched])
    result = storage.load_with_cache(db, "group-a", 0, 100, None, None, None, fetcher)
    assert fetcher.calls == [(0, 100)]
    assert len(result) == 1
    stored_count = db.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
    assert stored_count == 1


def test_gap_fill_fetches_only_uncovered_windows(db, waf_record):
    storage.save_records(db, "group-a", [waf_record(uri="/covered1", timestamp=10)])
    storage.record_fetch(db, "group-a", 0, 40, None, None, None, 1)
    storage.save_records(db, "group-a", [waf_record(uri="/covered2", timestamp=70)])
    storage.record_fetch(db, "group-a", 60, 80, None, None, None, 1)

    gap1_records = [waf_record(uri="/gap1", timestamp=50)]
    gap2_records = [waf_record(uri="/gap2", timestamp=90)]
    fetcher = _RecordingFetcher(records_by_call=[gap1_records, gap2_records])

    result = storage.load_with_cache(db, "group-a", 0, 100, None, None, None, fetcher)
    assert fetcher.calls == [(40, 60), (80, 100)]
    uris = {r["httpRequest"]["uri"] for r in result}
    assert uris == {"/covered1", "/covered2", "/gap1", "/gap2"}


def test_refresh_fetches_whole_window_and_extends_coverage(db, waf_record):
    storage.save_records(db, "group-a", [waf_record(uri="/a", timestamp=50)])
    storage.record_fetch(db, "group-a", 0, 100, None, None, None, 1)

    fetcher = _RecordingFetcher(records_by_call=[[waf_record(uri="/a", timestamp=50)]])
    storage.load_with_cache(
        db, "group-a", 0, 100, None, None, None, fetcher, refresh=True
    )
    assert fetcher.calls == [(0, 100)]
    fetch_log_rows = db.execute("SELECT count(*) FROM fetch_log").fetchone()[0]
    assert fetch_log_rows == 2


def test_fetch_failure_leaves_no_fetch_log_row_for_that_gap(db):
    fetcher = _RecordingFetcher(exc=RuntimeError("boom"))
    result = storage.load_with_cache(db, "group-a", 0, 100, None, None, None, fetcher)
    assert result == []
    fetch_log_rows = db.execute("SELECT count(*) FROM fetch_log").fetchone()[0]
    assert fetch_log_rows == 0


def test_fetch_failure_returns_cached_records(db, waf_record):
    """Offline scenario: window shifts so a small trailing gap exists, but
    the fetch for that gap fails (no network).  load_with_cache must still
    return the records already cached from the covered portion."""
    cached = [waf_record(uri="/cached", timestamp=50)]
    storage.save_records(db, "group-a", cached)
    storage.record_fetch(db, "group-a", 0, 100, None, None, None, 1)

    fetcher = _RecordingFetcher(exc=OSError("network unreachable"))
    result = storage.load_with_cache(db, "group-a", 0, 110, None, None, None, fetcher)
    assert fetcher.calls == [(100, 110)]
    assert len(result) == 1
    assert result[0]["httpRequest"]["uri"] == "/cached"


def test_multi_gap_failure_keeps_earlier_gap_coverage(db, waf_record):
    """A later gap failing must not undo the earlier gap that succeeded: its
    records stay persisted and its fetch_log row stays recorded, so the next
    run only retries the part that actually failed."""
    storage.save_records(db, "group-a", [waf_record(uri="/covered", timestamp=30)])
    storage.record_fetch(db, "group-a", 20, 40, None, None, None, 1)

    gap1_records = [waf_record(uri="/gap1", timestamp=10)]

    def fetch_first_then_fail(
        log_group, start_time, end_time, action_filter, profile, region
    ):
        if (start_time, end_time) == (0, 20):
            return gap1_records
        raise OSError("network unreachable")

    result = storage.load_with_cache(
        db, "group-a", 0, 100, None, None, None, fetch_first_then_fail
    )

    assert {r["httpRequest"]["uri"] for r in result} == {"/gap1", "/covered"}
    recorded = {
        (row["start_time"], row["end_time"])
        for row in db.execute("SELECT start_time, end_time FROM fetch_log")
    }
    assert recorded == {(20, 40), (0, 20)}


# --- auth_counts (CLI-01) -----------------------------------------------------


def test_upsert_then_get_auth_count_roundtrip(db):
    storage.upsert_auth_count(db, "p", "us-east-1", "grp", 42, 1000)
    assert storage.get_auth_count(db, "p", "us-east-1", "grp") == (42, 1000)


def test_repeat_upsert_replaces_rather_than_duplicates(db):
    storage.upsert_auth_count(db, "p", "us-east-1", "grp", 42, 1000)
    storage.upsert_auth_count(db, "p", "us-east-1", "grp", 7, 500)
    count = db.execute("SELECT count(*) FROM auth_counts").fetchone()[0]
    assert count == 1
    assert storage.get_auth_count(db, "p", "us-east-1", "grp") == (7, 500)


def test_get_auth_count_unknown_group_returns_none(db):
    assert storage.get_auth_count(db, "p", "us-east-1", "unknown-grp") is None


def test_upsert_auth_count_normalizes_none_profile_and_region(db):
    storage.upsert_auth_count(db, None, None, "grp", 1, 2)
    assert storage.get_auth_count(db, None, None, "grp") == (1, 2)
    assert storage.get_auth_count(db, "default", "", "grp") == (1, 2)


def test_record_auth_counts_matches_has_replayable_auth(db, waf_record):
    requests = [
        ReconstructedRequest(
            waf_record(uri="/a", headers={"Authorization": "Bearer x"})
        ),
        ReconstructedRequest(waf_record(uri="/b", cookies="session=abc")),
        ReconstructedRequest(waf_record(uri="/c")),
    ]
    expected_auth = sum(1 for r in requests if r.has_replayable_auth)
    expected_total = len(requests)

    result = storage.record_auth_counts(db, "p", "us-east-1", "grp", requests)

    assert result == (expected_auth, expected_total)
    assert storage.get_auth_count(db, "p", "us-east-1", "grp") == (
        expected_auth,
        expected_total,
    )


def test_record_auth_counts_empty_list_writes_zero_zero(db):
    result = storage.record_auth_counts(db, "p", "us-east-1", "grp", [])
    assert result == (0, 0)
    assert storage.get_auth_count(db, "p", "us-east-1", "grp") == (0, 0)


def test_count_auth_by_log_group_splits_auth_and_total(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        "grp",
        [
            waf_record(uri="/a", timestamp=1000, cookies="session=abc"),
            waf_record(uri="/b", timestamp=2000),
            waf_record(uri="/c", timestamp=3000),
        ],
    )

    assert storage.count_auth_by_log_group(db, "cwl", 0, 10_000) == {"grp": (1, 3)}


def test_count_auth_by_log_group_respects_window(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        "grp",
        [
            waf_record(uri="/in", timestamp=2000, cookies="session=abc"),
            waf_record(uri="/out", timestamp=9000, cookies="session=abc"),
        ],
    )

    assert storage.count_auth_by_log_group(db, "cwl", 1000, 3000) == {"grp": (1, 1)}


def test_count_auth_by_log_group_separates_groups(db, waf_record):
    storage.save_source_records(
        db, "cwl", "grp-a", [waf_record(uri="/a", timestamp=1000)]
    )
    storage.save_source_records(
        db,
        "cwl",
        "grp-b",
        [
            waf_record(uri="/b", timestamp=1000, cookies="session=abc"),
            waf_record(uri="/c", timestamp=1000),
        ],
    )

    assert storage.count_auth_by_log_group(db, "cwl", 0, 10_000) == {
        "grp-a": (0, 1),
        "grp-b": (1, 2),
    }


def test_count_auth_by_log_group_omits_groups_outside_window(db, waf_record):
    storage.save_source_records(
        db, "cwl", "grp", [waf_record(uri="/a", timestamp=9000)]
    )

    assert storage.count_auth_by_log_group(db, "cwl", 0, 1000) == {}


def test_count_auth_by_log_group_counts_shapeless_record_toward_total(db, waf_record):
    # The dedup index json_extracts `record`, so malformed JSON cannot reach the
    # table at all -- a non-object JSON value is the degenerate shape that can.
    storage.save_source_records(
        db, "cwl", "grp", [waf_record(uri="/a", timestamp=1000, cookies="s=1")]
    )
    with db:
        db.execute(
            "INSERT INTO cwl_logs(log_group, timestamp, action, record) "
            "VALUES (?, ?, ?, ?)",
            ("grp", 1000, "ALLOW", "[]"),
        )

    assert storage.count_auth_by_log_group(db, "cwl", 0, 10_000) == {"grp": (1, 2)}


def test_count_auth_by_log_group_applies_action_filter(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        "grp",
        [
            waf_record(uri="/a", timestamp=1000, action="ALLOW", cookies="s=1"),
            waf_record(uri="/b", timestamp=1000, action="BLOCK", cookies="s=1"),
        ],
    )

    assert storage.count_auth_by_log_group(db, "cwl", 0, 10_000, "BLOCK") == {
        "grp": (1, 1)
    }


def test_count_auth_by_log_group_counts_x_auth_token_as_auth(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        "grp",
        [
            waf_record(
                uri="/a",
                timestamp=1000,
                headers={"x-auth-token": "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8"},
            ),
            waf_record(uri="/b", timestamp=2000),
        ],
    )

    assert storage.count_auth_by_log_group(db, "cwl", 0, 10_000) == {"grp": (1, 2)}


def test_count_auth_by_log_group_counts_x_api_key_as_auth(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        "grp",
        [waf_record(uri="/a", timestamp=1000, headers={"x-api-key": "abc123"})],
    )

    assert storage.count_auth_by_log_group(db, "cwl", 0, 10_000) == {"grp": (1, 1)}


def test_count_auth_by_log_group_rejects_unknown_source(db):
    with pytest.raises(ValueError):
        storage.count_auth_by_log_group(db, "bogus", 0, 10_000)


# --- selector_counts (cached log-group overlay counts) -------------------------


def test_upsert_and_get_selector_counts_roundtrip(db):
    storage.upsert_selector_counts(db, "cwl", {"g1": (5, 100), "g2": (0, 10)})
    result = storage.get_selector_counts(db, "cwl")
    assert result == {"g1": (5, 100), "g2": (0, 10)}


def test_upsert_selector_counts_replaces_existing(db):
    storage.upsert_selector_counts(db, "cwl", {"g1": (1, 10)})
    storage.upsert_selector_counts(db, "cwl", {"g1": (5, 50)})
    result = storage.get_selector_counts(db, "cwl")
    assert result == {"g1": (5, 50)}


def test_get_selector_counts_scoped_by_source(db):
    storage.upsert_selector_counts(db, "cwl", {"g1": (1, 10)})
    storage.upsert_selector_counts(db, "s3", {"g2": (2, 20)})
    assert storage.get_selector_counts(db, "cwl") == {"g1": (1, 10)}
    assert storage.get_selector_counts(db, "s3") == {"g2": (2, 20)}


def test_refresh_selector_counts_all_groups(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        "g1",
        [
            waf_record(uri="/a", timestamp=1000, cookies="s=1"),
            waf_record(uri="/b", timestamp=2000),
        ],
    )
    storage.refresh_selector_counts(db, "cwl", 0, 10_000)
    result = storage.get_selector_counts(db, "cwl")
    assert result == {"g1": (1, 2)}


def test_refresh_selector_counts_single_group(db, waf_record):
    storage.save_source_records(
        db, "cwl", "g1", [waf_record(uri="/a", timestamp=1000, cookies="s=1")]
    )
    storage.save_source_records(
        db, "cwl", "g2", [waf_record(uri="/b", timestamp=2000, cookies="s=1")]
    )
    storage.refresh_selector_counts(db, "cwl", 0, 10_000, log_group="g1")
    result = storage.get_selector_counts(db, "cwl")
    assert result == {"g1": (1, 1)}
    assert "g2" not in result


def test_refresh_selector_counts_noop_for_missing_group(db, waf_record):
    storage.save_source_records(db, "cwl", "g1", [waf_record(uri="/a", timestamp=1000)])
    storage.refresh_selector_counts(db, "cwl", 0, 10_000, log_group="nonexistent")
    result = storage.get_selector_counts(db, "cwl")
    assert result == {}


def test_schema_v4_migration_creates_selector_counts(tmp_path):
    db = storage.open_db(str(tmp_path / "fresh.db"))
    tables = {
        row[0]
        for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert "selector_counts" in tables
    db.close()


# --- preferences ---------------------------------------------------------------


def test_get_preference_missing_key_returns_none_or_default(db):
    assert storage.get_preference(db, "replay_mode") is None
    assert storage.get_preference(db, "replay_mode", "firefox") == "firefox"


def test_set_then_get_preference_roundtrip(db):
    storage.set_preference(db, "replay_mode", "chrome")
    assert storage.get_preference(db, "replay_mode") == "chrome"


def test_repeat_set_preference_keeps_one_row_with_latest_value(db):
    storage.set_preference(db, "replay_mode", "chrome")
    storage.set_preference(db, "replay_mode", "firefox")
    count = db.execute("SELECT count(*) FROM preferences").fetchone()[0]
    assert count == 1
    assert storage.get_preference(db, "replay_mode") == "firefox"


def test_preference_survives_close_and_reopen(tmp_path):
    path = tmp_path / "logs.db"
    conn1 = storage.open_db(str(path))
    storage.set_preference(conn1, "auth_filter", "off")
    conn1.close()

    conn2 = storage.open_db(str(path))
    try:
        assert storage.get_preference(conn2, "auth_filter") == "off"
    finally:
        conn2.close()


def test_default_replay_mode_and_auth_filter_constants():
    assert storage.DEFAULT_REPLAY_MODE == "firefox"
    assert storage.DEFAULT_AUTH_FILTER == "on"


def test_record_count_is_fetched_count_not_inserted_count(db, waf_record):
    batch = [waf_record(uri="/dup", timestamp=10)]
    storage.save_records(db, "group-a", batch)

    fetcher = _RecordingFetcher(records_by_call=[batch])
    storage.load_with_cache(db, "group-a", 0, 100, None, None, None, fetcher)

    row = db.execute("SELECT record_count FROM fetch_log").fetchone()
    assert row["record_count"] == len(batch)
    stored_count = db.execute("SELECT count(*) FROM waf_logs").fetchone()[0]
    assert stored_count == 1


# --- Schema v3 migration (SRC-06) --------------------------------------------

_V3_TABLES = {
    "cwl_logs",
    "s3_logs",
    "waf_samples",
    "merged_logs",
    "cwl_fetch",
    "s3_fetch",
    "waf_fetch",
    "acl_mapping",
}


def test_v3_fresh_db(tmp_path):
    conn = storage.open_db(str(tmp_path / "fresh.db"))
    try:
        assert (
            conn.execute("PRAGMA user_version").fetchone()[0] == storage.SCHEMA_VERSION
        )
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert _V3_TABLES <= tables
    finally:
        conn.close()


def test_v3_migration_from_v2(tmp_path):
    path = tmp_path / "v2.db"
    raw = sqlite3.connect(path)
    raw.executescript(storage._SCHEMA)
    raw.executescript(storage._SCHEMA_V2)
    raw.execute(
        "INSERT INTO waf_logs(log_group, timestamp, action, record) "
        "VALUES (?, ?, ?, ?)",
        ("grp", 1000, "ALLOW", '{"timestamp":1000,"action":"ALLOW"}'),
    )
    raw.execute(
        "INSERT INTO auth_counts(profile, region, log_group, auth_count, events_scanned, scanned_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("default", "us-east-1", "grp", 5, 100, 1000),
    )
    raw.execute("PRAGMA user_version = 2")
    raw.commit()
    raw.close()

    conn = storage.open_db(str(path))
    try:
        assert (
            conn.execute("PRAGMA user_version").fetchone()[0] == storage.SCHEMA_VERSION
        )
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert _V3_TABLES <= tables
        assert conn.execute("SELECT count(*) FROM waf_logs").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM auth_counts").fetchone()[0] == 1
    finally:
        conn.close()


# --- Per-source CRUD (SRC-06) ------------------------------------------------


def test_save_load_source_cwl(db, waf_record):
    records = [waf_record(uri=f"/c{i}", timestamp=1000 + i) for i in range(3)]
    inserted = storage.save_source_records(db, "cwl", "grp", records)
    assert inserted == 3
    loaded = storage.load_source_records(db, "cwl", "grp", 0, 5000)
    assert len(loaded) == 3
    parsed = parse_all(loaded)
    uris = {r.full_url for r in parsed}
    assert len(uris) == 3
    assert all("/c" in u for u in uris)


def test_save_load_source_s3(db, waf_record):
    records = [waf_record(uri="/s", timestamp=2000)]
    assert storage.save_source_records(db, "s3", "grp", records) == 1
    loaded = storage.load_source_records(db, "s3", "grp", 0, 5000)
    assert len(loaded) == 1


def test_save_load_source_waf(db, waf_record):
    records = [waf_record(uri="/w", timestamp=3000)]
    assert storage.save_source_records(db, "waf", "grp", records) == 1
    loaded = storage.load_source_records(db, "waf", "grp", 0, 5000)
    assert len(loaded) == 1


def test_source_dedup(db, waf_record):
    records = [waf_record(uri="/d", timestamp=1000)]
    storage.save_source_records(db, "cwl", "grp", records)
    storage.save_source_records(db, "cwl", "grp", records)
    count = db.execute("SELECT count(*) FROM cwl_logs").fetchone()[0]
    assert count == 1


def test_invalid_source(db, waf_record):
    with pytest.raises(ValueError):
        storage.save_source_records(db, "invalid", "grp", [waf_record()])


def test_source_coverage(db):
    storage.record_source_fetch(db, "cwl", "grp", 0, 100, None, None, None, 5)
    ranges = storage.covered_source_ranges(db, "cwl", "grp", 0, 100, None)
    assert ranges == [(0, 100)]


def test_list_source_log_groups(db, waf_record):
    storage.save_source_records(db, "cwl", "grp-a", [waf_record(uri="/a")])
    storage.save_source_records(db, "cwl", "grp-b", [waf_record(uri="/b")])
    assert storage.list_source_log_groups(db, "cwl") == ["grp-a", "grp-b"]
    assert storage.list_source_log_groups(db, "s3") == []


# --- ACL mapping (SRC-06) ----------------------------------------------------


def test_upsert_acl_mapping(db):
    storage.upsert_acl_mapping(
        db, "arn:aws:wafv2::acl/test", "test-acl", "us-east-1", None, "grp", "bucket"
    )
    mapping = storage.get_acl_mapping_for_log_group(db, "grp")
    assert mapping is not None
    assert mapping["acl_arn"] == "arn:aws:wafv2::acl/test"
    assert mapping["acl_name"] == "test-acl"
    assert mapping["s3_bucket"] == "bucket"

    storage.upsert_acl_mapping(
        db,
        "arn:aws:wafv2::acl/test",
        "test-acl",
        "us-east-1",
        None,
        "grp",
        "new-bucket",
    )
    count = db.execute("SELECT count(*) FROM acl_mapping").fetchone()[0]
    assert count == 1
    mapping = storage.get_acl_mapping_for_log_group(db, "grp")
    assert mapping["s3_bucket"] == "new-bucket"


def test_get_acl_mapping_for_log_group(db):
    storage.upsert_acl_mapping(db, "arn:a", "acl-a", "us-east-1", None, "grp-a", None)
    storage.upsert_acl_mapping(
        db, "arn:b", "acl-b", "us-west-2", None, "grp-b", "bucket-b"
    )
    result = storage.get_acl_mapping_for_log_group(db, "grp-b")
    assert result is not None
    assert result["acl_arn"] == "arn:b"
    assert storage.get_acl_mapping_for_log_group(db, "grp-x") is None


def test_list_acl_mappings_filter(db):
    storage.upsert_acl_mapping(db, "arn:1", "a1", "us-east-1", None, "g1", None)
    storage.upsert_acl_mapping(db, "arn:2", "a2", "us-west-2", None, "g2", None)
    all_mappings = storage.list_acl_mappings(db)
    assert len(all_mappings) == 2
    east = storage.list_acl_mappings(db, region="us-east-1")
    assert len(east) == 1
    assert east[0]["acl_arn"] == "arn:1"


# --- Merged records (SRC-06) -------------------------------------------------


def test_save_load_merged(db, waf_record):
    r1 = waf_record(uri="/m1", timestamp=1000)
    r2 = waf_record(uri="/m2", timestamp=2000)
    key1 = storage.merge_key(r1)
    key2 = storage.merge_key(r2)
    sources_map = {key1: "cwl", key2: "cwl,waf"}
    inserted = storage.save_merged_records(db, "grp", [r1, r2], sources_map)
    assert inserted == 2

    loaded = storage.load_merged_records(db, "grp", 0, 5000)
    assert len(loaded) == 2
    assert loaded[0]["_sources"] == "cwl"
    assert loaded[1]["_sources"] == "cwl,waf"


def test_delete_merged(db, waf_record):
    r = waf_record(uri="/del", timestamp=1000)
    storage.save_merged_records(db, "grp", [r], {storage.merge_key(r): "cwl"})
    assert storage.delete_merged_records(db, "grp", 0, 5000) == 1
    assert storage.load_merged_records(db, "grp", 0, 5000) == []


def test_merged_upsert_replaces(db, waf_record):
    r = waf_record(uri="/rep", timestamp=1000, body='{"v":1}')
    key = storage.merge_key(r)
    storage.save_merged_records(db, "grp", [r], {key: "cwl"})
    r2 = waf_record(uri="/rep", timestamp=1000, body='{"v":2}')
    storage.save_merged_records(db, "grp", [r2], {key: "cwl,waf"})
    count = db.execute("SELECT count(*) FROM merged_logs").fetchone()[0]
    assert count == 1
    loaded = storage.load_merged_records(db, "grp", 0, 5000)
    assert loaded[0]["_sources"] == "cwl,waf"


# --- Source-aware cache (SRC-06) ----------------------------------------------


def test_source_cache_miss(db, waf_record):
    fetched = [waf_record(uri="/sc", timestamp=50)]
    fetcher = _RecordingFetcher(records_by_call=[fetched])
    result = storage.load_source_with_cache(
        db, "cwl", "grp", 0, 100, None, None, None, fetcher
    )
    assert fetcher.calls == [(0, 100)]
    assert len(result) == 1


def test_source_cache_hit(db, waf_record):
    storage.save_source_records(db, "cwl", "grp", [waf_record(uri="/h", timestamp=50)])
    storage.record_source_fetch(db, "cwl", "grp", 0, 100, None, None, None, 1)
    fetcher = _RecordingFetcher()
    result = storage.load_source_with_cache(
        db, "cwl", "grp", 0, 100, None, None, None, fetcher
    )
    assert fetcher.calls == []
    assert len(result) == 1


def test_source_cache_gap_fill(db, waf_record):
    storage.save_source_records(db, "cwl", "grp", [waf_record(uri="/g1", timestamp=20)])
    storage.record_source_fetch(db, "cwl", "grp", 0, 50, None, None, None, 1)
    gap_records = [waf_record(uri="/g2", timestamp=70)]
    fetcher = _RecordingFetcher(records_by_call=[gap_records])
    result = storage.load_source_with_cache(
        db, "cwl", "grp", 0, 100, None, None, None, fetcher
    )
    assert fetcher.calls == [(50, 100)]
    assert len(result) == 2
