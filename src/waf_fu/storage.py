"""SQLite persistence layer for WAF log records.

Units: `waf_logs.timestamp`, `fetch_log.start_time`, and `fetch_log.end_time`
are all milliseconds since epoch, matching the WAF record's own `timestamp`
field and CloudWatch's `startTime`/`endTime` parameters. `fetch_log.fetched_at`
is the one exception: seconds since epoch, since nothing compares it to a
window.

The caller owns the `sqlite3.Connection` returned by `open_db` and is
responsible for closing it. The connection may be shared across threads
(`check_same_thread=False`); writes are serialized by the module-level
`_write_lock`, so callers on a background thread may safely write. Reads
are not locked and may observe a concurrent write's committed state.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from waf_fu.debug import DEBUG, _redact_meta, _redact_path

if TYPE_CHECKING:
    from waf_fu.models import ReconstructedRequest

SCHEMA_VERSION: int = 4
DEFAULT_DB_PATH: str = "~/.waf-fu/logs.db"
DEFAULT_REPLAY_MODE: str = "firefox"
DEFAULT_AUTH_FILTER: str = "on"
DEFAULT_SORT_FIELD: str = "time"
DEFAULT_SORT_DIR: str = "asc"

# The three log sources feeding the unified inventory. All three produce
# records in the WAF JSON format (S3 natively, GetSampledRequests after
# transformation), so their tables share one schema and one set of functions.
SOURCES: set[str] = {"cwl", "s3", "waf"}
_LOG_TABLES: dict[str, str] = {"cwl": "cwl_logs", "s3": "s3_logs", "waf": "waf_samples"}
_FETCH_TABLES: dict[str, str] = {
    "cwl": "cwl_fetch",
    "s3": "s3_fetch",
    "waf": "waf_fetch",
}

_write_lock = threading.Lock()

# The dedup index wraps each key expression in `ifnull(..., '')` rather than
# using bare `json_extract`. SQLite treats NULLs as distinct in unique
# indexes, so a record missing `uri`/`clientIp`/`httpMethod` would otherwise
# duplicate on every overlapping fetch. This is a deliberate deviation from
# the literal locked DDL; it changes nothing for well-formed records.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS waf_logs (
  id        INTEGER PRIMARY KEY,
  log_group TEXT    NOT NULL,
  timestamp INTEGER NOT NULL,
  action    TEXT    NOT NULL,
  record    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_logs_group_ts ON waf_logs(log_group, timestamp);
CREATE INDEX IF NOT EXISTS ix_logs_action   ON waf_logs(action);
CREATE UNIQUE INDEX IF NOT EXISTS ix_logs_dedup ON waf_logs(
  log_group, timestamp,
  ifnull(json_extract(record, '$.httpRequest.uri'), ''),
  ifnull(json_extract(record, '$.httpRequest.clientIp'), ''),
  ifnull(json_extract(record, '$.httpRequest.httpMethod'), '')
);
-- record_count holds the count of records the fetch *returned*, not the
-- count newly inserted (those differ when a gap-fill re-fetches records
-- already present from an earlier overlapping fetch). Observability only;
-- nothing in the cache logic reads this column.
CREATE TABLE IF NOT EXISTS fetch_log (
  id            INTEGER PRIMARY KEY,
  log_group     TEXT    NOT NULL,
  start_time    INTEGER NOT NULL,
  end_time      INTEGER NOT NULL,
  action_filter TEXT,
  profile       TEXT,
  region        TEXT,
  fetched_at    INTEGER NOT NULL,
  record_count  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_fetch_lookup ON fetch_log(log_group, start_time, end_time);
"""

_SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS auth_counts (
  id              INTEGER PRIMARY KEY,
  profile         TEXT    NOT NULL,
  region          TEXT    NOT NULL,
  log_group       TEXT    NOT NULL,
  auth_count      INTEGER NOT NULL,
  events_scanned  INTEGER NOT NULL,
  scanned_at      INTEGER NOT NULL,
  UNIQUE(profile, region, log_group)
);
CREATE TABLE IF NOT EXISTS preferences (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""

# The v1 `waf_logs`/`fetch_log` tables stay in the file but no v3 code reads
# them: CloudWatch moves to cwl_logs/cwl_fetch so all three sources sit behind
# one interface. Every source table repeats the v1 dedup-index shape, including
# the `ifnull(...)` wrappers that keep NULL keys from duplicating on re-fetch.
_SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS cwl_logs (
  id        INTEGER PRIMARY KEY,
  log_group TEXT    NOT NULL,
  timestamp INTEGER NOT NULL,
  action    TEXT    NOT NULL,
  record    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cwl_group_ts ON cwl_logs(log_group, timestamp);
CREATE INDEX IF NOT EXISTS ix_cwl_action   ON cwl_logs(action);
CREATE UNIQUE INDEX IF NOT EXISTS ix_cwl_dedup ON cwl_logs(
  log_group, timestamp,
  ifnull(json_extract(record, '$.httpRequest.uri'), ''),
  ifnull(json_extract(record, '$.httpRequest.clientIp'), ''),
  ifnull(json_extract(record, '$.httpRequest.httpMethod'), '')
);

CREATE TABLE IF NOT EXISTS s3_logs (
  id        INTEGER PRIMARY KEY,
  log_group TEXT    NOT NULL,
  timestamp INTEGER NOT NULL,
  action    TEXT    NOT NULL,
  record    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_s3_group_ts ON s3_logs(log_group, timestamp);
CREATE INDEX IF NOT EXISTS ix_s3_action   ON s3_logs(action);
CREATE UNIQUE INDEX IF NOT EXISTS ix_s3_dedup ON s3_logs(
  log_group, timestamp,
  ifnull(json_extract(record, '$.httpRequest.uri'), ''),
  ifnull(json_extract(record, '$.httpRequest.clientIp'), ''),
  ifnull(json_extract(record, '$.httpRequest.httpMethod'), '')
);

CREATE TABLE IF NOT EXISTS waf_samples (
  id        INTEGER PRIMARY KEY,
  log_group TEXT    NOT NULL,
  timestamp INTEGER NOT NULL,
  action    TEXT    NOT NULL,
  record    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_waf_group_ts ON waf_samples(log_group, timestamp);
CREATE INDEX IF NOT EXISTS ix_waf_action   ON waf_samples(action);
CREATE UNIQUE INDEX IF NOT EXISTS ix_waf_dedup ON waf_samples(
  log_group, timestamp,
  ifnull(json_extract(record, '$.httpRequest.uri'), ''),
  ifnull(json_extract(record, '$.httpRequest.clientIp'), ''),
  ifnull(json_extract(record, '$.httpRequest.httpMethod'), '')
);

-- `sources` is a comma-separated list of the source keys that contributed to
-- the merged record ("cwl", "cwl,waf", ...), so the TUI knows which per-source
-- views it can offer for a selected row without re-querying every table.
CREATE TABLE IF NOT EXISTS merged_logs (
  id        INTEGER PRIMARY KEY,
  log_group TEXT    NOT NULL,
  timestamp INTEGER NOT NULL,
  action    TEXT    NOT NULL,
  record    TEXT    NOT NULL,
  sources   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_merged_group_ts ON merged_logs(log_group, timestamp);
CREATE INDEX IF NOT EXISTS ix_merged_action   ON merged_logs(action);
CREATE UNIQUE INDEX IF NOT EXISTS ix_merged_dedup ON merged_logs(
  log_group, timestamp,
  ifnull(json_extract(record, '$.httpRequest.uri'), ''),
  ifnull(json_extract(record, '$.httpRequest.clientIp'), ''),
  ifnull(json_extract(record, '$.httpRequest.httpMethod'), '')
);

CREATE TABLE IF NOT EXISTS cwl_fetch (
  id            INTEGER PRIMARY KEY,
  log_group     TEXT    NOT NULL,
  start_time    INTEGER NOT NULL,
  end_time      INTEGER NOT NULL,
  action_filter TEXT,
  profile       TEXT,
  region        TEXT,
  fetched_at    INTEGER NOT NULL,
  record_count  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cwl_fetch_lookup ON cwl_fetch(log_group, start_time, end_time);

CREATE TABLE IF NOT EXISTS s3_fetch (
  id            INTEGER PRIMARY KEY,
  log_group     TEXT    NOT NULL,
  start_time    INTEGER NOT NULL,
  end_time      INTEGER NOT NULL,
  action_filter TEXT,
  profile       TEXT,
  region        TEXT,
  fetched_at    INTEGER NOT NULL,
  record_count  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_s3_fetch_lookup ON s3_fetch(log_group, start_time, end_time);

CREATE TABLE IF NOT EXISTS waf_fetch (
  id            INTEGER PRIMARY KEY,
  log_group     TEXT    NOT NULL,
  start_time    INTEGER NOT NULL,
  end_time      INTEGER NOT NULL,
  action_filter TEXT,
  profile       TEXT,
  region        TEXT,
  fetched_at    INTEGER NOT NULL,
  record_count  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_waf_fetch_lookup ON waf_fetch(log_group, start_time, end_time);

-- Keyed by (acl_arn, profile): different profiles can see different ACLs, or
-- the same ACL through different permissions. log_group and s3_bucket are
-- nullable because an ACL may have only one logging destination configured.
CREATE TABLE IF NOT EXISTS acl_mapping (
  id        INTEGER PRIMARY KEY,
  acl_arn   TEXT    NOT NULL,
  acl_name  TEXT    NOT NULL,
  region    TEXT    NOT NULL,
  profile   TEXT    NOT NULL DEFAULT '',
  log_group TEXT,
  s3_bucket TEXT,
  cached_at INTEGER NOT NULL,
  UNIQUE(acl_arn, profile)
);

CREATE TABLE IF NOT EXISTS region_status (
  id            INTEGER PRIMARY KEY,
  profile       TEXT    NOT NULL,
  region        TEXT    NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  discovered_at INTEGER NOT NULL,
  UNIQUE(profile, region)
);
"""

_SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS selector_counts (
  source     TEXT    NOT NULL,
  log_group  TEXT    NOT NULL,
  auth_count INTEGER NOT NULL,
  total      INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(source, log_group)
);
"""


def _validate_source(source: str) -> None:
    """Raise if `source` is not one of the known log sources."""
    if source not in SOURCES:
        raise ValueError(
            f"unknown source {source!r}; expected one of {sorted(SOURCES)}"
        )


def open_db(path: str) -> sqlite3.Connection:
    """Open (creating and migrating if needed) the waf-fu SQLite database at `path`."""
    db_path = Path(path).expanduser()
    pre_existing_nonempty = db_path.exists() and db_path.stat().st_size > 0
    DEBUG(
        "open_db: path=%s exists=%s", _redact_path(str(db_path)), pre_existing_nonempty
    )
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    version = conn.execute("PRAGMA user_version").fetchone()[0]
    DEBUG("open_db: schema_version=%d (current=%d)", version, SCHEMA_VERSION)
    if version > SCHEMA_VERSION:
        conn.close()
        raise RuntimeError(
            f"{db_path} was written by a newer waf-fu (schema v{version}); "
            f"this build understands v{SCHEMA_VERSION}"
        )
    if version == 0:
        if pre_existing_nonempty:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if tables and "waf_logs" not in tables:
                conn.close()
                raise RuntimeError(
                    f"{db_path} is an existing SQLite database that waf-fu did not create"
                )
        conn.executescript(_SCHEMA)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()

    # Separate, non-elif branches (NOT `elif`): a brand-new database must fall
    # through every branch below as well as the `version == 0` branch above,
    # since `version` still holds the pre-migration value read at function
    # entry. Each branch is additive and idempotent (every statement is
    # `IF NOT EXISTS`), so a v1 or v2 database enters only the branches it
    # actually needs.
    if version < 2:
        DEBUG("open_db: migrating v%d -> v2", version)
        conn.executescript(_SCHEMA_V2)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()

    if version < 3:
        DEBUG("open_db: migrating v%d -> v3", version)
        conn.executescript(_SCHEMA_V3)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()

    if version < 4:
        DEBUG("open_db: migrating v%d -> v4", version)
        conn.executescript(_SCHEMA_V4)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()

    return conn


# DEPRECATED: use save_source_records instead. No production path calls this;
# waf_logs is now a dead-letter table holding only pre-v3 rows.
def save_records(conn: sqlite3.Connection, log_group: str, records: list[dict]) -> int:
    """Insert `records` for `log_group`, deduping on the composite key. Returns rows inserted."""
    if not records:
        return 0
    DEBUG(
        "save_records: log_group=%s records=%d", _redact_meta(log_group), len(records)
    )
    rows = [
        (
            log_group,
            int(r.get("timestamp") or 0),
            str(r.get("action") or ""),
            json.dumps(r, separators=(",", ":")),
        )
        for r in records
    ]
    with _write_lock, conn:
        cur = conn.executemany(
            "INSERT OR IGNORE INTO waf_logs(log_group, timestamp, action, record) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
    DEBUG(
        "save_records: inserted=%d (deduped=%d)",
        cur.rowcount,
        len(records) - cur.rowcount,
    )
    return cur.rowcount


# DEPRECATED: use load_source_records instead.
def load_records(
    conn: sqlite3.Connection,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None = None,
) -> list[dict]:
    """Load stored records for `log_group` within `[start_ms, end_ms]` inclusive."""
    DEBUG(
        "load_records: log_group=%s start_ms=%d end_ms=%d action=%s",
        _redact_meta(log_group),
        start_ms,
        end_ms,
        action_filter or "(all)",
    )
    sql = (
        "SELECT record FROM waf_logs "
        "WHERE log_group = ? AND timestamp >= ? AND timestamp <= ?"
    )
    params: list[object] = [log_group, start_ms, end_ms]
    if action_filter:
        sql += " AND action = ?"
        params.append(action_filter)
    sql += " ORDER BY timestamp"
    results = [json.loads(row["record"]) for row in conn.execute(sql, params)]
    DEBUG("load_records: returned %d records", len(results))
    return results


def record_fetch(
    conn: sqlite3.Connection,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None,
    profile: str | None,
    region: str | None,
    count: int,
) -> None:
    """Record that `[start_ms, end_ms]` has been fetched, for future coverage checks."""
    with _write_lock, conn:
        conn.execute(
            "INSERT INTO fetch_log"
            "(log_group, start_time, end_time, action_filter, profile, region, "
            "fetched_at, record_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                log_group,
                start_ms,
                end_ms,
                action_filter,
                profile,
                region,
                int(time.time()),
                count,
            ),
        )


def covered_ranges(
    conn: sqlite3.Connection,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None,
    profile: str | None = None,
    region: str | None = None,
) -> list[tuple[int, int]]:
    """Return previously-fetched `(start, end)` windows overlapping the requested range.

    `IS ?` is null-safe equality: NULL matches NULL, or the same value
    matches, with no branching.
    """
    rows = conn.execute(
        "SELECT start_time, end_time FROM fetch_log "
        "WHERE log_group = ? AND action_filter IS ? "
        "AND profile IS ? AND region IS ? "
        "AND end_time >= ? AND start_time <= ?",
        (log_group, action_filter, profile, region, start_ms, end_ms),
    ).fetchall()
    return [(row["start_time"], row["end_time"]) for row in rows]


# DEPRECATED: use list_source_log_groups instead.
def list_log_groups(conn: sqlite3.Connection) -> list[str]:
    """Return the distinct log groups that have stored records, for the offline selector."""
    return [
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT log_group FROM waf_logs ORDER BY log_group"
        )
    ]


# --- Per-source tables (schema v3) -------------------------------------------
#
# These mirror the v1 functions above one-for-one but resolve their table from
# `source` instead of hardcoding waf_logs/fetch_log. Table names cannot be
# bound as SQL parameters, so they are interpolated -- but only after
# `_validate_source` restricts `source` to the three literal keys of
# `_LOG_TABLES`/`_FETCH_TABLES`, so no caller-controlled text reaches the SQL.


def save_source_records(
    conn: sqlite3.Connection, source: str, log_group: str, records: list[dict]
) -> int:
    """Insert `records` into `source`'s log table, deduping. Returns rows inserted."""
    _validate_source(source)
    if not records:
        return 0
    table = _LOG_TABLES[source]
    DEBUG(
        "save_source_records: source=%s log_group=%s records=%d",
        source,
        _redact_meta(log_group),
        len(records),
    )
    rows = [
        (
            log_group,
            int(r.get("timestamp") or 0),
            str(r.get("action") or ""),
            json.dumps(r, separators=(",", ":")),
        )
        for r in records
    ]
    with _write_lock, conn:
        cur = conn.executemany(
            f"INSERT OR IGNORE INTO {table}(log_group, timestamp, action, record) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
    DEBUG(
        "save_source_records: source=%s inserted=%d (deduped=%d)",
        source,
        cur.rowcount,
        len(records) - cur.rowcount,
    )
    return cur.rowcount


def load_source_records(
    conn: sqlite3.Connection,
    source: str,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None = None,
) -> list[dict]:
    """Load `source`'s stored records for `log_group` within `[start_ms, end_ms]`."""
    _validate_source(source)
    table = _LOG_TABLES[source]
    DEBUG(
        "load_source_records: source=%s log_group=%s start_ms=%d end_ms=%d action=%s",
        source,
        _redact_meta(log_group),
        start_ms,
        end_ms,
        action_filter or "(all)",
    )
    sql = (
        f"SELECT record FROM {table} "
        "WHERE log_group = ? AND timestamp >= ? AND timestamp <= ?"
    )
    params: list[object] = [log_group, start_ms, end_ms]
    if action_filter:
        sql += " AND action = ?"
        params.append(action_filter)
    sql += " ORDER BY timestamp"
    results = [json.loads(row["record"]) for row in conn.execute(sql, params)]
    DEBUG("load_source_records: source=%s returned %d records", source, len(results))
    return results


def record_source_fetch(
    conn: sqlite3.Connection,
    source: str,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None,
    profile: str | None,
    region: str | None,
    count: int,
) -> None:
    """Record that `source` has fetched `[start_ms, end_ms]`, for coverage checks."""
    _validate_source(source)
    table = _FETCH_TABLES[source]
    with _write_lock, conn:
        conn.execute(
            f"INSERT INTO {table}"
            "(log_group, start_time, end_time, action_filter, profile, region, "
            "fetched_at, record_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                log_group,
                start_ms,
                end_ms,
                action_filter,
                profile,
                region,
                int(time.time()),
                count,
            ),
        )


def covered_source_ranges(
    conn: sqlite3.Connection,
    source: str,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None,
    profile: str | None = None,
    region: str | None = None,
) -> list[tuple[int, int]]:
    """Return `source`'s previously-fetched windows overlapping the requested range."""
    _validate_source(source)
    table = _FETCH_TABLES[source]
    rows = conn.execute(
        f"SELECT start_time, end_time FROM {table} "
        "WHERE log_group = ? AND action_filter IS ? "
        "AND profile IS ? AND region IS ? "
        "AND end_time >= ? AND start_time <= ?",
        (log_group, action_filter, profile, region, start_ms, end_ms),
    ).fetchall()
    return [(row["start_time"], row["end_time"]) for row in rows]


def list_source_log_groups(conn: sqlite3.Connection, source: str) -> list[str]:
    """Return the distinct log groups `source` has stored records for."""
    _validate_source(source)
    table = _LOG_TABLES[source]
    return [
        row[0]
        for row in conn.execute(
            f"SELECT DISTINCT log_group FROM {table} ORDER BY log_group"
        )
    ]


# --- Merged records (schema v3) ----------------------------------------------


def merge_key(record: dict) -> str:
    """Correlation key identifying one logical request across sources."""
    http = record.get("httpRequest") or {}
    timestamp = int(record.get("timestamp") or 0)
    return f"{timestamp}:{http.get('clientIp', '')}:{http.get('uri', '')}"


def save_merged_records(
    conn: sqlite3.Connection,
    log_group: str,
    records: list[dict],
    sources_map: dict[str, str],
) -> int:
    """Write merged `records` for `log_group`, tagging each with its contributing sources.

    `sources_map` maps a `merge_key` to a comma-separated source string
    (`"cwl,waf"`). Unlike the per-source tables this uses INSERT OR REPLACE:
    a re-run of the merge must overwrite the previous merged version of a
    record rather than silently keep the stale one.
    """
    if not records:
        return 0
    DEBUG(
        "save_merged_records: log_group=%s records=%d",
        _redact_meta(log_group),
        len(records),
    )
    rows = [
        (
            log_group,
            int(r.get("timestamp") or 0),
            str(r.get("action") or ""),
            json.dumps(r, separators=(",", ":")),
            sources_map.get(merge_key(r), ""),
        )
        for r in records
    ]
    with _write_lock, conn:
        cur = conn.executemany(
            "INSERT OR REPLACE INTO merged_logs"
            "(log_group, timestamp, action, record, sources) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
    return cur.rowcount


def load_merged_records(
    conn: sqlite3.Connection,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None = None,
) -> list[dict]:
    """Load merged records for `log_group` within `[start_ms, end_ms]` inclusive.

    Each returned dict carries an extra `_sources` key holding the stored
    provenance string. It is injected after `json.loads`, so it never becomes
    part of the persisted record.
    """
    sql = (
        "SELECT record, sources FROM merged_logs "
        "WHERE log_group = ? AND timestamp >= ? AND timestamp <= ?"
    )
    params: list[object] = [log_group, start_ms, end_ms]
    if action_filter:
        sql += " AND action = ?"
        params.append(action_filter)
    sql += " ORDER BY timestamp"
    results = []
    for row in conn.execute(sql, params):
        record = json.loads(row["record"])
        record["_sources"] = row["sources"]
        results.append(record)
    DEBUG("load_merged_records: returned %d records", len(results))
    return results


def delete_merged_records(
    conn: sqlite3.Connection, log_group: str, start_ms: int, end_ms: int
) -> int:
    """Delete merged records in `[start_ms, end_ms]` so a merge can re-run cleanly."""
    with _write_lock, conn:
        cur = conn.execute(
            "DELETE FROM merged_logs "
            "WHERE log_group = ? AND timestamp >= ? AND timestamp <= ?",
            (log_group, start_ms, end_ms),
        )
    return cur.rowcount


# --- ACL mapping cache (schema v3) -------------------------------------------

_ACL_COLUMN_NAMES = (
    "acl_arn",
    "acl_name",
    "region",
    "profile",
    "log_group",
    "s3_bucket",
    "cached_at",
)
_ACL_COLUMNS = ", ".join(_ACL_COLUMN_NAMES)


def _acl_row(row: sqlite3.Row) -> dict:
    return dict(zip(_ACL_COLUMN_NAMES, row, strict=True))


def upsert_acl_mapping(
    conn: sqlite3.Connection,
    acl_arn: str,
    acl_name: str,
    region: str,
    profile: str | None,
    log_group: str | None,
    s3_bucket: str | None,
) -> None:
    """Cache an ACL's logging destinations, replacing any existing (acl_arn, profile) row."""
    with _write_lock, conn:
        conn.execute(
            f"INSERT OR REPLACE INTO acl_mapping({_ACL_COLUMNS}) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                acl_arn,
                acl_name,
                region,
                profile or "",
                log_group,
                s3_bucket,
                int(time.time()),
            ),
        )


def get_acl_mapping_for_log_group(
    conn: sqlite3.Connection, log_group: str, profile: str | None = None
) -> dict | None:
    """Return the cached ACL mapping whose CWL destination is `log_group`, or None."""
    sql = f"SELECT {_ACL_COLUMNS} FROM acl_mapping WHERE log_group = ?"
    params: list[object] = [log_group]
    if profile is not None:
        sql += " AND profile = ?"
        params.append(profile)
    row = conn.execute(sql, params).fetchone()
    if row is None:
        return None
    return _acl_row(row)


def list_acl_mappings(
    conn: sqlite3.Connection, region: str | None = None, profile: str | None = None
) -> list[dict]:
    """Return cached ACL mappings, optionally narrowed to a region and/or profile."""
    sql = f"SELECT {_ACL_COLUMNS} FROM acl_mapping"
    clauses: list[str] = []
    params: list[object] = []
    if region is not None:
        clauses.append("region = ?")
        params.append(region)
    if profile is not None:
        clauses.append("profile = ?")
        params.append(profile)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY acl_name"
    return [_acl_row(row) for row in conn.execute(sql, params)]


def _auth_key(profile: str | None, region: str | None) -> tuple[str, str]:
    return (profile or "default", region or "")


def upsert_auth_count(
    conn: sqlite3.Connection,
    profile: str | None,
    region: str | None,
    log_group: str,
    auth_count: int,
    events_scanned: int,
) -> None:
    """Insert or replace the auth-count summary for (profile, region, log_group).

    `profile`/`region` are normalized via `_auth_key` (`None` -> `"default"`/
    `""`), matching the key convention the old JSON log-counts file used.
    """
    norm_profile, norm_region = _auth_key(profile, region)
    with _write_lock, conn:
        conn.execute(
            "INSERT INTO auth_counts"
            "(profile, region, log_group, auth_count, events_scanned, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(profile, region, log_group) "
            "DO UPDATE SET auth_count = excluded.auth_count, "
            "events_scanned = excluded.events_scanned, "
            "scanned_at = excluded.scanned_at",
            (
                norm_profile,
                norm_region,
                log_group,
                auth_count,
                events_scanned,
                int(time.time()),
            ),
        )


def get_auth_count(
    conn: sqlite3.Connection,
    profile: str | None,
    region: str | None,
    log_group: str,
) -> tuple[int, int] | None:
    """Return `(auth_count, events_scanned)` for (profile, region, log_group), or None."""
    norm_profile, norm_region = _auth_key(profile, region)
    row = conn.execute(
        "SELECT auth_count, events_scanned FROM auth_counts "
        "WHERE profile = ? AND region = ? AND log_group = ?",
        (norm_profile, norm_region, log_group),
    ).fetchone()
    if row is None:
        return None
    return (row["auth_count"], row["events_scanned"])


def count_auth_by_log_group(
    conn: sqlite3.Connection,
    source: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None = None,
) -> dict[str, tuple[int, int]]:
    """Return `{log_group: (auth_count, total)}` from `source`'s records in the window.

    Unlike `get_auth_count` (a snapshot keyed by profile/region) this is derived
    from the records themselves, so it always reflects the window the caller is
    actually looking at.
    """
    _validate_source(source)
    # Deferred: cloudwatch imports storage at module scope.
    from waf_fu.cloudwatch import _has_replayable_auth

    table = _LOG_TABLES[source]
    sql = (
        f"SELECT log_group, record FROM {table} WHERE timestamp >= ? AND timestamp <= ?"
    )
    params: list[object] = [start_ms, end_ms]
    if action_filter:
        sql += " AND action = ?"
        params.append(action_filter)

    tallies: dict[str, list[int]] = {}
    for row in conn.execute(sql, params):
        entry = tallies.setdefault(row["log_group"], [0, 0])
        entry[1] += 1
        try:
            record = json.loads(row["record"])
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(record, dict):
            continue
        headers = (record.get("httpRequest") or {}).get("headers") or []
        if _has_replayable_auth(headers):
            entry[0] += 1

    DEBUG(
        "count_auth_by_log_group: source=%s groups=%d start_ms=%d end_ms=%d",
        source,
        len(tallies),
        start_ms,
        end_ms,
    )
    return {group: (auth, total) for group, (auth, total) in tallies.items()}


def record_auth_counts(
    conn: sqlite3.Connection,
    profile: str | None,
    region: str | None,
    log_group: str,
    requests: list[ReconstructedRequest],
) -> tuple[int, int]:
    """Derive `(auth_count, total)` from parsed requests and upsert the summary.

    The one shared place the "which entries count as auth" rule lives for the
    load path -- `cloudwatch._has_replayable_auth` covers the raw-header
    (scan) path separately; this must not re-derive that logic.
    """
    auth_count = sum(1 for r in requests if r.has_replayable_auth)
    total = len(requests)
    upsert_auth_count(conn, profile, region, log_group, auth_count, total)
    return (auth_count, total)


# ── selector_counts (cached auth/total for log-group overlay) ────────────


def upsert_selector_counts(
    conn: sqlite3.Connection,
    source: str,
    counts: dict[str, tuple[int, int]],
) -> None:
    """Bulk upsert `{log_group: (auth_count, total)}` into ``selector_counts``."""
    _validate_source(source)
    now = int(time.time())
    with _write_lock, conn:
        for log_group, (auth, total) in counts.items():
            conn.execute(
                "INSERT INTO selector_counts"
                "(source, log_group, auth_count, total, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(source, log_group) "
                "DO UPDATE SET auth_count = excluded.auth_count, "
                "total = excluded.total, "
                "updated_at = excluded.updated_at",
                (source, log_group, auth, total, now),
            )


def get_selector_counts(
    conn: sqlite3.Connection,
    source: str,
) -> dict[str, tuple[int, int]]:
    """Return all cached ``{log_group: (auth_count, total)}`` for *source*."""
    _validate_source(source)
    rows = conn.execute(
        "SELECT log_group, auth_count, total FROM selector_counts WHERE source = ?",
        (source,),
    ).fetchall()
    return {r["log_group"]: (r["auth_count"], r["total"]) for r in rows}


def refresh_selector_counts(
    conn: sqlite3.Connection,
    source: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None = None,
    log_group: str | None = None,
) -> None:
    """Recompute auth/total counts from source records and cache them.

    When *log_group* is given, only that group is recomputed.  Otherwise all
    groups in the window are recomputed.
    """
    all_counts = count_auth_by_log_group(conn, source, start_ms, end_ms, action_filter)
    if log_group is not None:
        entry = all_counts.get(log_group)
        if entry is not None:
            upsert_selector_counts(conn, source, {log_group: entry})
    else:
        if all_counts:
            upsert_selector_counts(conn, source, all_counts)


def upsert_region_status(
    conn: sqlite3.Connection,
    profile: str | None,
    region: str,
    enabled: bool,
) -> None:
    """Record whether `region` is enabled (API-reachable) for `profile`."""
    norm_profile = profile or "default"
    with _write_lock, conn:
        conn.execute(
            "INSERT INTO region_status (profile, region, enabled, discovered_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(profile, region) "
            "DO UPDATE SET enabled = excluded.enabled, "
            "discovered_at = excluded.discovered_at",
            (norm_profile, region, int(enabled), int(time.time())),
        )


def get_enabled_regions(
    conn: sqlite3.Connection,
    profile: str | None,
) -> set[str] | None:
    """Return the set of enabled regions for `profile`, or None if no data cached."""
    norm_profile = profile or "default"
    rows = conn.execute(
        "SELECT region, enabled FROM region_status WHERE profile = ?",
        (norm_profile,),
    ).fetchall()
    if not rows:
        return None
    return {row["region"] for row in rows if row["enabled"]}


def get_preference(
    conn: sqlite3.Connection, key: str, default: str | None = None
) -> str | None:
    """Return the stored preference value for `key`, or `default` if unset."""
    row = conn.execute("SELECT value FROM preferences WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    return row["value"]


def set_preference(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Insert or replace the preference value for `key`."""
    with _write_lock, conn:
        conn.execute(
            "INSERT INTO preferences (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def compute_gaps(
    start_ms: int, end_ms: int, covered: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Sub-ranges of `[start_ms, end_ms)` not covered by any range in `covered`.

    An empty return means full coverage: zero CloudWatch calls are needed.
    """
    gaps: list[tuple[int, int]] = []
    cursor = start_ms
    for c_start, c_end in sorted(covered):
        if c_end <= cursor:
            continue
        if c_start >= end_ms:
            break
        if c_start > cursor:
            gaps.append((cursor, min(c_start, end_ms)))
        cursor = max(cursor, c_end)
        if cursor >= end_ms:
            return gaps
    if cursor < end_ms:
        gaps.append((cursor, end_ms))
    return gaps


# DEPRECATED: use load_source_with_cache instead.
def load_with_cache(
    conn: sqlite3.Connection,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None,
    profile: str | None,
    region: str | None,
    fetch_fn: Callable[..., list[dict]],
    refresh: bool = False,
) -> list[dict]:
    """Load records for `[start_ms, end_ms]`, fetching only uncovered gaps.

    `refresh=True` skips the coverage check entirely and re-fetches the
    whole requested window (still persisted, still recorded, extending
    future coverage).

    `record_fetch` is called only after `fetch_fn` returns and `save_records`
    commits — recording coverage before a successful fetch would poison the
    cache permanently on failure (an expired token, a throttle) since every
    later run would report a cache hit with zero records. On a multi-gap
    fill where a later gap fails, earlier gaps remain legitimately recorded.

    `fetch_fn` is called with keyword names matching
    `cloudwatch.fetch_logs_from_cloudwatch`'s actual parameters
    (`log_group`, `start_time`, `end_time`, `action_filter`, `profile`,
    `region`) but with millisecond-int values rather than `datetime`
    objects, since this module stays in ms throughout and never imports
    `cloudwatch`. Callers pass a thin wrapper that converts ms to
    `datetime` before delegating to the real fetch function.
    """
    if refresh:
        gaps = [(start_ms, end_ms)]
        DEBUG("load_with_cache: refresh=True, forcing full fetch")
    else:
        covered = covered_ranges(
            conn, log_group, start_ms, end_ms, action_filter, profile, region
        )
        gaps = compute_gaps(start_ms, end_ms, covered)
        DEBUG(
            "load_with_cache: log_group=%s window=[%d,%d] covered_ranges=%d gaps=%d",
            _redact_meta(log_group),
            start_ms,
            end_ms,
            len(covered),
            len(gaps),
        )

    if not gaps:
        DEBUG("load_with_cache: full cache hit, no fetch needed")

    for i, (g_start, g_end) in enumerate(gaps):
        DEBUG(
            "load_with_cache: fetching gap %d/%d [%d,%d]",
            i + 1,
            len(gaps),
            g_start,
            g_end,
        )
        try:
            records = fetch_fn(
                log_group=log_group,
                start_time=g_start,
                end_time=g_end,
                action_filter=action_filter,
                profile=profile,
                region=region,
            )
        except Exception as exc:
            # Network/credential failure filling a gap -- return whatever is
            # already cached rather than losing all data.  Earlier gaps that
            # succeeded are already persisted; only this gap and later ones
            # are skipped.
            DEBUG("load_with_cache: fetch FAILED gap %d/%d: %s", i + 1, len(gaps), exc)
            break
        DEBUG(
            "load_with_cache: gap %d/%d returned %d records",
            i + 1,
            len(gaps),
            len(records),
        )
        save_records(conn, log_group, records)
        record_fetch(
            conn,
            log_group,
            g_start,
            g_end,
            action_filter,
            profile,
            region,
            len(records),
        )

    return load_records(conn, log_group, start_ms, end_ms, action_filter)


def load_source_with_cache(
    conn: sqlite3.Connection,
    source: str,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None,
    profile: str | None,
    region: str | None,
    fetch_fn: Callable[..., list[dict]],
    refresh: bool = False,
) -> list[dict]:
    """Like `load_with_cache` but targets source-specific tables."""
    _validate_source(source)
    if refresh:
        gaps = [(start_ms, end_ms)]
    else:
        covered = covered_source_ranges(
            conn, source, log_group, start_ms, end_ms, action_filter, profile, region
        )
        gaps = compute_gaps(start_ms, end_ms, covered)

    for g_start, g_end in gaps:
        try:
            records = fetch_fn(
                log_group=log_group,
                start_time=g_start,
                end_time=g_end,
                action_filter=action_filter,
                profile=profile,
                region=region,
            )
        except Exception:
            break
        save_source_records(conn, source, log_group, records)
        record_source_fetch(
            conn,
            source,
            log_group,
            g_start,
            g_end,
            action_filter,
            profile,
            region,
            len(records),
        )

    return load_source_records(conn, source, log_group, start_ms, end_ms, action_filter)
