"""Field-level best-of merge across the CWL, S3, and GetSampledRequests sources.

The three log sources describe the same requests from different angles: CWL and
S3 carry the request body and full rule metadata but honour the ACL's
`RedactedFields` configuration, while `GetSampledRequests` never redacts but
never carries a body. Merging is therefore per-field, not per-record: a single
merged record can take its `Authorization` header from WAF sampling and its body
from CWL.

Records are correlated by `correlation_key` (timestamp truncated to the second,
plus clientIp and URI). Second-level tolerance matters because sampled-request
timestamps have no sub-second precision while CWL timestamps are milliseconds.

This module knows nothing about how records were fetched -- it reads the
already-normalized records out of the storage tables, so it never imports
`cloudwatch`, `s3`, or `waf_api`. Every function except `run_merge` is pure and
testable without a database.
"""

from __future__ import annotations

import copy
import sqlite3
from collections.abc import Mapping

# Order in which sources are preferred when no redaction is involved. CWL is
# canonical, S3 supplements it, and WAF sampling only fills in what the other
# two had masked.
_SOURCE_PRIORITY: list[str] = ["cwl", "s3", "waf"]


def correlation_key(record: dict) -> str:
    """Build a `'{ts_seconds}:{clientIp}:{uri}'` correlation key for a WAF record."""
    http = record.get("httpRequest") or {}
    ts_sec = int(record.get("timestamp") or 0) // 1000
    return f"{ts_sec}:{http.get('clientIp') or ''}:{http.get('uri') or ''}"


def is_redacted(value: str | None) -> bool:
    """True if `value` looks redacted/masked: empty, "REDACTED", or containing "***".

    Deliberately conservative -- anything ambiguous counts as *not* redacted, so
    the source-priority order decides instead.
    """
    if not value:
        return True
    stripped = value.strip()
    return stripped.upper() == "REDACTED" or "***" in stripped


def _ordered_sources(by_source: Mapping[str, object]) -> list[str]:
    """Source keys of `by_source`, highest priority first, unknown keys last."""
    known = [s for s in _SOURCE_PRIORITY if s in by_source]
    return known + [s for s in by_source if s not in _SOURCE_PRIORITY]


def _header_pair(header: dict) -> tuple[str, str]:
    """Return `(name, value)` from a header dict in either casing.

    WAF log records (CWL, S3) use `{"name", "value"}`; `GetSampledRequests`
    returns the API-native `{"Name", "Value"}` and `waf_api` passes it through
    untouched, so both spellings reach the merge.
    """
    name = header.get("name", header.get("Name"))
    value = header.get("value", header.get("Value"))
    return (str(name or ""), str(value or ""))


def merge_headers(headers_by_source: dict[str, list[dict]]) -> list[dict]:
    """Merge `httpRequest.headers` arrays across sources, header by header.

    Headers are matched on a case-insensitive name. For each name the value
    comes from the highest-priority source whose value is not redacted, falling
    back to the highest-priority source when every value is redacted. Names
    unique to a lower-priority source are appended after the CWL ones, so CWL's
    header order survives the merge.
    """
    values_by_name: dict[str, dict[str, str]] = {}
    display_names: dict[str, str] = {}
    order: list[str] = []

    for source in _ordered_sources(headers_by_source):
        for header in headers_by_source.get(source) or []:
            name, value = _header_pair(header)
            if not name:
                continue
            key = name.lower()
            if key not in values_by_name:
                values_by_name[key] = {}
                display_names[key] = name
                order.append(key)
            values_by_name[key].setdefault(source, value)

    merged: list[dict] = []
    for key in order:
        values = values_by_name[key]
        ordered = _ordered_sources(values)
        chosen = next(
            (values[s] for s in ordered if not is_redacted(values[s])),
            values[ordered[0]],
        )
        merged.append({"name": display_names[key], "value": chosen})
    return merged


def _best_http_field(
    records_by_source: dict[str, dict], sources: list[str], field: str
) -> str | None:
    """Best value for `httpRequest[field]`: first non-redacted in priority order."""
    values = {}
    for source in sources:
        http = records_by_source[source].get("httpRequest") or {}
        if field in http:
            values[source] = http[field]
    if not values:
        return None
    ordered = _ordered_sources(values)
    return next(
        (values[s] for s in ordered if not is_redacted(str(values[s] or ""))),
        values[ordered[0]],
    )


def merge_record_group(records_by_source: dict[str, dict]) -> dict:
    """Merge one correlated group of records into a single best-of WAF record.

    `records_by_source` maps a source key (`"cwl"`, `"s3"`, `"waf"`) to that
    source's version of the request.
    """
    sources = _ordered_sources(records_by_source)
    if not sources:
        return {}
    # A record seen by exactly one non-sampling source needs no merging at all.
    # Sampled-only records still go through the merge so their API-cased headers
    # are normalized and the absent body is made explicit.
    if len(sources) == 1 and sources[0] != "waf":
        return records_by_source[sources[0]]

    merged = copy.deepcopy(records_by_source[sources[0]])
    http: dict = merged.setdefault("httpRequest", {})

    http["headers"] = merge_headers(
        {
            source: (records_by_source[source].get("httpRequest") or {}).get("headers")
            or []
            for source in sources
        }
    )

    for field in ("uri", "args", "httpMethod", "clientIp", "country", "httpVersion"):
        best = _best_http_field(records_by_source, sources, field)
        if best is not None:
            http[field] = best

    # WAF sampling never carries a body, so it is excluded as a body source
    # outright rather than losing to CWL/S3 on priority.
    body_source = next(
        (
            s
            for s in ("cwl", "s3")
            if (records_by_source.get(s, {}).get("httpRequest") or {}).get(
                "requestBody"
            )
        ),
        None,
    )
    if body_source is None:
        http["requestBody"] = ""
        http["requestBodySize"] = 0
    else:
        body_http = records_by_source[body_source]["httpRequest"]
        http["requestBody"] = body_http.get("requestBody", "")
        http["requestBodySize"] = body_http.get(
            "requestBodySize", len(body_http.get("requestBody") or "")
        )

    # Top-level metadata (action, terminatingRuleId, ruleGroupList, labels, ...)
    # only ever comes from CWL then S3; a sampled request carries a thin subset
    # of it and would otherwise overwrite a legitimately empty log field.
    for source in sources[1:]:
        if source == "waf":
            continue
        for key, value in records_by_source[source].items():
            if key == "httpRequest":
                continue
            if not merged.get(key):
                merged[key] = copy.deepcopy(value)

    return merged


def correlate_records(
    cwl_records: list[dict],
    s3_records: list[dict],
    waf_records: list[dict],
) -> list[dict[str, dict]]:
    """Group records from the three sources by `correlation_key`.

    Each returned element maps a source key to that source's record, e.g.
    `{"cwl": {...}, "waf": {...}}`. A record matching nothing in the other
    sources becomes its own single-entry group. Duplicates within one source
    (two CWL rows one millisecond apart) keep the first record seen.
    """
    groups: dict[str, dict[str, dict]] = {}
    for source, records in (
        ("cwl", cwl_records),
        ("s3", s3_records),
        ("waf", waf_records),
    ):
        for record in records:
            groups.setdefault(correlation_key(record), {}).setdefault(source, record)
    return list(groups.values())


def run_merge(
    conn: sqlite3.Connection,
    log_group: str,
    start_ms: int,
    end_ms: int,
    action_filter: str | None = None,
) -> int:
    """Merge every source's records for `[start_ms, end_ms]` into `merged_logs`.

    Existing merged rows for the window are deleted first, so a re-run after a
    new fetch replaces the previous merge rather than layering onto it. Returns
    the number of merged records written.
    """
    from waf_fu import storage

    per_source = {
        source: storage.load_source_records(
            conn, source, log_group, start_ms, end_ms, action_filter
        )
        for source in _SOURCE_PRIORITY
    }

    merged_records: list[dict] = []
    sources_map: dict[str, str] = {}
    for group in correlate_records(
        per_source["cwl"], per_source["s3"], per_source["waf"]
    ):
        merged = merge_record_group(group)
        if not merged:
            continue
        merged_records.append(merged)
        # Keyed with storage's own merge_key (full-millisecond timestamp), not
        # correlation_key -- save_merged_records looks the provenance up by
        # merge_key, so a second-granularity key would never match.
        sources_map[storage.merge_key(merged)] = ",".join(_ordered_sources(group))

    storage.delete_merged_records(conn, log_group, start_ms, end_ms)
    storage.save_merged_records(conn, log_group, merged_records, sources_map)
    return len(merged_records)
