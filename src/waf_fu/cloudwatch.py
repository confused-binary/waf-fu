"""CloudWatch log fetching, log group discovery, and auth-count scanning."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

from waf_fu import storage
from waf_fu.debug import DEBUG, _redact_meta
from waf_fu.jwt import jwt_is_valid

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# WAF log fetching
# ═══════════════════════════════════════════════════════════════════════════════


def fetch_logs_from_cloudwatch(
    log_group: str,
    start_time: datetime,
    end_time: datetime,
    profile: str | None = None,
    region: str | None = None,
    action_filter: str | None = None,
) -> list[dict]:
    from waf_fu.aws_session import get_session

    session = get_session(profile)
    client = session.client("logs", **({"region_name": region} if region else {}))

    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    DEBUG(
        "fetch_logs: log_group=%s start_ms=%d end_ms=%d profile=%s region=%s action=%s",
        _redact_meta(log_group),
        start_ms,
        end_ms,
        _redact_meta(profile, "(default)"),
        region or "(default)",
        action_filter or "(all)",
    )

    events: list[dict] = []
    pages = 0
    parse_errors = 0
    kwargs: dict[str, Any] = {
        "logGroupName": log_group,
        "startTime": start_ms,
        "endTime": end_ms,
        "interleaved": True,
    }

    while True:
        resp = client.filter_log_events(**kwargs)
        pages += 1
        page_events = resp.get("events", [])
        for event in page_events:
            try:
                record = json.loads(event["message"])
                if action_filter and record.get("action") != action_filter:
                    continue
                events.append(record)
            except json.JSONDecodeError:
                parse_errors += 1
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token

    DEBUG(
        "fetch_logs: done pages=%d events=%d parse_errors=%d",
        pages,
        len(events),
        parse_errors,
    )
    return events


_DEFAULT_LOG_PREFIXES = [
    "aws-waf-logs-",
]


def fetch_waf_log_groups(
    profile: str | None = None,
    region: str | None = None,
    prefixes: list[str] | None = None,
    connect_timeout: int = 3,
    read_timeout: int = 5,
) -> list[str]:
    """List CloudWatch log groups matching WAF-related prefixes.

    Default prefix: aws-waf-logs-* (direct WAF → CloudWatch).
    Additional prefixes can be supplied via the prefixes parameter.
    """
    from botocore.config import Config

    from waf_fu.aws_session import get_session

    session = get_session(profile)
    client = session.client(
        "logs",
        config=Config(
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries={"max_attempts": 1},
        ),
        **({"region_name": region} if region else {}),
    )

    search_prefixes = list(_DEFAULT_LOG_PREFIXES)
    for p in prefixes or []:
        if p not in search_prefixes:
            search_prefixes.append(p)

    DEBUG(
        "fetch_waf_log_groups: profile=%s region=%s prefixes=%s",
        _redact_meta(profile, "(default)"),
        region or "(default)",
        search_prefixes,
    )

    seen: set[str] = set()
    groups: list[str] = []

    for prefix in search_prefixes:
        kwargs: dict[str, Any] = {"logGroupNamePrefix": prefix}
        while True:
            resp = client.describe_log_groups(**kwargs)
            for lg in resp.get("logGroups", []):
                name = lg["logGroupName"]
                if name not in seen:
                    seen.add(name)
                    groups.append(name)
            token = resp.get("nextToken")
            if not token:
                break
            kwargs["nextToken"] = token

    groups.sort()
    DEBUG("fetch_waf_log_groups: found %d groups", len(groups))
    return groups


def run_inventory(
    profile: str | None = None,
    prefixes: list[str] | None = None,
) -> None:
    """Scan all AWS regions for WAF-related log groups and print a summary table."""
    # Suppress all AWS SDK error logging during parallel scan
    # (unreachable regions trigger ConnectTimeoutError tracebacks at ERROR level)
    for _lib in ("botocore", "boto3", "urllib3", "s3transfer"):
        logging.getLogger(_lib).setLevel(logging.CRITICAL)

    # Force short timeouts on internal AWS credential resolution (STS/SSO)
    os.environ.setdefault("AWS_METADATA_SERVICE_TIMEOUT", "3")
    os.environ.setdefault("AWS_METADATA_SERVICE_NUM_ATTEMPTS", "1")

    print(f"Scanning {len(AWS_REGIONS)} regions for WAF log groups…", file=sys.stderr)
    print(
        f"Prefixes: {', '.join(_DEFAULT_LOG_PREFIXES + (prefixes or []))}",
        file=sys.stderr,
    )
    print(file=sys.stderr)

    results: dict[str, list[str]] = {}
    skipped: list[str] = []

    def _scan_region(region: str) -> tuple[str, list[str], str]:
        try:
            groups = fetch_waf_log_groups(
                profile=profile,
                region=region,
                prefixes=prefixes,
            )
            return region, groups, ""
        except Exception as exc:
            # Extract short error description
            err_name = type(exc).__name__
            return region, [], err_name

    # Parallel scan — one thread per region, short timeouts
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(AWS_REGIONS)) as pool:
        futures = {pool.submit(_scan_region, r): r for r in AWS_REGIONS}
        done = 0
        try:
            for future in concurrent.futures.as_completed(futures, timeout=15):
                done += 1
                try:
                    region, groups, err = future.result(timeout=5)
                except Exception:
                    region = futures[future]
                    groups = []
                    err = "timeout"
                if groups:
                    results[region] = groups
                elif err:
                    skipped.append(f"{region} ({err})")
                print(
                    f"\r  Scanned {done}/{len(AWS_REGIONS)} regions"
                    f" — {len(results)} with logs so far…",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
        except concurrent.futures.TimeoutError:
            timed_out = len(AWS_REGIONS) - done
            print(
                f"\r  Scanned {done}/{len(AWS_REGIONS)} regions"
                f" ({timed_out} timed out)"
                f" — {len(results)} with logs      ",
                file=sys.stderr,
                flush=True,
            )
            # Mark remaining futures as skipped
            for f, r in futures.items():
                if not f.done():
                    skipped.append(f"{r} (timeout)")
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            print(
                f"\n\n  Inventory cancelled. Partial results: "
                f"{done}/{len(AWS_REGIONS)} regions scanned"
                f" — {len(results)} with logs.",
                file=sys.stderr,
            )
            for f, r in futures.items():
                if not f.done():
                    skipped.append(f"{r} (cancelled)")

    print("\r" + " " * 60 + "\r", end="", file=sys.stderr)

    if not results:
        print("No WAF log groups found in any region.")
        if skipped:
            print(f"\nSkipped {len(skipped)} region(s): {', '.join(skipped)}")
        return

    # Sort by region name
    sorted_regions = sorted(results.keys())

    # Table header
    max_region = max(len(r) for r in sorted_regions)
    col_r = max(max_region, 6)  # "Region" header
    total_groups = sum(len(g) for g in results.values())

    print(f"{'Region':<{col_r}}  {'Count':>5}  Log Groups")
    print(f"{'─' * col_r}  {'─' * 5}  {'─' * 50}")

    for region in sorted_regions:
        groups = results[region]
        first = groups[0] if groups else ""
        print(f"{region:<{col_r}}  {len(groups):>5}  {first}")
        for g in groups[1:]:
            print(f"{'':<{col_r}}  {'':>5}  {g}")

    print(f"{'─' * col_r}  {'─' * 5}  {'─' * 50}")
    print(f"{'TOTAL':<{col_r}}  {total_groups:>5}  across {len(results)} region(s)")

    if skipped:
        print(f"\nSkipped {len(skipped)} region(s): {', '.join(skipped)}")


AWS_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-south-1",
    "eu-south-2",
    "eu-north-1",
    "il-central-1",
    "me-south-1",
    "me-central-1",
    "sa-east-1",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Auth count scanning (SQLite-backed — see waf_fu.storage.upsert_auth_count)
# ═══════════════════════════════════════════════════════════════════════════════


def _has_replayable_auth(headers: list[dict]) -> bool:
    """Check if a WAF log entry's headers contain usable authentication data.

    Mirrors ``ReconstructedRequest.has_replayable_auth`` for raw header dicts:
    authorization (excluding expired JWTs), cookies, and every name in
    ``ReconstructedRequest._AUTH_HEADER_NAMES`` (x-auth-token, x-api-key, etc.).
    """
    from waf_fu.models import ReconstructedRequest

    for header in headers:
        name = header.get("name", "").lower()
        value = header.get("value", "")
        if not value:
            continue
        if name == "authorization":
            jwt_status = jwt_is_valid(value)
            return jwt_status is not False
        if name == "cookie":
            return True
        if name in ReconstructedRequest._AUTH_HEADER_NAMES:
            return True
    return False


def count_auth_in_log_group(
    log_group: str,
    profile: str | None = None,
    region: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    max_events: int = 1000,
) -> tuple[int, int, list[dict]]:
    """Scan up to max_events in a log group and count entries with replayable auth.
    Returns (auth_count, total_events_scanned, records), where records is the
    list of successfully-parsed WAF records examined (records that fail to
    parse still count toward total_events_scanned but are not appended)."""
    from waf_fu.aws_session import get_session

    session = get_session(profile)
    client = session.client("logs", **({"region_name": region} if region else {}))

    if end_time is None:
        end_time = datetime.now(UTC)
    if start_time is None:
        start_time = end_time - timedelta(hours=6)

    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    DEBUG("count_auth: log_group=%s max_events=%d", _redact_meta(log_group), max_events)

    auth_count = 0
    total_scanned = 0
    records: list[dict] = []
    kwargs: dict[str, Any] = {
        "logGroupName": log_group,
        "startTime": start_ms,
        "endTime": end_ms,
        "interleaved": True,
    }

    while True:
        resp = client.filter_log_events(**kwargs)
        for event in resp.get("events", []):
            total_scanned += 1
            try:
                record = json.loads(event["message"])
                records.append(record)
                http_req = record.get("httpRequest", {})
                if _has_replayable_auth(http_req.get("headers", [])):
                    auth_count += 1
            except (json.JSONDecodeError, AttributeError):
                pass
            if max_events > 0 and total_scanned >= max_events:
                DEBUG(
                    "count_auth: hit max_events limit, auth=%d/%d",
                    auth_count,
                    total_scanned,
                )
                return auth_count, total_scanned, records
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token

    DEBUG("count_auth: done auth=%d/%d", auth_count, total_scanned)
    return auth_count, total_scanned, records


def scan_region_auth_counts(
    profile: str | None,
    region: str,
    conn: sqlite3.Connection,
    prefixes: list[str] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    max_events: int = 1000,
    progress_callback=None,
) -> dict[str, int]:
    """Scan all WAF log groups in a single region, writing an auth-count
    summary row and the sampled records to `conn` for each group.
    Returns {log_group: auth_count}."""
    for _lib in ("botocore", "boto3", "urllib3", "s3transfer"):
        logging.getLogger(_lib).setLevel(logging.CRITICAL)

    DEBUG(
        "scan_region: region=%s profile=%s", region, _redact_meta(profile, "(default)")
    )
    try:
        groups = fetch_waf_log_groups(
            profile=profile,
            region=region,
            prefixes=prefixes,
        )
    except Exception as exc:
        DEBUG("scan_region: failed to list groups in %s: %s", region, exc)
        return {}

    if not groups:
        DEBUG("scan_region: no groups in %s", region)
        return {}

    DEBUG("scan_region: %s has %d groups", region, len(groups))
    results: dict[str, int] = {}

    for i, lg in enumerate(groups):
        if progress_callback:
            progress_callback(region, lg, i + 1, len(groups))
        try:
            count, scanned, records = count_auth_in_log_group(
                lg,
                profile=profile,
                region=region,
                start_time=start_time,
                end_time=end_time,
                max_events=max_events,
            )
            results[lg] = count
            # save first so a sampled record set is persisted even
            # if it duplicates rows from an earlier fetch (INSERT OR IGNORE).
            storage.save_source_records(conn, "cwl", lg, records)
            storage.upsert_auth_count(conn, profile, region, lg, count, scanned)
        except Exception as exc:
            DEBUG(
                "scan_region: error scanning %s in %s: %s",
                _redact_meta(lg),
                region,
                exc,
            )

    DEBUG("scan_region: %s complete, %d groups with auth", region, len(results))
    return results


def scan_all_regions_auth_counts(
    profile: str | None,
    conn: sqlite3.Connection,
    prefixes: list[str] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    max_events: int = 1000,
    progress_callback=None,
) -> dict[str, dict[str, int]]:
    """Scan every region boto3 reports as supporting wafv2 for auth counts.
    Returns {region: {log_group: count}}."""
    from waf_fu.aws_session import get_session

    session = get_session(profile)
    regions = session.get_available_regions("wafv2")
    if not regions:
        return {}

    all_results: dict[str, dict[str, int]] = {}

    def _scan_one(region: str) -> tuple[str, dict[str, int]]:
        result = scan_region_auth_counts(
            profile=profile,
            region=region,
            conn=conn,
            prefixes=prefixes,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            progress_callback=progress_callback,
        )
        return region, result

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(regions)) as pool:
        futures = {pool.submit(_scan_one, r): r for r in regions}
        for future in concurrent.futures.as_completed(futures):
            try:
                region, result = future.result(timeout=300)
                if result:
                    all_results[region] = result
            except Exception:
                pass

    return all_results
