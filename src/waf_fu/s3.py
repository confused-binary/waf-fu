"""S3 WAF log fetching: bucket discovery, date-path listing, gzip NDJSON parsing."""

from __future__ import annotations

import gzip
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

WAF_BUCKET_PREFIX = "aws-waf-logs-"


def _client_kwargs(region: str | None) -> dict[str, str]:
    return {"region_name": region} if region else {}


def _session(profile: str | None, region: str | None = None) -> Any:
    from waf_fu.aws_session import get_session

    return get_session(profile)


def _list_common_prefixes(client: Any, bucket: str, prefix: str) -> list[str]:
    """Return the immediate child path segments under `prefix` in `bucket`."""
    segments: list[str] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "Bucket": bucket,
            "Prefix": prefix,
            "Delimiter": "/",
        }
        if token:
            kwargs["ContinuationToken"] = token
        resp = client.list_objects_v2(**kwargs)
        for entry in resp.get("CommonPrefixes", []):
            segment = entry.get("Prefix", "")[len(prefix) :].strip("/")
            if segment:
                segments.append(segment)
        token = resp.get("NextContinuationToken")
        if not token:
            break
    return segments


def discover_waf_buckets(
    profile: str | None = None,
    region: str | None = None,
) -> list[str]:
    """List S3 buckets matching the aws-waf-logs-* naming convention."""
    client = _session(profile).client("s3", **_client_kwargs(region))
    resp = client.list_buckets()
    names = [
        b["Name"]
        for b in resp.get("Buckets", [])
        if b["Name"].startswith(WAF_BUCKET_PREFIX)
    ]
    names.sort()
    logger.debug("discover_waf_buckets: found %d bucket(s)", len(names))
    return names


def list_waf_acl_names(
    bucket: str,
    profile: str | None = None,
    region: str | None = None,
) -> list[str]:
    """Discover distinct WAF ACL names writing to a bucket.

    Walks AWSLogs/{account}/WAFLogs/{region}/ with Delimiter='/' and collects
    the ACL-name level of the WAF log path hierarchy.
    """
    client = _session(profile).client("s3", **_client_kwargs(region))

    acl_names: set[str] = set()
    for account in _list_common_prefixes(client, bucket, "AWSLogs/"):
        base = f"AWSLogs/{account}/WAFLogs/"
        regions = [region] if region else _list_common_prefixes(client, bucket, base)
        for log_region in regions:
            acl_names.update(
                _list_common_prefixes(client, bucket, f"{base}{log_region}/")
            )

    logger.debug("list_waf_acl_names: %s has %d ACL(s)", bucket, len(acl_names))
    return sorted(acl_names)


def fetch_logs_from_s3(
    bucket: str,
    start_time: datetime,
    end_time: datetime,
    acl_name: str | None = None,
    profile: str | None = None,
    region: str | None = None,
    action_filter: str | None = None,
) -> list[dict]:
    """Fetch WAF log records from S3 for the given time range.

    Lists objects by date-path prefix, downloads each gzip NDJSON object,
    parses records, and returns them as list[dict] -- same format as
    fetch_logs_from_cloudwatch.
    """
    session = _session(profile)
    rkw = _client_kwargs(region)
    client = session.client("s3", **rkw)
    account = session.client("sts", **rkw).get_caller_identity()["Account"]
    log_region = region or session.region_name

    acl_names = (
        [acl_name]
        if acl_name
        else list_waf_acl_names(bucket, profile=profile, region=region)
    )
    hour_prefixes = _date_prefixes(start_time, end_time)

    records: list[dict] = []
    objects = 0
    for acl in acl_names:
        for hour in hour_prefixes:
            prefix = f"AWSLogs/{account}/WAFLogs/{log_region}/{acl}/{hour}/"
            token: str | None = None
            while True:
                kwargs: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
                if token:
                    kwargs["ContinuationToken"] = token
                resp = client.list_objects_v2(**kwargs)
                for obj in resp.get("Contents", []):
                    body = client.get_object(Bucket=bucket, Key=obj["Key"])[
                        "Body"
                    ].read()
                    objects += 1
                    for record in _parse_s3_object(body):
                        if action_filter and record.get("action") != action_filter:
                            continue
                        records.append(record)
                token = resp.get("NextContinuationToken")
                if not token:
                    break

    logger.debug(
        "fetch_logs_from_s3: bucket=%s acls=%d objects=%d records=%d",
        bucket,
        len(acl_names),
        objects,
        len(records),
    )
    return records


def fetch_latest_s3_records(
    bucket: str,
    acl_name: str | None = None,
    profile: str | None = None,
    region: str | None = None,
    action_filter: str | None = None,
) -> list[dict]:
    """Fetch records from just the single most-recent WAF log object in `bucket`.

    Lighter weight than `fetch_logs_from_s3`: rather than listing and downloading
    every object in a time range, this walks backwards hour-by-hour (up to 48h)
    until it finds the first non-empty hour prefix, downloads only the most
    recent object in that hour, and returns immediately. Used by
    `--auth-count-sample` for a fast multi-bucket triage.
    """
    session = _session(profile)
    rkw = _client_kwargs(region)
    client = session.client("s3", **rkw)
    account = session.client("sts", **rkw).get_caller_identity()["Account"]
    log_region = region or session.region_name

    acl_names = (
        [acl_name]
        if acl_name
        else list_waf_acl_names(bucket, profile=profile, region=region)
    )

    cursor = datetime.now(tz=UTC)
    objects_checked = 0
    for _ in range(48):
        hour = (
            f"{cursor.year:04d}/{cursor.month:02d}/{cursor.day:02d}/{cursor.hour:02d}"
        )
        for acl in acl_names:
            prefix = f"AWSLogs/{account}/WAFLogs/{log_region}/{acl}/{hour}/"
            resp = client.list_objects_v2(Bucket=bucket, Prefix=prefix)
            contents = resp.get("Contents", [])
            if not contents:
                continue
            objects_checked += len(contents)
            latest_key = max(contents, key=lambda o: o["Key"])["Key"]
            body = client.get_object(Bucket=bucket, Key=latest_key)["Body"].read()
            records = _parse_s3_object(body)
            if action_filter:
                records = [r for r in records if r.get("action") == action_filter]
            logger.debug(
                "fetch_latest_s3_records: bucket=%s objects_checked=%d records=%d",
                bucket,
                objects_checked,
                len(records),
            )
            return records
        cursor -= timedelta(hours=1)

    logger.debug(
        "fetch_latest_s3_records: bucket=%s objects_checked=%d records=0 "
        "(nothing found in 48h)",
        bucket,
        objects_checked,
    )
    return []


def _date_prefixes(start: datetime, end: datetime) -> list[str]:
    """Generate YYYY/MM/dd/HH path segments covering start through end (inclusive)."""
    cursor = start.replace(minute=0, second=0, microsecond=0)
    last = end.replace(minute=0, second=0, microsecond=0)

    prefixes: list[str] = []
    while cursor <= last:
        prefixes.append(
            f"{cursor.year:04d}/{cursor.month:02d}/{cursor.day:02d}/{cursor.hour:02d}"
        )
        cursor += timedelta(hours=1)
    return prefixes


def _parse_s3_object(body: bytes) -> list[dict]:
    """Decompress gzip bytes and parse newline-delimited JSON records."""
    text = gzip.decompress(body).decode("utf-8")

    records: list[dict] = []
    parse_errors = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            parse_errors += 1

    if parse_errors:
        logger.warning("skipped %d malformed NDJSON line(s)", parse_errors)
    return records
