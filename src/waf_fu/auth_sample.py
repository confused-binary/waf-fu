"""Shared auth-count sampling logic used by both CLI (-ac) and TUI (c/C)."""

from __future__ import annotations

import concurrent.futures
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any

from waf_fu import s3 as s3_mod
from waf_fu import storage, waf_api
from waf_fu.cloudwatch import (
    AWS_REGIONS,
    count_auth_in_log_group,
    fetch_waf_log_groups,
)
from waf_fu.debug import DEBUG

_WORKERS = 8

ProgressCallback = Callable[[str, str], None]
"""on_progress(phase, message) -- called under a lock, safe to update UI."""


def all_wafv2_regions(profile: str | None) -> list[str]:
    """Regions the account has opted into that also offer wafv2."""
    from waf_fu.aws_session import get_session

    session = get_session(profile)
    all_wafv2 = set(session.get_available_regions("wafv2") or AWS_REGIONS)

    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        resp = ec2.describe_regions(
            Filters=[
                {
                    "Name": "opt-in-status",
                    "Values": ["opt-in-not-required", "opted-in"],
                }
            ],
            AllRegions=False,
        )
        opted_in = {r["RegionName"] for r in resp.get("Regions", [])}
        if opted_in:
            result = sorted(all_wafv2 & opted_in)
            DEBUG(
                "wafv2_regions: %d opted-in, %d with wafv2, %d after intersection",
                len(opted_in),
                len(all_wafv2),
                len(result),
            )
            return result
    except Exception as exc:
        DEBUG("wafv2_regions: ec2:DescribeRegions failed, using full list: %s", exc)

    return sorted(all_wafv2)


def discover_region(profile: str | None, region: str) -> dict[str, Any]:
    """Discover CWL log groups, WAF ACLs and log destinations in one region."""
    from botocore.exceptions import BotoCoreError, ClientError

    DEBUG("discover_region: region=%s profile=%s", region, profile)

    try:
        raw_log_groups = fetch_waf_log_groups(profile=profile, region=region)
    except (ClientError, BotoCoreError) as exc:
        DEBUG("discover_region: CWL discovery failed in %s: %s", region, exc)
        raw_log_groups = None
    try:
        raw_acls = waf_api.list_web_acls(profile=profile, region=region)
    except (ClientError, BotoCoreError) as exc:
        DEBUG("discover_region: WAF discovery failed in %s: %s", region, exc)
        raw_acls = None

    enabled = raw_log_groups is not None or raw_acls is not None
    log_groups = raw_log_groups or []
    acls = raw_acls or []

    mappings = []
    for acl in acls:
        try:
            dest = waf_api.get_logging_configuration(
                acl.get("ARN", ""), profile, region
            )
        except (ClientError, BotoCoreError):
            dest = None
        mappings.append(
            {
                "acl_arn": acl.get("ARN", ""),
                "acl_name": acl.get("Name", ""),
                "log_group": (dest or {}).get("log_group"),
                "s3_bucket": (dest or {}).get("s3_bucket"),
            }
        )

    DEBUG(
        "discover_region: region=%s enabled=%s cwl=%d acls=%d",
        region, enabled, len(log_groups), len(acls),
    )
    return {
        "region": region,
        "log_groups": log_groups,
        "mappings": mappings,
        "enabled": enabled,
    }


def _is_access_denied(exc: Exception) -> bool:
    """True when *exc* is a ClientError with an access-denied error code."""
    from botocore.exceptions import ClientError

    if not isinstance(exc, ClientError):
        return False
    code = exc.response.get("Error", {}).get("Code", "")
    return code in ("AccessDenied", "AccessDeniedException")


class SampleResult:
    """Mutable accumulator for auth-count sample results."""

    __slots__ = (
        "auth_total",
        "counts",
        "denied",
        "discovered",
        "regions_scanned",
        "scanned_total",
    )

    def __init__(self) -> None:
        self.counts: dict[str, int] = {"cwl": 0, "s3": 0, "waf": 0}
        self.denied: dict[str, int] = {"cwl": 0, "s3": 0, "waf": 0}
        self.auth_total: int = 0
        self.scanned_total: int = 0
        self.regions_scanned: int = 0
        self.discovered: list[dict[str, Any]] = []

    @property
    def waf_denied(self) -> int:
        return self.denied["waf"]

    def summary(self) -> str:
        parts = []
        if self.regions_scanned > 1:
            parts.append(f"({self.regions_scanned} regions)")
        line = f"Sample done {' '.join(parts)}: ".lstrip(": ") if parts else "Sample done: "
        line = line.rstrip()
        line += (
            f" CWL={self.counts['cwl']:,}"
            f" S3={self.counts['s3']:,}"
            f" WAF={self.counts['waf']:,}"
        )
        if self.scanned_total:
            line += f" (auth: {self.auth_total:,}/{self.scanned_total:,})"
        total_denied = sum(self.denied.values())
        if total_denied:
            denied_parts = [
                f"{k.upper()}={v:,}" for k, v in self.denied.items() if v
            ]
            line += f" | denied: {' '.join(denied_parts)}"
        return line


def run_auth_count_sample(
    conn: Any,
    regions: list[str],
    profile: str | None,
    start_time: datetime,
    end_time: datetime,
    *,
    log_location: str | None = None,
    action_filter: str | None = None,
    s3_region: str | None = None,
    on_progress: ProgressCallback | None = None,
) -> SampleResult:
    """Discover and sample auth counts across the given regions.

    This is the single implementation backing CLI ``-ac``, TUI ``c``
    (single region) and TUI ``C`` (all regions). Callers differ only in
    which regions they pass and how they render progress.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    result = SampleResult()
    result.regions_scanned = len(regions)

    do_cwl = not log_location or log_location == "cwl"
    do_s3 = not log_location or log_location == "s3"
    do_waf = not log_location or log_location == "waf"

    lock = threading.Lock()

    def _progress(phase: str, msg: str) -> None:
        if on_progress:
            on_progress(phase, msg)

    # --- region discovery (concurrent) --------------------------------------
    disc_done = 0

    def _discover_one(rgn: str) -> dict[str, Any]:
        nonlocal disc_done
        info = discover_region(profile, rgn)
        with lock:
            disc_done += 1
            _progress("discover", f"Discovering {disc_done}/{len(regions)} regions")
        return info

    _progress("discover", f"Discovering sources in {len(regions)} regions")
    with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        discovered = list(pool.map(_discover_one, regions))
    result.discovered = discovered

    # Cache region + ACL status
    for info in discovered:
        storage.upsert_region_status(
            conn, profile, info["region"], info["enabled"]
        )
        for mapping in info["mappings"]:
            storage.upsert_acl_mapping(
                conn,
                mapping["acl_arn"],
                mapping["acl_name"],
                info["region"],
                profile,
                mapping["log_group"],
                mapping["s3_bucket"],
            )

    # --- build work lists ---------------------------------------------------
    cwl_items: list[tuple[str, str]] = []
    if do_cwl:
        cwl_items = [
            (r["region"], lg) for r in discovered for lg in r["log_groups"]
        ]

    s3_buckets: list[str] = []
    if do_s3:
        try:
            s3_buckets = s3_mod.discover_waf_buckets(
                profile=profile, region=s3_region
            )
        except (ClientError, BotoCoreError) as exc:
            DEBUG("auth_count_sample: S3 discovery failed: %s", exc)

    acl_targets: list[tuple[str, dict]] = []
    if do_waf:
        acl_targets = [
            (r["region"], m)
            for r in discovered
            for m in r["mappings"]
            if m.get("acl_arn")
        ]

    # Interleave so no single source starves others in the pool
    typed_work: list[tuple[str, Any]] = []
    queues: dict[str, Any] = {
        "cwl": iter(cwl_items),
        "s3": iter(s3_buckets),
        "waf": iter(acl_targets),
    }
    active = list(queues)
    while active:
        for src in list(active):
            item = next(queues[src], None)
            if item is None:
                active.remove(src)
            else:
                typed_work.append((src, item))

    total_work = len(typed_work)
    if total_work == 0:
        _progress("done", "No sources found")
        return result

    work_done = 0

    def _tick() -> None:
        nonlocal work_done
        work_done += 1
        _progress("sample", f"Sampling {work_done}/{total_work}")

    # --- worker functions ---------------------------------------------------
    def _do_cwl(region_lg: tuple[str, str]) -> None:
        rgn, lg = region_lg
        try:
            ac, total_scanned, records = count_auth_in_log_group(
                lg,
                profile=profile,
                region=rgn,
                start_time=start_time,
                end_time=end_time,
                max_events=10000,
            )
        except (ClientError, BotoCoreError) as exc:
            with lock:
                if _is_access_denied(exc):
                    result.denied["cwl"] += 1
                else:
                    DEBUG("auth_count_sample: CWL error %s: %s", lg, exc)
                _tick()
            return
        with lock:
            storage.save_source_records(conn, "cwl", lg, records)
            storage.upsert_auth_count(conn, profile, rgn, lg, ac, total_scanned)
            result.counts["cwl"] += total_scanned
            result.auth_total += ac
            result.scanned_total += total_scanned
            _tick()

    def _do_s3(bucket: str) -> None:
        try:
            records = s3_mod.fetch_latest_s3_records(
                bucket,
                profile=profile,
                region=s3_region,
                action_filter=action_filter,
            )
        except (ClientError, BotoCoreError) as exc:
            with lock:
                if _is_access_denied(exc):
                    result.denied["s3"] += 1
                else:
                    DEBUG("auth_count_sample: S3 error %s: %s", bucket, exc)
                _tick()
            return
        with lock:
            if records:
                storage.save_source_records(conn, "s3", bucket, records)
                result.counts["s3"] += len(records)
            _tick()

    def _do_waf(region_mapping: tuple[str, dict]) -> None:
        rgn, mapping = region_mapping
        acl_arn = mapping["acl_arn"]
        acl_id = acl_arn.rsplit("/", 1)[-1]
        try:
            samples = waf_api.fetch_all_sampled_for_acl(
                acl_arn,
                mapping["acl_name"],
                acl_id,
                start_time,
                end_time,
                profile,
                rgn,
            )
        except (ClientError, BotoCoreError) as exc:
            with lock:
                if _is_access_denied(exc):
                    result.denied["waf"] += 1
                else:
                    DEBUG("auth_count_sample: WAF error %s: %s", mapping["acl_name"], exc)
                _tick()
            return
        with lock:
            if samples:
                key = mapping.get("log_group") or mapping["acl_name"]
                storage.save_source_records(conn, "waf", key, samples)
                result.counts["waf"] += len(samples)
            _tick()

    dispatchers = {"cwl": _do_cwl, "s3": _do_s3, "waf": _do_waf}
    active_sources = {s for s, _ in typed_work}
    ac_workers = min(total_work, _WORKERS * len(active_sources))

    _progress("sample", f"Sampling 0/{total_work}")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(ac_workers, 1)
    ) as pool:
        futures = [
            pool.submit(dispatchers[src], item) for src, item in typed_work
        ]
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as exc:
                DEBUG("auth_count_sample: worker error: %s", exc)

    return result
