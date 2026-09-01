"""Command-line entry point: argparse definition and mode dispatch."""

from __future__ import annotations

import argparse
import concurrent.futures
import curses
import logging
import sqlite3
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from waf_fu import merge, storage, waf_api
from waf_fu import s3 as s3_mod
from waf_fu.banner import banner_ansi
from waf_fu.cloudwatch import fetch_logs_from_cloudwatch
from waf_fu.debug import (
    DEBUG,
    _console_suppressor,
    _init_debug,
    _redact_meta,
    _redact_path,
    _set_redact,
)
from waf_fu.export import export_har, export_json, write_curl_script
from waf_fu.models import load_filter_rules_yaml, parse_all, parse_time_arg
from waf_fu.tui import WafTUI

# ═══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════════════════════

logger = logging.getLogger(__name__)

# Region fan-out for --inventory. Bounded well below the region count so a
# scan of every region does not open ~30 concurrent AWS sessions at once.
_INVENTORY_WORKERS = 8


def _progress_bar(current: int, total: int, width: int = 30) -> str:
    """Render a `[####------] 40%`-style progress bar for stderr status lines."""
    fraction = 0.0 if total <= 0 else min(max(current / total, 0.0), 1.0)
    filled = round(fraction * width)
    bar = "#" * filled + "-" * (width - filled)
    pct = round(fraction * 100)
    return f"[{bar}] {pct:3d}%"


def _try_aws[T](what: str, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T | None:
    """Run an optional AWS call, returning None instead of raising.

    S3 and WAF-API access are additive: a user holding only CloudWatch
    permissions must still get a working tool, so `AccessDenied`, missing
    credentials and unreachable endpoints all degrade to "this source has
    nothing to offer" rather than aborting the run.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        return fn(*args, **kwargs)
    except (ClientError, BotoCoreError) as exc:
        logger.debug("%s unavailable: %s", what, exc)
        DEBUG(
            "_try_aws FAILED: %s | profile=%s region=%s | %s: %s",
            what,
            kwargs.get("profile", "(pos/unset)"),
            kwargs.get("region", "(pos/unset)"),
            type(exc).__name__,
            exc,
        )
        return None


def _acl_id_from_arn(acl_arn: str) -> str:
    """WAF ACL ARNs end in `.../webacl/{name}/{id}`; GetWebACL needs that id."""
    return acl_arn.rsplit("/", 1)[-1]


def _fetch_via_cloudwatch_ms(
    *,
    log_group: str,
    start_time: int,
    end_time: int,
    action_filter: str | None = None,
    profile: str | None = None,
    region: str | None = None,
) -> list[dict]:
    """`storage.load_source_with_cache`'s `fetch_fn` seam: it calls `fetch_fn` with
    millisecond-int `start_time`/`end_time`, but `fetch_logs_from_cloudwatch`
    takes `datetime` objects. This wrapper converts before delegating, so
    `storage.py` never imports `cloudwatch` or boto3.
    """
    return fetch_logs_from_cloudwatch(
        log_group=log_group,
        start_time=datetime.fromtimestamp(start_time / 1000, tz=UTC),
        end_time=datetime.fromtimestamp(end_time / 1000, tz=UTC),
        profile=profile,
        region=region,
        action_filter=action_filter,
    )


def _s3_fetch_adapter(bucket: str, acl_name: str | None) -> Callable[..., list[dict]]:
    """Build a `storage.load_source_with_cache` `fetch_fn` bound to one S3 bucket.

    The bucket is captured rather than derived from `log_group` because the two
    deliberately differ: `--inventory` files an ACL's S3 rows under that
    ACL's CloudWatch log group so the merge correlates them with the CWL rows.
    """

    def _fetch(
        *,
        log_group: str,
        start_time: int,
        end_time: int,
        action_filter: str | None = None,
        profile: str | None = None,
        region: str | None = None,
    ) -> list[dict]:
        return s3_mod.fetch_logs_from_s3(
            bucket=bucket,
            start_time=datetime.fromtimestamp(start_time / 1000, tz=UTC),
            end_time=datetime.fromtimestamp(end_time / 1000, tz=UTC),
            acl_name=acl_name,
            profile=profile,
            region=region,
            action_filter=action_filter,
        )

    return _fetch


def _enrich_with_waf_samples(
    conn: sqlite3.Connection,
    profile: str | None,
    log_group: str,
    start_time: datetime,
    end_time: datetime,
) -> int:
    """Fetch GetSampledRequests records for `log_group`'s cached ACL. Returns count.

    Samples are stored under the CloudWatch log group key rather than the ACL
    name so `merge.run_merge` correlates them with that group's other sources.
    Returns 0 whenever no mapping is cached or the WAF API is unavailable.
    """
    mapping = storage.get_acl_mapping_for_log_group(conn, log_group)
    if not mapping or not mapping.get("acl_arn"):
        logger.debug("no cached ACL mapping for %s; skipping WAF sampling", log_group)
        return 0

    acl_arn = mapping["acl_arn"]
    samples = _try_aws(
        f"WAF sampling for {mapping['acl_name']}",
        waf_api.fetch_all_sampled_for_acl,
        acl_arn,
        mapping["acl_name"],
        _acl_id_from_arn(acl_arn),
        start_time,
        end_time,
        profile,
        mapping["region"] or None,
    )
    if not samples:
        return 0
    storage.save_source_records(conn, "waf", log_group, samples)
    return len(samples)


def _prompt_choice(kind: str, items: list[str]) -> str | None:
    """Pick one of `items` on the terminal, auto-selecting a lone candidate.

    This runs before curses starts, so it is a plain numbered prompt rather
    than one of the TUI's overlay selectors.
    """
    if not items:
        return None
    if len(items) == 1:
        print(f"Using the only {kind}: {items[0]}", file=sys.stderr)
        return items[0]

    print(f"Select a {kind}:", file=sys.stderr)
    for index, item in enumerate(items, 1):
        print(f"  {index:>3}. {item}", file=sys.stderr)
    try:
        answer = input(f"{kind} [1-{len(items)}]: ").strip()
    except EOFError:
        return None
    if not answer.isdigit() or not 1 <= int(answer) <= len(items):
        return None
    return items[int(answer) - 1]


def _resolve_product_target(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    """Fill `args.log_group` for `--log-location s3`/`--log-location waf` when it is absent.

    For those two products `--log-group` does not name a CloudWatch group at
    all: it is the S3 bucket (optionally `bucket:acl-name`) or the web ACL name.
    """
    if args.log_location == "s3":
        buckets = (
            _try_aws(
                "S3 bucket discovery",
                s3_mod.discover_waf_buckets,
                profile=args.profile,
                region=args.region,
            )
            or []
        )
        chosen = _prompt_choice("S3 bucket", buckets)
        if not chosen:
            parser.error(
                "--log-location s3 found no WAF log bucket to read "
                "(pass --log-group BUCKET[:ACL_NAME])"
            )
    else:
        acls = (
            _try_aws(
                "WAF ACL discovery",
                waf_api.list_web_acls,
                profile=args.profile,
                region=args.region,
            )
            or []
        )
        chosen = _prompt_choice("WAF ACL", [acl.get("Name", "") for acl in acls])
        if not chosen:
            parser.error(
                "--log-location waf found no web ACL to sample (pass --log-group ACL_NAME)"
            )
    args.log_group = chosen


def _load_waf_samples(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    start_time: datetime,
    end_time: datetime,
) -> list[dict]:
    """`--log-location waf`: sample one ACL named by `--log-group` via GetSampledRequests.

    Samples are stored under the ACL name, keeping them separate from the
    CloudWatch-keyed rows the default enrichment path writes for the same ACL.
    """
    acl_name = args.log_group
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    acls = (
        _try_aws(
            "WAF ACL lookup",
            waf_api.list_web_acls,
            profile=args.profile,
            region=args.region,
        )
        or []
    )
    acl = next((a for a in acls if a.get("Name") == acl_name), None)
    if acl is None:
        logger.debug("no web ACL named %s; serving cached samples only", acl_name)
        return storage.load_source_records(
            conn, "waf", acl_name, start_ms, end_ms, args.action
        )

    acl_arn = acl.get("ARN", "")
    destinations = (
        _try_aws(
            f"logging configuration for {acl_name}",
            waf_api.get_logging_configuration,
            acl_arn,
            args.profile,
            args.region,
        )
        or {}
    )
    storage.upsert_acl_mapping(
        conn,
        acl_arn,
        acl_name,
        args.region or "",
        args.profile,
        destinations.get("log_group"),
        destinations.get("s3_bucket"),
    )

    samples = _try_aws(
        f"WAF sampling for {acl_name}",
        waf_api.fetch_all_sampled_for_acl,
        acl_arn,
        acl_name,
        acl.get("Id") or _acl_id_from_arn(acl_arn),
        start_time,
        end_time,
        args.profile,
        args.region,
    )
    if samples:
        storage.save_source_records(conn, "waf", acl_name, samples)

    records = storage.load_source_records(
        conn, "waf", acl_name, start_ms, end_ms, args.action
    )
    # GetSampledRequests returns API-native {Name, Value} headers and waf_api
    # stores them untouched. The merge normalizes that casing, but --log-location waf
    # skips the merge, so parsing would otherwise see no headers at all.
    for record in records:
        http = record.get("httpRequest") or {}
        http["headers"] = merge.merge_headers({"waf": http.get("headers") or []})
    return records


def _load_records(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    start_time: datetime,
    end_time: datetime,
) -> list[dict]:
    """Load one run's records, honouring `--log-location`.

    With no `--log-location` the CloudWatch rows are enriched with WAF sampled
    requests (which `RedactedFields` never masks) and merged. That enrichment is
    best-effort: an uncached ACL mapping, an inaccessible WAF API or an empty
    merge each leave the plain CloudWatch rows in place.
    """
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    if args.log_location == "s3":
        bucket, _, acl_name = args.log_group.partition(":")
        return storage.load_source_with_cache(
            conn,
            "s3",
            args.log_group,
            start_ms,
            end_ms,
            args.action,
            args.profile,
            args.region,
            _s3_fetch_adapter(bucket, acl_name or None),
            args.refresh,
        )

    if args.log_location == "waf":
        return _load_waf_samples(conn, args, start_time, end_time)

    records = storage.load_source_with_cache(
        conn,
        "cwl",
        args.log_group,
        start_ms,
        end_ms,
        args.action,
        args.profile,
        args.region,
        _fetch_via_cloudwatch_ms,
        args.refresh,
    )
    if args.log_location == "cwl":
        return records

    if not _enrich_with_waf_samples(
        conn, args.profile, args.log_group, start_time, end_time
    ):
        return records
    if not merge.run_merge(conn, args.log_group, start_ms, end_ms, args.action):
        return records
    return storage.load_merged_records(
        conn, args.log_group, start_ms, end_ms, args.action
    )


def _load_db_only_records(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    start_time: datetime,
    end_time: datetime,
) -> list[dict]:
    """`--db-only`: read straight from SQLite. No AWS calls, no fetch-coverage
    bookkeeping (unlike `_load_records`'s cache path, which would otherwise
    mark the whole -- possibly all-time -- requested window as covered).
    """
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)
    source = args.log_location or "cwl"

    if source == "cwl":
        records = storage.load_merged_records(
            conn, args.log_group, start_ms, end_ms, args.action
        )
        if not records:
            records = storage.load_source_records(
                conn, "cwl", args.log_group, start_ms, end_ms, args.action
            )
        return records
    return storage.load_source_records(
        conn, source, args.log_group, start_ms, end_ms, args.action
    )


def _all_wafv2_regions(profile: str | None) -> list[str]:
    from waf_fu.auth_sample import all_wafv2_regions

    return all_wafv2_regions(profile)


def _discover_region(profile: str | None, region: str) -> dict[str, Any]:
    from waf_fu.auth_sample import discover_region

    return discover_region(profile, region)


def _run_auto_inventory(
    args: argparse.Namespace, start_time: datetime, end_time: datetime
) -> None:
    """Discover, fetch and merge every log source across every region, then report."""
    conn = storage.open_db(args.sqlite)
    cancelled = False
    regions: list[str] = []
    discovered: list[dict[str, Any]] = []
    buckets: list[str] = []
    counts = {"cwl": 0, "s3": 0, "waf": 0}
    merge_keys: set[str] = set()
    log_group_total = 0
    acl_total = 0
    merged_total = 0
    try:
        regions = _all_wafv2_regions(args.profile)
        print(
            f"Scanning {len(regions)} regions for WAF log sources…",
            file=sys.stderr,
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=_INVENTORY_WORKERS
        ) as pool:
            futures = {
                pool.submit(_discover_region, args.profile, region): region
                for region in regions
            }
            done = 0
            try:
                for future in concurrent.futures.as_completed(futures):
                    discovered.append(future.result())
                    done += 1
                    bar = _progress_bar(done, len(regions))
                    print(
                        f"\r  Regions {bar} {done}/{len(regions)}",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )
            except KeyboardInterrupt:
                pool.shutdown(wait=False, cancel_futures=True)
                raise

        print(
            f"\rDiscovered {len(regions)} regions" + " " * 40,
            file=sys.stderr,
            flush=True,
        )

        # ACL mappings are cached first so the CWL fetch loop below can look up
        # each log group's ACL when enriching with sampled requests.
        for result in discovered:
            for mapping in result["mappings"]:
                storage.upsert_acl_mapping(
                    conn,
                    mapping["acl_arn"],
                    mapping["acl_name"],
                    result["region"],
                    args.profile,
                    mapping["log_group"],
                    mapping["s3_bucket"],
                )
                acl_total += 1

        # S3 bucket listing is account-global, so it is done once rather than
        # once per region.
        buckets = (
            _try_aws(
                "S3 bucket discovery",
                s3_mod.discover_waf_buckets,
                profile=args.profile,
                region=args.region,
            )
            or []
        )

        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)

        log_group_target = sum(len(r["log_groups"]) for r in discovered)
        for result in discovered:
            for log_group in result["log_groups"]:
                log_group_total += 1
                bar = _progress_bar(log_group_total, log_group_target)
                print(
                    f"\r  CWL     {bar} {log_group_total}/{log_group_target}",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
                counts["cwl"] += len(
                    storage.load_source_with_cache(
                        conn,
                        "cwl",
                        log_group,
                        start_ms,
                        end_ms,
                        args.action,
                        args.profile,
                        result["region"],
                        _fetch_via_cloudwatch_ms,
                        args.refresh,
                    )
                )
                counts["waf"] += _enrich_with_waf_samples(
                    conn, args.profile, log_group, start_time, end_time
                )
                merge_keys.add(log_group)

        cached_mappings = storage.list_acl_mappings(conn)
        for i, bucket in enumerate(buckets):
            bar = _progress_bar(i + 1, len(buckets))
            print(
                f"\r  S3      {bar} {i + 1}/{len(buckets)}",
                end="",
                file=sys.stderr,
                flush=True,
            )
            mapping = next(
                (
                    m
                    for m in cached_mappings
                    if m["s3_bucket"] == bucket and m["log_group"]
                ),
                None,
            )
            key = mapping["log_group"] if mapping else bucket
            counts["s3"] += len(
                storage.load_source_with_cache(
                    conn,
                    "s3",
                    key,
                    start_ms,
                    end_ms,
                    args.action,
                    args.profile,
                    mapping["region"] if mapping else args.region,
                    _s3_fetch_adapter(bucket, mapping["acl_name"] if mapping else None),
                    args.refresh,
                )
            )
            merge_keys.add(key)

        merged_total = sum(
            merge.run_merge(conn, key, start_ms, end_ms, args.action)
            for key in sorted(merge_keys)
        )
    except KeyboardInterrupt:
        cancelled = True
        print(
            "\n\n  Inventory cancelled. Showing partial results.",
            file=sys.stderr,
        )
    finally:
        conn.close()

    print("\r" + " " * 80 + "\r", end="")
    print()
    if cancelled:
        print("(partial results — cancelled before completion)")
    print(f"Regions scanned:     {len(regions)}")
    print(f"CWL log groups:      {log_group_total}")
    print(f"S3 buckets:          {len(buckets)}")
    print(f"WAF ACLs:            {acl_total}")
    print(f"Records (cwl):       {counts['cwl']}")
    print(f"Records (s3):        {counts['s3']}")
    print(f"Records (waf):       {counts['waf']}")
    print(f"Merged records:      {merged_total}")


def _run_auth_count_sample(
    args: argparse.Namespace, start_time: datetime, end_time: datetime
) -> None:
    """Lightweight multi-source auth triage via shared auth_sample module."""
    from waf_fu.auth_sample import all_wafv2_regions, run_auth_count_sample

    conn = storage.open_db(args.sqlite)
    cancelled = False

    all_regions = all_wafv2_regions(args.profile)
    if args.refresh:
        regions = all_regions
    else:
        cached_enabled = storage.get_enabled_regions(conn, args.profile)
        if cached_enabled is not None:
            regions = [r for r in all_regions if r in cached_enabled]
            skipped = len(all_regions) - len(regions)
            if skipped:
                print(
                    f"Skipping {skipped} disabled regions "
                    f"(use --refresh to re-scan all)",
                    file=sys.stderr,
                )
        else:
            regions = all_regions

    print(
        f"Sampling auth counts across {len(regions)} regions…",
        file=sys.stderr,
    )

    def _on_progress(phase: str, msg: str) -> None:
        if phase in ("discover", "sample"):
            print(f"\r  {msg:<72}", end="", file=sys.stderr, flush=True)

    try:
        sr = run_auth_count_sample(
            conn,
            regions,
            args.profile,
            start_time,
            end_time,
            log_location=args.log_location,
            action_filter=args.action,
            s3_region=args.region,
            on_progress=_on_progress,
        )
        source = args.log_location or "cwl"
        storage.refresh_selector_counts(
            conn,
            source,
            int(start_time.timestamp() * 1000),
            int(end_time.timestamp() * 1000),
            args.action,
        )
    except KeyboardInterrupt:
        cancelled = True
        sr = None
        print(
            "\n\n  Auth count sample cancelled.",
            file=sys.stderr,
        )
    finally:
        conn.close()

    print("\r" + " " * 80 + "\r", end="")
    print()

    if sr is None:
        return
    if cancelled:
        print("(partial results — cancelled before completion)")
    print("Auth Count Sample Results")
    print("-------------------------")
    print(f"Regions scanned:     {sr.regions_scanned:,}")
    cwl_line = f"CWL records:         {sr.counts['cwl']:,}"
    if sr.scanned_total:
        cwl_line += f"  (auth: {sr.auth_total:,}/{sr.scanned_total:,})"
    print(cwl_line)
    print(f"S3 records:          {sr.counts['s3']:,}")
    print(f"WAF samples:         {sr.counts['waf']:,}")
    total_denied = sum(sr.denied.values())
    if total_denied:
        print()
        labels = {
            "cwl": "CWL FilterLogEvents",
            "s3": "S3 GetObject",
            "waf": "WAF GetSampledRequests",
        }
        for src, count in sr.denied.items():
            if count:
                print(f"{labels[src]} denied: {count:,}")


def main() -> None:
    _DESC = "Browse, filter, replay, and export AWS WAF v2 logs."

    class _BannerParser(argparse.ArgumentParser):
        def format_help(self):
            return banner_ansi(_DESC) + "\n" + super().format_help()

    class _CompactHelp(argparse.HelpFormatter):
        def __init__(self, prog):
            super().__init__(prog, max_help_position=40, width=90)

    parser = _BannerParser(
        prog="waf-fu",
        add_help=False,
        formatter_class=_CompactHelp,
    )

    # ── AWS ──
    aws = parser.add_argument_group("AWS")
    aws.add_argument("-p", "--profile", help="AWS CLI profile name")
    aws.add_argument("-r", "--region", help="AWS region")
    source_group = aws.add_mutually_exclusive_group()
    source_group.add_argument(
        "-lg", "--log-group", help="CloudWatch log group (omit for picker)"
    )
    source_group.add_argument(
        "-s3", "--s3-bucket", metavar="BUCKET", help="S3 bucket for WAF logs"
    )
    aws.add_argument(
        "-ll",
        "--log-location",
        choices=["cwl", "s3", "waf"],
        default=None,
        help="Single source: cwl, s3, or waf",
    )

    # ── System ──
    system = parser.add_argument_group("System")
    system.add_argument("-h", "--help", action="help", help="Show this help and exit")
    system.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    system.add_argument(
        "-d",
        "--debug",
        nargs="?",
        const="waf-fu_debug.log",
        default=None,
        metavar="PATH",
        help="Debug log file (default: waf-fu_debug.log)",
    )
    system.add_argument(
        "-R", "--redact", action="store_true", help="Redact client data in debug output"
    )
    system.add_argument(
        "-db",
        "--sqlite",
        default=storage.DEFAULT_DB_PATH,
        metavar="PATH",
        help=f"SQLite DB path (default: {storage.DEFAULT_DB_PATH})",
    )
    system.add_argument(
        "--chromedriver", metavar="PATH", help="Custom chromedriver path"
    )
    system.add_argument("--geckodriver", metavar="PATH", help="Custom geckodriver path")
    system.add_argument(
        "-D",
        "--db-only",
        action="store_true",
        help="Load from SQLite only, no AWS calls",
    )

    # ── Lookup & Filtering ──
    lookup = parser.add_argument_group("Lookup & Filtering")
    lookup.add_argument(
        "-I",
        "--inventory",
        action="store_true",
        help="Fetch all sources across all regions, then exit",
    )
    lookup.add_argument(
        "-ac",
        "--auth-count-sample",
        action="store_true",
        help="Sample auth counts from all sources, then exit",
    )
    lookup.add_argument(
        "-f", "--refresh", action="store_true", help="Force re-fetch, bypass cache"
    )
    lookup.add_argument(
        "-s",
        "--start",
        help="Start time: relative (1h/30m/3d/2w) or ISO-8601 (default: 60m)",
    )
    lookup.add_argument(
        "-e", "--end", help="End time: relative or ISO-8601 (default: now)"
    )
    lookup.add_argument("-a", "--action", help="Filter by action (ALLOW, BLOCK, COUNT)")
    lookup.add_argument(
        "-n", "--limit", type=int, default=0, help="Max entries to load (0=all)"
    )
    lookup.add_argument(
        "-F", "--filters", metavar="FILE", help="YAML filter rules file"
    )

    # ── Output ──
    output = parser.add_argument_group("Output")
    output.add_argument(
        "-m",
        "--mode",
        choices=["tui", "batch-curl", "batch-json", "batch-har"],
        default="tui",
        help="Output mode (default: tui)",
    )
    output.add_argument("-o", "--output", help="Output file for batch modes")
    output.add_argument(
        "-x", "--proxy", default="", metavar="URL", help="Proxy URL for replay"
    )
    output.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=30.0,
        metavar="N",
        help="Replay timeout in seconds (default: 30)",
    )
    output.add_argument(
        "-ar",
        "--auto-refresh",
        type=int,
        default=0,
        metavar="SECS",
        help="TUI auto-refresh interval (0=off)",
    )
    output.add_argument(
        "-E", "--export", metavar="PATH", help="Export cached logs to JSON"
    )

    args = parser.parse_args()

    if args.s3_bucket:
        if args.log_location and args.log_location != "s3":
            parser.error(
                "--s3-bucket implies --log-location s3; "
                "do not combine with a different --log-location"
            )
        args.log_location = "s3"
        args.log_group = args.s3_bucket

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
    )
    # Install console suppressor so TUI can silence console without
    # killing file-based debug logging
    for h in logging.root.handlers:
        h.addFilter(_console_suppressor)
    # Silence noisy AWS SDK loggers (SSO token caching, endpoint discovery, etc.)
    for _lib in ("botocore", "boto3", "urllib3", "s3transfer"):
        logging.getLogger(_lib).setLevel(logging.WARNING)

    if args.redact:
        _set_redact(True)

    if args.debug:
        _init_debug(args.debug)
        DEBUG("")
        DEBUG("=" * 72)
        DEBUG("=== waf-fu debug session started ===")
        DEBUG("=" * 72)
        DEBUG(
            "args: mode=%s proxy=%s verbose=%s redact=%s",
            args.mode,
            args.proxy or "(none)",
            args.verbose,
            args.redact,
        )
        DEBUG(
            "args: log_group=%s profile=%s region=%s",
            _redact_meta(args.log_group),
            _redact_meta(args.profile, "(default)"),
            args.region or "(none)",
        )
        DEBUG(
            "args: sqlite=%s refresh=%s log_location=%s inventory=%s "
            "auth_count_sample=%s db_only=%s",
            _redact_path(args.sqlite),
            args.refresh,
            args.log_location or "(all)",
            args.inventory,
            args.auth_count_sample,
            args.db_only,
        )
        DEBUG(
            "args: start=%s end=%s action=%s limit=%s timeout=%s",
            args.start or "(default)",
            args.end or "(default)",
            args.action or "(all)",
            args.limit,
            args.timeout,
        )
        print(f"Debug logging to: {args.debug}", file=sys.stderr)

    # ── Time window ──
    now = datetime.now(UTC)
    end_time = parse_time_arg(args.end, reference=now) if args.end else now
    start_time = (
        parse_time_arg(args.start, reference=end_time)
        if args.start
        else end_time - timedelta(minutes=60)
    )

    # ── --db-only: no AWS calls anywhere in this run ──
    if args.db_only:
        if not Path(args.sqlite).expanduser().exists():
            parser.error(f"--db-only: database not found at {args.sqlite}")
        if not args.start and not args.end:
            # No time range given: load everything ever cached for the group.
            start_time = datetime.fromtimestamp(0, tz=UTC)
            end_time = datetime(9999, 12, 31, tzinfo=UTC)

    # ── Inventory mode — discover, fetch and merge every source, then exit ──
    if args.inventory:
        if args.db_only:
            parser.error("--inventory always calls AWS; incompatible with --db-only")
        _run_auto_inventory(args, start_time, end_time)
        return

    # ── Auth-count sample mode — lightweight multi-source triage, then exit ──
    if args.auth_count_sample:
        if args.db_only:
            parser.error(
                "--auth-count-sample always calls AWS; incompatible with --db-only"
            )
        _run_auth_count_sample(args, start_time, end_time)
        return

    # ── Export mode — database-to-JSON, terminal like --inventory ──
    if args.export:
        if not args.log_group:
            parser.error("--export requires --log-group")
        export_conn = storage.open_db(args.sqlite)
        try:
            records = storage.load_source_records(
                export_conn,
                "cwl",
                args.log_group,
                int(start_time.timestamp() * 1000),
                int(end_time.timestamp() * 1000),
                args.action,
            )
        finally:
            export_conn.close()
        export_json(parse_all(records), args.export)
        print(f"✔ Exported {len(records)} entries to {args.export}", file=sys.stderr)
        return

    conn = storage.open_db(args.sqlite)

    initial_mode = (
        storage.get_preference(conn, "replay_mode", storage.DEFAULT_REPLAY_MODE)
        or storage.DEFAULT_REPLAY_MODE
    )
    auth_pref_on = (
        storage.get_preference(conn, "auth_filter", storage.DEFAULT_AUTH_FILTER) == "on"
    )
    initial_sort_field = (
        storage.get_preference(conn, "sort_field", storage.DEFAULT_SORT_FIELD)
        or storage.DEFAULT_SORT_FIELD
    )
    initial_sort_dir = (
        storage.get_preference(conn, "sort_dir", storage.DEFAULT_SORT_DIR)
        or storage.DEFAULT_SORT_DIR
    )
    if args.debug:
        DEBUG(
            "resolved: initial_mode=%s auth_filter_pref=%s", initial_mode, auth_pref_on
        )

    # ── Load filter rules from YAML if provided ──
    yaml_filter_rules = []
    if args.filters:
        try:
            yaml_filter_rules = load_filter_rules_yaml(args.filters)
            print(
                f"Loaded {len(yaml_filter_rules)} filter rules from {args.filters}",
                file=sys.stderr,
            )
        except Exception as exc:
            print(f"Error loading filters file: {exc}", file=sys.stderr)
            sys.exit(1)

    # ── --log-location s3/waf pick their own target when --log-group is absent ──
    if not args.log_group and args.log_location in ("s3", "waf"):
        if args.db_only:
            parser.error(
                "--db-only requires --log-group or --s3-bucket when --log-location "
                "is s3 or waf (buckets/ACLs cannot be auto-discovered without AWS access)"
            )
        _resolve_product_target(args, parser)

    # ── If no source specified, launch TUI with log group selector ──
    if not args.log_group:
        if args.mode.startswith("batch"):
            print("batch modes require --log-group", file=sys.stderr)
            sys.exit(1)

        tui = WafTUI(
            [],
            initial_mode=initial_mode,
            auth_filter_default=auth_pref_on,
            source_info={
                "log_group": "",
                "profile": args.profile or "",
                "region": args.region or "",
            },
            initial_filter_rules=yaml_filter_rules,
            aws_context={
                "profile": args.profile,
                "region": args.region,
                "start_time": start_time,
                "end_time": end_time,
                "action_filter": args.action,
                "limit": args.limit,
            },
            proxy=args.proxy,
            timeout=args.timeout,
            db=conn,
            auto_refresh_interval=args.auto_refresh,
            chromedriver_path=args.chromedriver or "",
            geckodriver_path=args.geckodriver or "",
            initial_sort_field=initial_sort_field,
            initial_sort_dir=initial_sort_dir,
            log_location=args.log_location,
            db_only=args.db_only,
        )
        # Suppress console logging during TUI (file debug logging continues)
        _console_suppressor.suppress = True
        try:
            post_output = curses.wrapper(tui.run)
        except KeyboardInterrupt:
            post_output = tui.post_exit_output
        finally:
            _console_suppressor.suppress = False
            tui._cleanup_browser()
            conn.close()

        if post_output:
            curls = [c for c in post_output if c.lstrip().startswith("curl ")]
            errors = [c for c in post_output if not c.lstrip().startswith("curl ")]
            if curls:
                print("\n" + "=" * 72)
                print(f"  {len(curls)} curl command(s) staged during session")
                print("=" * 72 + "\n")
                for i, cmd in enumerate(curls, 1):
                    print(f"# --- Replay {i} ---")
                    print(cmd)
                    print()
            for msg in errors:
                print(msg, file=sys.stderr)
        return

    # ── Load data ──
    print("Loading WAF logs…", file=sys.stderr)
    if args.db_only:
        records = _load_db_only_records(conn, args, start_time, end_time)
    else:
        records = _load_records(conn, args, start_time, end_time)

    if not records:
        if args.mode.startswith("batch"):
            print("No records found — nothing to export.", file=sys.stderr)
            sys.exit(0)
        print(
            "No records found yet — launching TUI (press F5 to refresh).",
            file=sys.stderr,
        )
        records = []

    requests = parse_all(records)
    if args.limit > 0:
        requests = requests[: args.limit]

    print(f"Loaded {len(requests)} entries.", file=sys.stderr)

    auth_count, total = storage.record_auth_counts(
        conn, args.profile, args.region, args.log_group, requests
    )
    storage.refresh_selector_counts(
        conn,
        args.log_location or "cwl",
        int(start_time.timestamp() * 1000),
        int(end_time.timestamp() * 1000),
        args.action,
        log_group=args.log_group,
    )

    # ── Batch modes ──
    if args.mode == "batch-curl":
        out = args.output or "replay.sh"
        write_curl_script(requests, out)
        print(f"✔ Wrote {len(requests)} curl commands to {out}")
        conn.close()
        return
    elif args.mode == "batch-json":
        out = args.output or "replay.json"
        export_json(requests, out)
        print(f"✔ Exported {len(requests)} requests to {out}")
        conn.close()
        return
    elif args.mode == "batch-har":
        out = args.output or "replay.har"
        export_har(requests, out)
        print(f"✔ Exported {len(requests)} entries to {out}")
        conn.close()
        return

    # ── Interactive TUI ──
    auth_default = auth_pref_on
    if auth_default and auth_count == 0:
        print(
            "Note: no entries have replayable auth data -- starting with auth filter OFF.",
            file=sys.stderr,
        )
        auth_default = False
    elif auth_default:
        print(
            f"Auth filter ON: {auth_count}/{total} entries have replayable auth (press 't' to toggle).",
            file=sys.stderr,
        )

    tui = WafTUI(
        requests,
        initial_mode=initial_mode,
        auth_filter_default=auth_default,
        source_info={
            "log_group": args.log_group or "",
            "profile": args.profile or "",
            "region": args.region or "",
        },
        initial_filter_rules=yaml_filter_rules,
        aws_context={
            "profile": args.profile,
            "region": args.region,
            "start_time": start_time,
            "end_time": end_time,
            "action_filter": args.action,
            "limit": args.limit,
        },
        proxy=args.proxy,
        timeout=args.timeout,
        db=conn,
        auto_refresh_interval=args.auto_refresh,
        chromedriver_path=args.chromedriver or "",
        geckodriver_path=args.geckodriver or "",
        initial_sort_field=initial_sort_field,
        initial_sort_dir=initial_sort_dir,
        log_location=args.log_location,
        db_only=args.db_only,
    )
    # Suppress console logging during TUI (file debug logging continues)
    _console_suppressor.suppress = True
    try:
        post_output = curses.wrapper(tui.run)
    except KeyboardInterrupt:
        post_output = tui.post_exit_output
    finally:
        _console_suppressor.suppress = False
        tui._cleanup_browser()
        conn.close()

    if post_output:
        curls = [c for c in post_output if c.lstrip().startswith("curl ")]
        errors = [c for c in post_output if not c.lstrip().startswith("curl ")]
        if curls:
            print("\n" + "=" * 72)
            print(f"  {len(curls)} curl command(s) staged during session")
            print("=" * 72 + "\n")
            for i, cmd in enumerate(curls, 1):
                print(f"# --- Replay {i} ---")
                print(cmd)
                print()
        for msg in errors:
            print(msg, file=sys.stderr)
