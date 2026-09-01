"""WAF v2 API client for sampled requests.

Wraps the WAF v2 `GetSampledRequests` API and its supporting calls (listing web
ACLs, discovering rules, reading logging destinations). `SampledHTTPRequest` is
a different schema from the WAF log records emitted to CloudWatch Logs or S3, so
`_transform_sampled_request` maps it into the unified WAF log record format used
by `storage.save_source_records("waf", ...)`.

`RedactedFields` from the WAF logging configuration does *not* apply to sampled
requests, so headers arrive unredacted here even when they are masked in the
CWL/S3 log sources.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

MAX_SAMPLED_ITEMS = 500
MAX_SAMPLE_WINDOW = timedelta(hours=3)


def _make_client(profile: str | None = None, region: str | None = None) -> Any:
    """Create a `wafv2` client for the given profile/region."""
    from waf_fu.aws_session import get_session

    return get_session(profile).client(
        "wafv2", **({"region_name": region} if region else {})
    )


def _sample_timestamp_ms(value: Any) -> int:
    """Normalize a SampledHTTPRequest Timestamp to epoch milliseconds."""
    if isinstance(value, datetime):
        return int(value.timestamp() * 1000)
    if isinstance(value, (int, float)):
        return int(value * 1000)
    return 0


def _transform_sampled_request(sample: dict, acl_arn: str) -> dict:
    """Map one SampledHTTPRequest onto the unified WAF log record schema."""
    request = sample.get("Request") or {}

    raw_uri = request.get("URI", "") or ""
    uri, sep, args = raw_uri.partition("?")

    http_request = {
        "headers": request.get("Headers", []),
        "uri": uri,
        "args": args if sep else "",
        "httpMethod": request.get("Method", ""),
        "clientIp": request.get("ClientIP", ""),
        "country": request.get("Country", ""),
        "httpVersion": request.get("HTTPVersion", ""),
        "requestBody": "",
        "requestBodySize": 0,
    }

    return {
        "timestamp": _sample_timestamp_ms(sample.get("Timestamp", 0)),
        "action": sample.get("Action", ""),
        "httpRequest": http_request,
        "labels": sample.get("Labels", []),
        "terminatingRuleId": sample.get("RuleNameWithinRuleGroup", ""),
        "webaclId": acl_arn,
        "_responseCode": sample.get("ResponseCodeSent"),
        "_source": "waf_sampled",
    }


def list_web_acls(
    profile: str | None = None,
    region: str | None = None,
    scope: str = "REGIONAL",
) -> list[dict]:
    """Return every web ACL in `scope` for the given profile/region."""
    client = _make_client(profile, region)
    response = client.list_web_acls(Scope=scope)
    acls: list[dict] = response.get("WebACLs", [])
    logger.debug("list_web_acls: scope=%s count=%d", scope, len(acls))
    return acls


def get_web_acl_rules(
    acl_name: str,
    acl_id: str,
    profile: str | None = None,
    region: str | None = None,
    scope: str = "REGIONAL",
) -> list[dict]:
    """Return `[{"Name": ..., "MetricName": ...}]` for every rule in the ACL.

    MetricName is what `GetSampledRequests` calls `RuleMetricName`.
    """
    client = _make_client(profile, region)
    response = client.get_web_acl(Name=acl_name, Scope=scope, Id=acl_id)
    rules = response.get("WebACL", {}).get("Rules", [])
    result = [
        {
            "Name": rule.get("Name", ""),
            "MetricName": rule.get("VisibilityConfig", {}).get("MetricName", ""),
        }
        for rule in rules
    ]
    logger.debug("get_web_acl_rules: acl=%s rules=%d", acl_name, len(result))
    return result


def get_logging_configuration(
    acl_arn: str,
    profile: str | None = None,
    region: str | None = None,
) -> dict | None:
    """Return the ACL's log destinations, or None when logging is not configured."""
    client = _make_client(profile, region)
    try:
        response = client.get_logging_configuration(ResourceArn=acl_arn)
    except client.exceptions.WAFNonexistentItemException:
        logger.debug("get_logging_configuration: no logging config for %s", acl_arn)
        return None

    log_group: str | None = None
    s3_bucket: str | None = None
    config = response.get("LoggingConfiguration", {})
    for arn in config.get("LogDestinationConfigs", []):
        if arn.startswith("arn:aws:logs:"):
            name = arn.split(":log-group:", 1)[-1]
            log_group = name.removesuffix(":*")
        elif arn.startswith("arn:aws:s3:::"):
            s3_bucket = arn[len("arn:aws:s3:::") :]
        elif arn.startswith("arn:aws:firehose:"):
            logger.debug("get_logging_configuration: firehose destination skipped")

    return {"log_group": log_group, "s3_bucket": s3_bucket}


def get_sampled_requests(
    acl_arn: str,
    rule_metric: str,
    start_time: datetime,
    end_time: datetime,
    profile: str | None = None,
    region: str | None = None,
    scope: str = "REGIONAL",
    max_items: int = MAX_SAMPLED_ITEMS,
) -> list[dict]:
    """Fetch sampled requests for one rule, transformed to WAF log record format."""
    max_items = min(max_items, MAX_SAMPLED_ITEMS)
    if end_time - start_time > MAX_SAMPLE_WINDOW:
        logger.warning(
            "get_sampled_requests: window > 3h, clamping start to %s",
            end_time - MAX_SAMPLE_WINDOW,
        )
        start_time = end_time - MAX_SAMPLE_WINDOW

    client = _make_client(profile, region)
    response = client.get_sampled_requests(
        WebAclArn=acl_arn,
        RuleMetricName=rule_metric,
        Scope=scope,
        TimeWindow={"StartTime": start_time, "EndTime": end_time},
        MaxItems=max_items,
    )
    samples = [
        _transform_sampled_request(item, acl_arn)
        for item in response.get("SampledRequests", [])
    ]
    logger.debug("get_sampled_requests: rule=%s samples=%d", rule_metric, len(samples))
    return samples


def fetch_all_sampled_for_acl(
    acl_arn: str,
    acl_name: str,
    acl_id: str,
    start_time: datetime,
    end_time: datetime,
    profile: str | None = None,
    region: str | None = None,
) -> list[dict]:
    """Fetch samples for every rule in an ACL, deduplicated and sorted by time.

    The same request can be sampled under several rules, so records are deduped
    on the same key the storage layer uses.
    """
    from botocore.exceptions import ClientError

    rules = get_web_acl_rules(acl_name, acl_id, profile, region)
    if not rules:
        logger.debug("fetch_all_sampled_for_acl: no rules on %s", acl_name)
        return []

    all_samples: list[dict] = []
    seen: set[tuple[int, str, str, str]] = set()

    for rule in rules:
        try:
            samples = get_sampled_requests(
                acl_arn, rule["MetricName"], start_time, end_time, profile, region
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "AccessDeniedException":
                raise
            logger.warning(
                "fetch_all_sampled_for_acl: rule %s failed, skipping",
                rule.get("Name", ""),
                exc_info=True,
            )
            continue

        for record in samples:
            http_request = record["httpRequest"]
            key = (
                record["timestamp"],
                http_request["clientIp"],
                http_request["httpMethod"],
                http_request["uri"],
            )
            if key not in seen:
                seen.add(key)
                all_samples.append(record)
        logger.debug(
            "fetch_all_sampled_for_acl: rule=%s fetched=%d",
            rule.get("Name", ""),
            len(samples),
        )

    logger.info(
        "fetch_all_sampled_for_acl: acl=%s unique_samples=%d",
        acl_name,
        len(all_samples),
    )
    all_samples.sort(key=lambda r: r["timestamp"])
    return all_samples
