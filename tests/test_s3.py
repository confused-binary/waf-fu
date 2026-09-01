"""Mocked S3 coverage for the WAF log fetcher (SRC-01, SRC-02)."""

from __future__ import annotations

import gzip
import io
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import boto3
from botocore.response import StreamingBody
from botocore.stub import Stubber

from waf_fu.s3 import (
    _date_prefixes,
    _parse_s3_object,
    discover_waf_buckets,
    fetch_logs_from_s3,
    list_waf_acl_names,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
BUCKET = "aws-waf-logs-test"
ACL = "test-acl"
START = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)
END = datetime(2026, 1, 1, 0, 55, tzinfo=UTC)
HOUR_PREFIX = f"AWSLogs/{ACCOUNT}/WAFLogs/{REGION}/{ACL}/2026/01/01/00/"


def _waf_record(
    method: str,
    uri: str,
    action: str = "ALLOW",
    timestamp: int = 1735689600000,
) -> dict:
    return {
        "timestamp": timestamp,
        "action": action,
        "httpRequest": {
            "httpMethod": method,
            "uri": uri,
            "headers": [{"name": "Host", "value": "target.example.com"}],
        },
    }


def _make_gzip_ndjson(records: list[dict]) -> bytes:
    body = "\n".join(json.dumps(r) for r in records)
    return gzip.compress(body.encode("utf-8"))


def _streaming(data: bytes) -> StreamingBody:
    return StreamingBody(io.BytesIO(data), len(data))


def _stub_session(monkeypatch, clients: dict) -> None:
    monkeypatch.setattr(
        boto3,
        "Session",
        lambda **kwargs: SimpleNamespace(
            client=lambda service, **_: clients[service],
            region_name=REGION,
        ),
    )


def _stub_sts(account: str = ACCOUNT):
    client = boto3.client("sts", region_name=REGION)
    stubber = Stubber(client)
    stubber.add_response(
        "get_caller_identity",
        {"Account": account, "Arn": f"arn:aws:iam::{account}:user/test", "UserId": "U"},
        {},
    )
    return client, stubber


# ── _date_prefixes ──────────────────────────────────────────────────────────


def test_date_prefixes_single_hour():
    start = datetime(2026, 1, 1, 3, 10, tzinfo=UTC)
    end = datetime(2026, 1, 1, 3, 50, tzinfo=UTC)
    assert _date_prefixes(start, end) == ["2026/01/01/03"]


def test_date_prefixes_spans_hours():
    start = datetime(2026, 1, 1, 1, 30, tzinfo=UTC)
    end = datetime(2026, 1, 1, 4, 15, tzinfo=UTC)
    assert _date_prefixes(start, end) == [
        "2026/01/01/01",
        "2026/01/01/02",
        "2026/01/01/03",
        "2026/01/01/04",
    ]


def test_date_prefixes_crosses_midnight():
    start = datetime(2026, 1, 31, 23, 10, tzinfo=UTC)
    end = datetime(2026, 2, 1, 1, 5, tzinfo=UTC)
    assert _date_prefixes(start, end) == [
        "2026/01/31/23",
        "2026/02/01/00",
        "2026/02/01/01",
    ]


# ── _parse_s3_object ────────────────────────────────────────────────────────


def test_parse_s3_object_valid():
    records = [
        _waf_record("GET", "/one"),
        _waf_record("POST", "/two"),
        _waf_record("GET", "/three"),
    ]
    parsed = _parse_s3_object(_make_gzip_ndjson(records))

    assert parsed == records


def test_parse_s3_object_skips_bad_lines():
    good = _waf_record("GET", "/ok")
    raw = "\n".join([json.dumps(good), "{not json", "", "also-garbage"])
    parsed = _parse_s3_object(gzip.compress(raw.encode("utf-8")))

    assert parsed == [good]


def test_parse_s3_object_empty():
    assert _parse_s3_object(gzip.compress(b"")) == []


# ── discover_waf_buckets ────────────────────────────────────────────────────


def test_discover_waf_buckets_filters_by_prefix(monkeypatch):
    client = boto3.client("s3", region_name=REGION)
    stubber = Stubber(client)
    stubber.add_response(
        "list_buckets",
        {
            "Buckets": [
                {"Name": "aws-waf-logs-prod"},
                {"Name": "unrelated-bucket"},
                {"Name": "aws-waf-logs-dev"},
            ]
        },
        {},
    )
    stubber.activate()
    _stub_session(monkeypatch, {"s3": client})

    assert discover_waf_buckets() == ["aws-waf-logs-dev", "aws-waf-logs-prod"]
    stubber.deactivate()


# ── list_waf_acl_names ──────────────────────────────────────────────────────


def test_list_waf_acl_names_returns_acl_names(monkeypatch):
    client = boto3.client("s3", region_name=REGION)
    stubber = Stubber(client)
    stubber.add_response(
        "list_objects_v2",
        {"CommonPrefixes": [{"Prefix": f"AWSLogs/{ACCOUNT}/"}]},
        {"Bucket": BUCKET, "Prefix": "AWSLogs/", "Delimiter": "/"},
    )
    stubber.add_response(
        "list_objects_v2",
        {"CommonPrefixes": [{"Prefix": f"AWSLogs/{ACCOUNT}/WAFLogs/{REGION}/"}]},
        {
            "Bucket": BUCKET,
            "Prefix": f"AWSLogs/{ACCOUNT}/WAFLogs/",
            "Delimiter": "/",
        },
    )
    stubber.add_response(
        "list_objects_v2",
        {
            "CommonPrefixes": [
                {"Prefix": f"AWSLogs/{ACCOUNT}/WAFLogs/{REGION}/zeta-acl/"},
                {"Prefix": f"AWSLogs/{ACCOUNT}/WAFLogs/{REGION}/alpha-acl/"},
            ]
        },
        {
            "Bucket": BUCKET,
            "Prefix": f"AWSLogs/{ACCOUNT}/WAFLogs/{REGION}/",
            "Delimiter": "/",
        },
    )
    stubber.activate()
    _stub_session(monkeypatch, {"s3": client})

    assert list_waf_acl_names(BUCKET) == ["alpha-acl", "zeta-acl"]
    stubber.deactivate()


# ── fetch_logs_from_s3 ──────────────────────────────────────────────────────


def test_fetch_logs_basic(monkeypatch):
    key = f"{HOUR_PREFIX}00/log.gz"
    records = [_waf_record("POST", "/login"), _waf_record("GET", "/dashboard")]

    s3_client = boto3.client("s3", region_name=REGION)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "list_objects_v2",
        {"Contents": [{"Key": key}]},
        {"Bucket": BUCKET, "Prefix": HOUR_PREFIX},
    )
    s3_stubber.add_response(
        "get_object",
        {"Body": _streaming(_make_gzip_ndjson(records))},
        {"Bucket": BUCKET, "Key": key},
    )
    sts_client, sts_stubber = _stub_sts()
    s3_stubber.activate()
    sts_stubber.activate()
    _stub_session(monkeypatch, {"s3": s3_client, "sts": sts_client})

    fetched = fetch_logs_from_s3(
        bucket=BUCKET,
        start_time=START,
        end_time=END,
        acl_name=ACL,
        region=REGION,
    )

    assert fetched == records
    s3_stubber.deactivate()
    sts_stubber.deactivate()


def test_fetch_logs_action_filter(monkeypatch):
    key = f"{HOUR_PREFIX}00/log.gz"
    allowed = _waf_record("GET", "/allowed", action="ALLOW")
    blocked = _waf_record("GET", "/blocked", action="BLOCK")

    s3_client = boto3.client("s3", region_name=REGION)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "list_objects_v2",
        {"Contents": [{"Key": key}]},
        {"Bucket": BUCKET, "Prefix": HOUR_PREFIX},
    )
    s3_stubber.add_response(
        "get_object",
        {"Body": _streaming(_make_gzip_ndjson([allowed, blocked]))},
        {"Bucket": BUCKET, "Key": key},
    )
    sts_client, sts_stubber = _stub_sts()
    s3_stubber.activate()
    sts_stubber.activate()
    _stub_session(monkeypatch, {"s3": s3_client, "sts": sts_client})

    fetched = fetch_logs_from_s3(
        bucket=BUCKET,
        start_time=START,
        end_time=END,
        acl_name=ACL,
        region=REGION,
        action_filter="BLOCK",
    )

    assert fetched == [blocked]
    s3_stubber.deactivate()
    sts_stubber.deactivate()


def test_fetch_logs_empty_bucket(monkeypatch):
    s3_client = boto3.client("s3", region_name=REGION)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "list_objects_v2",
        {"KeyCount": 0},
        {"Bucket": BUCKET, "Prefix": HOUR_PREFIX},
    )
    sts_client, sts_stubber = _stub_sts()
    s3_stubber.activate()
    sts_stubber.activate()
    _stub_session(monkeypatch, {"s3": s3_client, "sts": sts_client})

    fetched = fetch_logs_from_s3(
        bucket=BUCKET,
        start_time=START,
        end_time=END,
        acl_name=ACL,
        region=REGION,
    )

    assert fetched == []
    s3_stubber.deactivate()
    sts_stubber.deactivate()
