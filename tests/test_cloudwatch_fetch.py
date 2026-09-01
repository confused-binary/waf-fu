"""Mocked CloudWatch coverage for fetch_logs_from_cloudwatch (QUAL-01)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from waf_fu.cloudwatch import fetch_logs_from_cloudwatch
from waf_fu.models import parse_all

START = datetime(2026, 1, 1, tzinfo=UTC)
END = datetime(2026, 1, 2, tzinfo=UTC)
START_MS = int(START.timestamp() * 1000)
END_MS = int(END.timestamp() * 1000)


def _waf_message(method: str, uri: str) -> str:
    return json.dumps(
        {
            "timestamp": 1735689600000,
            "httpRequest": {
                "httpMethod": method,
                "uri": uri,
                "headers": [{"name": "Host", "value": "target.example.com"}],
            },
        }
    )


def _stub_client_returning(monkeypatch, client) -> None:
    monkeypatch.setattr(
        boto3,
        "Session",
        lambda **kwargs: SimpleNamespace(client=lambda service: client),
    )


def test_fetch_logs_from_cloudwatch_returns_expected_requests(monkeypatch):
    client = boto3.client("logs", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response(
        "filter_log_events",
        {
            "events": [
                {"message": _waf_message("POST", "/login")},
                {"message": _waf_message("GET", "/dashboard")},
            ]
        },
        {
            "logGroupName": "aws-waf-logs-test",
            "startTime": START_MS,
            "endTime": END_MS,
            "interleaved": True,
        },
    )
    stubber.activate()
    _stub_client_returning(monkeypatch, client)

    records = fetch_logs_from_cloudwatch(
        log_group="aws-waf-logs-test",
        start_time=START,
        end_time=END,
    )
    reqs = parse_all(records)

    assert [r.method for r in reqs] == ["POST", "GET"]
    assert [r.uri for r in reqs] == ["/login", "/dashboard"]
    stubber.deactivate()


def test_fetch_logs_from_cloudwatch_paginates_with_next_token(monkeypatch):
    client = boto3.client("logs", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response(
        "filter_log_events",
        {
            "events": [{"message": _waf_message("GET", "/page-one")}],
            "nextToken": "token-2",
        },
        {
            "logGroupName": "aws-waf-logs-test",
            "startTime": START_MS,
            "endTime": END_MS,
            "interleaved": True,
        },
    )
    stubber.add_response(
        "filter_log_events",
        {"events": [{"message": _waf_message("POST", "/page-two")}]},
        {
            "logGroupName": "aws-waf-logs-test",
            "startTime": START_MS,
            "endTime": END_MS,
            "interleaved": True,
            "nextToken": "token-2",
        },
    )
    stubber.activate()
    _stub_client_returning(monkeypatch, client)

    records = fetch_logs_from_cloudwatch(
        log_group="aws-waf-logs-test",
        start_time=START,
        end_time=END,
    )
    reqs = parse_all(records)

    assert [r.method for r in reqs] == ["GET", "POST"]
    assert [r.uri for r in reqs] == ["/page-one", "/page-two"]
    stubber.deactivate()


def test_fetch_logs_from_cloudwatch_applies_action_filter(monkeypatch):
    client = boto3.client("logs", region_name="us-east-1")
    stubber = Stubber(client)
    events = [
        {
            "message": json.dumps(
                {
                    "timestamp": 1735689600000,
                    "action": "BLOCK",
                    "httpRequest": {"httpMethod": "GET", "uri": "/blocked"},
                }
            )
        },
        {
            "message": json.dumps(
                {
                    "timestamp": 1735689600000,
                    "action": "ALLOW",
                    "httpRequest": {"httpMethod": "GET", "uri": "/allowed"},
                }
            )
        },
    ]
    stubber.add_response(
        "filter_log_events",
        {"events": events},
        {
            "logGroupName": "aws-waf-logs-test",
            "startTime": START_MS,
            "endTime": END_MS,
            "interleaved": True,
        },
    )
    stubber.activate()
    _stub_client_returning(monkeypatch, client)

    records = fetch_logs_from_cloudwatch(
        log_group="aws-waf-logs-test",
        start_time=START,
        end_time=END,
        action_filter="ALLOW",
    )
    reqs = parse_all(records)

    assert [r.uri for r in reqs] == ["/allowed"]
    stubber.deactivate()
