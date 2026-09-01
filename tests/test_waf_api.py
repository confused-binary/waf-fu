"""Mocked WAFv2 coverage for waf_api.py (SRC-03). No real AWS calls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.stub import Stubber

from waf_fu import waf_api

ACL_ARN = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-acl/abc-123"
ACL_NAME = "test-acl"
ACL_ID = "abc-123"
END = datetime(2026, 8, 10, 12, 0, 0, tzinfo=UTC)
START = END - timedelta(hours=1)


@pytest.fixture
def wafv2_client():
    return boto3.client(
        "wafv2",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


@pytest.fixture
def stub_client(monkeypatch, wafv2_client):
    """Yield a Stubber whose client replaces waf_api._make_client."""
    stubber = Stubber(wafv2_client)
    stubber.activate()
    monkeypatch.setattr(waf_api, "_make_client", lambda *a, **k: wafv2_client)
    yield stubber
    stubber.deactivate()


@pytest.fixture
def sample_request():
    return {
        "Request": {
            "ClientIP": "1.2.3.4",
            "Country": "US",
            "URI": "/login?user=admin",
            "Method": "POST",
            "HTTPVersion": "HTTP/2.0",
            "Headers": [
                {"Name": "Host", "Value": "example.com"},
                {"Name": "User-Agent", "Value": "Mozilla/5.0"},
            ],
        },
        "Weight": 1,
        "Timestamp": END,
        "Action": "BLOCK",
        "RuleNameWithinRuleGroup": "rate-limit-login",
        "Labels": [{"Name": "awswaf:managed:aws:bot-control:bot:verified"}],
        "ResponseCodeSent": 403,
    }


def _rule(name: str, metric: str) -> dict:
    return {
        "Name": name,
        "Priority": 0,
        "Statement": {
            "IPSetReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/x/1"
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": metric,
        },
    }


def _get_web_acl_response(rules: list[dict]) -> dict:
    return {
        "WebACL": {
            "Name": ACL_NAME,
            "Id": ACL_ID,
            "ARN": ACL_ARN,
            "DefaultAction": {"Allow": {}},
            "Rules": rules,
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "test-acl",
            },
        }
    }


def _sampled_response(samples: list[dict]) -> dict:
    return {
        "SampledRequests": samples,
        "PopulationSize": len(samples),
        "TimeWindow": {"StartTime": START, "EndTime": END},
    }


def _sample_at(ts: datetime, client_ip: str, uri: str, method: str = "GET") -> dict:
    return {
        "Request": {
            "ClientIP": client_ip,
            "Country": "US",
            "URI": uri,
            "Method": method,
            "HTTPVersion": "HTTP/1.1",
            "Headers": [{"Name": "Host", "Value": "example.com"}],
        },
        "Weight": 1,
        "Timestamp": ts,
        "Action": "ALLOW",
    }


def _sampled_params(rule_metric: str, start: datetime = START) -> dict:
    return {
        "WebAclArn": ACL_ARN,
        "RuleMetricName": rule_metric,
        "Scope": "REGIONAL",
        "TimeWindow": {"StartTime": start, "EndTime": END},
        "MaxItems": 500,
    }


# ── transform ────────────────────────────────────────────────────────────────


def test_transform_sampled_request(sample_request):
    result = waf_api._transform_sampled_request(sample_request, ACL_ARN)

    assert result["timestamp"] == int(sample_request["Timestamp"].timestamp() * 1000)
    assert result["action"] == "BLOCK"
    assert result["terminatingRuleId"] == "rate-limit-login"
    assert result["webaclId"] == ACL_ARN
    assert result["_responseCode"] == 403
    assert result["_source"] == "waf_sampled"
    assert len(result["labels"]) == 1

    http_request = result["httpRequest"]
    assert http_request["uri"] == "/login"
    assert http_request["args"] == "user=admin"
    assert http_request["httpMethod"] == "POST"
    assert http_request["clientIp"] == "1.2.3.4"
    assert http_request["country"] == "US"
    assert http_request["httpVersion"] == "HTTP/2.0"
    assert http_request["requestBody"] == ""
    assert http_request["requestBodySize"] == 0
    assert http_request["headers"] == [
        {"Name": "Host", "Value": "example.com"},
        {"Name": "User-Agent", "Value": "Mozilla/5.0"},
    ]


def test_transform_uri_no_query_string(sample_request):
    sample_request["Request"]["URI"] = "/healthcheck"

    result = waf_api._transform_sampled_request(sample_request, ACL_ARN)

    assert result["httpRequest"]["uri"] == "/healthcheck"
    assert result["httpRequest"]["args"] == ""


def test_transform_minimal_sample():
    result = waf_api._transform_sampled_request({"Request": {"Method": "GET"}}, ACL_ARN)

    assert result["timestamp"] == 0
    assert result["action"] == ""
    assert result["labels"] == []
    assert result["terminatingRuleId"] == ""
    assert result["_responseCode"] is None
    assert result["httpRequest"] == {
        "headers": [],
        "uri": "",
        "args": "",
        "httpMethod": "GET",
        "clientIp": "",
        "country": "",
        "httpVersion": "",
        "requestBody": "",
        "requestBodySize": 0,
    }


def test_transform_epoch_seconds_timestamp(sample_request):
    sample_request["Timestamp"] = 1786276800.5

    result = waf_api._transform_sampled_request(sample_request, ACL_ARN)

    assert result["timestamp"] == 1786276800500


# ── API wrappers ─────────────────────────────────────────────────────────────


def test_list_web_acls(stub_client):
    stub_client.add_response(
        "list_web_acls",
        {
            "WebACLs": [
                {"Name": "acl-one", "Id": "1", "ARN": ACL_ARN},
                {"Name": "acl-two", "Id": "2", "ARN": ACL_ARN},
            ]
        },
        {"Scope": "REGIONAL"},
    )

    acls = waf_api.list_web_acls()

    assert [a["Name"] for a in acls] == ["acl-one", "acl-two"]
    stub_client.assert_no_pending_responses()


def test_get_web_acl_rules(stub_client):
    stub_client.add_response(
        "get_web_acl",
        _get_web_acl_response(
            [_rule("rule-a", "metric-a"), _rule("rule-b", "metric-b"), _rule("c", "mc")]
        ),
        {"Name": ACL_NAME, "Scope": "REGIONAL", "Id": ACL_ID},
    )

    rules = waf_api.get_web_acl_rules(ACL_NAME, ACL_ID)

    assert rules == [
        {"Name": "rule-a", "MetricName": "metric-a"},
        {"Name": "rule-b", "MetricName": "metric-b"},
        {"Name": "c", "MetricName": "mc"},
    ]
    stub_client.assert_no_pending_responses()


def test_get_logging_configuration_cwl_and_s3(stub_client):
    stub_client.add_response(
        "get_logging_configuration",
        {
            "LoggingConfiguration": {
                "ResourceArn": ACL_ARN,
                "LogDestinationConfigs": [
                    "arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-test:*",
                    "arn:aws:s3:::my-waf-bucket",
                ],
            }
        },
        {"ResourceArn": ACL_ARN},
    )

    config = waf_api.get_logging_configuration(ACL_ARN)

    assert config == {"log_group": "aws-waf-logs-test", "s3_bucket": "my-waf-bucket"}
    stub_client.assert_no_pending_responses()


def test_get_logging_configuration_not_configured(stub_client):
    stub_client.add_client_error(
        "get_logging_configuration",
        service_error_code="WAFNonexistentItemException",
        http_status_code=400,
    )

    assert waf_api.get_logging_configuration(ACL_ARN) is None
    stub_client.assert_no_pending_responses()


def test_get_sampled_requests(stub_client):
    stub_client.add_response(
        "get_sampled_requests",
        _sampled_response(
            [
                _sample_at(END, "1.1.1.1", "/a?x=1"),
                _sample_at(END, "2.2.2.2", "/b", method="POST"),
            ]
        ),
        _sampled_params("metric-a"),
    )

    records = waf_api.get_sampled_requests(ACL_ARN, "metric-a", START, END)

    assert len(records) == 2
    assert records[0]["httpRequest"]["uri"] == "/a"
    assert records[0]["httpRequest"]["args"] == "x=1"
    assert records[1]["httpRequest"]["httpMethod"] == "POST"
    assert all(r["webaclId"] == ACL_ARN for r in records)
    stub_client.assert_no_pending_responses()


def test_get_sampled_requests_enforces_3h_cap(stub_client):
    clamped_start = END - timedelta(hours=3)
    stub_client.add_response(
        "get_sampled_requests",
        _sampled_response([]),
        _sampled_params("metric-a", start=clamped_start),
    )

    records = waf_api.get_sampled_requests(
        ACL_ARN, "metric-a", END - timedelta(hours=12), END
    )

    assert records == []
    stub_client.assert_no_pending_responses()


def test_get_sampled_requests_caps_max_items(stub_client):
    stub_client.add_response(
        "get_sampled_requests", _sampled_response([]), _sampled_params("metric-a")
    )

    waf_api.get_sampled_requests(ACL_ARN, "metric-a", START, END, max_items=9000)

    stub_client.assert_no_pending_responses()


# ── orchestrator ─────────────────────────────────────────────────────────────


def test_fetch_all_sampled_for_acl(stub_client):
    later = END
    earlier = END - timedelta(minutes=30)
    shared = _sample_at(earlier, "1.1.1.1", "/shared")

    stub_client.add_response(
        "get_web_acl",
        _get_web_acl_response([_rule("rule-a", "metric-a"), _rule("rule-b", "mb")]),
        {"Name": ACL_NAME, "Scope": "REGIONAL", "Id": ACL_ID},
    )
    stub_client.add_response(
        "get_sampled_requests",
        _sampled_response([shared, _sample_at(later, "2.2.2.2", "/only-a")]),
        _sampled_params("metric-a"),
    )
    stub_client.add_response(
        "get_sampled_requests",
        _sampled_response([shared, _sample_at(later, "3.3.3.3", "/only-b")]),
        _sampled_params("mb"),
    )

    records = waf_api.fetch_all_sampled_for_acl(ACL_ARN, ACL_NAME, ACL_ID, START, END)

    assert len(records) == 3
    assert [r["timestamp"] for r in records] == sorted(r["timestamp"] for r in records)
    assert records[0]["httpRequest"]["uri"] == "/shared"
    stub_client.assert_no_pending_responses()


def test_fetch_all_sampled_for_acl_no_rules(stub_client):
    stub_client.add_response(
        "get_web_acl",
        _get_web_acl_response([]),
        {"Name": ACL_NAME, "Scope": "REGIONAL", "Id": ACL_ID},
    )

    assert (
        waf_api.fetch_all_sampled_for_acl(ACL_ARN, ACL_NAME, ACL_ID, START, END) == []
    )
    stub_client.assert_no_pending_responses()


def test_fetch_all_sampled_for_acl_rule_error(stub_client):
    stub_client.add_response(
        "get_web_acl",
        _get_web_acl_response([_rule("rule-a", "metric-a"), _rule("rule-b", "mb")]),
        {"Name": ACL_NAME, "Scope": "REGIONAL", "Id": ACL_ID},
    )
    stub_client.add_client_error(
        "get_sampled_requests",
        service_error_code="WAFInvalidParameterException",
        http_status_code=400,
    )
    stub_client.add_response(
        "get_sampled_requests",
        _sampled_response([_sample_at(END, "3.3.3.3", "/only-b")]),
        _sampled_params("mb"),
    )

    records = waf_api.fetch_all_sampled_for_acl(ACL_ARN, ACL_NAME, ACL_ID, START, END)

    assert len(records) == 1
    assert records[0]["httpRequest"]["uri"] == "/only-b"
    stub_client.assert_no_pending_responses()
