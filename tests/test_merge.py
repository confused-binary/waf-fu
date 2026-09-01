"""Coverage for merge.py: redaction detection, correlation, field-level
best-of merging, and the run_merge integration against a real SQLite file.
"""

from __future__ import annotations

import pytest

from waf_fu import merge, storage


@pytest.fixture
def db(tmp_path):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    yield conn
    conn.close()


def headers_dict(record: dict) -> dict[str, str]:
    """Flatten a merged record's headers to `{lower_name: value}`."""
    return {
        h["name"].lower(): h["value"] for h in record["httpRequest"]["headers"] or []
    }


def sampled_record(
    timestamp: int = 1735689600000,
    uri: str = "/",
    client_ip: str = "203.0.113.7",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    action: str = "ALLOW",
) -> dict:
    """A waf_api-shaped sampled record: API-native {Name, Value} header casing."""
    return {
        "timestamp": timestamp,
        "action": action,
        "httpRequest": {
            "headers": [{"Name": n, "Value": v} for n, v in (headers or {}).items()],
            "uri": uri,
            "args": "",
            "httpMethod": method,
            "clientIp": client_ip,
            "country": "US",
            "httpVersion": "HTTP/2",
            "requestBody": "",
            "requestBodySize": 0,
        },
        "labels": [],
        "terminatingRuleId": "",
        "webaclId": "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test/abc",
        "_source": "waf_sampled",
    }


# --- is_redacted -------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["REDACTED", "redacted", "Redacted", "***", "value***masked", ""]
)
def test_redacted_patterns(value):
    assert merge.is_redacted(value) is True


@pytest.mark.parametrize(
    "value", ["Bearer token", "normal value", "RE DACTED", "a*b*c"]
)
def test_not_redacted_patterns(value):
    assert merge.is_redacted(value) is False


def test_redacted_none():
    assert merge.is_redacted(None) is True


# --- correlation_key ---------------------------------------------------------


def test_correlation_key_basic(waf_record):
    record = waf_record(timestamp=1735689600000, client_ip="198.51.100.4", uri="/login")
    assert merge.correlation_key(record) == "1735689600:198.51.100.4:/login"


def test_correlation_key_timestamp_tolerance(waf_record):
    same_second = waf_record(timestamp=1735689600999)
    base = waf_record(timestamp=1735689600000)
    next_second = waf_record(timestamp=1735689601000)
    assert merge.correlation_key(base) == merge.correlation_key(same_second)
    assert merge.correlation_key(base) != merge.correlation_key(next_second)


def test_correlation_key_missing_fields():
    assert merge.correlation_key({}) == "0::"


# --- merge_headers -----------------------------------------------------------


def test_merge_headers_redacted_replaced():
    merged = merge.merge_headers(
        {
            "cwl": [{"name": "Authorization", "value": "REDACTED"}],
            "waf": [{"Name": "Authorization", "Value": "Bearer eyJ..."}],
        }
    )
    assert merged == [{"name": "Authorization", "value": "Bearer eyJ..."}]


def test_merge_headers_cwl_wins_when_both_clear():
    merged = merge.merge_headers(
        {
            "cwl": [{"name": "Host", "value": "example.com"}],
            "s3": [{"name": "Host", "value": "example.org"}],
        }
    )
    assert merged == [{"name": "Host", "value": "example.com"}]


def test_merge_headers_union():
    merged = merge.merge_headers(
        {
            "cwl": [{"name": "Host", "value": "example.com"}],
            "waf": [{"Name": "X-Custom", "Value": "abc"}],
        }
    )
    assert merged == [
        {"name": "Host", "value": "example.com"},
        {"name": "X-Custom", "value": "abc"},
    ]


def test_merge_headers_case_insensitive():
    merged = merge.merge_headers(
        {
            "cwl": [{"name": "authorization", "value": "***"}],
            "waf": [{"Name": "Authorization", "Value": "Bearer eyJ..."}],
        }
    )
    assert merged == [{"name": "authorization", "value": "Bearer eyJ..."}]


def test_merge_headers_all_redacted_keeps_priority_value():
    merged = merge.merge_headers(
        {
            "cwl": [{"name": "Cookie", "value": "REDACTED"}],
            "waf": [{"Name": "Cookie", "Value": "***"}],
        }
    )
    assert merged == [{"name": "Cookie", "value": "REDACTED"}]


def test_merge_headers_preserves_cwl_order():
    merged = merge.merge_headers(
        {
            "waf": [{"Name": "X-Late", "Value": "z"}],
            "cwl": [
                {"name": "Host", "value": "example.com"},
                {"name": "Accept", "value": "*/*"},
            ],
        }
    )
    assert [h["name"] for h in merged] == ["Host", "Accept", "X-Late"]


# --- merge_record_group ------------------------------------------------------


def test_merge_single_source(waf_record):
    record = waf_record(body="a=1")
    assert merge.merge_record_group({"cwl": record}) is record


def test_merge_cwl_waf_redacted_header(waf_record):
    cwl = waf_record(
        method="POST",
        uri="/login",
        headers={"Authorization": "REDACTED"},
        body='{"user":"admin"}',
    )
    waf = sampled_record(
        uri="/login", method="POST", headers={"Authorization": "Bearer eyJ..."}
    )

    merged = merge.merge_record_group({"cwl": cwl, "waf": waf})

    assert headers_dict(merged)["authorization"] == "Bearer eyJ..."
    assert merged["httpRequest"]["requestBody"] == '{"user":"admin"}'
    assert merged["httpRequest"]["requestBodySize"] == len('{"user":"admin"}')
    # The CWL record itself is untouched by the merge.
    assert headers_dict(cwl)["authorization"] == "REDACTED"


def test_merge_cwl_s3_body_from_cwl(waf_record):
    cwl = waf_record(body="from-cwl")
    s3 = waf_record(body="from-s3")
    merged = merge.merge_record_group({"cwl": cwl, "s3": s3})
    assert merged["httpRequest"]["requestBody"] == "from-cwl"


def test_merge_s3_body_when_cwl_body_empty(waf_record):
    cwl = waf_record(body="")
    s3 = waf_record(body="from-s3")
    merged = merge.merge_record_group({"cwl": cwl, "s3": s3})
    assert merged["httpRequest"]["requestBody"] == "from-s3"


def test_merge_waf_only_no_body():
    waf = sampled_record(headers={"Authorization": "Bearer eyJ..."})
    merged = merge.merge_record_group({"waf": waf})
    assert merged["httpRequest"]["requestBody"] == ""
    assert merged["httpRequest"]["requestBodySize"] == 0
    # Sampled-only records still get their API-cased headers normalized.
    assert merged["httpRequest"]["headers"] == [
        {"name": "Authorization", "value": "Bearer eyJ..."}
    ]


def test_merge_redacted_args(waf_record):
    cwl = waf_record(args="REDACTED")
    s3 = waf_record(args="q=secret&page=2")
    merged = merge.merge_record_group({"cwl": cwl, "s3": s3})
    assert merged["httpRequest"]["args"] == "q=secret&page=2"


def test_merge_preserves_metadata(waf_record):
    cwl = waf_record(
        terminating_rule_id="BlockBadBots",
        rule_group_list=[{"ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet"}],
    )
    cwl["labels"] = [{"name": "awswaf:managed:aws:core"}]
    waf = sampled_record(headers={"Authorization": "Bearer eyJ..."})
    waf["terminatingRuleId"] = "SomeSampledRule"

    merged = merge.merge_record_group({"cwl": cwl, "waf": waf})

    assert merged["terminatingRuleId"] == "BlockBadBots"
    assert merged["ruleGroupList"] == [
        {"ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet"}
    ]
    assert merged["labels"] == [{"name": "awswaf:managed:aws:core"}]
    assert merged["action"] == "ALLOW"


def test_merge_s3_fills_metadata_missing_from_cwl(waf_record):
    cwl = waf_record(terminating_rule_id="")
    s3 = waf_record(terminating_rule_id="BlockBadBots")
    merged = merge.merge_record_group({"cwl": cwl, "s3": s3})
    assert merged["terminatingRuleId"] == "BlockBadBots"


def test_merge_empty_group():
    assert merge.merge_record_group({}) == {}


# --- correlate_records -------------------------------------------------------


def test_correlate_exact_match(waf_record):
    cwl = waf_record(uri="/login", timestamp=1735689600000)
    waf = sampled_record(uri="/login", timestamp=1735689600000)
    groups = merge.correlate_records([cwl], [], [waf])
    assert len(groups) == 1
    assert set(groups[0]) == {"cwl", "waf"}


def test_correlate_tolerance(waf_record):
    cwl = waf_record(timestamp=1000500)
    waf = sampled_record(timestamp=1000000)
    groups = merge.correlate_records([cwl], [], [waf])
    assert len(groups) == 1
    assert set(groups[0]) == {"cwl", "waf"}


def test_correlate_no_match(waf_record):
    groups = merge.correlate_records(
        [waf_record(uri="/a"), waf_record(uri="/b")], [], []
    )
    assert len(groups) == 2
    assert all(set(g) == {"cwl"} for g in groups)


def test_correlate_three_sources(waf_record):
    cwl = waf_record(uri="/pay")
    s3 = waf_record(uri="/pay")
    waf = sampled_record(uri="/pay")
    groups = merge.correlate_records([cwl], [s3], [waf])
    assert len(groups) == 1
    assert set(groups[0]) == {"cwl", "s3", "waf"}


def test_correlate_duplicate_within_source_keeps_first(waf_record):
    first = waf_record(uri="/dup", timestamp=1735689600000, body="first")
    second = waf_record(uri="/dup", timestamp=1735689600400, body="second")
    groups = merge.correlate_records([first, second], [], [])
    assert len(groups) == 1
    assert groups[0]["cwl"] is first


# --- run_merge ---------------------------------------------------------------

LOG_GROUP = "aws-waf-logs-test"
WINDOW = (1735689000000, 1735690000000)


def test_run_merge_cwl_only(db, waf_record):
    records = [waf_record(uri="/a"), waf_record(uri="/b")]
    storage.save_source_records(db, "cwl", LOG_GROUP, records)

    count = merge.run_merge(db, LOG_GROUP, *WINDOW)

    assert count == 2
    merged = storage.load_merged_records(db, LOG_GROUP, *WINDOW)
    assert len(merged) == 2
    assert {r["_sources"] for r in merged} == {"cwl"}
    assert {r["httpRequest"]["uri"] for r in merged} == {"/a", "/b"}


def test_run_merge_cwl_waf_enrichment(db, waf_record):
    cwl = waf_record(
        method="POST",
        uri="/login",
        headers={"Authorization": "REDACTED"},
        body='{"user":"admin"}',
    )
    waf = sampled_record(
        uri="/login", method="POST", headers={"Authorization": "Bearer eyJ..."}
    )
    storage.save_source_records(db, "cwl", LOG_GROUP, [cwl])
    storage.save_source_records(db, "waf", LOG_GROUP, [waf])

    count = merge.run_merge(db, LOG_GROUP, *WINDOW)

    assert count == 1
    merged = storage.load_merged_records(db, LOG_GROUP, *WINDOW)[0]
    assert merged["_sources"] == "cwl,waf"
    assert headers_dict(merged)["authorization"] == "Bearer eyJ..."
    assert merged["httpRequest"]["requestBody"] == '{"user":"admin"}'


def test_run_merge_waf_only_marks_source(db):
    storage.save_source_records(
        db, "waf", LOG_GROUP, [sampled_record(headers={"Cookie": "session=abc"})]
    )

    merge.run_merge(db, LOG_GROUP, *WINDOW)

    merged = storage.load_merged_records(db, LOG_GROUP, *WINDOW)[0]
    assert merged["_sources"] == "waf"
    assert merged["httpRequest"]["requestBody"] == ""
    assert headers_dict(merged)["cookie"] == "session=abc"


def test_run_merge_replaces_previous(db, waf_record):
    storage.save_source_records(db, "cwl", LOG_GROUP, [waf_record(uri="/a")])

    merge.run_merge(db, LOG_GROUP, *WINDOW)
    second = merge.run_merge(db, LOG_GROUP, *WINDOW)

    assert second == 1
    rows = db.execute("SELECT COUNT(*) FROM merged_logs").fetchone()[0]
    assert rows == 1


def test_run_merge_respects_window(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        LOG_GROUP,
        [waf_record(uri="/in", timestamp=1735689600000)],
    )
    storage.save_source_records(
        db,
        "cwl",
        LOG_GROUP,
        [waf_record(uri="/out", timestamp=1835689600000)],
    )

    count = merge.run_merge(db, LOG_GROUP, *WINDOW)

    assert count == 1
    merged = storage.load_merged_records(db, LOG_GROUP, *WINDOW)
    assert merged[0]["httpRequest"]["uri"] == "/in"


def test_run_merge_action_filter(db, waf_record):
    storage.save_source_records(
        db,
        "cwl",
        LOG_GROUP,
        [waf_record(uri="/allow"), waf_record(uri="/block", action="BLOCK")],
    )

    count = merge.run_merge(db, LOG_GROUP, *WINDOW, action_filter="BLOCK")

    assert count == 1
    merged = storage.load_merged_records(db, LOG_GROUP, *WINDOW)
    assert merged[0]["httpRequest"]["uri"] == "/block"


def test_run_merge_empty_sources(db):
    assert merge.run_merge(db, LOG_GROUP, *WINDOW) == 0
    assert storage.load_merged_records(db, LOG_GROUP, *WINDOW) == []
