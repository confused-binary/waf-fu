"""Tests for the per-mode header replay policy in waf_fu.replay.fidelity."""

from __future__ import annotations

import pytest

from waf_fu.replay.fidelity import (
    COOKIE_ATTRIBUTE_NOTE,
    fidelity_report,
    replayable_headers,
    skipped_headers,
)

_ALWAYS_SKIPPED_NAMES = {
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
}


def test_skipped_headers_chrome_includes_host_and_framing_headers():
    skipped = skipped_headers("chrome")
    assert _ALWAYS_SKIPPED_NAMES <= skipped.keys()
    assert "host" in skipped
    for reason in skipped.values():
        assert reason and isinstance(reason, str)


def test_skipped_headers_firefox_is_subset_of_chrome():
    chrome = skipped_headers("chrome")
    firefox = skipped_headers("firefox")
    assert firefox.keys() < chrome.keys()
    chrome_only = chrome.keys() - firefox.keys()
    assert chrome_only == {"host", "upgrade"}
    for reason in firefox.values():
        assert reason and isinstance(reason, str)


def test_skipped_headers_curl_omits_host_and_cookie():
    skipped = skipped_headers("curl")
    assert _ALWAYS_SKIPPED_NAMES <= skipped.keys()
    assert "host" not in skipped
    assert "cookie" not in skipped
    for reason in skipped.values():
        assert reason and isinstance(reason, str)


def test_skipped_headers_unknown_mode_raises():
    with pytest.raises(ValueError):
        skipped_headers("edge")


# Regression: measured against real Chrome 151/chromedriver 151 and
# Firefox 153/geckodriver 0.37.1 (see 02-02-PLAN.md verified_facts). Chrome's
# CDP Fetch.continueRequest rejects a Host override outright with
# -32602 "Unsafe header: Host"; Firefox's BiDi network.continueRequest lets
# it through to the wire. A future "helpful" unification of the two modes
# must fail this test loudly.
def test_host_skip_is_chrome_only_regression():
    assert "host" in skipped_headers("chrome")
    assert "host" not in skipped_headers("firefox")


def test_replayable_headers_chrome_drops_host_and_content_length(make_request):
    req = make_request(
        headers={
            "Content-Length": "10",
            "User-Agent": "test-agent",
            "X-Custom": "value",
        }
    )
    result = replayable_headers(req, "chrome")
    assert "Host" not in result
    assert "Content-Length" not in result
    assert result["User-Agent"] == "test-agent"
    assert result["X-Custom"] == "value"
    names = list(result)
    assert names.index("User-Agent") < names.index("X-Custom")


def test_replayable_headers_firefox_also_returns_host(make_request):
    req = make_request(
        headers={
            "Content-Length": "10",
            "User-Agent": "test-agent",
            "X-Custom": "value",
        }
    )
    result = replayable_headers(req, "firefox")
    assert result["Host"] == "target.example.com"
    assert "Content-Length" not in result
    assert result["User-Agent"] == "test-agent"
    assert result["X-Custom"] == "value"


def test_fidelity_report_firefox_all_replayable_by_default(make_request):
    req = make_request()
    report = fidelity_report(req, "firefox")
    assert report.skipped == ()
    assert report.all_replayable is True
    assert report.curl_fallback is False


def test_fidelity_report_chrome_curl_fallback_when_host_present(make_request):
    req = make_request()
    report = fidelity_report(req, "chrome")
    assert report.curl_fallback is True
    for name, reason in report.skipped:
        assert name in req.headers
        assert reason == skipped_headers("chrome")[name.lower()]


@pytest.mark.parametrize("mode", ["chrome", "firefox", "curl"])
def test_fidelity_report_cookie_note_present_when_cookies_set(make_request, mode):
    req = make_request(cookies="sid=1")
    report = fidelity_report(req, mode)
    assert report.cookie_note == COOKIE_ATTRIBUTE_NOTE


@pytest.mark.parametrize("mode", ["chrome", "firefox", "curl"])
def test_fidelity_report_cookie_note_empty_when_no_cookies(make_request, mode):
    req = make_request()
    report = fidelity_report(req, mode)
    assert report.cookie_note == ""


def test_fidelity_report_unknown_mode_raises(make_request):
    req = make_request()
    with pytest.raises(ValueError):
        fidelity_report(req, "edge")
