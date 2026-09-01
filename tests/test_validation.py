"""Tests for pre-replay request validation in waf_fu.replay.validation."""

from __future__ import annotations

import pytest

from waf_fu.replay.validation import VALID_METHODS, validate_request


def test_valid_get_request_has_no_errors(make_request):
    req = make_request()
    assert validate_request(req) == []


@pytest.mark.parametrize("method", ["", "GE T", "FETCH", "get"])
def test_bad_method_produces_exactly_one_error(make_request, method):
    req = make_request(method=method)
    errors = validate_request(req)
    assert len(errors) == 1
    assert "method" in errors[0].lower()


def test_valid_methods_are_uppercase_only():
    assert VALID_METHODS == {"GET", "POST", "HEAD", "OPTIONS"}
    assert "get" not in VALID_METHODS


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_removed_write_methods_produce_exactly_one_error(make_request, method):
    req = make_request(method=method)
    errors = validate_request(req)
    assert len(errors) == 1
    assert "method" in errors[0].lower()


def test_empty_host_produces_url_error(make_request):
    req = make_request(host="")
    errors = validate_request(req)
    assert any("url" in e.lower() for e in errors)


def test_non_http_scheme_produces_scheme_error(make_request):
    req = make_request(scheme="ftp")
    errors = validate_request(req)
    assert any("scheme" in e.lower() for e in errors)


def test_header_name_with_empty_string_is_rejected(make_request):
    req = make_request(headers={"": "value"})
    errors = validate_request(req)
    assert any("''" in e for e in errors)


def test_header_name_with_space_is_rejected(make_request):
    req = make_request(headers={"X Custom": "value"})
    errors = validate_request(req)
    assert any("X Custom" in e for e in errors)


def test_header_name_with_colon_is_rejected(make_request):
    req = make_request(headers={"X-Custom:": "value"})
    errors = validate_request(req)
    assert any("X-Custom:" in e for e in errors)


def test_header_name_with_control_char_is_rejected(make_request):
    name = "X-Cus\x01tom"
    req = make_request(headers={name: "value"})
    errors = validate_request(req)
    assert any(repr(name) in e for e in errors)


def test_header_value_with_cr_is_rejected(make_request):
    req = make_request(headers={"X-Custom": "va\rlue"})
    errors = validate_request(req)
    assert any("X-Custom" in e for e in errors)


def test_header_value_with_lf_is_rejected(make_request):
    req = make_request(headers={"X-Custom": "va\nlue"})
    errors = validate_request(req)
    assert any("X-Custom" in e for e in errors)


def test_multiple_problems_produce_multiple_errors_in_stable_order(make_request):
    req = make_request(method="FETCH", host="")
    errors_1 = validate_request(req)
    errors_2 = validate_request(req)
    assert len(errors_1) >= 2
    assert errors_1 == errors_2


def test_all_errors_are_strings(make_request):
    req = make_request(method="FETCH", scheme="ftp", headers={"": "\r\n"})
    errors = validate_request(req)
    assert errors
    for e in errors:
        assert isinstance(e, str)
        assert e
