"""Tests for curl command generation in waf_fu.replay.curl."""

from __future__ import annotations

import shlex

from waf_fu.replay.curl import to_curl


def test_curl_includes_host_header(make_request):
    req = make_request(host="target.example.com")
    argv = shlex.split(to_curl(req))
    idx = argv.index("-H")
    assert argv[idx + 1] == "Host: target.example.com"


def test_curl_omits_content_length_and_hop_by_hop_headers(make_request):
    req = make_request(
        headers={
            "Content-Length": "42",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
            "Keep-Alive": "timeout=5",
        }
    )
    cmd = to_curl(req)
    argv = shlex.split(cmd)
    header_values = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-H"]
    assert not any(v.lower().startswith("content-length:") for v in header_values)
    assert not any(v.lower().startswith("connection:") for v in header_values)
    assert not any(v.lower().startswith("transfer-encoding:") for v in header_values)
    assert not any(v.lower().startswith("keep-alive:") for v in header_values)


def test_curl_passes_cookies_via_cookie_flag_not_header(make_request):
    req = make_request(cookies="sid=1; x=2")
    argv = shlex.split(to_curl(req))
    idx = argv.index("--cookie")
    assert argv[idx + 1] == "sid=1; x=2"
    header_values = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-H"]
    assert not any(v.lower().startswith("cookie:") for v in header_values)


def test_curl_no_cookies_means_no_cookie_flag(make_request):
    req = make_request()
    argv = shlex.split(to_curl(req))
    assert "--cookie" not in argv


def test_curl_method_and_body_round_trip_non_ascii(make_request):
    req = make_request(method="POST", body="café ☃")
    argv = shlex.split(to_curl(req))
    x_idx = argv.index("-X")
    assert argv[x_idx + 1] == "POST"
    data_idx = argv.index("--data-raw")
    assert argv[data_idx + 1] == "café ☃"


def test_curl_compressed_only_with_accept_encoding_header(make_request):
    req_with = make_request(headers={"Accept-Encoding": "gzip"})
    req_without = make_request()
    assert "--compressed" in shlex.split(to_curl(req_with))
    assert "--compressed" not in shlex.split(to_curl(req_without))


def test_curl_proxy_flag_present_only_when_passed(make_request):
    req = make_request()
    assert "--proxy" not in shlex.split(to_curl(req))
    argv = shlex.split(to_curl(req, proxy="http://127.0.0.1:8080"))
    idx = argv.index("--proxy")
    assert argv[idx + 1] == "http://127.0.0.1:8080"


def test_curl_shell_quoting_survives_quotes_and_spaces(make_request):
    req = make_request(headers={"X-Custom": 'it\'s a "test" value'})
    cmd = to_curl(req)
    argv = shlex.split(cmd)
    header_values = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-H"]
    assert 'X-Custom: it\'s a "test" value' in header_values


def test_curl_round_trips_through_shlex_split(make_request):
    req = make_request(
        method="POST",
        cookies="sid=1",
        body="a=b&c=d",
        headers={"User-Agent": "test agent"},
    )
    cmd = to_curl(req, proxy="socks5://127.0.0.1:1080")
    argv = shlex.split(cmd)
    assert argv[0] == "curl"
    assert "-sS" in argv
    assert argv[argv.index("-X") + 1] == "POST"
    assert argv[argv.index("--proxy") + 1] == "socks5://127.0.0.1:1080"
    assert argv[argv.index("--cookie") + 1] == "sid=1"
    assert argv[argv.index("--data-raw") + 1] == "a=b&c=d"
    assert argv[-1] == req.full_url
