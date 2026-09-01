"""Tests for the Firefox BiDi replay backend."""

from __future__ import annotations

import inspect
import time

import pytest

from waf_fu.replay import firefox

# --- Task 1: options construction + WebExtension deletion ------------------


def test_firefox_options_no_proxy_sets_web_socket_url():
    opts = firefox._firefox_options("")
    assert opts.enable_bidi is True
    assert "network.proxy.type" not in opts.preferences


def test_proxy_http_sets_proxy_preferences():
    opts = firefox._firefox_options("http://127.0.0.1:8080")
    prefs = opts.preferences
    assert prefs["network.proxy.type"] == 1
    assert prefs["network.proxy.http"] == "127.0.0.1"
    assert prefs["network.proxy.http_port"] == 8080
    assert prefs["network.proxy.ssl"] == "127.0.0.1"
    assert prefs["network.proxy.ssl_port"] == 8080
    assert opts.enable_bidi is True


def test_proxy_socks_sets_socks_preferences():
    opts = firefox._firefox_options("socks5://127.0.0.1:1080")
    prefs = opts.preferences
    assert prefs["network.proxy.socks"] == "127.0.0.1"
    assert prefs["network.proxy.socks_port"] == 1080
    assert prefs["network.proxy.socks_version"] == 5
    assert opts.enable_bidi is True


def test_webextension_machinery_deleted():
    for name in (
        "cleanup_extension",
        "_install_firefox_header_extension",
        "_ff_set_pending_headers",
        "_inject_cookies_standard",
    ):
        assert not hasattr(firefox, name), f"{name} should have been deleted"


def test_tui_imports_cleanly_without_cleanup_extension_call():
    from waf_fu.tui import WafTUI

    source = inspect.getsource(WafTUI._cleanup_browser)
    assert "cleanup_extension" not in source


# --- Task 2: BiDi request interception for method, headers and body -------


def _drive(driver, request, via="get"):
    """Make the fake driver dispatch `request` through the registered
    handler synchronously, mirroring the real BiDi listener firing during
    navigation. `via="get"` (default) fires on driver.get() — true for GET
    replays. `via="script"` fires on execute_async_script() instead, since
    non-GET replays are issued via fetch() from page context."""
    if via == "script":
        original_async = driver.execute_async_script

        def _async_script(script, *args):
            result = original_async(script, *args)
            driver.network.dispatch(request)
            return result

        driver.execute_async_script = _async_script
        return

    original_get = driver.get

    def _get(url):
        original_get(url)
        driver.network.dispatch(request)

    driver.get = _get


def _continue_commands(conn):
    return [c for c in conn.commands if c["method"] == "network.continueRequest"]


def test_apply_and_navigate_registers_one_handler_and_navigates(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request()
    request, conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert fake_firefox_driver.navigations == [req.full_url]
    assert len(_continue_commands(conn)) == 1


@pytest.mark.parametrize("method", ["POST"])
@pytest.mark.parametrize(
    "body,content_type",
    [
        ('{"a":1}', "application/json"),
        ("a=1&b=2", "application/x-www-form-urlencoded"),
        ("vålue-ü", "text/plain"),
    ],
)
def test_method_and_body_matrix(
    make_request, fake_firefox_driver, make_bidi_request, method, body, content_type
):
    req = make_request(method=method, body=body, headers={"Content-Type": content_type})
    request, conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request, via="script")

    firefox.apply_and_navigate(fake_firefox_driver, req)

    params = _continue_commands(conn)[0]["params"]
    assert params["method"] == method
    assert params["body"] == {"type": "string", "value": body}


def test_no_body_override_when_body_empty(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(method="GET")
    request, conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    params = _continue_commands(conn)[0]["params"]
    assert "body" not in params


def test_header_fidelity_includes_host_and_cookie(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(host="target.example.com", cookies="sid=abc; theme=dark")
    request, conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    params = _continue_commands(conn)[0]["params"]
    header_names = {h["name"] for h in params["headers"]}
    assert "Host" in header_names
    assert "Cookie" in header_names
    cookie_value = next(
        h["value"]["value"] for h in params["headers"] if h["name"] == "Cookie"
    )
    assert cookie_value == "sid=abc; theme=dark"


def test_non_target_url_passes_through_unmodified(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request()
    request, conn = make_bidi_request(url="https://other.example.com/")
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    params = _continue_commands(conn)[0]["params"]
    assert "method" not in params
    assert "headers" not in params
    assert "body" not in params


def test_handler_removed_and_cleared_before_next_registration(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request()
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert fake_firefox_driver.network.cleared == 1
    assert fake_firefox_driver.network.removed


def test_get_replay_runs_no_scripts(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(method="GET")
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert fake_firefox_driver.scripts == []
    assert fake_firefox_driver.async_scripts == []


@pytest.mark.parametrize("method", ["POST"])
def test_non_get_replay_records_one_async_fetch_and_never_navigates_to_target(
    make_request, fake_firefox_driver, make_bidi_request, method
):
    req = make_request(method=method, body="x")
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request, via="script")

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert len(fake_firefox_driver.async_scripts) == 1
    _script, url, script_method, body = fake_firefox_driver.async_scripts[0]
    assert url == req.full_url
    assert script_method == method
    assert body == "x"
    assert req.full_url not in fake_firefox_driver.navigations


def test_timeout_raises_and_leaves_handler_registered(
    make_request, fake_firefox_driver
):
    req = make_request()

    def _slow_get(url):
        time.sleep(0.5)

    fake_firefox_driver.get = _slow_get

    with pytest.raises(TimeoutError):
        firefox.apply_and_navigate(fake_firefox_driver, req, timeout=0.05)

    assert fake_firefox_driver.network.removed == []


# --- Task 3: cookie attribute fidelity via BiDi storage.setCookie ---------


def test_cookie_attributes_two_fragments_produce_two_set_cookie_calls(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(
        host="target.example.com",
        scheme="https",
        cookies="sid=abc; theme=dark",
    )
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    cookies = fake_firefox_driver.storage.cookies
    assert len(cookies) == 2
    by_name = {c["name"]: c for c in cookies}
    assert set(by_name) == {"sid", "theme"}

    sid = by_name["sid"]
    assert sid["value"] == {"type": "string", "value": "abc"}
    assert sid["domain"] == "target.example.com"
    assert sid["path"] == "/"
    assert sid["secure"] is True
    assert sid["httpOnly"] is False
    assert sid["sameSite"] == "lax"


def test_cookie_domain_strips_port(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(host="target.example.com:8443", cookies="sid=abc")
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert fake_firefox_driver.storage.cookies[0]["domain"] == "target.example.com"


def test_cookie_secure_false_for_http(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(scheme="http", cookies="sid=abc")
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert fake_firefox_driver.storage.cookies[0]["secure"] is False


def test_cookies_set_before_any_navigation(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(cookies="sid=abc")
    request, _conn = make_bidi_request(url=req.full_url)

    original_get = fake_firefox_driver.get

    def _get(url):
        # Cookies must already be set by the time navigation starts.
        assert fake_firefox_driver.storage.cookies
        original_get(url)
        fake_firefox_driver.network.dispatch(request)

    fake_firefox_driver.get = _get
    assert fake_firefox_driver.navigations == []

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert fake_firefox_driver.storage.cookies


def test_cookie_fragment_without_equals_is_skipped(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request(cookies="sid=abc")
    req.cookies = "sid=abc; malformed"
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert len(fake_firefox_driver.storage.cookies) == 1
    assert fake_firefox_driver.storage.cookies[0]["name"] == "sid"


def test_cookie_set_failure_does_not_abort_remaining_cookies(
    make_request, fake_firefox_driver, make_bidi_request, monkeypatch
):
    req = make_request(cookies="sid=abc; theme=dark")
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    calls = []
    original_set_cookie = fake_firefox_driver.storage.set_cookie

    def _flaky_set_cookie(cookie=None, partition=None):
        calls.append(cookie)
        if cookie["name"] == "sid":
            raise RuntimeError("boom")
        original_set_cookie(cookie=cookie, partition=partition)

    fake_firefox_driver.storage.set_cookie = _flaky_set_cookie

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert len(calls) == 2
    assert fake_firefox_driver.storage.cookies == [
        c for c in calls if c["name"] == "theme"
    ]


def test_no_cookies_means_no_set_cookie_calls(
    make_request, fake_firefox_driver, make_bidi_request
):
    req = make_request()
    request, _conn = make_bidi_request(url=req.full_url)
    _drive(fake_firefox_driver, request)

    firefox.apply_and_navigate(fake_firefox_driver, req)

    assert fake_firefox_driver.storage.cookies == []


# --- Task 1 (quick-2): _fetch_with_method and path-scoped addon pattern ---


def test_fetch_with_method_success_writes_body_and_stages_origin(
    make_request, fake_firefox_driver
):
    req = make_request(method="POST", body="payload", host="target.example.com")

    firefox._fetch_with_method(fake_firefox_driver, req, 5.0)

    assert fake_firefox_driver.navigations == [f"{req.scheme}://{req.host}"]
    assert fake_firefox_driver.script_timeouts == [5.0]
    _script, url, method, body = fake_firefox_driver.async_scripts[0]
    assert url == req.full_url
    assert method == "POST"
    assert body == "payload"
    _doc_script, written_body = fake_firefox_driver.scripts[0]
    assert written_body == "<html>ok</html>"


def test_fetch_with_method_raising_script_never_falls_back_to_get(
    make_request, fake_firefox_driver
):
    req = make_request(method="POST")
    fake_firefox_driver.async_result = RuntimeError("script exploded")

    with pytest.raises(RuntimeError):
        firefox._fetch_with_method(fake_firefox_driver, req, 5.0)

    assert req.full_url not in fake_firefox_driver.navigations
    assert fake_firefox_driver.navigations == [f"{req.scheme}://{req.host}"]


def test_fetch_with_method_status_zero_raises_and_never_navigates_to_target(
    make_request, fake_firefox_driver
):
    req = make_request(method="POST")
    fake_firefox_driver.async_result = {
        "status": 0,
        "text": "TypeError: NetworkError when attempting to fetch resource.",
    }

    with pytest.raises(RuntimeError, match="POST"):
        firefox._fetch_with_method(fake_firefox_driver, req, 5.0)

    assert req.full_url not in fake_firefox_driver.navigations
    assert fake_firefox_driver.navigations == [f"{req.scheme}://{req.host}"]


def test_install_header_addon_pattern_is_path_scoped(fake_firefox_driver):
    firefox._install_header_addon(
        fake_firefox_driver,
        {"X-Test": "1"},
        "https://t.example.com/api/v1/thing?q=1",
    )

    source = fake_firefox_driver.addon_sources[0]
    assert '"https://t.example.com/api/v1/thing*"' in source
    assert '"https://t.example.com/*"' not in source
    assert '"https://t.example.com/other*"' not in source


def test_install_header_addon_pattern_empty_path_defaults_to_root(
    fake_firefox_driver,
):
    firefox._install_header_addon(
        fake_firefox_driver, {"X-Test": "1"}, "https://t.example.com"
    )

    source = fake_firefox_driver.addon_sources[0]
    assert '"https://t.example.com/*"' in source


# --- Task 2 (quick-2): non-GET routing through fetch in both branches -----


def test_navigate_with_method_removed():
    assert not hasattr(firefox, "_navigate_with_method")


def test_webextension_branch_get_navigates_directly(
    make_request, fake_firefox_driver_no_bidi
):
    req = make_request(method="GET")

    firefox.apply_and_navigate(fake_firefox_driver_no_bidi, req)

    assert fake_firefox_driver_no_bidi.navigations == [req.full_url]
    assert fake_firefox_driver_no_bidi.async_scripts == []


def test_webextension_branch_post_uses_form_submission(
    make_request, fake_firefox_driver_no_bidi
):
    req = make_request(method="POST", body="a=1")

    firefox.apply_and_navigate(fake_firefox_driver_no_bidi, req)

    assert len(fake_firefox_driver_no_bidi.navigations) == 1
    assert fake_firefox_driver_no_bidi.navigations[0].startswith(
        "data:text/html;base64,"
    )
    assert fake_firefox_driver_no_bidi.async_scripts == []


def test_addon_fetch_replay_removed():
    assert not hasattr(firefox, "_replay_via_addon_fetch")
    assert not hasattr(firefox, "_REPLAY_ADDON_BG_TEMPLATE")
