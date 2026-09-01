"""Wire-level assertions on the CDP commands sent during a Chrome replay."""

from __future__ import annotations

import base64

import pytest
import trio
from conftest import attach_fake_bidi_connection

from waf_fu.replay import chrome


def _paused_wire(url, method="GET", headers=None, request_id="req-1"):
    return {
        "requestId": request_id,
        "request": {
            "url": url,
            "method": method,
            "headers": headers or {},
            "initialPriority": "Medium",
            "referrerPolicy": "strict-origin-when-cross-origin",
        },
        "frameId": "F1",
        "resourceType": "Document",
    }


def _wire_session(cdp_devtools, fake_cdp_session):
    """A FakeCdpSession pre-seeded with responses for Page/Runtime commands,
    so the real generators don't crash on post-yield attribute access."""
    session = fake_cdp_session()
    session.responses["Page.enable"] = {}
    session.responses["Page.disable"] = {}
    session.responses["Page.navigate"] = {"frameId": "F1"}
    session.responses["Runtime.evaluate"] = {
        "result": {"type": "undefined"},
    }
    return session


def _attach(fake_cdp_driver, session, cdp_devtools):
    attach_fake_bidi_connection(fake_cdp_driver, session, cdp_devtools)
    return fake_cdp_driver


# --- Task 1: _replay_async command sequence and behavior -------------------


def test_command_sequence_get_uses_page_navigate(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="GET", uri="/resource")
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url, "GET"))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    trio.run(chrome._replay_async, driver, req, 5.0)

    methods = [c["method"] for c in session.commands]
    assert methods == [
        "Page.enable",
        "Fetch.enable",
        "Page.navigate",
        "Fetch.continueRequest",
        "Fetch.disable",
        "Page.disable",
    ]
    nav_params = session.commands_named("Page.navigate")[0]
    assert nav_params["url"] == req.full_url


def test_command_sequence_post_uses_form_submit(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="POST", uri="/submit", body="a=1")
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url, "POST"))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    trio.run(chrome._replay_async, driver, req, 5.0)

    methods = [c["method"] for c in session.commands]
    assert methods == [
        "Page.enable",
        "Fetch.enable",
        "Runtime.evaluate",
        "Fetch.continueRequest",
        "Fetch.disable",
        "Page.disable",
    ]
    eval_params = session.commands_named("Runtime.evaluate")[0]
    assert req.full_url in eval_params["expression"]
    assert "method='POST'" in eval_params["expression"]


def test_continue_request_method_matches_req_method(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="POST", uri="/x")
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    trio.run(chrome._replay_async, driver, req, 5.0)

    params = session.commands_named("Fetch.continueRequest")[0]
    assert params["method"] == "POST"


def test_post_data_is_base64_of_utf8_body_non_ascii(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    body = '{"k":"vålue-ü"}'
    req = make_request(method="POST", uri="/x", body=body)
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    trio.run(chrome._replay_async, driver, req, 5.0)

    params = session.commands_named("Fetch.continueRequest")[0]
    assert base64.b64decode(params["postData"]).decode("utf-8") == body


def test_no_post_data_key_when_body_empty(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="GET", uri="/x")
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    trio.run(chrome._replay_async, driver, req, 5.0)

    params = session.commands_named("Fetch.continueRequest")[0]
    assert "postData" not in params


def test_header_fidelity(cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request):
    devtools = cdp_devtools
    req = make_request(
        method="POST",
        uri="/x",
        headers={"X-Custom": "abc", "User-Agent": "ua-1"},
    )
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    trio.run(chrome._replay_async, driver, req, 5.0)

    params = session.commands_named("Fetch.continueRequest")[0]
    sent = {h["name"]: h["value"] for h in params["headers"]}
    assert sent["X-Custom"] == "abc"
    assert sent["User-Agent"] == "ua-1"
    assert "Host" not in sent


def test_different_url_is_passed_through_untouched(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="GET", uri="/x")
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(
            _paused_wire("https://cdn.example.com/favicon.ico", request_id="sub-1")
        )
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    with pytest.raises(TimeoutError):
        trio.run(chrome._replay_async, driver, req, 0.05)

    params = session.commands_named("Fetch.continueRequest")[0]
    assert set(params.keys()) == {"requestId"}
    assert params["requestId"] == "sub-1"


def test_timeout_raises_when_no_matching_event_arrives(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="GET", uri="/x")
    session = _wire_session(devtools, fake_cdp_session)
    driver = _attach(fake_cdp_driver, session, devtools)

    with pytest.raises(TimeoutError):
        trio.run(chrome._replay_async, driver, req, 0.05)

    assert session.commands[-1]["method"] == "Page.disable"
    assert session.commands[-2]["method"] == "Fetch.disable"


# --- Task 2: apply_and_navigate rewire, one Fetch-based path for every method


@pytest.mark.parametrize(
    "method,body",
    [
        ("POST", '{"a":1}'),
        ("POST", '{"k":"vålue-ü"}'),
        ("GET", ""),
    ],
)
def test_apply_and_navigate_method_and_body(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request, method, body
):
    devtools = cdp_devtools
    req = make_request(method=method, uri="/x", body=body)
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    chrome.apply_and_navigate(driver, req, timeout=5.0)

    params = session.commands_named("Fetch.continueRequest")[0]
    assert params["method"] == method
    if body:
        assert base64.b64decode(params["postData"]).decode("utf-8") == body
    else:
        assert "postData" not in params


def test_apply_and_navigate_never_uses_execute_script(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="POST", uri="/x", body="x")
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url))
    )
    driver = _attach(fake_cdp_driver, session, devtools)
    driver.execute_script = None  # would raise TypeError if ever called

    chrome.apply_and_navigate(driver, req, timeout=5.0)


def test_set_extra_http_headers_never_sent(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="POST", uri="/x", body="x")
    session = _wire_session(devtools, fake_cdp_session)
    session.queue_event(
        devtools.fetch.RequestPaused.from_json(_paused_wire(req.full_url))
    )
    driver = _attach(fake_cdp_driver, session, devtools)

    chrome.apply_and_navigate(driver, req, timeout=5.0)

    assert not any(
        name == "Network.setExtraHTTPHeaders" for name, _ in driver.cdp_calls
    )


def test_apply_and_navigate_forwards_timeout(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="GET", uri="/x")
    session = _wire_session(devtools, fake_cdp_session)
    driver = _attach(fake_cdp_driver, session, devtools)

    with pytest.raises(TimeoutError, match="0.05s"):
        chrome.apply_and_navigate(driver, req, timeout=0.05)


def test_timeout_error_propagates_out_of_apply_and_navigate(
    cdp_devtools, fake_cdp_session, fake_cdp_driver, make_request
):
    devtools = cdp_devtools
    req = make_request(method="GET", uri="/x")
    session = _wire_session(devtools, fake_cdp_session)
    driver = _attach(fake_cdp_driver, session, devtools)

    with pytest.raises(TimeoutError):
        chrome.apply_and_navigate(driver, req, timeout=0.05)


# --- Task 3: cookie attribute fidelity and proxy wiring ---------------------


def test_cookie_attributes(fake_cdp_driver, make_request):
    req = make_request(
        method="GET",
        uri="/app/settings",
        cookies="sid=abc123",
        scheme="https",
    )

    chrome._inject_cookies_cdp(fake_cdp_driver, req)

    name, params = fake_cdp_driver.cdp_calls[0]
    assert name == "Network.setCookie"
    assert params["name"] == "sid"
    assert params["value"] == "abc123"
    assert params["domain"] == "target.example.com"
    assert params["path"] == "/app/settings"
    assert params["secure"] is True
    assert params["sameSite"] == "Lax"


def test_inject_cookies_path_is_request_path_not_hardcoded_root(
    fake_cdp_driver, make_request
):
    req = make_request(uri="/a/b/c", cookies="x=1")

    chrome._inject_cookies_cdp(fake_cdp_driver, req)

    _, params = fake_cdp_driver.cdp_calls[0]
    assert params["path"] == "/a/b/c"


def test_inject_cookies_domain_strips_port_from_host(fake_cdp_driver, make_request):
    req = make_request(host="target.example.com:8443", cookies="x=1")

    chrome._inject_cookies_cdp(fake_cdp_driver, req)

    _, params = fake_cdp_driver.cdp_calls[0]
    assert params["domain"] == "target.example.com"


def test_inject_cookies_skips_fragments_without_equals(fake_cdp_driver, make_request):
    req = make_request(cookies="a=1; malformed; b=2")

    chrome._inject_cookies_cdp(fake_cdp_driver, req)

    names = [params["name"] for _, params in fake_cdp_driver.cdp_calls]
    assert names == ["a", "b"]


def test_inject_cookies_continues_after_one_failure(fake_cdp_driver, make_request):
    req = make_request(cookies="a=1; b=2")
    calls = []

    def flaky_execute_cdp_cmd(name, params):
        calls.append((name, params))
        if params["name"] == "a":
            raise RuntimeError("boom")
        return {}

    fake_cdp_driver.execute_cdp_cmd = flaky_execute_cdp_cmd

    chrome._inject_cookies_cdp(fake_cdp_driver, req)

    names = [params["name"] for _, params in calls]
    assert names == ["a", "b"]


def test_bidi_failure_falls_back_to_network_set_extra_headers(
    fake_cdp_driver, make_request
):
    """When the CDP session approach crashes, apply_and_navigate should
    fall back to Network.setExtraHTTPHeaders."""
    req = make_request(
        method="GET",
        uri="/cable",
        headers={"Pragma": "no-cache", "Cache-Control": "no-cache"},
    )

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def broken_session(driver, *, new_tab=False):
        raise RuntimeError("CDP session exploded")
        yield  # noqa: unreachable

    chrome._open_cdp_session = broken_session

    chrome.apply_and_navigate(fake_cdp_driver, req, timeout=5.0)

    cdp_names = [name for name, _ in fake_cdp_driver.cdp_calls]
    assert "Network.enable" in cdp_names
    assert "Network.setExtraHTTPHeaders" in cdp_names
    assert "Network.disable" in cdp_names
    assert fake_cdp_driver.current_url == req.full_url

    set_headers_call = next(
        params
        for name, params in fake_cdp_driver.cdp_calls
        if name == "Network.setExtraHTTPHeaders" and params.get("headers")
    )
    assert "Pragma" in set_headers_call["headers"]
    assert "Cache-Control" in set_headers_call["headers"]


def test_proxy_adds_proxy_server_argument():
    opts = chrome._chrome_options("http://127.0.0.1:8080")
    assert "--proxy-server=http://127.0.0.1:8080" in opts.arguments


def test_proxy_absent_produces_no_proxy_server_argument():
    opts = chrome._chrome_options("")
    assert not any(arg.startswith("--proxy-server=") for arg in opts.arguments)
