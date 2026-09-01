"""Proof the shared fixtures in conftest.py behave as documented."""

import curses

import trio

from waf_fu.tui import WafTUI


def test_default_make_request(make_request):
    req = make_request()
    assert req.method == "GET"
    assert req.host == "target.example.com"
    assert req.scheme == "https"
    assert req.full_url == "https://target.example.com/"


def test_args_appear_in_full_url(make_request):
    req = make_request(args="a=1")
    assert req.full_url == "https://target.example.com/?a=1"


def test_cookies_populate_request_and_headers(make_request):
    req = make_request(cookies="sid=1; x=2")
    assert req.cookies == "sid=1; x=2"
    assert req.headers["Cookie"] == "sid=1; x=2"


def test_scheme_http_flips_request_scheme(make_request):
    req = make_request(scheme="http")
    assert req.scheme == "http"


def test_caller_header_overrides_default_host(make_request):
    req = make_request(headers={"Host": "other.example"})
    assert req.host == "other.example"


def test_body_populates_request(make_request):
    req = make_request(body='{"a":1}')
    assert req.body == '{"a":1}'


def test_fake_cdp_session_captures_real_wire_dicts(cdp_devtools, fake_cdp_session):
    devtools = cdp_devtools
    session = fake_cdp_session()

    async def _drive():
        await session.execute(devtools.fetch.enable())
        await session.execute(
            devtools.fetch.continue_request(
                request_id=devtools.fetch.RequestId("r1"),
                method="POST",
                post_data="eA==",
                headers=[devtools.fetch.HeaderEntry(name="X-A", value="1")],
            )
        )

    trio.run(_drive)

    assert session.commands[0]["method"] == "Fetch.enable"
    continue_params = session.commands[1]["params"]
    assert continue_params["requestId"] == "r1"
    assert continue_params["method"] == "POST"
    assert continue_params["postData"] == "eA=="
    assert continue_params["headers"] == [{"name": "X-A", "value": "1"}]


def test_fake_cdp_session_listen_delivers_queued_events_then_stops(
    cdp_devtools, fake_cdp_session
):
    devtools = cdp_devtools
    session = fake_cdp_session()
    event = devtools.fetch.RequestPaused(
        request_id=devtools.fetch.RequestId("r1"),
        request=devtools.network.Request(
            url="https://target.example.com/",
            method="GET",
            headers=devtools.network.Headers(),
            initial_priority=devtools.network.ResourcePriority.MEDIUM,
            referrer_policy="strict-origin-when-cross-origin",
        ),
        frame_id=devtools.page.FrameId("f1"),
        resource_type=devtools.network.ResourceType.DOCUMENT,
        response_error_reason=None,
        response_status_code=None,
        response_status_text=None,
        response_headers=None,
        network_id=None,
        redirected_request_id=None,
    )
    session.queue_event(event)

    async def _listen():
        received = []
        async for evt in session.listen(devtools.fetch.RequestPaused):
            received.append(evt)
        return received

    received = trio.run(_listen)
    assert received == [event]


def test_fake_bidi_network_dispatch_produces_continue_request(
    fake_firefox_driver, make_bidi_request
):
    def _handler(request):
        request.set_method("POST")
        request.set_headers({"X-A": "1"})
        request.set_body("hello")

    fake_firefox_driver.network.add_request_handler(_handler)
    request, conn = make_bidi_request()
    fake_firefox_driver.network.dispatch(request)

    assert len(conn.commands) == 1
    command = conn.commands[0]
    assert command["method"] == "network.continueRequest"
    params = command["params"]
    assert params["request"] == "req-1"
    assert params["method"] == "POST"
    assert {"name": "X-A", "value": {"type": "string", "value": "1"}} in params[
        "headers"
    ]
    assert params["body"] == {"type": "string", "value": "hello"}


def test_fake_bidi_network_observer_handler_still_continues(
    fake_firefox_driver, make_bidi_request
):
    def _observer(request):
        pass

    fake_firefox_driver.network.add_request_handler(_observer)
    request, conn = make_bidi_request()
    fake_firefox_driver.network.dispatch(request)

    assert len(conn.commands) == 1
    assert conn.commands[0]["method"] == "network.continueRequest"


def test_fake_bidi_storage_records_set_cookie(fake_firefox_driver):
    cookie = {"name": "sid", "value": "1"}
    fake_firefox_driver.storage.set_cookie(cookie)
    assert fake_firefox_driver.storage.cookies == [cookie]


# ── scripted_stdscr / headless_curses (drives WafTUI.run() headlessly) ──────


def test_scripted_stdscr_drives_run_headlessly(
    make_request, scripted_stdscr, headless_curses
):
    requests = [make_request(uri="/a"), make_request(uri="/b")]
    t = WafTUI(requests, auth_filter_default=False, db=None)

    stdscr = scripted_stdscr([curses.KEY_DOWN, ord("q")])
    t.run(stdscr)

    assert t.cursor == 1


def test_scripted_stdscr_on_exhaust_contract(scripted_stdscr):
    # Pins the on_exhaust contract directly so a future edit cannot silently
    # reintroduce a hang: run()'s loop exits on ord("q") (the default), while
    # overlay loops (05-02/05-03) need on_exhaust=27 (Esc) instead.
    assert scripted_stdscr([], on_exhaust=27).getch() == 27
    assert scripted_stdscr([]).getch() == ord("q")
