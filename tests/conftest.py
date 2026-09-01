"""Shared pytest fixtures for waf-fu tests.

Provides WAF-record/ReconstructedRequest factories plus high-fidelity fakes
for Chrome's CDP session and Firefox's BiDi network layer, built around
selenium's own command generators and wrapper classes so a test failure means
the production code sent the wrong protocol message, not that a hand-rolled
mock disagreed.
"""

from __future__ import annotations

import contextlib

import pytest
import trio

import waf_fu.tui as tui_module
from waf_fu.aws_session import clear_cache as _clear_session_cache
from waf_fu.models import ReconstructedRequest


@pytest.fixture(autouse=True)
def _fresh_aws_session_cache():
    """Drop cached boto3 sessions so monkeypatched tests start clean."""
    _clear_session_cache()
    yield
    _clear_session_cache()


def _build_waf_record(
    method="GET",
    uri="/",
    args="",
    host="target.example.com",
    scheme="https",
    headers=None,
    cookies="",
    body="",
    timestamp=1735689600000,
    action="ALLOW",
    client_ip="203.0.113.7",
    country="US",
    http_version="HTTP/2",
    terminating_rule_id="",
    rule_group_list=None,
) -> dict:
    # Ordered so callers can override Host/x-forwarded-proto/Cookie by name
    # (case-insensitively) via `headers` without duplicating the header.
    ordered: dict[str, str] = {}

    def _set(name: str, value: str) -> None:
        existing = next((k for k in ordered if k.lower() == name.lower()), None)
        if existing is not None:
            del ordered[existing]
        ordered[name] = value

    _set("Host", host)
    _set("x-forwarded-proto", scheme)
    for name, value in (headers or {}).items():
        _set(name, value)
    if cookies:
        _set("Cookie", cookies)

    raw_headers = [{"name": n, "value": v} for n, v in ordered.items()]
    record = {
        "timestamp": timestamp,
        "action": action,
        "terminatingRuleId": terminating_rule_id,
        "httpRequest": {
            "httpMethod": method,
            "uri": uri,
            "args": args,
            "httpVersion": http_version,
            "clientIp": client_ip,
            "country": country,
            "headers": raw_headers,
            "requestBody": body,
            "requestBodySize": len(body) if body else 0,
        },
    }
    if rule_group_list is not None:
        record["ruleGroupList"] = rule_group_list
    return record


@pytest.fixture
def waf_record():
    """Factory returning a WAF log record dict from keyword arguments."""
    return _build_waf_record


@pytest.fixture
def make_request():
    """Factory returning a ReconstructedRequest built from keyword arguments."""

    def _make(**kwargs) -> ReconstructedRequest:
        return ReconstructedRequest(_build_waf_record(**kwargs))

    return _make


# --- Chrome CDP fakes -------------------------------------------------------


@pytest.fixture
def cdp_devtools():
    """The real devtools module selenium's cdp.import_devtools falls back to
    for chromedriver 151 (no v151 module on disk)."""
    from selenium.webdriver.common.devtools import v150 as devtools

    return devtools


class FakeCdpSession:
    """Records the real CDP wire dicts produced by selenium's own command
    generators, so a test failure means production code sent the wrong
    protocol message rather than disagreeing with a hand-rolled mock."""

    def __init__(self):
        self.commands: list[dict] = []
        self.responses: dict[str, object] = {}
        self._pending: list[object] = []

    async def execute(self, cmd):
        wire = next(cmd)
        self.commands.append(wire)
        result = None
        try:
            cmd.send(self.responses.get(wire["method"]))
        except StopIteration as stop:
            result = stop.value
        return result

    def queue_event(self, event) -> None:
        self._pending.append(event)

    def listen(self, *event_types, buffer_size=10):
        sender, receiver = trio.open_memory_channel(
            max(buffer_size, len(self._pending) + 1)
        )
        for event in self._pending:
            if type(event) in event_types:
                sender.send_nowait(event)
        sender.close()
        return receiver

    def commands_named(self, method: str) -> list[dict]:
        return [c["params"] for c in self.commands if c["method"] == method]


@pytest.fixture
def fake_cdp_session():
    """Returns the FakeCdpSession class so a test can construct one per
    scenario (rather than sharing a single instance)."""
    return FakeCdpSession


def attach_fake_bidi_connection(driver, session, devtools) -> None:
    """Replace chrome._open_cdp_session with a fake that yields
    (devtools, session, target_id) without opening a real CDP WebSocket."""
    from waf_fu.replay import chrome

    @contextlib.asynccontextmanager
    async def _cm(driver, *, new_tab=False):
        yield devtools, session, driver.current_window_handle

    chrome._open_cdp_session = _cm


class _FakeCdpDriver:
    """Recording stand-in for a Chrome WebDriver. A small class rather than a
    bare MagicMock, so attribute typos in production code fail loudly."""

    def __init__(self):
        self.cdp_calls: list[tuple[str, dict]] = []
        self.current_url = "about:blank"
        self.title = ""
        self.window_handles = ["w1"]
        self.current_window_handle = "w1"

    def execute_cdp_cmd(self, name, params):
        self.cdp_calls.append((name, params))
        return {}

    def set_page_load_timeout(self, timeout):
        self._page_load_timeout = timeout

    def get(self, url):
        self.current_url = url


@pytest.fixture
def fake_cdp_driver():
    """bidi_connection is left unset; attach it via attach_fake_bidi_connection."""
    return _FakeCdpDriver()


# --- Firefox BiDi fakes ------------------------------------------------------


class _RecordingConn:
    """Records the real BiDi wire dicts produced by selenium's own
    command_builder generators (as used by _network_handlers.Request)."""

    def __init__(self):
        self.commands: list[dict] = []

    def execute(self, cmd):
        wire = next(cmd)
        self.commands.append(wire)
        try:
            cmd.send(None)
        except StopIteration:
            pass
        return {}


@pytest.fixture
def make_bidi_request():
    """Factory returning a real intercepted-request object plus its
    recording connection. `deferred=True` mirrors how the high-level
    add_request_handler registry drives it in production: mutations are
    recorded and the outbound command is deferred until `_resolve()`."""

    def _make(
        url="https://target.example.com/",
        method="GET",
        headers=None,
        request_id="req-1",
    ):
        from selenium.webdriver.common.bidi._network_handlers import Request

        conn = _RecordingConn()
        params = {
            "request": {
                "request": request_id,
                "url": url,
                "method": method,
                "headers": [
                    {"name": n, "value": {"type": "string", "value": v}}
                    for n, v in (headers or {}).items()
                ],
            }
        }
        return Request(conn, params, deferred=True), conn

    return _make


class FakeBidiNetwork:
    """Recording stand-in for driver.network, built around selenium's real
    Request wrapper so the reconciliation logic under test is selenium's own."""

    def __init__(self):
        self._handlers: dict[str, object] = {}
        self._counter = 0
        self.removed: list[str] = []
        self.cleared = 0

    def add_request_handler(self, callback):
        self._counter += 1
        handler_id = f"request-handler-{self._counter}"
        self._handlers[handler_id] = callback
        return handler_id

    def remove_request_handler(self, handler_id):
        self._handlers.pop(handler_id, None)
        self.removed.append(handler_id)

    def clear_request_handlers(self):
        self.cleared += 1
        self._handlers.clear()

    def dispatch(self, request):
        """Test helper: invoke every registered callback, then reconcile —
        mirrors selenium's registry behaviour."""
        for callback in list(self._handlers.values()):
            callback(request)
        request._resolve()


class FakeBidiStorage:
    def __init__(self):
        self.cookies: list = []

    def set_cookie(self, cookie=None, partition=None):
        self.cookies.append(cookie)


class _FakeFirefoxDriver:
    """Recording stand-in for a Firefox WebDriver."""

    def __init__(self):
        self.network = FakeBidiNetwork()
        self.storage = FakeBidiStorage()
        self.navigations: list[str] = []
        self.current_url = "about:blank"
        self.title = ""
        self.window_handles = ["w1"]
        self.page_load_timeouts: list[float] = []
        self.scripts: list[tuple] = []
        self.async_scripts: list[tuple] = []
        self.script_timeouts: list[float] = []
        self.addon_sources: list[str] = []
        self.uninstalled: list[str] = []
        self.async_result: object = {"status": 200, "text": "<html>ok</html>"}

    def get(self, url):
        self.navigations.append(url)
        self.current_url = url

    def set_page_load_timeout(self, seconds):
        self.page_load_timeouts.append(seconds)

    def execute_script(self, script, *args):
        self.scripts.append((script, *args))

    def set_script_timeout(self, seconds):
        self.script_timeouts.append(seconds)

    def execute_async_script(self, script, *args):
        self.async_scripts.append((script, *args))
        if isinstance(self.async_result, Exception):
            raise self.async_result
        return self.async_result

    def install_addon(self, path, temporary=False):
        import os as _os

        with open(_os.path.join(path, "background.js")) as f:
            self.addon_sources.append(f.read())
        return f"addon-{len(self.addon_sources)}"

    def uninstall_addon(self, addon_id):
        self.uninstalled.append(addon_id)


@pytest.fixture
def fake_firefox_driver():
    return _FakeFirefoxDriver()


class _NoBidiFirefoxDriver(_FakeFirefoxDriver):
    """Mirrors selenium's lazy-init BiDi failure: accessing .network raises,
    matching what _has_bidi_network probes for."""

    @property
    def network(self):
        raise RuntimeError("bidi unavailable")

    @network.setter
    def network(self, value):
        pass


@pytest.fixture
def fake_firefox_driver_no_bidi():
    return _NoBidiFirefoxDriver()


# --- Headless curses harness (WafTUI._draw / run()) -------------------------


@pytest.fixture
def headless_curses(monkeypatch):
    """Neutralize the curses calls that require a real terminal so _draw()
    and run() can be exercised in-process. Constants (A_*, KEY_*) are left
    real — they work without initscr()."""
    for name in ("curs_set", "start_color", "use_default_colors", "init_pair"):
        monkeypatch.setattr(tui_module.curses, name, lambda *a, **k: None)
    monkeypatch.setattr(tui_module.curses, "color_pair", lambda n: 0)


@pytest.fixture
def scripted_stdscr():
    class _ScriptedStdscr:
        """stdscr stand-in whose getch() replays a scripted key sequence.
        Captures every addnstr() payload in .drawn so tests can assert on
        rendered text. Not a MagicMock, so an attribute typo in production
        code fails loudly."""

        def __init__(self, keys=(), size=(40, 120), on_exhaust=None):
            self._keys = list(keys)
            self._size = size
            self._on_exhaust = ord("q") if on_exhaust is None else on_exhaust
            self.drawn: list[str] = []

        def getmaxyx(self):
            return self._size

        def getch(self):
            # Exhausted script returns the caller's escape key so the loop
            # under test terminates instead of spinning forever. Default
            # ord("q") exits run(); overlays need on_exhaust=27 (Esc).
            return self._keys.pop(0) if self._keys else self._on_exhaust

        def timeout(self, ms):
            pass

        def erase(self):
            pass

        def refresh(self):
            pass

        def addnstr(self, y, x, text, n, attr=0):
            self.drawn.append(text)

    return _ScriptedStdscr
