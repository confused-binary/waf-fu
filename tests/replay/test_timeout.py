"""Timeout, cancellation and validation-gate assertions.

Covers plan 02-06: threading --timeout through open_request (task 2), and
the validation gate / TimeoutError / KeyboardInterrupt handling inside
WafTUI._execute_replay (task 3).
"""

from __future__ import annotations

import curses

import pytest

from waf_fu.replay import open_request
from waf_fu.tui import WafTUI

# --- Task 2: open_request threads timeout, lets TimeoutError/KeyboardInterrupt through ---


def test_open_request_forwards_timeout_to_chrome_backend(
    fake_cdp_driver, make_request, monkeypatch
):
    calls = []

    def _record(driver, req, timeout, *, new_tab=False):
        calls.append((driver, req, timeout))

    monkeypatch.setattr("waf_fu.replay.chrome.apply_and_navigate", _record)
    monkeypatch.setattr("waf_fu.replay._is_chrome_driver", lambda driver: True)
    req = make_request()

    result = open_request(fake_cdp_driver, req, timeout=12.5)

    assert calls == [(fake_cdp_driver, req, 12.5)]
    assert result == fake_cdp_driver.title


def test_open_request_forwards_timeout_to_firefox_backend(
    fake_firefox_driver, make_request, monkeypatch
):
    calls = []

    def _record(driver, req, timeout):
        calls.append((driver, req, timeout))

    monkeypatch.setattr("waf_fu.replay.firefox.apply_and_navigate", _record)
    monkeypatch.setattr("waf_fu.replay._is_chrome_driver", lambda driver: False)
    req = make_request()

    result = open_request(fake_firefox_driver, req, timeout=7.0)

    assert calls == [(fake_firefox_driver, req, 7.0)]
    assert result == fake_firefox_driver.title


def test_open_request_default_timeout_is_thirty(
    fake_cdp_driver, make_request, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        "waf_fu.replay.chrome.apply_and_navigate",
        lambda driver, req, timeout, *, new_tab=False: calls.append(timeout),
    )
    monkeypatch.setattr("waf_fu.replay._is_chrome_driver", lambda driver: True)
    open_request(fake_cdp_driver, make_request())
    assert calls == [30.0]


def test_open_request_lets_timeout_error_propagate(
    fake_cdp_driver, make_request, monkeypatch
):
    def _raise(driver, req, timeout, *, new_tab=False):
        raise TimeoutError("navigation hung")

    monkeypatch.setattr("waf_fu.replay.chrome.apply_and_navigate", _raise)
    monkeypatch.setattr("waf_fu.replay._is_chrome_driver", lambda driver: True)

    with pytest.raises(TimeoutError):
        open_request(fake_cdp_driver, make_request(), timeout=0.05)


def test_open_request_lets_keyboard_interrupt_propagate(
    fake_firefox_driver, make_request, monkeypatch
):
    def _raise(driver, req, timeout):
        raise KeyboardInterrupt()

    monkeypatch.setattr("waf_fu.replay.firefox.apply_and_navigate", _raise)
    monkeypatch.setattr("waf_fu.replay._is_chrome_driver", lambda driver: False)

    with pytest.raises(KeyboardInterrupt):
        open_request(fake_firefox_driver, make_request())


def test_open_request_still_stringifies_other_exceptions(
    fake_cdp_driver, make_request, monkeypatch
):
    def _raise(driver, req, timeout, *, new_tab=False):
        raise ValueError("boom")

    monkeypatch.setattr("waf_fu.replay.chrome.apply_and_navigate", _raise)
    monkeypatch.setattr("waf_fu.replay._is_chrome_driver", lambda driver: True)

    result = open_request(fake_cdp_driver, make_request())
    assert result == "ERROR: boom"


def test_open_request_chrome_passes_new_tab_to_backend(
    fake_cdp_driver, make_request, monkeypatch
):
    calls = []

    def _record(driver, req, timeout, *, new_tab=False):
        calls.append({"new_tab": new_tab})

    monkeypatch.setattr("waf_fu.replay.chrome.apply_and_navigate", _record)
    monkeypatch.setattr("waf_fu.replay._is_chrome_driver", lambda driver: True)

    open_request(fake_cdp_driver, make_request(), new_tab=True)

    assert calls == [{"new_tab": True}]


def test_is_chrome_driver_true_for_chrome_module_driver():
    from waf_fu.replay import _is_chrome_driver

    class _StubChromeDriver:
        pass

    _StubChromeDriver.__module__ = "selenium.webdriver.chrome.webdriver"
    assert _is_chrome_driver(_StubChromeDriver()) is True


def test_is_chrome_driver_false_for_non_chrome_module_driver():
    from waf_fu.replay import _is_chrome_driver

    class _StubFirefoxDriver:
        pass

    _StubFirefoxDriver.__module__ = "selenium.webdriver.firefox.webdriver"
    assert _is_chrome_driver(_StubFirefoxDriver()) is False


# --- Task 3: validation gate, timeout and cancellation in the TUI ---


class _StubStdscr:
    """Minimal stdscr stand-in — WafTUI.__init__ never touches curses, and
    the real curses.endwin()/_draw() calls are patched around this stub."""

    def __init__(self):
        self.refreshed = 0

    def refresh(self):
        self.refreshed += 1


class _FakeDriver:
    def __init__(self):
        self.quit_called = False
        self.close_called = False
        self.window_handles = ["w1"]
        self.current_url = "about:blank"

    def quit(self):
        self.quit_called = True

    def close(self):
        self.close_called = True


@pytest.fixture(autouse=True)
def _patch_curses_endwin(monkeypatch):
    monkeypatch.setattr(curses, "endwin", lambda: None)


def _make_tui(requests, mode="chrome"):
    tui = WafTUI(requests, initial_mode=mode, auth_filter_default=False, timeout=9.0)
    tui._draw = lambda stdscr: None
    return tui


def test_validation_failure_blocks_before_browser(make_request, monkeypatch):
    bad_req = make_request(scheme="ftp")
    tui = _make_tui([bad_req])

    def _assert_not_called(browser=""):
        raise AssertionError(
            "_ensure_browser must not be called on a validation failure"
        )

    monkeypatch.setattr(tui, "_ensure_browser", _assert_not_called)

    tui._execute_replay(_StubStdscr())

    assert tui.status_msg.startswith("✘ Cannot replay:")
    assert tui.status_kind == "error"


def test_validation_failure_preserves_selection(make_request, monkeypatch):
    bad_req = make_request(scheme="ftp")
    tui = _make_tui([bad_req])
    tui.selected.add(id(bad_req))

    def _assert_not_called(browser=""):
        raise AssertionError(
            "_ensure_browser must not be called on a validation failure"
        )

    monkeypatch.setattr(tui, "_ensure_browser", _assert_not_called)

    tui._execute_replay(_StubStdscr())

    assert id(bad_req) in tui.selected


def test_validation_gate_also_applies_to_curl_mode(make_request):
    bad_req = make_request(scheme="ftp")
    tui = _make_tui([bad_req], mode="curl")

    tui._execute_replay(_StubStdscr())

    assert tui.status_msg.startswith("✘ Cannot replay:")
    assert tui.post_exit_output == []


def test_timeout_error_sets_yellow_status_and_returns_to_tui(make_request, monkeypatch):
    good_req = make_request()
    tui = _make_tui([good_req])
    fake_driver = _FakeDriver()
    monkeypatch.setattr(tui, "_ensure_browser", lambda browser="": (fake_driver, ""))

    def _raise(driver, req, new_tab=False, timeout=30.0):
        raise TimeoutError("hung")

    monkeypatch.setattr("waf_fu.tui.open_request", _raise)

    stdscr = _StubStdscr()
    tui._execute_replay(stdscr)

    assert tui.status_msg == "Replay timed out after 9s"
    assert tui.status_kind == "warn"
    assert stdscr.refreshed == 1
    assert not fake_driver.quit_called
    assert not fake_driver.close_called


def test_keyboard_interrupt_sets_cancelled_status_and_returns_to_tui(
    make_request, monkeypatch
):
    good_req = make_request()
    tui = _make_tui([good_req])
    fake_driver = _FakeDriver()
    monkeypatch.setattr(tui, "_ensure_browser", lambda browser="": (fake_driver, ""))

    def _raise(driver, req, new_tab=False, timeout=30.0):
        raise KeyboardInterrupt()

    monkeypatch.setattr("waf_fu.tui.open_request", _raise)

    stdscr = _StubStdscr()
    tui._execute_replay(stdscr)

    assert tui.status_msg == "Replay cancelled"
    assert tui.status_kind == "warn"
    assert stdscr.refreshed == 1
    assert not fake_driver.quit_called
    assert not fake_driver.close_called


def test_base_exception_group_keyboard_interrupt_sets_cancelled_status(
    make_request, monkeypatch
):
    good_req = make_request()
    tui = _make_tui([good_req])
    fake_driver = _FakeDriver()
    monkeypatch.setattr(tui, "_ensure_browser", lambda browser="": (fake_driver, ""))

    def _raise(driver, req, new_tab=False, timeout=30.0):
        raise BaseExceptionGroup("cancel", [KeyboardInterrupt()])

    monkeypatch.setattr("waf_fu.tui.open_request", _raise)

    stdscr = _StubStdscr()
    tui._execute_replay(stdscr)

    assert tui.status_msg == "Replay cancelled"
    assert tui.status_kind == "warn"


def test_unexpected_base_exception_sets_error_status(make_request, monkeypatch):
    good_req = make_request()
    tui = _make_tui([good_req])
    fake_driver = _FakeDriver()
    monkeypatch.setattr(tui, "_ensure_browser", lambda browser="": (fake_driver, ""))

    def _raise(driver, req, new_tab=False, timeout=30.0):
        raise SystemExit(1)

    monkeypatch.setattr("waf_fu.tui.open_request", _raise)

    stdscr = _StubStdscr()
    tui._execute_replay(stdscr)

    assert tui.status_msg.startswith("Replay failed:")
    assert tui.status_kind == "error"


def test_timeout_on_target_n_stops_remaining_targets(make_request, monkeypatch):
    reqs = [make_request(), make_request(), make_request()]
    tui = _make_tui(reqs)
    for r in reqs:
        tui.selected.add(id(r))
    fake_driver = _FakeDriver()
    monkeypatch.setattr(tui, "_ensure_browser", lambda browser="": (fake_driver, ""))

    calls = []

    def _open(driver, req, new_tab=False, timeout=30.0):
        calls.append(req)
        if len(calls) == 2:
            raise TimeoutError("hung")
        return "ok"

    monkeypatch.setattr("waf_fu.tui.open_request", _open)

    tui._execute_replay(_StubStdscr())

    assert len(calls) == 2


def test_successful_replay_clears_selection(make_request, monkeypatch):
    good_req = make_request()
    tui = _make_tui([good_req])
    tui.selected.add(id(good_req))
    fake_driver = _FakeDriver()
    monkeypatch.setattr(tui, "_ensure_browser", lambda browser="": (fake_driver, ""))
    monkeypatch.setattr(
        "waf_fu.tui.open_request",
        lambda driver, req, new_tab=False, timeout=30.0: "Example",
    )

    tui._execute_replay(_StubStdscr())

    assert tui.selected == set()
    assert tui.status_kind == ""
