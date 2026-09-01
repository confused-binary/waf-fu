"""Replay backend contract.

Each backend module (`waf_fu.replay.chrome`, `waf_fu.replay.firefox`) exposes
three module-level functions:

- `find_binary() -> str | None`
- `launch_driver(proxy: str = "") -> tuple[Any, str]` returning
  `(driver, error_message)` where exactly one element is truthy.
- `apply_and_navigate(driver, req, timeout) -> None` which applies headers
  and cookies then performs the navigation or fetch, raising `TimeoutError`
  if it hangs past `timeout` seconds.

This module also exposes the dispatch layer used by callers that don't know
which backend a driver belongs to:

- `launch_driver(browser, proxy="") -> tuple[Any, str]` picks the backend by
  name and delegates to its `launch_driver`.
- `open_request(driver, req, new_tab=False, timeout=30.0) -> str` picks the
  backend by inspecting the driver and delegates to its `apply_and_navigate`,
  forwarding `timeout`. `TimeoutError` and `KeyboardInterrupt` propagate to
  the caller instead of being stringified.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from waf_fu.debug import (
    DEBUG,
    _redact_cookies,
    _redact_headers,
    _redact_meta,
    _redact_url,
)
from waf_fu.replay.fidelity import fidelity_report


def _find_driver(name: str, extra_paths: tuple[str, ...] = ()) -> str | None:
    """Find a webdriver binary (chromedriver, geckodriver) on the system."""
    path = shutil.which(name)
    if path:
        return path
    for p in extra_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Last resort: search common parent dirs for the binary name
    for parent in (
        "/usr/bin",
        "/usr/local/bin",
        "/usr/lib",
        "/usr/lib64",
        "/opt/google/chrome",
        "/opt/chromium",
        os.path.expanduser("~/.local/bin"),
    ):
        candidate = os.path.join(parent, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _is_chrome_driver(driver) -> bool:
    """Check if a driver is Chrome (supports CDP)."""
    module = type(driver).__module__ or ""
    return "chrome" in module or "chromium" in module


def launch_driver(
    browser: str,
    proxy: str = "",
    *,
    chromedriver_path: str = "",
    geckodriver_path: str = "",
) -> tuple[Any, str]:
    """Launch a browser driver for the given backend name."""
    try:
        if browser == "chrome":
            from waf_fu.replay import chrome

            return chrome.launch_driver(proxy, chromedriver_path=chromedriver_path)
        elif browser == "firefox":
            from waf_fu.replay import firefox

            return firefox.launch_driver(proxy, geckodriver_path=geckodriver_path)
        else:
            # Unreachable in practice: WafTUI._ensure_browser normalizes any
            # unrecognized value to "chrome" before calling. Kept for parity
            # with the original.
            return None, f"Unknown browser: {browser}"
    except Exception as exc:
        DEBUG("ensure_browser: %s launch failed: %s", browser, exc)
        return None, f"{browser.title()} launch failed: {exc}"


def open_request(driver, req, new_tab: bool = False, timeout: float = 30.0) -> str:
    """Load a single request into a browser driver (Chrome or Firefox).
    If new_tab is True, opens a new tab first."""
    is_chrome = _is_chrome_driver(driver)
    browser_tag = "chrome" if is_chrome else "firefox"
    DEBUG(
        "replay: browser=%s method=%s url=%s new_tab=%s timeout=%s",
        browser_tag,
        req.method,
        _redact_url(req.full_url),
        new_tab,
        timeout,
    )
    DEBUG(
        "replay: scheme=%s host=%s uri=%s http_version=%s",
        req.scheme,
        _redact_meta(req.host),
        req.uri,
        req.http_version,
    )
    DEBUG(
        "replay: client_ip=[REDACTED-IP] country=%s action=%s rule=%s",
        req.country,
        req.action,
        req.terminating_rule_id,
    )
    DEBUG(
        "replay: original headers (%d): %s",
        len(req.headers),
        _redact_headers(req.headers),
    )
    DEBUG(
        "replay: cookies=%s",
        _redact_cookies(req.cookies) if req.cookies else "(none)",
    )
    DEBUG(
        "replay: body=%d bytes, content_type=%s",
        len(req.body) if req.body else 0,
        req.content_type or "(none)",
    )
    DEBUG(
        "replay: auth=%s jwt_valid=%s edited=%s",
        "present" if req.authorization else "none",
        req.jwt_valid,
        req.edited,
    )
    report = fidelity_report(req, browser_tag)
    if report.skipped:
        for name, reason in report.skipped:
            DEBUG("replay: SKIPPED header %s: %s", name, reason)
    else:
        DEBUG(
            "replay: all %d headers replayable in %s mode",
            len(req.headers),
            browser_tag,
        )
    if report.cookie_note:
        DEBUG("replay: cookie note: %s", report.cookie_note)
    if report.body_note:
        DEBUG("replay: body note: %s", report.body_note)

    try:
        if new_tab and not is_chrome:
            driver.switch_to.new_window("tab")
            DEBUG("replay: opened new tab, handle=%s", driver.current_window_handle)

        if is_chrome:
            from waf_fu.replay import chrome

            chrome.apply_and_navigate(driver, req, timeout, new_tab=new_tab)
        else:
            from waf_fu.replay import firefox

            firefox.apply_and_navigate(driver, req, timeout)

        current_url = driver.current_url
        title = driver.title
        DEBUG(
            "replay: completed, url=%s page title=%s",
            _redact_url(current_url) if current_url else "(none)",
            title,
        )
        return title

    except TimeoutError:
        # TimeoutError is an OSError subclass and would otherwise be caught
        # by the `except Exception` below — re-raise so the caller can tell
        # a hang apart from any other failure. KeyboardInterrupt needs no
        # such clause: it's a BaseException and already escapes `except
        # Exception` unchanged. Do not widen that handler to catch it.
        raise
    except Exception as exc:
        DEBUG("replay: EXCEPTION: %s", exc)
        return f"ERROR: {exc}"
