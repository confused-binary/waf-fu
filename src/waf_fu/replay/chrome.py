"""Chrome/Chromium replay backend (CDP)."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import urllib.parse
from typing import Any

import trio

from waf_fu.debug import (
    DEBUG,
    _redact_cookies,
    _redact_header,
    _redact_meta,
    _redact_url,
)
from waf_fu.models import ReconstructedRequest
from waf_fu.replay import _find_driver
from waf_fu.replay.fidelity import replayable_headers

# Time given, after the target request is answered, for in-flight
# subresources to be released before Fetch is disabled (measured necessary
# in 02-RESEARCH.md's Wave 0 spike, verified_facts #8).
_SUBRESOURCE_GRACE = 1.0


def find_binary() -> str | None:
    """Find Chrome/Chromium binary on the system."""
    for name in (
        "google-chrome-stable",
        "google-chrome",
        "chromium-browser",
        "chromium",
        "chrome",
    ):
        path = shutil.which(name)
        if path:
            return path
    for path in (
        "/opt/google/chrome/google-chrome",
        "/usr/lib64/chromium-browser/chromium-browser",
        "/usr/lib/chromium-browser/chromium-browser",
        "/snap/bin/chromium",
    ):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _inject_cookies_cdp(driver, req: ReconstructedRequest) -> None:
    """Set cookies via Chrome DevTools Protocol."""
    domain = req.host.split(":")[0]
    path = urllib.parse.urlsplit(req.full_url).path or "/"
    for fragment in req.cookies.split(";"):
        fragment = fragment.strip()
        if "=" not in fragment:
            continue
        name, _, value = fragment.partition("=")
        cname = name.strip()
        try:
            driver.execute_cdp_cmd(
                "Network.setCookie",
                {
                    "name": cname,
                    "value": value.strip(),
                    "domain": domain,
                    "url": f"{req.scheme}://{req.host}{path}",
                    "path": path,
                    "secure": req.scheme == "https",
                    "httpOnly": False,
                    "sameSite": "Lax",
                },
            )
            DEBUG(
                "cdp cookie set: %s domain=%s path=%s",
                cname,
                _redact_meta(domain),
                path,
            )
        except Exception as exc:
            DEBUG(
                "cdp cookie FAILED: %s domain=%s: %s", cname, _redact_meta(domain), exc
            )


def _chrome_options(proxy: str = "") -> Any:
    """Build Chrome options. Pure and testable without launching anything."""
    from selenium.webdriver.chrome.options import Options

    opts = Options()
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--ignore-certificate-errors")
    opts.accept_insecure_certs = True
    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")
    return opts


def launch_driver(proxy: str = "", *, chromedriver_path: str = "") -> tuple[Any, str]:
    try:
        from selenium import webdriver
    except ImportError:
        DEBUG("ensure_browser: selenium not installed")
        return None, "selenium not installed — pip install selenium"

    from selenium.webdriver.chrome.service import Service

    opts = _chrome_options(proxy)

    chrome_bin = find_binary()
    DEBUG("ensure_browser: chrome binary=%s", chrome_bin or "(not found)")
    if chrome_bin:
        opts.binary_location = chrome_bin

    if not chromedriver_path:
        chromedriver_path = (
            _find_driver(
                "chromedriver",
                (
                    "/usr/lib64/chromium-browser/chromedriver",
                    "/usr/local/bin/chromedriver",
                    "/usr/lib/chromium-browser/chromedriver",
                    "/opt/google/chrome/chromedriver",
                    "/snap/bin/chromedriver",
                    "/usr/bin/chromedriver",
                ),
            )
            or ""
        )
    DEBUG("ensure_browser: chromedriver=%s", chromedriver_path or "(not found)")
    if proxy:
        DEBUG("ensure_browser: proxy=%s", proxy)

    service = (
        Service(executable_path=chromedriver_path) if chromedriver_path else Service()
    )

    try:
        driver = webdriver.Chrome(
            service=service,
            options=opts,
        )
    except Exception as ch_exc:
        err = str(ch_exc)
        parts = []
        if not chrome_bin:
            parts.append(
                "Chrome/Chromium binary not found. Install it:\n"
                "  sudo dnf install chromium  (Fedora)\n"
                "  sudo apt install chromium-browser  (Debian/Ubuntu)"
            )
        if not chromedriver_path:
            parts.append(
                "chromedriver not found. Install it:\n"
                "  sudo dnf install chromedriver  (Fedora)\n"
                "  sudo apt install chromium-chromedriver  (Debian/Ubuntu)"
            )
        if parts:
            return None, "\n".join(parts) + f"\n\nUnderlying error: {err}"
        return (
            None,
            f"Chrome launch failed (binary={chrome_bin}, driver={chromedriver_path}): {err}",
        )

    return driver, ""


def _cdp_header_entries(devtools: Any, req: ReconstructedRequest) -> list:
    """HeaderEntry list for every header replayable_headers(req, 'chrome')
    allows through, in the WAF log's original order and casing."""
    return [
        devtools.fetch.HeaderEntry(name=name, value=value)
        for name, value in replayable_headers(req, "chrome").items()
    ]


def _cdp_post_data(req: ReconstructedRequest) -> str | None:
    """Base64 of the utf-8 body, or None (not "") for an empty body so
    continue_request omits postData entirely."""
    if not req.body:
        return None
    return base64.b64encode(req.body.encode("utf-8")).decode("ascii")


def _get_cdp_info(driver: Any) -> tuple[str, str]:
    """Extract the CDP WebSocket URL and devtools version from a driver."""
    if driver.caps.get("se:cdp"):
        ws_url = driver.caps.get("se:cdp")
        version = driver.caps.get("se:cdpVersion").split(".")[0]
    else:
        version, ws_url = driver._get_cdp_details()
    return ws_url, version


def _patch_event_handler(obj: Any) -> None:
    """Make a CdpBase's event handler resilient to unrecognised CDP events.

    Chrome may emit events that the bundled devtools module cannot parse
    (e.g. Chrome 151 vs selenium's v150 protocol stubs).  Without this
    patch the KeyError kills the reader task and tears down the whole
    BiDi session.
    """
    orig = obj._handle_event

    def _safe_handle_event(data: dict) -> None:
        try:
            orig(data)
        except KeyError:
            DEBUG(
                "replay: chrome ignored unrecognised CDP event: %s",
                data.get("method", "?"),
            )

    obj._handle_event = _safe_handle_event


@contextlib.asynccontextmanager
async def _open_cdp_session(driver: Any, *, new_tab: bool = False):
    """Open a CDP session, optionally creating a new tab first.

    When ``new_tab=True``, uses ``Target.createTarget`` to open a blank
    tab via the same CDP connection used for replay.  This eliminates the
    race condition between WebDriver tab creation and CDP target
    registration -- the target ID is returned synchronously by CDP,
    so ``Fetch.enable`` is guaranteed to be active before any navigation.
    """
    from selenium.webdriver.common.bidi import cdp

    ws_url, ver = _get_cdp_info(driver)
    devtools = cdp.import_devtools(ver)

    async with cdp.open_cdp(ws_url) as conn:
        _patch_event_handler(conn)

        if new_tab:
            target_id = await conn.execute(
                devtools.target.create_target(url="about:blank")
            )
            DEBUG("replay: chrome created CDP target %s", target_id)
        else:
            targets = await conn.execute(devtools.target.get_targets())
            page_targets = [t for t in targets if t.type_ == "page"]
            if page_targets:
                target_id = page_targets[0].target_id
                DEBUG("replay: chrome resolved existing target %s", target_id)
            else:
                target_id = await conn.execute(
                    devtools.target.create_target(url="about:blank")
                )
                DEBUG("replay: chrome no page target found, created %s", target_id)

        async with conn.open_session(target_id) as session:
            _patch_event_handler(session)
            yield devtools, session, str(target_id)


async def _replay_async(
    driver: Any, req: ReconstructedRequest, timeout: float, new_tab: bool = False
) -> str | None:
    async with _open_cdp_session(driver, new_tab=new_tab) as (
        devtools,
        session,
        target_id,
    ):
        # Page.enable initialises the page lifecycle on the target,
        # which must happen before Fetch can intercept document
        # navigations on newly created tabs (Chromium bug: Fetch
        # silently misses the first document request from about:blank
        # when the page domain is uninitialised).
        await session.execute(devtools.page.enable())
        await session.execute(devtools.fetch.enable())
        DEBUG("replay: chrome Page.enable + Fetch.enable complete")

        target_url = req.full_url
        done = trio.Event()
        handled = False
        pass_through_count = 0

        async def _continue_with_retry(
            session, devtools, event, req, headers, post_data
        ):
            remaining = list(headers)
            while True:
                try:
                    await session.execute(
                        devtools.fetch.continue_request(
                            request_id=event.request_id,
                            method=req.method,
                            headers=remaining,
                            post_data=post_data,
                        )
                    )
                    return
                except Exception as exc:
                    err = str(exc)
                    if "Unsafe header:" not in err:
                        raise
                    unsafe = err.split("Unsafe header:")[-1].strip().rstrip(">").strip()
                    before = len(remaining)
                    remaining = [
                        h for h in remaining if h.name.lower() != unsafe.lower()
                    ]
                    if len(remaining) == before:
                        raise
                    DEBUG(
                        "replay: chrome retrying without unsafe header %s (%d remaining)",
                        unsafe,
                        len(remaining),
                    )

        # Register the event channel before scheduling the listener
        # or navigating so no RequestPaused events are silently dropped.
        fetch_events = session.listen(devtools.fetch.RequestPaused)

        async def listener() -> None:
            nonlocal handled, pass_through_count
            async for event in fetch_events:
                paused_url = event.request.url
                try:
                    if not handled and paused_url == target_url:
                        handled = True
                        DEBUG(
                            "replay: chrome REQUEST MATCHED, intercepting (resource_type=%s)",
                            getattr(event, "resource_type", "unknown"),
                        )
                        headers = _cdp_header_entries(devtools, req)
                        post_data = _cdp_post_data(req)
                        DEBUG(
                            "replay: chrome Fetch.continueRequest with method=%s, "
                            "%d headers, body=%d bytes",
                            req.method,
                            len(headers),
                            len(req.body) if req.body else 0,
                        )
                        await _continue_with_retry(
                            session, devtools, event, req, headers, post_data
                        )
                        DEBUG("replay: chrome Fetch.continueRequest succeeded")
                        done.set()
                    else:
                        pass_through_count += 1
                        if not handled:
                            DEBUG(
                                "replay: chrome URL MISMATCH, pass-through #%d: %s",
                                pass_through_count,
                                _redact_url(paused_url),
                            )
                        await session.execute(
                            devtools.fetch.continue_request(request_id=event.request_id)
                        )
                except Exception as exc:
                    DEBUG("replay: chrome Fetch.requestPaused handling FAILED: %s", exc)
                    try:
                        await session.execute(
                            devtools.fetch.continue_request(request_id=event.request_id)
                        )
                    except Exception as exc2:
                        DEBUG("replay: chrome pass-through continue FAILED: %s", exc2)

        async with trio.open_nursery() as nursery:
            nursery.start_soon(listener)
            is_post = req.method.upper() == "POST"
            if is_post:
                url_js = json.dumps(target_url)
                js = f"var f=document.createElement('form');f.method='POST';f.action={url_js};document.body.appendChild(f);f.submit();"
                DEBUG(
                    "replay: chrome POST form-submit to %s",
                    _redact_url(target_url),
                )
                await session.execute(devtools.runtime.evaluate(expression=js))
            else:
                DEBUG("replay: chrome navigating to %s", _redact_url(target_url))
                await session.execute(devtools.page.navigate(url=target_url))
            with trio.move_on_after(timeout) as scope:
                await done.wait()
            timed_out = scope.cancelled_caught
            if not timed_out:
                DEBUG(
                    "replay: chrome target request handled, waiting %gs for subresources",
                    _SUBRESOURCE_GRACE,
                )
                await trio.sleep(_SUBRESOURCE_GRACE)
            try:
                await session.execute(devtools.fetch.disable())
                await session.execute(devtools.page.disable())
                DEBUG("replay: chrome Fetch.disable + Page.disable complete")
            except Exception as exc:
                DEBUG("replay: domain disable failed: %s", exc)
            nursery.cancel_scope.cancel()

        DEBUG(
            "replay: chrome done handled=%s subresources_passed=%d timed_out=%s",
            handled,
            pass_through_count,
            timed_out,
        )
        if timed_out:
            raise TimeoutError(f"replay timed out after {timeout:g}s")

    return target_id if new_tab else None


def _flatten_exception(exc: Exception) -> str:
    """Extract sub-exceptions from ExceptionGroup for clearer logging."""
    parts = [f"{type(exc).__name__}: {exc}"]
    children = getattr(exc, "exceptions", None)
    if children:
        for sub in children:
            parts.append(f"  sub-exception: {type(sub).__name__}: {sub}")
    return "\n".join(parts)


def _post_via_form_fallback(
    driver: Any, req: ReconstructedRequest, timeout: float
) -> None:
    """POST via JS form submission in the fallback path.

    Creates a hidden form targeting ``req.full_url``, appends a body
    textarea when the request has one, and submits.  The browser sends a
    real POST with Network.setExtraHTTPHeaders applied.
    """
    import time

    url_js = json.dumps(req.full_url)
    js = f"var f=document.createElement('form');f.method='POST';f.action={url_js};"
    if req.body:
        body_b64 = base64.b64encode(req.body.encode("utf-8")).decode("ascii")
        js += (
            "var t=document.createElement('textarea');"
            f"t.name='body';t.value=atob('{body_b64}');"
            "t.style.display='none';f.appendChild(t);"
        )
    js += "document.body.appendChild(f);f.submit();"
    DEBUG("replay: chrome fallback POST form-submit to %s", _redact_url(req.full_url))
    old_url = driver.current_url
    driver.execute_script(js)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            current = driver.current_url
            if current != old_url:
                state = driver.execute_script("return document.readyState")
                if state == "complete":
                    return
        except Exception:
            pass
        time.sleep(0.15)
    DEBUG("replay: chrome fallback POST timed out after %gs", timeout)


def _replay_cdp_fallback(
    driver: Any, req: ReconstructedRequest, timeout: float
) -> None:
    """Header injection via Network.setExtraHTTPHeaders when BiDi Fetch fails.

    Less precise than Fetch interception (applies to all requests, not just
    the target) but works without the BiDi WebSocket / Trio async machinery.
    POST requests use a JS form submission so the server sees the correct
    HTTP method.
    """
    headers = replayable_headers(req, "chrome")
    is_post = req.method.upper() == "POST"
    DEBUG(
        "replay: chrome cdp fallback injecting %d headers via Network.setExtraHTTPHeaders (method=%s)",
        len(headers),
        req.method,
    )
    driver.execute_cdp_cmd("Network.enable", {})
    driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": headers})
    driver.set_page_load_timeout(timeout)
    try:
        if is_post:
            _post_via_form_fallback(driver, req, timeout)
        else:
            driver.get(req.full_url)
    finally:
        driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": {}})
        driver.execute_cdp_cmd("Network.disable", {})


def apply_and_navigate(
    driver: Any,
    req: ReconstructedRequest,
    timeout: float = 30.0,
    *,
    new_tab: bool = False,
) -> None:
    cookie_count = req.cookies.count(";") + 1 if req.cookies else 0
    if req.cookies:
        domain = req.host.split(":")[0]
        path = urllib.parse.urlsplit(req.full_url).path or "/"
        DEBUG(
            "replay: chrome injecting %d cookie(s) via CDP, domain=%s path=%s secure=%s: %s",
            cookie_count,
            _redact_meta(domain),
            path,
            req.scheme == "https",
            _redact_cookies(req.cookies),
        )
        _inject_cookies_cdp(driver, req)
    else:
        DEBUG("replay: chrome no cookies to inject")

    replay_headers = replayable_headers(req, "chrome")
    for name, value in replay_headers.items():
        DEBUG("replay: chrome header: %s: %s", name, _redact_header(name, value))
    DEBUG(
        "replay: chrome method=%s body=%d bytes",
        req.method,
        len(req.body) if req.body else 0,
    )

    try:
        target_id = trio.run(_replay_async, driver, req, timeout, new_tab)
        if target_id:
            driver.switch_to.window(target_id)
    except TimeoutError:
        raise
    except BaseExceptionGroup as eg:
        # trio.run wraps KeyboardInterrupt in a BaseExceptionGroup when the
        # nursery has an in-flight CDP task. Unwrap it so callers see a
        # plain KeyboardInterrupt instead of an opaque exception group.
        kb = eg.subgroup(KeyboardInterrupt)
        if kb is not None:
            raise KeyboardInterrupt() from eg
        raise
    except Exception as exc:
        DEBUG("replay: chrome CDP Fetch FAILED:\n%s", _flatten_exception(exc))
        DEBUG("replay: chrome falling back to Network.setExtraHTTPHeaders")
        if new_tab:
            driver.switch_to.new_window("tab")
        _replay_cdp_fallback(driver, req, timeout)
