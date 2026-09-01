"""Firefox replay backend (WebDriver BiDi network interception)."""

from __future__ import annotations

import json as _json
import os
import shutil
import tempfile
import threading
import traceback
from typing import Any
from urllib.parse import urlsplit

from waf_fu.debug import (
    DEBUG,
    _redact_cookies,
    _redact_header,
    _redact_meta,
    _redact_url,
)
from waf_fu.models import ReconstructedRequest
from waf_fu.replay.fidelity import replayable_headers


def find_binary() -> str | None:
    """Find Firefox binary on the system."""
    for name in ("firefox", "firefox-esr"):
        path = shutil.which(name)
        if path:
            return path
    for path in (
        "/usr/lib64/firefox/firefox",
        "/usr/lib/firefox/firefox",
        "/snap/bin/firefox",
    ):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _firefox_options(proxy: str = ""):
    """Build Firefox Options with BiDi enabled and proxy preferences set."""
    from selenium.webdriver.firefox.options import Options

    opts = Options()
    opts.add_argument("--width=1920")
    opts.add_argument("--height=1080")
    opts.accept_insecure_certs = True
    opts.web_socket_url = True
    opts.set_preference("security.sandbox.content.level", 0)
    opts.set_preference("security.data_uri.block_toplevel_data_uri_navigations", False)
    if proxy:
        from urllib.parse import urlparse

        normalized = proxy if "://" in proxy else f"http://{proxy}"
        p = urlparse(normalized)
        host = p.hostname or "127.0.0.1"
        port = int(p.port) if p.port else 8080
        scheme = (p.scheme or "http").lower()

        opts.set_preference("network.proxy.type", 1)
        opts.set_preference("network.proxy.no_proxies_on", "")
        opts.set_preference("network.proxy.allow_hijacking_localhost", True)

        if scheme.startswith("socks"):
            opts.set_preference("network.proxy.socks", str(host))
            opts.set_preference("network.proxy.socks_port", int(port))
            socks_ver = 5 if "5" in scheme else 4
            opts.set_preference("network.proxy.socks_version", int(socks_ver))
            opts.set_preference("network.proxy.socks_remote_dns", True)
        else:
            opts.set_preference("network.proxy.http", str(host))
            opts.set_preference("network.proxy.http_port", int(port))
            opts.set_preference("network.proxy.ssl", str(host))
            opts.set_preference("network.proxy.ssl_port", int(port))
            opts.set_preference("network.proxy.ftp", str(host))
            opts.set_preference("network.proxy.ftp_port", int(port))

    return opts


def launch_driver(proxy: str = "", *, geckodriver_path: str = "") -> tuple[Any, str]:
    try:
        from selenium import webdriver
    except ImportError:
        DEBUG("ensure_browser: selenium not installed")
        return None, "selenium not installed — pip install selenium"

    from selenium.webdriver.firefox.service import Service

    opts = _firefox_options(proxy)

    ff_bin = find_binary()
    DEBUG("ensure_browser: firefox binary=%s", ff_bin or "(not found)")
    if ff_bin:
        opts.binary_location = ff_bin

    if proxy:
        DEBUG("ensure_browser: proxy=%s", proxy)

    gecko_path = geckodriver_path or shutil.which("geckodriver")
    DEBUG("ensure_browser: geckodriver=%s", gecko_path or "(not found)")
    service = Service(executable_path=gecko_path) if gecko_path else Service()

    try:
        driver = webdriver.Firefox(
            service=service,
            options=opts,
        )
    except Exception as ff_exc:
        err = str(ff_exc)
        parts = []
        if not ff_bin:
            parts.append(
                "Firefox binary not found. Install it:\n"
                "  sudo dnf install firefox  (Fedora)\n"
                "  sudo apt install firefox  (Debian/Ubuntu)"
            )
        parts.append(
            "geckodriver not found or incompatible. Install it:\n"
            "  sudo dnf install geckodriver  (Fedora)\n"
            "  sudo apt install firefox-geckodriver  (Debian/Ubuntu)\n"
            "  or https://github.com/mozilla/geckodriver/releases"
        )
        return None, "\n".join(parts) + f"\n\nUnderlying error: {err}"

    return driver, ""


def _inject_cookies_bidi(driver, req: ReconstructedRequest) -> None:
    """Set cookies via BiDi storage.setCookie. Needs no page context, so this
    runs before any navigation — no data: staging load required."""
    domain = req.host.split(":")[0]
    path = urlsplit(req.full_url).path or "/"
    for fragment in req.cookies.split(";"):
        fragment = fragment.strip()
        if "=" not in fragment:
            continue
        name, _, value = fragment.partition("=")
        cname = name.strip()
        try:
            driver.storage.set_cookie(
                cookie={
                    "name": cname,
                    "value": {"type": "string", "value": value.strip()},
                    "domain": domain,
                    "path": path,
                    "secure": req.scheme == "https",
                    "httpOnly": False,
                    "sameSite": "lax",
                }
            )
            DEBUG("bidi cookie set: %s domain=%s", cname, _redact_meta(domain))
        except Exception as exc:
            DEBUG(
                "bidi cookie FAILED: %s domain=%s: %s", cname, _redact_meta(domain), exc
            )


def _has_bidi_network(driver) -> bool:
    """Check whether the driver exposes the BiDi network API.

    In Selenium 4.26+, driver.network is a lazy-init property that calls
    _start_bidi() on first access.  hasattr() swallows that exception,
    making BiDi look absent even when it's available.  Use try/except
    so we see (and log) the real failure."""
    try:
        net = driver.network
        return net is not None
    except Exception as exc:
        DEBUG(
            "replay: firefox BiDi network probe failed: %s: %s",
            type(exc).__name__,
            exc,
        )
        DEBUG("replay: firefox BiDi traceback:\n%s", traceback.format_exc())
        return False


_active_header_addon: str | None = None


def _install_header_addon(driver, headers: dict, target_url: str) -> None:
    """Install a temporary WebExtension that injects headers via
    webRequest.onBeforeSendHeaders. Works without BiDi."""
    global _active_header_addon

    _uninstall_header_addon(driver)

    addon_dir = tempfile.mkdtemp(prefix="waf_fu_headers_")

    manifest = {
        "manifest_version": 2,
        "name": "waf-fu header injector",
        "version": "1.0",
        "permissions": [
            "webRequest",
            "webRequestBlocking",
            "<all_urls>",
        ],
        "background": {"scripts": ["background.js"]},
    }

    parts = urlsplit(target_url)
    path = parts.path or "/"
    url_pattern = f"{parts.scheme}://{parts.hostname}{path}*"

    bg_js = (
        "const HEADERS = " + _json.dumps(headers) + ";\n"
        "browser.webRequest.onBeforeSendHeaders.addListener(\n"
        "  function(details) {\n"
        "    var dominated = {};\n"
        "    for (var k in HEADERS) dominated[k.toLowerCase()] = true;\n"
        "    var out = details.requestHeaders.filter(\n"
        "      function(h) { return !dominated[h.name.toLowerCase()]; }\n"
        "    );\n"
        "    for (var k in HEADERS) out.push({name: k, value: HEADERS[k]});\n"
        "    return {requestHeaders: out};\n"
        "  },\n"
        "  {urls: [" + _json.dumps(url_pattern) + "]},\n"
        "  ['blocking', 'requestHeaders']\n"
        ");\n"
    )

    with open(os.path.join(addon_dir, "manifest.json"), "w") as f:
        _json.dump(manifest, f)
    with open(os.path.join(addon_dir, "background.js"), "w") as f:
        f.write(bg_js)

    try:
        addon_id = driver.install_addon(addon_dir, temporary=True)
        _active_header_addon = addon_id
        DEBUG(
            "replay: firefox header addon installed id=%s pattern=%s headers=%d",
            addon_id,
            url_pattern,
            len(headers),
        )
    except Exception as exc:
        DEBUG("replay: firefox header addon install failed: %s", exc)
        _active_header_addon = None
    finally:
        shutil.rmtree(addon_dir, ignore_errors=True)


def _uninstall_header_addon(driver) -> None:
    global _active_header_addon
    if _active_header_addon:
        try:
            driver.uninstall_addon(_active_header_addon)
            DEBUG("replay: firefox uninstalled previous header addon")
        except Exception:
            pass
        _active_header_addon = None


def _inject_cookies_webdriver(driver, req: ReconstructedRequest) -> None:
    """Fallback cookie injection via the standard WebDriver add_cookie API.
    Requires the browser to be on the target domain first."""
    domain = req.host.split(":")[0]
    path = urlsplit(req.full_url).path or "/"
    try:
        driver.get(f"{req.scheme}://{domain}/")
    except Exception as exc:
        DEBUG("webdriver cookie staging nav failed: %s", exc)
        return
    for fragment in req.cookies.split(";"):
        fragment = fragment.strip()
        if "=" not in fragment:
            continue
        name, _, value = fragment.partition("=")
        cname = name.strip()
        try:
            driver.add_cookie(
                {
                    "name": cname,
                    "value": value.strip(),
                    "domain": domain,
                    "path": path,
                    "secure": req.scheme == "https",
                }
            )
            DEBUG("webdriver cookie set: %s domain=%s", cname, _redact_meta(domain))
        except Exception as exc:
            DEBUG(
                "webdriver cookie FAILED: %s domain=%s: %s",
                cname,
                _redact_meta(domain),
                exc,
            )


def _post_via_form(driver, req: ReconstructedRequest) -> None:
    """POST replays via HTML form submission, a genuine browser navigation
    so headers injected by the WebExtension reach the proxy correctly."""
    import base64
    import html as _html

    body = req.body or ""
    action = _html.escape(req.full_url, quote=True)
    inputs = ""
    if body:
        ct = (req.content_type or "").lower()
        if "x-www-form-urlencoded" in ct or not ct:
            from urllib.parse import unquote

            for pair in body.split("&"):
                eq = pair.find("=")
                if eq > -1:
                    n = _html.escape(unquote(pair[:eq]), quote=True)
                    v = _html.escape(unquote(pair[eq + 1 :]), quote=True)
                else:
                    n = _html.escape(unquote(pair), quote=True)
                    v = ""
                inputs += f'<input type="hidden" name="{n}" value="{v}">'

    page = (
        "<html><body>"
        f'<form id="f" method="POST" action="{action}">'
        f"{inputs}</form>"
        '<script>document.getElementById("f").submit();</script>'
        "</body></html>"
    )
    data_uri = "data:text/html;base64," + base64.b64encode(page.encode()).decode()

    DEBUG("replay: firefox using form submission for POST")
    driver.get(data_uri)


def _fetch_with_method(driver, req: ReconstructedRequest, timeout: float) -> None:
    """Issue a non-GET replay via same-origin fetch() from page context.

    Deliberately has no `driver.get(req.full_url)` fallback on any failure
    path: a fetch that throws or returns status 0 propagates as an
    exception, because falling back to a plain GET would silently
    downgrade the replayed method and send the WAF a request the TUI
    reports as a success."""
    method = req.method.upper()
    body = req.body or ""
    target_origin = f"{req.scheme}://{req.host}"

    driver.set_script_timeout(timeout)
    driver.get(target_origin)

    result = driver.execute_async_script(
        "var done = arguments[arguments.length - 1];\n"
        "var url = arguments[0], method = arguments[1], body = arguments[2];\n"
        "fetch(url, {method: method, body: body || null,\n"
        "  redirect: 'follow', credentials: 'include'})\n"
        "  .then(function(r) { return r.text().then(function(t) {\n"
        "    return {status: r.status, text: t}; }); })\n"
        "  .catch(function(e) { return {status: 0, text: e.toString()}; })\n"
        "  .then(done);\n",
        req.full_url,
        method,
        body,
    )

    status = result.get("status", 0) if isinstance(result, dict) else 0
    resp_body = result.get("text", "") if isinstance(result, dict) else str(result)
    DEBUG(
        "replay: firefox fetch method=%s status=%s body=%d bytes",
        method,
        status,
        len(resp_body),
    )
    if status == 0:
        raise RuntimeError(
            f"firefox {method} replay via fetch failed: {resp_body[:200]}"
        )
    driver.execute_script(
        "document.open(); document.write(arguments[0]); document.close();", resp_body
    )


def apply_and_navigate(
    driver, req: ReconstructedRequest, timeout: float = 30.0
) -> None:
    cookie_count = req.cookies.count(";") + 1 if req.cookies else 0
    if req.cookies:
        domain = req.host.split(":")[0]
        path = urlsplit(req.full_url).path or "/"
        if hasattr(driver, "storage") and driver.storage is not None:
            DEBUG(
                "replay: firefox injecting %d cookie(s) via BiDi storage, "
                "domain=%s path=%s secure=%s: %s",
                cookie_count,
                _redact_meta(domain),
                path,
                req.scheme == "https",
                _redact_cookies(req.cookies),
            )
            _inject_cookies_bidi(driver, req)
        else:
            DEBUG(
                "replay: firefox injecting %d cookie(s) via WebDriver fallback, "
                "domain=%s: %s",
                cookie_count,
                _redact_meta(domain),
                _redact_cookies(req.cookies),
            )
            _inject_cookies_webdriver(driver, req)
    else:
        DEBUG("replay: firefox no cookies to inject")

    headers = dict(replayable_headers(req, "firefox"))
    if req.cookies and not any(name.lower() == "cookie" for name in headers):
        headers["Cookie"] = req.cookies
        DEBUG(
            "replay: firefox added Cookie to injected headers (not in replayable set)"
        )

    for name, value in headers.items():
        DEBUG("replay: firefox header: %s: %s", name, _redact_header(name, value))
    DEBUG(
        "replay: firefox method=%s body=%d bytes",
        req.method,
        len(req.body) if req.body else 0,
    )

    if not _has_bidi_network(driver):
        DEBUG(
            "replay: firefox BiDi network not available, "
            "using webextension for header injection",
        )
        if headers:
            _install_header_addon(driver, headers, req.full_url)
        driver.set_page_load_timeout(timeout)
        if req.method.upper() == "GET":
            driver.get(req.full_url)
        else:
            _post_via_form(driver, req)
        return

    driver.network.clear_request_handlers()
    DEBUG("replay: firefox cleared previous request handlers")

    handler_hit = threading.Event()
    handler_error: list[Exception] = []

    def _urls_match(intercepted: str, target: str) -> bool:
        if intercepted == target:
            return True
        try:
            a = urlsplit(intercepted)
            b = urlsplit(target)
            return (
                a.scheme == b.scheme
                and a.hostname == b.hostname
                and (a.port or (443 if a.scheme == "https" else 80))
                == (b.port or (443 if b.scheme == "https" else 80))
                and a.path == b.path
                and a.query == b.query
            )
        except Exception:
            return False

    def _handler(request) -> None:
        if not _urls_match(request.url, req.full_url):
            DEBUG(
                "replay: firefox handler URL MISMATCH, pass-through: %s",
                _redact_url(request.url),
            )
            return
        handler_hit.set()
        DEBUG("replay: firefox handler REQUEST MATCHED, intercepting")
        try:
            request.set_method(req.method)
            request.set_headers(headers)
            if req.body:
                request.set_body(req.body)
                DEBUG(
                    "replay: firefox set method=%s, %d headers, body=%d bytes",
                    req.method,
                    len(headers),
                    len(req.body),
                )
            else:
                DEBUG(
                    "replay: firefox set method=%s, %d headers, no body",
                    req.method,
                    len(headers),
                )
        except Exception as exc:
            handler_error.append(exc)
            DEBUG("replay: firefox intercept failed: %s", exc)

    handler_id = driver.network.add_request_handler(_handler)
    DEBUG(
        "replay: firefox navigating to %s with %d injected headers",
        _redact_url(req.full_url),
        len(headers),
    )

    thread_error: list[BaseException] = []

    def _navigate() -> None:
        try:
            if req.method.upper() == "GET":
                driver.get(req.full_url)
            else:
                _fetch_with_method(driver, req, timeout)
        except BaseException as exc:
            thread_error.append(exc)

    thread = threading.Thread(target=_navigate, daemon=True)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        DEBUG(
            "replay: firefox navigation timed out after %gs (handler_hit=%s)",
            timeout,
            handler_hit.is_set(),
        )
        raise TimeoutError(f"replay timed out after {timeout:g}s")

    driver.network.remove_request_handler(handler_id)
    DEBUG(
        "replay: firefox done handler_hit=%s error=%s",
        handler_hit.is_set(),
        type(thread_error[0]).__name__ if thread_error else "none",
    )
    if handler_error:
        DEBUG(
            "replay: firefox WARNING handler interception error: %s",
            handler_error[0],
        )
    if not handler_hit.is_set():
        DEBUG(
            "replay: firefox WARNING handler never matched target URL %s",
            _redact_url(req.full_url),
        )
    if thread_error:
        raise thread_error[0]
