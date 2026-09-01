"""Debug file logging with client-data redaction.

Downstream modules must import the FUNCTION (`from waf_fu.debug import DEBUG`),
never the `_debug_logger` variable, so that `_init_debug` mutating the global
is visible everywhere.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse, urlunparse

_debug_logger: logging.Logger | None = None
_redact_enabled: bool = False


def _set_redact(enabled: bool) -> None:
    global _redact_enabled
    _redact_enabled = enabled


def _init_debug(path: str) -> None:
    global _debug_logger
    _debug_logger = logging.getLogger("waf_replay.debug")
    _debug_logger.setLevel(logging.DEBUG)
    _debug_logger.propagate = False
    h = logging.FileHandler(path, mode="a")
    h.setFormatter(logging.Formatter("%(asctime)s  %(funcName)s  %(message)s"))
    _debug_logger.addHandler(h)


def DEBUG(msg: str, *args) -> None:
    if _debug_logger is not None:
        _debug_logger.debug(msg, *args, stacklevel=2)


_SAFE_DEBUG_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "content-type",
        "connection",
        "pragma",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "x-requested-with",
    }
)


def _redact_meta(value: str | None, fallback: str = "(none)") -> str:
    if not value:
        return fallback
    if _redact_enabled:
        return "[REDACTED]"
    return value


def _redact_path(value: str | None, fallback: str = "(none)") -> str:
    if not value:
        return fallback
    if _redact_enabled:
        from pathlib import PurePosixPath

        return str(PurePosixPath(value).name)
    return value


def _redact_header(name: str, value: str) -> str:
    if not _redact_enabled:
        return value
    low = name.lower()
    if low in _SAFE_DEBUG_HEADERS:
        return value
    if low == "authorization":
        scheme = value.split(None, 1)[0] if " " in value else "token"
        return f"{scheme} [REDACTED]"
    return "[REDACTED]"


def _redact_headers(headers: dict[str, str]) -> str:
    parts = [f"{k}: {_redact_header(k, v)}" for k, v in headers.items()]
    return "{" + ", ".join(parts) + "}"


def _redact_url(url: str) -> str:
    if not _redact_enabled:
        return url
    p = urlparse(url)
    netloc = "[REDACTED]" if p.netloc else ""
    base = urlunparse((p.scheme, netloc, p.path, "", "", ""))
    if not p.query:
        return base
    params = p.query.split("&")
    redacted = []
    for param in params:
        if "=" in param:
            k, _, _ = param.partition("=")
            redacted.append(f"{k}=[REDACTED]")
        else:
            redacted.append(param)
    return f"{base}?{'&'.join(redacted)}"


def _redact_cookies(cookie_str: str) -> str:
    if not cookie_str:
        return "(none)"
    if not _redact_enabled:
        return cookie_str
    parts = []
    for frag in cookie_str.split(";"):
        frag = frag.strip()
        if "=" in frag:
            cname, _, _ = frag.partition("=")
            parts.append(f"{cname.strip()}=[REDACTED]")
        elif frag:
            parts.append(frag)
    return "; ".join(parts)


class _ConsoleSuppressor(logging.Filter):
    """Blocks console log output during TUI without affecting file handlers."""

    suppress = False

    def filter(self, record):
        return not self.suppress


_console_suppressor = _ConsoleSuppressor()
