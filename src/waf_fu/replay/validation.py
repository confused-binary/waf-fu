"""Pre-replay request validation.

Runs before any driver call, so a malformed request never reaches the
browser or the target — that is the point of REPLAY-09.
"""

from __future__ import annotations

import string
from urllib.parse import urlsplit

from waf_fu.models import ReconstructedRequest

VALID_METHODS: frozenset[str] = frozenset({"GET", "POST", "HEAD", "OPTIONS"})

_HEADER_NAME_CHARS = frozenset(string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~")
_HEADER_VALUE_BAD_CHARS = frozenset("\r\n\x00")


def validate_request(req: ReconstructedRequest) -> list[str]:
    """Return a list of human-readable problems with `req`. An empty list
    means the request is safe to replay. Never raises — the caller turns a
    non-empty list into a status-bar message and blocks the replay."""
    errors: list[str] = []

    if req.method not in VALID_METHODS:
        errors.append(f"Invalid HTTP method: {req.method!r}")

    parsed = urlsplit(req.full_url)
    if parsed.scheme not in ("http", "https"):
        errors.append(f"Invalid URL scheme: {parsed.scheme!r} (must be http or https)")
    if not parsed.netloc:
        errors.append(f"URL has no host: {req.full_url!r}")

    for name, value in req.headers.items():
        if not name or any(ch not in _HEADER_NAME_CHARS for ch in name):
            errors.append(f"Malformed header name: {name!r}")
        if any(ch in _HEADER_VALUE_BAD_CHARS for ch in value):
            errors.append(
                f"Header {name!r} value contains a CR, LF, or NUL byte "
                "(request-splitting risk)"
            )

    return errors
