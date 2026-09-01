"""Single source of truth for what each replay mode can and cannot reproduce.

chrome.py, firefox.py, curl.py and tui.py all ask the same question — "will
this header survive this replay mode?" — and must answer it identically.
This module owns that answer so the four consumers cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass

from waf_fu.models import ReconstructedRequest

MODES: frozenset[str] = frozenset({"chrome", "firefox", "curl"})

# Headers every mode skips by default, with a shared fallback reason.
# Reasons that differ per mode (e.g. curl's wording) are supplied by
# _REASONS below and take priority over this fallback.
ALWAYS_SKIPPED: dict[str, str] = {
    "content-length": "recomputed by the browser from the actual body length",
    "connection": "hop-by-hop framing header, not settable at the interception layer",
    "keep-alive": "hop-by-hop framing header, not settable at the interception layer",
    "transfer-encoding": (
        "hop-by-hop framing header, not settable at the interception layer"
    ),
}

# Extra per-mode entries beyond ALWAYS_SKIPPED. Chrome uniquely rejects a
# Host override (measured: CDP Fetch.continueRequest fails with
# -32602 "Unsafe header: Host"); Firefox's BiDi network.continueRequest
# accepts it, so Firefox and curl add nothing here.
MODE_SKIPPED: dict[str, dict[str, str]] = {
    "chrome": {
        "host": "Chrome rejects a Host override (CDP 'Unsafe header: Host') — use curl mode",
        "upgrade": "Chrome rejects Upgrade (CDP 'Unsafe header: Upgrade') — use curl mode",
    },
    "firefox": {},
    "curl": {},
}

# Per-mode overrides of ALWAYS_SKIPPED's default reason, keyed by
# (mode, header). Falls back to ALWAYS_SKIPPED[header] when absent.
_REASONS: dict[tuple[str, str], str] = {
    ("curl", "content-length"): "omitted so curl recalculates it from --data-raw",
    ("curl", "connection"): "hop-by-hop framing header, managed by curl",
    ("curl", "keep-alive"): "hop-by-hop framing header, managed by curl",
    ("curl", "transfer-encoding"): "hop-by-hop framing header, managed by curl",
}

COOKIE_ATTRIBUTE_NOTE = (
    "Domain and Path are inferred from the logged Host and URI, and Secure "
    "from the scheme; HttpOnly and SameSite are defaults, because a WAF "
    "request log records only the Cookie request header and never the "
    "Set-Cookie attributes."
)

BODY_AUTH_NOTE = (
    "POST body authentication (username, password, client_secret, etc.) "
    "cannot be replayed: WAF logs record body field names but not values. "
    "The request will be sent without credentials — an unauthenticated "
    "response is expected."
)

BODY_EMPTY_NOTE = (
    "POST body content is not available: WAF logs record body field names "
    "but not values. The request will be sent with an empty body — the "
    "server may reject it."
)


def skipped_headers(mode: str) -> dict[str, str]:
    """Lowercase header name -> human-readable reason it can't be replayed
    in `mode`. Raises ValueError for an unrecognized mode rather than
    silently reporting perfect fidelity."""
    if mode not in MODES:
        raise ValueError(f"unknown replay mode: {mode!r}")
    result = {
        header: _REASONS.get((mode, header), default_reason)
        for header, default_reason in ALWAYS_SKIPPED.items()
    }
    result.update(MODE_SKIPPED[mode])
    return result


def replayable_headers(req: ReconstructedRequest, mode: str) -> dict[str, str]:
    """Original-cased headers from `req` that survive replay in `mode`,
    preserving `req.headers`' insertion order."""
    skip = skipped_headers(mode)
    return {
        name: value for name, value in req.headers.items() if name.lower() not in skip
    }


@dataclass(frozen=True)
class FidelityReport:
    mode: str
    replayable: tuple[str, ...]
    skipped: tuple[tuple[str, str], ...]
    cookie_note: str
    body_note: str = ""

    @property
    def all_replayable(self) -> bool:
        return not self.skipped

    @property
    def curl_fallback(self) -> bool:
        return self.mode != "curl" and bool(self.skipped)


def fidelity_report(req: ReconstructedRequest, mode: str) -> FidelityReport:
    """Per-mode fidelity summary for `req`. Raises ValueError for an
    unrecognized mode."""
    skip = skipped_headers(mode)
    replayable: list[str] = []
    skipped: list[tuple[str, str]] = []
    for name in req.headers:
        reason = skip.get(name.lower())
        if reason is not None:
            skipped.append((name, reason))
        else:
            replayable.append(name)
    cookie_note = COOKIE_ATTRIBUTE_NOTE if req.cookies else ""
    body_note = ""
    if req.method.upper() == "POST" and req.content_type and not req.body:
        if not req.has_replayable_auth:
            body_note = BODY_AUTH_NOTE
        else:
            body_note = BODY_EMPTY_NOTE
    return FidelityReport(
        mode=mode,
        replayable=tuple(replayable),
        skipped=tuple(skipped),
        cookie_note=cookie_note,
        body_note=body_note,
    )
