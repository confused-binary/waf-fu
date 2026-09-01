"""curl command generation for a reconstructed request."""

from __future__ import annotations

import shlex

from waf_fu.models import ReconstructedRequest
from waf_fu.replay.fidelity import skipped_headers


def to_curl(req: ReconstructedRequest, compressed: bool = True, proxy: str = "") -> str:
    parts = ["curl", "-sS", "-X", req.method]
    if proxy:
        parts += ["--proxy", proxy]
    skip = skipped_headers("curl")
    # Host is intentionally emitted (locked CURL-01 decision): curl handles a
    # Host override cleanly, unlike Chrome, so it stays useful for
    # host-header injection testing. Cookie is routed to --cookie below
    # instead of -H, so it is excluded from the -H loop here even though
    # it is not part of the skip policy (it *is* replayed, just differently).
    for name, value in req.headers.items():
        low = name.lower()
        if low in skip or low == "cookie":
            continue
        parts += ["-H", f"{name}: {value}"]
    if req.cookies:
        parts += ["--cookie", req.cookies]
    if req.body:
        parts += ["--data-raw", req.body]
    if compressed and any(h.lower() == "accept-encoding" for h in req.headers):
        parts.append("--compressed")
    parts.append(req.full_url)
    return " ".join(shlex.quote(p) for p in parts)
