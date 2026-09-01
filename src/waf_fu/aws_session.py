"""Thread-safe boto3 session cache.

Role-assumption chains (profile A assumes role B assumes role C) resolve
on every ``boto3.Session()`` construction. When the tool fans out across
20+ regions with 8 concurrent workers, each creating its own session, the
STS ``AssumeRole`` calls saturate the API rate limit and produce
throttling errors that ``_try_aws`` silently swallows as "unavailable."

Caching one session per profile resolves the chain once; subsequent
``session.client(service, region_name=...)`` calls reuse the cached
credentials without additional STS traffic.
"""

from __future__ import annotations

import threading
from typing import Any

_cache: dict[str | None, Any] = {}
_lock = threading.Lock()


def get_session(profile: str | None = None) -> Any:
    """Return a cached ``boto3.Session`` for *profile*, creating on first call."""
    with _lock:
        if profile not in _cache:
            import boto3

            kwargs: dict[str, str] = {}
            if profile:
                kwargs["profile_name"] = profile
            _cache[profile] = boto3.Session(**kwargs)
        return _cache[profile]


def clear_cache() -> None:
    """Drop all cached sessions. Used by tests that mock ``boto3.Session``."""
    with _lock:
        _cache.clear()
