"""JWT decode and expiry helpers (stdlib only, no PyJWT)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime


def _b64_decode_segment(segment: str) -> bytes:
    """Decode a URL-safe base64 JWT segment, adding padding as needed."""
    rem = len(segment) % 4
    if rem:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment)


def decode_jwt_payload(token: str) -> dict | None:
    """Decode the payload of a JWT without verifying the signature.
    Returns the claims dict, or None if the token isn't a valid JWT."""
    # Strip "Bearer " prefix if present
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload_bytes = _b64_decode_segment(parts[1])
        return json.loads(payload_bytes)
    except Exception:
        return None


def is_jwt_header(segment: str) -> bool:
    """Check if a base64url segment decodes to a JSON object with an 'alg' key."""
    try:
        data = json.loads(_b64_decode_segment(segment))
        return isinstance(data, dict) and "alg" in data
    except Exception:
        return False


def jwt_expiry(token: str) -> datetime | None:
    """Return the expiry datetime of a JWT, or None if not a JWT / no exp."""
    payload = decode_jwt_payload(token)
    if payload is None:
        return None
    exp = payload.get("exp")
    if exp is None:
        return None
    try:
        return datetime.fromtimestamp(int(exp), tz=UTC)
    except (ValueError, TypeError, OSError):
        return None


def jwt_is_valid(token: str) -> bool | None:
    """Check if a JWT's exp claim is in the future.
    Returns True (valid), False (expired), or None (not a JWT / no exp)."""
    exp_dt = jwt_expiry(token)
    if exp_dt is None:
        return None
    return exp_dt > datetime.now(UTC)
