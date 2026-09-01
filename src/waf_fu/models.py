"""WAF log record parsing: ReconstructedRequest, FilterRule, ExcludeRule, parse_all."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import cast

from waf_fu.jwt import decode_jwt_payload, is_jwt_header, jwt_expiry, jwt_is_valid

_RELATIVE_RE = re.compile(
    r"^\s*(\d+)\s*"
    r"(mo(?:nths?)?|m(?:in(?:ute)?s?)?|h(?:(?:ou)?rs?)?|d(?:ays?)?|w(?:eeks?)?|y(?:(?:ea)?rs?)?)"
    r"\s*$",
    re.IGNORECASE,
)

_UNIT_MAP = {
    "m": "minutes",
    "min": "minutes",
    "mins": "minutes",
    "minute": "minutes",
    "minutes": "minutes",
    "h": "hours",
    "hr": "hours",
    "hrs": "hours",
    "hour": "hours",
    "hours": "hours",
    "d": "days",
    "day": "days",
    "days": "days",
    "w": "weeks",
    "week": "weeks",
    "weeks": "weeks",
    "mo": "months",
    "month": "months",
    "months": "months",
    "y": "years",
    "yr": "years",
    "yrs": "years",
    "year": "years",
    "years": "years",
}


def parse_time_arg(value: str, *, reference: datetime) -> datetime:
    """Parse a time string as either a relative offset (e.g. '1h', '3 days')
    or an ISO-8601 timestamp. Relative offsets are subtracted from *reference*.
    """
    m = _RELATIVE_RE.match(value)
    if m:
        amount = int(m.group(1))
        unit = _UNIT_MAP[m.group(2).lower()]
        if unit == "months":
            return reference - timedelta(days=amount * 30)
        if unit == "years":
            return reference - timedelta(days=amount * 365)
        return reference - timedelta(**{unit: amount})
    return datetime.fromisoformat(value)


class ReconstructedRequest:
    _AUTH_HEADER_NAMES = frozenset(
        {
            "x-api-key",
            "x-auth-token",
            "x-amz-security-token",
            "x-csrf-token",
            "x-webhook-signature",
            "x-hub-signature-256",
            "x-slack-signature",
        }
    )

    _AUTH_QUERY_NAMES = frozenset(
        {
            "api_key",
            "apikey",
            "token",
            "x-amz-signature",
            "x-amz-credential",
            "x-amz-security-token",
            "hmac",
            "signature",
        }
    )

    def __init__(self, record: dict):
        self.raw = record
        self.timestamp = record.get("timestamp", 0)

        http = record.get("httpRequest", {})
        self.method: str = http.get("httpMethod", "GET")
        self.uri: str = http.get("uri", "/")
        self.args: str = http.get("args", "")
        self.args_redacted: bool = self.args == "REDACTED"
        if self.args_redacted:
            self.args = ""
        self.http_version: str = http.get("httpVersion", "HTTP/1.1")
        self.client_ip: str = http.get("clientIp", "")
        self.country: str = http.get("country", "")

        raw_headers = http.get("headers", [])
        self.headers: dict[str, str] = {}
        self.host = self.cookies = self.user_agent = ""
        self.referer = self.content_type = self.authorization = ""
        self.accept = self.origin = ""

        self._auth_headers: list[str] = []

        for h in raw_headers:
            name, value = h.get("name", ""), h.get("value", "")
            self.headers[name] = value
            low = name.lower()
            if low == "host":
                self.host = value
            elif low == "cookie":
                self.cookies = value
            elif low == "user-agent":
                self.user_agent = value
            elif low == "referer":
                self.referer = value
            elif low == "content-type":
                self.content_type = value
            elif low == "authorization":
                self.authorization = value
            elif low == "accept":
                self.accept = value
            elif low == "origin":
                self.origin = value
            elif low in self._AUTH_HEADER_NAMES:
                self._auth_headers.append(low)

        self.body: str = http.get("requestBody", "") or ""
        self.body_size: int = http.get("requestBodySize", 0)
        self.scheme = self._infer_scheme(http)

        self.action: str = record.get("action", "")
        self.rule_group_list = record.get("ruleGroupList", [])
        self.terminating_rule_id: str = record.get("terminatingRuleId", "")
        self.terminating_rule_type: str = record.get("terminatingRuleType", "")
        self.labels: list[str] = [
            lbl.get("name", "") for lbl in record.get("labels", [])
        ]
        self.rate_based_rule_list = record.get("rateBasedRuleList", [])
        self.web_acl_id: str = record.get("webaclId", "")

        # --- JWT analysis -----------------------------------------------------
        self.jwt_payload: dict | None = None
        self.jwt_exp: datetime | None = None
        self.jwt_valid: bool | None = None  # True/False/None(no JWT or no exp)
        if self.authorization:
            self.jwt_payload = decode_jwt_payload(self.authorization)
            self.jwt_exp = jwt_expiry(self.authorization)
            self.jwt_valid = jwt_is_valid(self.authorization)

        self.any_jwt_expired: bool = self.jwt_valid is False
        if not self.any_jwt_expired:
            for token in self._iter_jwt_candidates():
                v = jwt_is_valid(token)
                if v is False:
                    self.any_jwt_expired = True
                    break

        self.cookie_has_jwt: bool = False
        self.cookie_jwt_valid: bool | None = None
        for token in self._iter_cookie_jwts():
            self.cookie_has_jwt = True
            v = jwt_is_valid(token)
            if v is False:
                self.cookie_jwt_valid = False
                break
            if v is True and self.cookie_jwt_valid is None:
                self.cookie_jwt_valid = True

        self.auth_header_jwt_valid: bool | None = None
        for name in self._auth_headers:
            val = self.headers.get(name, "") or self.headers.get(name.title(), "")
            if not val:
                for k, v in self.headers.items():
                    if k.lower() == name:
                        val = v
                        break
            if val and val.count(".") == 2 and decode_jwt_payload(val) is not None:
                v = jwt_is_valid(val)
                if v is False:
                    self.auth_header_jwt_valid = False
                    break
                if v is True and self.auth_header_jwt_valid is None:
                    self.auth_header_jwt_valid = True

        # Set when user edits this request in the TUI
        self.edited: bool = False

        # Pre-compute matched data presence from ruleGroupList
        self._matched_data: list[dict[str, object]] | None = None

    @property
    def matched_data_entries(self) -> list[dict[str, object]]:
        """Extract all matchedData from ruleGroupList with context.

        Returns a list of dicts with keys: rule_id, action, location,
        condition_type, matched_data (list[str]).
        """
        if self._matched_data is not None:
            return self._matched_data
        entries: list[dict[str, object]] = []
        for rg in self.rule_group_list:
            for rule in rg.get("nonTerminatingMatchingRules") or []:
                for detail in rule.get("ruleMatchDetails") or []:
                    md = detail.get("matchedData")
                    if md:
                        entries.append(
                            {
                                "rule_id": rule.get("ruleId", ""),
                                "action": rule.get("action", ""),
                                "location": detail.get("location", ""),
                                "condition_type": detail.get("conditionType", ""),
                                "matched_data": md,
                            }
                        )
        self._matched_data = entries
        return entries

    @property
    def has_matched_data(self) -> bool:
        return len(self.matched_data_entries) > 0

    @property
    def has_replayable_auth(self) -> bool:
        """Entry has authentication data suitable for replay.
        Expired JWTs are excluded; cookies, auth headers, and auth query
        params all qualify."""
        if self.jwt_valid is False:
            return False
        if self.authorization:
            return True
        if self.cookies:
            return True
        if self._auth_headers:
            return True
        return bool(self.args and self._has_auth_query_param())

    _JWT_FRAGMENT_RE = re.compile(r"[A-Za-z0-9_.-]+")

    def _iter_cookie_jwts(self):
        """Yield JWT-shaped tokens from cookies, including truncated ones."""
        seen = set()
        for frag in self._JWT_FRAGMENT_RE.findall(self.cookies):
            parts = frag.split(".")
            if len(parts) < 2:
                continue
            for i in range(len(parts) - 2):
                candidate = f"{parts[i]}.{parts[i+1]}.{parts[i+2]}"
                if candidate not in seen and decode_jwt_payload(candidate) is not None:
                    seen.add(candidate)
                    yield candidate
            for i in range(len(parts) - 1):
                if is_jwt_header(parts[i]):
                    candidate = ".".join(parts[i:])
                    if candidate not in seen:
                        seen.add(candidate)
                        yield candidate
                    break

    def _iter_jwt_candidates(self):
        """Yield JWT-shaped tokens from cookies and auth headers."""
        yield from self._iter_cookie_jwts()
        for name in self._auth_headers:
            val = self.headers.get(name, "") or self.headers.get(name.title(), "")
            if not val:
                for k, v in self.headers.items():
                    if k.lower() == name:
                        val = v
                        break
            if val and val.count(".") == 2 and decode_jwt_payload(val) is not None:
                yield val

    def _has_auth_query_param(self) -> bool:
        for part in self.args.split("&"):
            key = part.split("=", 1)[0].lower()
            if key in self._AUTH_QUERY_NAMES:
                return True
        return False

    def _infer_scheme(self, http: dict) -> str:
        for h in http.get("headers", []):
            low = h.get("name", "").lower()
            val = h.get("value", "").lower()
            if low == "x-forwarded-proto":
                return val
            if low == "x-forwarded-port":
                return "https" if val == "443" else "http"
        return "https"

    _STATIC_EXTENSIONS = frozenset(
        {
            ".css",
            ".js",
            ".map",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".ico",
            ".svg",
            ".webp",
            ".avif",
            ".apng",
            ".tif",
            ".tiff",
            ".woff",
            ".woff2",
            ".ttf",
            ".otf",
            ".eot",
            ".swf",
            ".cur",
        }
    )

    @property
    def is_static_asset(self) -> bool:
        path = self.uri.split("?", 1)[0].lower()
        dot = path.rfind(".")
        if dot == -1:
            return False
        return path[dot:] in self._STATIC_EXTENSIONS

    @property
    def full_url(self) -> str:
        qs = f"?{self.args}" if self.args else ""
        return f"{self.scheme}://{self.host}{self.uri}{qs}"

    @property
    def datetime_utc(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp / 1000, tz=UTC)

    def list_line(self) -> str:
        """One-line summary for the bottom pane list."""
        if self.jwt_valid is True:
            auth_tag = "[JWT\u2714] "
        elif self.jwt_valid is False:
            auth_tag = "[JWT\u2718] "
        elif self.cookie_jwt_valid is True:
            auth_tag = "[JWT\u2714] "
        elif self.cookie_jwt_valid is False:
            auth_tag = "[JWT\u2718] "
        elif self.cookie_has_jwt:
            auth_tag = "[JWT?] "
        elif self.auth_header_jwt_valid is True:
            auth_tag = "[JWT✔] "
        elif self.auth_header_jwt_valid is False:
            auth_tag = "[JWT✘] "
        elif self.authorization:
            auth_tag = "[AUTH] "
        elif self.cookies:
            auth_tag = "[COOKIE] "
        elif self._auth_headers:
            auth_tag = "[KEY] "
        elif self.args and self._has_auth_query_param():
            auth_tag = "[QAUTH] "
        else:
            auth_tag = ""
        match_tag = "[MATCH] " if self.has_matched_data else ""
        redact_tag = "[REDACTED-TF-CONFIG] " if self.args_redacted else ""
        edit_tag = "[EDITED] " if self.edited else ""
        return (
            f"{self.datetime_utc:%Y-%m-%d %H:%M:%S}  "
            f"{self.action:<7s}  {self.method:<6s} {auth_tag}{match_tag}{edit_tag}{redact_tag}{self.full_url}  "
            f"(client={self.client_ip}, country={self.country}, "
            f"rule={self.terminating_rule_id})"
        )

    def matchable_text(self) -> str:
        """Full-text representation for exclude/include pattern matching.
        Covers URL, headers, cookies, body, IPs, labels, rules — everything."""
        if not hasattr(self, "_matchable_cache"):
            parts = [
                self.full_url,
                self.method,
                self.client_ip,
                self.country,
                self.action,
                self.terminating_rule_id,
                self.terminating_rule_type,
                self.user_agent,
                self.referer,
                self.cookies,
                self.body,
                self.origin,
                self.content_type,
                self.authorization,
                " ".join(self.labels),
            ]
            for name, value in self.headers.items():
                parts.append(f"{name}: {value}")
            self._matchable_cache = "\n".join(parts)
        return self._matchable_cache


class ExcludeRule:
    """A single exclude pattern — either a plain case-insensitive substring
    or a regex.  Prefix the input with ~ for regex."""

    def __init__(self, pattern: str):
        self.raw = pattern
        if pattern.startswith("~"):
            self.is_regex = True
            self.regex: re.Pattern[str] | None = re.compile(
                pattern[1:], re.IGNORECASE | re.MULTILINE
            )
            self.display = f"~{pattern[1:]}"
        else:
            self.is_regex = False
            self.regex = None
            self.plain = pattern.lower()
            self.display = pattern

    def matches(self, text: str) -> bool:
        if self.is_regex:
            return cast("re.Pattern[str]", self.regex).search(text) is not None
        return self.plain in text.lower()

    def __repr__(self):
        kind = "regex" if self.is_regex else "str"
        return f"ExcludeRule({kind}: {self.display})"


class FilterRule:
    """A single filter rule -- include (keep matches) or exclude (drop matches).
    Prefix with ~ for regex.  Plain text is case-insensitive substring match."""

    def __init__(self, pattern: str, mode: str = "exclude", enabled: bool = True):
        self.raw = pattern
        self.mode = mode  # "include" or "exclude"
        self.enabled = enabled
        if pattern.startswith("~"):
            self.is_regex = True
            self.regex: re.Pattern[str] | None = re.compile(
                pattern[1:], re.IGNORECASE | re.MULTILINE
            )
            self.display = f"~{pattern[1:]}"
        else:
            self.is_regex = False
            self.regex = None
            self.plain = pattern.lower()
            self.display = pattern

    def matches(self, text: str) -> bool:
        if self.is_regex:
            return cast("re.Pattern[str]", self.regex).search(text) is not None
        return self.plain in text.lower()

    def __repr__(self):
        kind = "regex" if self.is_regex else "str"
        en = "" if self.enabled else " disabled"
        return f"FilterRule({self.mode} {kind}: {self.display}{en})"


def load_filter_rules_yaml(path: str) -> list[FilterRule]:
    """Load filter rules from a YAML file.  Returns a list of FilterRule objects."""
    import yaml

    with open(path) as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict) or "filters" not in data:
        raise ValueError(f"{path}: expected a top-level 'filters' key")

    rules: list[FilterRule] = []
    for entry in data["filters"]:
        if isinstance(entry, str):
            rules.append(FilterRule(entry, mode="exclude"))
            continue
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("pattern", "")
        if not pattern:
            continue
        mode = entry.get("mode", "exclude")
        if mode not in ("include", "exclude"):
            raise ValueError(f"{path}: invalid mode '{mode}' (use include or exclude)")
        enabled = entry.get("enabled", True)
        rules.append(FilterRule(pattern, mode=mode, enabled=enabled))
    return rules


def parse_all(records: list[dict]) -> list[ReconstructedRequest]:
    out = [ReconstructedRequest(r) for r in records]
    out.sort(key=lambda r: r.timestamp)
    return out
