"""Split-pane curses interface for browsing and replaying WAF log entries."""

from __future__ import annotations

import base64
import binascii
import curses
import json
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any

from waf_fu import merge, storage
from waf_fu import s3 as s3_mod
from waf_fu.cloudwatch import (
    AWS_REGIONS,
    fetch_logs_from_cloudwatch,
    fetch_waf_log_groups,
)
from waf_fu.debug import DEBUG, _redact_meta, _redact_url
from waf_fu.jwt import decode_jwt_payload, jwt_expiry, jwt_is_valid
from waf_fu.models import (
    FilterRule,
    ReconstructedRequest,
    parse_all,
    parse_time_arg,
)
from waf_fu.replay import launch_driver, open_request
from waf_fu.replay.curl import to_curl
from waf_fu.replay.validation import validate_request

# ═══════════════════════════════════════════════════════════════════════════════
# Detail pane content builder
# ═══════════════════════════════════════════════════════════════════════════════


def detail_line_kind(line: str) -> str:
    """Classify a detail-pane line for colouring.

    Returns 'section' | 'ok' | 'bad' | 'plain'.
    """
    if line.startswith("═══"):
        return "section"
    stripped = line.lstrip()
    if stripped.startswith("✔"):
        return "ok"
    if stripped.startswith("✘"):
        return "bad"
    return "plain"


_B64_RE = re.compile(r"[A-Za-z0-9+/\-_]{16,}={0,3}")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _is_printable(data: bytes) -> bool:
    """True if data is mostly printable ASCII/UTF-8."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t ")
    return len(text) > 0 and printable / len(text) >= 0.8


def _try_decode(value: str) -> list[tuple[str, str]]:
    """Try to decode a string value. Returns list of (encoding_name, decoded_text)."""
    results: list[tuple[str, str]] = []
    if not value or len(value) < 8:
        return results

    if _URL_ENCODED_RE.search(value):
        decoded = urllib.parse.unquote(value)
        if decoded != value:
            results.append(("url", decoded))

    for m in _B64_RE.finditer(value):
        candidate = m.group()
        if len(candidate) < 16:
            continue
        for variant in (candidate, candidate.replace("-", "+").replace("_", "/")):
            padded = variant + "=" * (-len(variant) % 4)
            try:
                raw = base64.b64decode(padded, validate=True)
            except (binascii.Error, ValueError):
                continue
            if _is_printable(raw):
                decoded_text = raw.decode("utf-8", errors="replace")
                results.append(("base64", decoded_text))
                break

    if _HEX_RE.match(value) and len(value) % 2 == 0:
        try:
            raw = bytes.fromhex(value)
            if _is_printable(raw):
                results.append(("hex", raw.decode("utf-8", errors="replace")))
        except ValueError:
            pass

    return results


def _scan_for_decodable(req: Any) -> list[tuple[str, str, str, str]]:
    """Scan request fields for decodable content.

    Returns list of (source_label, encoding, original, decoded).
    """
    found: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _check(label: str, value: str) -> None:
        if not value or value in seen:
            return
        seen.add(value)
        for enc, decoded in _try_decode(value):
            found.append((label, enc, value, decoded))

    for name, value in req.headers.items():
        low = name.lower()
        if low == "cookie":
            continue
        _check(name, value)

    if req.cookies:
        for fragment in req.cookies.split(";"):
            fragment = fragment.strip()
            if "=" in fragment:
                cname, _, cval = fragment.partition("=")
                _check(f"cookie: {cname.strip()}", cval.strip())
            elif fragment:
                _check("cookie", fragment)

    if req.args:
        for part in req.args.split("&"):
            if "=" in part:
                pname, _, pval = part.partition("=")
                _check(f"query: {pname}", pval)
            elif part:
                _check("query", part)

    for segment in req.uri.split("/"):
        if segment and len(segment) >= 16:
            _check(f"path: .../{segment[:20]}", segment)

    return found


def build_detail_lines(
    req: ReconstructedRequest, mode: str, proxy: str = "", source_view: str = "merged"
) -> list[str]:
    """Build the lines shown in the top (detail) pane."""
    lines: list[str] = []

    # ── Overview ──
    lines.append("═══ REQUEST OVERVIEW ═══")
    lines.append("")
    if req.edited:
        lines.append(
            "  ✎ THIS REQUEST HAS BEEN EDITED — replay will use modified values"
        )
        lines.append("")
    lines.append(f"  Timestamp     {req.datetime_utc:%Y-%m-%d %H:%M:%S} UTC")
    lines.append(f"  Method        {req.method}")
    lines.append(f"  URL           {req.full_url}")
    if req.args_redacted:
        lines.append("  Query String  ⚠ REDACTED-TF-CONFIG")
    lines.append(f"  HTTP Version  {req.http_version}")
    lines.append(f"  Client IP     {req.client_ip}")
    lines.append(f"  Country       {req.country}")
    lines.append("")

    # ── WAF Decision ──
    lines.append("═══ WAF DECISION ═══")
    lines.append("")
    lines.append(f"  Action              {req.action}")
    lines.append(f"  Terminating Rule    {req.terminating_rule_id}")
    lines.append(f"  Rule Type           {req.terminating_rule_type}")
    if req.labels:
        lines.append(f"  Labels              {', '.join(req.labels)}")
    if req.rate_based_rule_list:
        for rb in req.rate_based_rule_list:
            lines.append(
                f"  Rate-Based Rule     {rb.get('rateBasedRuleId', '?')}  "
                f"count={rb.get('limitValue', '?')}"
            )
    if req.rule_group_list:
        for rg in req.rule_group_list:
            rg_id = rg.get("ruleGroupId", "?")
            lines.append(f"  Rule Group          {rg_id}")
            term_rule = rg.get("terminatingRule") or {}
            if term_rule and term_rule.get("ruleId"):
                lines.append(
                    f"    Terminating       {term_rule.get('ruleId', '')} ({term_rule.get('action', '')})"
                )
            for rule in rg.get("nonTerminatingMatchingRules") or []:
                lines.append(
                    f"    Non-Term Match    {rule.get('ruleId', '')} ({rule.get('action', '')})"
                )
            for rule in rg.get("excludedRules") or []:
                lines.append(f"    Excluded          {rule.get('ruleId', '')}")
    lines.append("")

    # ── Matched Data ──
    if req.has_matched_data:
        lines.append("═══ MATCHED DATA ═══")
        lines.append("")
        for entry in req.matched_data_entries:
            rule_id = entry.get("rule_id", "?")
            location = entry.get("location", "?")
            condition = entry.get("condition_type", "?")
            lines.append(f"  Rule: {rule_id}  Location: {location}  Type: {condition}")
            md_vals: list[str] = entry.get("matched_data") or []  # type: ignore[assignment]
            for md_val in md_vals:
                display = md_val if len(md_val) <= 100 else md_val[:97] + "..."
                lines.append(f"    → {display}")
        lines.append("")

    # ── JWT Details ──
    if req.jwt_payload is not None:
        lines.append("═══ JWT TOKEN ═══")
        lines.append("")
        if req.jwt_valid is True:
            lines.append("  Status            ✔ VALID (not expired)")
        elif req.jwt_valid is False:
            lines.append("  Status            ✘ EXPIRED")
        else:
            lines.append("  Status            ? (no exp claim)")
        if req.jwt_exp:
            now = datetime.now(UTC)
            delta = req.jwt_exp - now
            if delta.total_seconds() > 0:
                mins = int(delta.total_seconds() // 60)
                lines.append(
                    f"  Expires           {req.jwt_exp:%Y-%m-%d %H:%M:%S} UTC  ({mins}m remaining)"
                )
            else:
                ago = int(-delta.total_seconds() // 60)
                lines.append(
                    f"  Expires           {req.jwt_exp:%Y-%m-%d %H:%M:%S} UTC  (expired {ago}m ago)"
                )

        # Show key claims
        for claim_key in (
            "sub",
            "iss",
            "aud",
            "iat",
            "nbf",
            "azp",
            "scope",
            "scp",
            "email",
            "name",
            "cognito:groups",
            "cognito:username",
            "client_id",
            "token_use",
            "custom:role",
        ):
            val = req.jwt_payload.get(claim_key)
            if val is not None:
                display_key = claim_key.replace("cognito:", "cognito:")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                # Format iat/nbf as timestamps
                if claim_key in ("iat", "nbf"):
                    try:
                        val = f"{val}  ({datetime.fromtimestamp(int(val), tz=UTC):%Y-%m-%d %H:%M:%S} UTC)"
                    except Exception:
                        pass
                lines.append(f"  {display_key:<18s}  {val}")

        # Full payload dump
        lines.append("")
        lines.append("  ── Full Payload ──")
        for pline in json.dumps(req.jwt_payload, indent=2).splitlines():
            lines.append(f"    {pline}")
        lines.append("")

    # ── Decoded Content ──
    decoded_items = _scan_for_decodable(req)
    if decoded_items:
        lines.append("═══ DECODED CONTENT ═══")
        lines.append("")
        for source_label, encoding, original, decoded in decoded_items:
            lines.append(f"  {source_label} ({encoding})")
            orig_display = original if len(original) <= 72 else original[:69] + "..."
            lines.append(f"    Encoded   {orig_display}")
            decoded_lines = decoded.splitlines()
            lines.append(f"    Decoded   {decoded_lines[0]}")
            for extra_line in decoded_lines[1:]:
                lines.append(f"              {extra_line}")
            lines.append("")

    # ── Headers ──
    lines.append("═══ HEADERS ═══")
    lines.append("")
    if req.headers:
        max_name_len = max(len(n) for n in req.headers) if req.headers else 0
        for name, value in req.headers.items():
            lines.append(f"  {name:<{max_name_len}}  {value}")
    else:
        lines.append("  (none)")
    lines.append("")

    # ── Cookies ──
    if req.cookies:
        lines.append("═══ COOKIES ═══")
        lines.append("")
        for fragment in req.cookies.split(";"):
            fragment = fragment.strip()
            if fragment:
                lines.append(f"  {fragment}")
        lines.append("")

    # ── Body ──
    if req.body:
        lines.append("═══ BODY ═══")
        lines.append(f"  (size inspected: {req.body_size} bytes)")
        lines.append("")
        # Try to pretty-print JSON bodies
        try:
            parsed = json.loads(req.body)
            for bline in json.dumps(parsed, indent=2).splitlines():
                lines.append(f"  {bline}")
        except (json.JSONDecodeError, TypeError):
            for bline in req.body.splitlines():
                lines.append(f"  {bline}")
        lines.append("")
    elif source_view == "waf" or str(req.raw.get("_sources") or "") == "waf":
        lines.append("═══ BODY ═══")
        lines.append("")
        lines.append("  (body not available via WAF sampling API)")
        lines.append("")

    # ── Raw JSON (collapsed preview) ──
    lines.append("═══ RAW JSON ═══")
    lines.append("")
    for rline in json.dumps(req.raw, indent=2).splitlines():
        lines.append(f"  {rline}")

    return lines


def build_json_lines(req: ReconstructedRequest) -> list[str]:
    """Full raw JSON view of the WAF log record."""
    lines = ["═══ RAW JSON ═══", ""]
    for rline in json.dumps(req.raw, indent=2).splitlines():
        lines.append(f"  {rline}")
    return lines


def build_headers_lines(req: ReconstructedRequest) -> list[str]:
    """Compact view: just the request line, headers, and cookies."""
    lines = []

    lines.append(f"  {req.method} {req.full_url} {req.http_version}")
    lines.append("")

    lines.append("═══ HEADERS ═══")
    lines.append("")
    if req.headers:
        max_name_len = max(len(n) for n in req.headers)
        for name, value in req.headers.items():
            lines.append(f"  {name:<{max_name_len}}  {value}")
    else:
        lines.append("  (none)")
    lines.append("")

    if req.cookies:
        lines.append("═══ COOKIES ═══")
        lines.append("")
        for fragment in req.cookies.split(";"):
            fragment = fragment.strip()
            if fragment:
                lines.append(f"  {fragment}")
        lines.append("")

    return lines


def max_hscroll_offset(item: str, avail: int) -> int:
    """Largest horizontal offset that still shows the tail of `item`."""
    return max(0, len(item) - avail)


def hscroll_window(item: str, avail: int, offset: int) -> str:
    """Return at most `avail` characters of `item` starting at `offset`,
    with ellipses marking text hidden to the left and right."""
    if avail <= 0:
        return ""
    if len(item) <= avail:
        return item

    offset = max(0, min(offset, max_hscroll_offset(item, avail)))
    has_left = offset > 0
    has_right = offset + avail < len(item)

    if not has_left and not has_right:
        return item[:avail]
    if has_left and not has_right:
        if avail <= 1:
            return "…"
        return "…" + item[len(item) - (avail - 1) :]
    if not has_left and has_right:
        if avail <= 1:
            return "…"
        return item[: avail - 1] + "…"

    # Both sides hidden.
    if avail <= 2:
        return "…" * avail
    return "…" + item[offset + 1 : offset + avail - 1] + "…"


def _fetch_from_cloudwatch_ms(
    log_group: str,
    start_time: int,
    end_time: int,
    action_filter: str | None,
    profile: str | None,
    region: str | None,
) -> list[dict]:
    """Adapt storage.load_source_with_cache's ms-int fetch_fn contract to
    cloudwatch.fetch_logs_from_cloudwatch's datetime parameters, so
    storage.py never has to import cloudwatch (or boto3)."""
    return fetch_logs_from_cloudwatch(
        log_group=log_group,
        start_time=datetime.fromtimestamp(start_time / 1000, tz=UTC),
        end_time=datetime.fromtimestamp(end_time / 1000, tz=UTC),
        profile=profile,
        region=region,
        action_filter=action_filter,
    )


def _s3_fetch_adapter(bucket: str, acl_name: str | None):
    """Build a fetch_fn bound to one S3 bucket for storage.load_source_with_cache."""

    def _fetch(
        *,
        log_group: str,
        start_time: int,
        end_time: int,
        action_filter: str | None = None,
        profile: str | None = None,
        region: str | None = None,
    ) -> list[dict]:
        return s3_mod.fetch_logs_from_s3(
            bucket=bucket,
            start_time=datetime.fromtimestamp(start_time / 1000, tz=UTC),
            end_time=datetime.fromtimestamp(end_time / 1000, tz=UTC),
            acl_name=acl_name,
            profile=profile,
            region=region,
            action_filter=action_filter,
        )

    return _fetch


class WafTUI:
    """Split-pane terminal UI for browsing and replaying WAF log entries."""

    _MODES = ("firefox", "chrome", "curl")
    _VIEW_MODES = ("detail", "json", "headers")
    _SORT_FIELDS = ("time", "method", "url")
    _SORT_DIRS = ("asc", "desc")

    def __init__(
        self,
        requests: list[ReconstructedRequest],
        initial_mode: str = "chrome",
        auth_filter_default: bool = True,
        source_info: dict | None = None,
        initial_filter_rules: list[FilterRule] | None = None,
        aws_context: dict | None = None,
        proxy: str = "",
        timeout: float = 30.0,
        db: sqlite3.Connection | None = None,
        auto_refresh_interval: int = 0,
        chromedriver_path: str = "",
        geckodriver_path: str = "",
        initial_sort_field: str = storage.DEFAULT_SORT_FIELD,
        initial_sort_dir: str = storage.DEFAULT_SORT_DIR,
        log_location: str | None = None,
        db_only: bool = False,
    ):
        self.all_requests = requests
        self.filtered: list[ReconstructedRequest] = list(requests)
        self.mode = initial_mode  # "curl" or "chrome"
        self.log_location: str | None = log_location
        # No AWS API calls anywhere in this session: log selection and
        # reload/refresh read straight from the SQLite cache.
        self.db_only: bool = db_only
        self.proxy: str = proxy
        self.timeout: float = timeout
        self.chromedriver_path: str = chromedriver_path
        self.geckodriver_path: str = geckodriver_path

        # Track which requests have been edited (by id)
        self._edited: set[int] = set()

        # Detail view mode
        self.view_mode: str = "detail"

        # Per-record source view: "merged" (best-of) or one contributing source
        self._source_view: str = "merged"
        self._source_req: ReconstructedRequest | None = None

        # Source context for display
        self.source_info: dict = source_info or {}

        # AWS context for re-loading from a different log group
        self.aws_context: dict = aws_context or {}

        # SQLite connection for cached log-group loads; TUI borrows, never owns
        self.db: sqlite3.Connection | None = db

        self._load_thread: threading.Thread | None = None
        self._load_status: str = ""
        self._load_lock = threading.Lock()
        self._pending_load: dict | None = None

        # List pane state
        self.cursor = 0
        self.list_scroll = 0
        self.h_offset = 0

        # Detail pane state
        self.detail_scroll = 0
        self.detail_h_offset = 0
        self.detail_lines: list[str] = []

        # If True, show log group selector on first draw
        self._needs_log_selection: bool = len(requests) == 0

        # Unified filter rules -- applied in order (include keeps, exclude drops)
        self.filter_rules: list[FilterRule] = list(initial_filter_rules or [])

        self.auth_filter: bool = auth_filter_default

        # Hide blocked/denied entries toggle
        self.hide_blocks: bool = False
        self._BLOCK_ACTIONS = frozenset({"BLOCK", "DENY"})

        # Status message (shown briefly after actions)
        self.status_msg = ""
        self.status_time = 0.0
        # Severity of status_msg: "" (plain), "error" (red), "warn" (yellow)
        self.status_kind: str = ""

        # Multi-select: tracks id() of selected ReconstructedRequest objects
        self.selected: set[int] = set()

        # Persistent browser driver — reused across replays
        self._browser_driver: Any = None
        self._browser_type: str = ""  # "chrome" or "firefox"

        # Accumulated output to print AFTER curses exits
        self.post_exit_output: list[str] = []

        # Auto-refresh state
        self.auto_refresh: bool = auto_refresh_interval > 0
        self.auto_refresh_interval: int = (
            auto_refresh_interval if auto_refresh_interval > 0 else 10
        )
        self._last_refresh_time: float = time.time()

        # List sort configuration
        self.sort_field: str = (
            initial_sort_field
            if initial_sort_field in self._SORT_FIELDS
            else storage.DEFAULT_SORT_FIELD
        )
        self.sort_dir: str = (
            initial_sort_dir
            if initial_sort_dir in self._SORT_DIRS
            else storage.DEFAULT_SORT_DIR
        )

        # Detail pane search state
        self._search_pattern: str = ""
        self._search_re: re.Pattern | None = None
        self._search_matches: list[
            tuple[int, int, int]
        ] = []  # (line_idx, col_start, col_end)
        self._search_match_idx: int = -1

        # Apply initial filter
        self._apply_filter()

    # ── layout helpers ──────────────────────────────────────────────────────

    def _layout(self, term_h: int, term_w: int):
        """Compute pane geometry.  Returns (detail_h, list_h, divider_y)."""
        # Reserve 1 row for status bar at very bottom
        usable = term_h - 1
        list_h = min(10, usable - 5)
        detail_h = usable - list_h - 1
        divider_y = detail_h
        return detail_h, list_h, divider_y

    def _scroll_to_cursor(self):
        self.list_scroll = min(self.list_scroll, self.cursor)
        if self.cursor >= self.list_scroll + 10:
            self.list_scroll = max(self.cursor - 9, 0)
        self.h_offset = 0

    # ── source views ────────────────────────────────────────────────────────

    def _available_source_views(self) -> list[str]:
        """Source views selectable for the current record: always "merged",
        plus every source its `_sources` provenance says contributed."""
        views = ["merged"]
        if not self.filtered or not 0 <= self.cursor < len(self.filtered):
            return views
        provenance = str(self.filtered[self.cursor].raw.get("_sources") or "")
        for name in provenance.split(","):
            name = name.strip()
            if name in storage.SOURCES and name not in views:
                views.append(name)
        return views

    def _cycle_source_view(self) -> None:
        """Advance to the next source view available for the current record."""
        views = self._available_source_views()
        idx = views.index(self._source_view) if self._source_view in views else 0
        self._source_view = views[(idx + 1) % len(views)]
        self._source_req = None

    def _reset_source_view(self) -> None:
        self._source_view = "merged"
        self._source_req = None

    def _load_record_for_source(
        self, req: ReconstructedRequest, source: str
    ) -> ReconstructedRequest:
        """Return `req` as `source` recorded it, or `req` itself when that
        source has no matching record (or there is no database to read)."""
        log_group = self.source_info.get("log_group", "")
        if source == "merged" or self.db is None or not log_group:
            return req
        try:
            records = storage.load_source_records(
                self.db,
                source,
                log_group,
                req.timestamp - 1000,
                req.timestamp + 1000,
            )
        except Exception:
            return req
        target = merge.correlation_key(req.raw)
        for record in records:
            if merge.correlation_key(record) == target:
                # Through merge_record_group so a sampled record's API-cased
                # headers are normalized before parsing.
                return ReconstructedRequest(merge.merge_record_group({source: record}))
        return req

    def _detail_request(self) -> ReconstructedRequest:
        """The record the detail pane should render for the current cursor."""
        req = self.filtered[self.cursor]
        if self._source_view == "merged":
            return req
        if self._source_req is None:
            self._source_req = self._load_record_for_source(req, self._source_view)
        return self._source_req

    # ── drawing ─────────────────────────────────────────────────────────────

    def _draw(self, stdscr):
        stdscr.erase()
        term_h, term_w = stdscr.getmaxyx()
        if term_h < 10 or term_w < 40:
            stdscr.addnstr(0, 0, "Terminal too small", term_w - 1)
            stdscr.refresh()
            return

        detail_h, list_h, div_y = self._layout(term_h, term_w)
        status_y = term_h - 1

        # Rebuild detail lines for current selection
        if self.filtered:
            req = self._detail_request()
            if self.view_mode == "json":
                self.detail_lines = build_json_lines(req)
            elif self.view_mode == "headers":
                self.detail_lines = build_headers_lines(req)
            else:
                self.detail_lines = build_detail_lines(
                    req, self.mode, self.proxy, self._source_view
                )
        else:
            self.detail_lines = ["", "  (no entries match current filter)"]

        # Clamp scroll to content — keeps position stable across entries
        # while preventing scrolling past shorter entries
        max_scroll = max(len(self.detail_lines) - detail_h, 0)
        self.detail_scroll = min(self.detail_scroll, max_scroll)

        # Keep search matches in sync with current detail content
        if self._search_re is not None:
            self._rebuild_search_matches()
            if self._search_match_idx >= len(self._search_matches):
                self._search_match_idx = 0 if self._search_matches else -1

        # Build per-line match index for visible search highlights
        search_by_line: dict[int, list[tuple[int, int, bool]]] = {}
        if self._search_re is not None:
            active_match = (
                self._search_matches[self._search_match_idx]
                if 0 <= self._search_match_idx < len(self._search_matches)
                else None
            )
            for i, (ml, ms, me) in enumerate(self._search_matches):
                is_active = (ml, ms, me) == active_match
                search_by_line.setdefault(ml, []).append((ms, me, is_active))

        # ── Top pane: detail ──
        for row in range(detail_h):
            line_idx = self.detail_scroll + row
            if line_idx < len(self.detail_lines):
                raw_line = self.detail_lines[line_idx]
                kind = detail_line_kind(raw_line)
                if kind == "section":
                    base_attr = curses.A_BOLD | curses.color_pair(3)
                elif kind == "ok":
                    base_attr = curses.color_pair(5)
                elif kind == "bad":
                    base_attr = curses.color_pair(1)
                else:
                    base_attr = 0

                line_matches = search_by_line.get(line_idx)
                if not line_matches:
                    line = raw_line
                    if self.detail_h_offset > 0:
                        line = line[self.detail_h_offset :]
                    self._safe_addnstr(stdscr, row, 0, line, term_w - 1, base_attr)
                else:
                    h_off = self.detail_h_offset
                    col = 0
                    segments: list[tuple[str, int]] = []
                    prev = 0
                    for ms, me, is_active in sorted(line_matches):
                        if prev < ms:
                            segments.append((raw_line[prev:ms], base_attr))
                        hl_attr = (
                            curses.color_pair(9) | curses.A_BOLD
                            if is_active
                            else curses.color_pair(8) | curses.A_BOLD
                        )
                        segments.append((raw_line[ms:me], hl_attr))
                        prev = me
                    if prev < len(raw_line):
                        segments.append((raw_line[prev:], base_attr))

                    for text, attr in segments:
                        if h_off > 0:
                            if h_off >= len(text):
                                h_off -= len(text)
                                continue
                            text = text[h_off:]
                            h_off = 0
                        if col >= term_w - 1:
                            break
                        maxlen = term_w - 1 - col
                        self._safe_addnstr(stdscr, row, col, text, maxlen, attr)
                        col += min(len(text), maxlen)

        # ── Divider ──
        auth_indicator = " auth-only " if self.auth_filter else " all "
        block_indicator = " BLOCK:hidden " if self.hide_blocks else ""
        n_filt = len(self.filter_rules)
        filt_indicator = f" rules:{n_filt}" if n_filt else ""
        view_indicator = f" view:{self.view_mode}"
        sort_indicator = f" sort:{self.sort_field}/{self.sort_dir}"
        if self.auto_refresh:
            remaining = max(
                0,
                self.auto_refresh_interval - (time.time() - self._last_refresh_time),
            )
            refresh_indicator = f" auto:{int(remaining)}s"
        else:
            refresh_indicator = ""
        mode_label = f" MODE: {self.mode.upper()} │{auth_indicator}{block_indicator}{filt_indicator}{view_indicator}{sort_indicator}{refresh_indicator} "
        sel_count = len(self.selected)
        sel_label = f" sel:{sel_count}" if sel_count else ""
        edit_count = sum(1 for r in self.filtered if r.edited)
        edit_label = f" ✎:{edit_count}" if edit_count else ""
        match_count = sum(1 for r in self.filtered if r.has_matched_data)
        match_label = f" ⚑:{match_count}" if match_count else ""
        if self.filtered:
            count_label = (
                f"{sel_label}{edit_label}{match_label}  "
                f"{self.cursor + 1}/{len(self.filtered)} entries "
            )
        else:
            count_label = f"{sel_label}{edit_label}{match_label}  0/0 entries "
        divider_text = "─" * term_w
        # Embed labels into divider
        if term_w > len(mode_label) + len(count_label) + 10:
            ml = 2
            cl = term_w - len(count_label) - 2
            divider_text = (
                divider_text[:ml]
                + mode_label
                + "─" * (cl - ml - len(mode_label))
                + count_label
                + divider_text[cl + len(count_label) :]
            )
        self._safe_addnstr(
            stdscr,
            div_y,
            0,
            divider_text[:term_w],
            term_w - 1,
            curses.A_BOLD | curses.color_pair(2),
        )

        # ── Bottom pane: list ──
        list_start_y = div_y + 1
        visible_rows = list_h

        # Ensure scroll follows cursor
        self.list_scroll = min(self.list_scroll, self.cursor)
        if self.cursor >= self.list_scroll + visible_rows:
            self.list_scroll = self.cursor - visible_rows + 1

        longest_line = max((len(r.list_line()) for r in self.filtered), default=0)

        for row in range(visible_rows):
            idx = self.list_scroll + row
            y = list_start_y + row
            if y >= term_h - 1:
                break
            if idx < len(self.filtered):
                req_obj = self.filtered[idx]
                is_selected = id(req_obj) in self.selected
                is_edited = req_obj.edited
                is_matched = req_obj.has_matched_data
                m0 = "⚑" if is_matched else " "
                m1 = "✎" if is_edited else " "
                m2 = "●" if is_selected else " "
                marker = f"{m0}{m1}{m2} "
                raw = req_obj.list_line()
                if len(raw) < longest_line:
                    raw = raw + " " * (longest_line - len(raw))
                avail = max(term_w - 1 - len(marker), 0)
                text = hscroll_window(raw, avail, self.h_offset)
                line = marker + text

                if idx == self.cursor:
                    attr = curses.A_REVERSE | curses.A_BOLD
                elif is_selected:
                    attr = curses.A_BOLD | curses.color_pair(3)  # cyan bold
                elif is_matched:
                    attr = curses.A_BOLD | curses.color_pair(7)  # blue bold
                elif is_edited:
                    attr = curses.A_BOLD | curses.color_pair(6)  # magenta bold
                else:
                    action = req_obj.action
                    if action in self._BLOCK_ACTIONS:
                        attr = curses.color_pair(1)  # red
                    elif req_obj.any_jwt_expired:
                        attr = curses.color_pair(4)  # yellow — expired JWT
                    else:
                        attr = curses.color_pair(5)  # green
                self._safe_addnstr(stdscr, y, 0, line, term_w - 1, attr)

        # ── Status bar ──
        load_status = self._get_load_status() if self._is_loading() else ""
        elapsed = time.time() - self.status_time
        bar_attr = curses.A_REVERSE
        source_prefix = (
            f" Source: {self._source_view} │" if self._source_view != "merged" else ""
        )
        if load_status:
            bar_text = f"{source_prefix} [LOADING] {load_status}"
        elif self.status_msg and elapsed < 5.0:
            bar_text = f"{source_prefix} {self.status_msg}"
            if self.status_kind == "error":
                bar_attr = curses.A_REVERSE | curses.color_pair(1)
            elif self.status_kind == "warn":
                bar_attr = curses.A_REVERSE | curses.color_pair(4)
        else:
            # Normal state: left = source info, right = key hints
            left_parts: list[str] = []
            if self.source_info.get("log_group"):
                left_parts.append(self.source_info["log_group"])
            if self.source_info.get("profile"):
                left_parts.append(f"profile:{self.source_info['profile']}")
            if self.source_info.get("region"):
                left_parts.append(f"region:{self.source_info['region']}")
            left = source_prefix + (" " + " │ ".join(left_parts) if left_parts else "")

            filter_hint = ""
            if self.filter_rules:
                filter_hint = f" rules:{len(self.filter_rules)}"
            right = (
                f"↑↓:nav  Space:sel  Enter:replay  v:view  f:filter  "
                f"l:log  r:region  h:help  q:quit{filter_hint} "
            )

            gap = term_w - len(left) - len(right)
            if gap >= 1:
                bar_text = left + " " * gap + right
            else:
                bar_text = right.rjust(term_w)

        self._safe_addnstr(
            stdscr,
            status_y,
            0,
            bar_text.ljust(term_w)[:term_w],
            term_w - 1,
            bar_attr,
        )
        if source_prefix:
            self._safe_addnstr(
                stdscr,
                status_y,
                0,
                source_prefix,
                term_w - 1,
                curses.A_REVERSE | curses.color_pair(7),
            )

        stdscr.refresh()

    def _safe_addnstr(self, win, y, x, text, maxlen, attr=0):
        """Write to screen, silently ignore curses errors at edges."""
        try:
            win.addnstr(y, x, text, maxlen, attr)
        except curses.error:
            pass

    # ── search / filter ─────────────────────────────────────────────────────

    _DISPLAY_METHODS = frozenset({"GET", "POST"})

    def _apply_filter(self, preserve_cursor: bool = False):
        cursor_key = None
        if preserve_cursor and self.filtered and 0 <= self.cursor < len(self.filtered):
            r = self.filtered[self.cursor]
            cursor_key = (r.timestamp, r.method, r.uri, r.client_ip)

        pool = list(self.all_requests)
        DEBUG("filter: starting with %d entries", len(pool))

        pool = [r for r in pool if r.method in self._DISPLAY_METHODS]
        DEBUG("filter: after method filter=%d", len(pool))

        if self.auth_filter:
            pool = [
                r
                for r in pool
                if r.has_replayable_auth or r.action in self._BLOCK_ACTIONS
            ]
            DEBUG("filter: after auth_filter=%d", len(pool))

        # Hide blocked/denied entries
        if self.hide_blocks:
            pool = [r for r in pool if r.action not in self._BLOCK_ACTIONS]
            DEBUG("filter: after hide_blocks=%d", len(pool))

        # Unified filter rules -- applied in order (disabled rules are skipped)
        for i, rule in enumerate(self.filter_rules):
            if not rule.enabled:
                continue
            if rule.mode == "exclude":
                pool = [r for r in pool if not rule.matches(r.matchable_text())]
            else:  # include
                pool = [r for r in pool if rule.matches(r.matchable_text())]
            DEBUG("filter: rule %d (%s %s)=%d", i, rule.mode, rule.display, len(pool))

        self.filtered = self._sort_pool(pool)

        if cursor_key and self.filtered:
            for i, r in enumerate(self.filtered):
                if (r.timestamp, r.method, r.uri, r.client_ip) == cursor_key:
                    self.cursor = i
                    self._scroll_to_cursor()
                    return
        self.cursor = min(self.cursor, max(len(self.filtered) - 1, 0))
        self.list_scroll = 0
        self.h_offset = 0
        self.detail_scroll = 0
        self.detail_h_offset = 0

    def _filter_prompt_pattern(self, stdscr, prompt: str, prefill: str = "") -> str:
        """Collect a pattern string on the status bar with live regex validation.
        Supports left/right cursor navigation, Home/End, and in-place editing.
        Returns the confirmed pattern or empty string on cancel."""
        term_h, term_w = stdscr.getmaxyx()
        curses.curs_set(1)
        buf: list[str] = list(prefill)
        pos = len(buf)
        error_msg = ""

        while True:
            text = "".join(buf)
            before = text[:pos]
            after = text[pos:]
            display = prompt + before + "█" + after + error_msg
            self._safe_addnstr(
                stdscr,
                term_h - 1,
                0,
                display.ljust(term_w),
                term_w - 1,
                curses.A_REVERSE | curses.A_BOLD,
            )
            stdscr.refresh()

            ch = stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                break
            elif ch == 27:
                buf = []
                break
            elif ch == curses.KEY_LEFT:
                pos = max(pos - 1, 0)
            elif ch == curses.KEY_RIGHT:
                pos = min(pos + 1, len(buf))
            elif ch == curses.KEY_HOME:
                pos = 0
            elif ch == curses.KEY_END:
                pos = len(buf)
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if pos > 0:
                    buf.pop(pos - 1)
                    pos -= 1
                error_msg = ""
            elif ch == curses.KEY_DC:
                if pos < len(buf):
                    buf.pop(pos)
                error_msg = ""
            elif 32 <= ch <= 126:
                buf.insert(pos, chr(ch))
                pos += 1
                error_msg = ""

            text = "".join(buf)
            if text.startswith("~") and len(text) > 1:
                try:
                    re.compile(text[1:])
                    error_msg = ""
                except re.error as e:
                    error_msg = f"  (invalid regex: {e})"

        curses.curs_set(0)
        return "".join(buf).strip()

    def _show_filter_manager(self, stdscr):
        """Interactive overlay to manage the unified filter rules list."""
        cursor = 0
        scroll = 0

        while True:
            term_h, term_w = stdscr.getmaxyx()
            attr_border = curses.A_BOLD | curses.color_pair(2)
            attr_title = curses.A_BOLD | curses.color_pair(3)
            n_rules = len(self.filter_rules)

            header_lines = [
                "FILTER RULES (applied in order, top to bottom)",
                "",
                "Rules are applied sequentially to the request list.",
                "INCLUDE rules keep only matching entries.",
                "EXCLUDE rules remove matching entries.",
                "Prefix pattern with ~ for regex; plain text is substring match.",
                "",
            ]

            if n_rules:
                header_lines.append("       #  Mode       Type     Pattern")
                header_lines.append(" " + "-" * 54)

            example_lines = [
                "",
                "EXAMPLES (prefix ~ for regex):",
                "  ~\\.(css|js|png|jpg|gif|ico)$   Exclude static assets",
                "  ~POST                           Include POST requests only",
                "  ~(bot|crawl|spider)             Exclude bots/crawlers",
                "  /api/v2                         Include paths with /api/v2",
                "  ~Authorization:.*Bearer         Include bearer-auth requests",
                "  ~^((?!.*\\.js).)*$               Exclude .js files (negative lookahead)",
            ]

            footer = (
                "a:add  e:edit  Space:on/off  i:incl/excl  d:delete  "
                "J:down  K:up  c:clear  Esc:close"
            )

            # Box sizing
            all_text = header_lines + example_lines + [footer]
            content_w = max(len(l) for l in all_text) + 2
            if n_rules:
                for rule in self.filter_rules:
                    rule_line_w = len(f"  99  EXCLUDE   [regex]  {rule.display}") + 4
                    content_w = max(content_w, rule_line_w)

            box_w = min(content_w + 4, term_w - 4)
            inner_w = box_w - 2

            rule_area = min(
                max(n_rules, 1), term_h - len(header_lines) - len(example_lines) - 6
            )
            box_h = (
                len(header_lines) + rule_area + len(example_lines) + 4
            )  # borders + footer
            box_h = min(box_h, term_h - 2)

            start_y = max((term_h - box_h) // 2, 0)
            start_x = max((term_w - box_w) // 2, 0)

            if n_rules:
                cursor = max(0, min(cursor, n_rules - 1))
                scroll = min(scroll, cursor)
                if cursor >= scroll + rule_area:
                    scroll = cursor - rule_area + 1
            else:
                cursor = 0
                scroll = 0

            # Draw
            top = "┌" + "─" * (box_w - 2) + "┐"
            empty = "│" + " " * (box_w - 2) + "│"
            bottom = "└" + "─" * (box_w - 2) + "┘"

            stdscr.erase()
            self._safe_addnstr(
                stdscr, start_y, start_x, top, term_w - start_x - 1, attr_border
            )

            row = start_y + 1
            for line in header_lines:
                if row >= start_y + box_h - 2:
                    break
                padded = f"│ {line:<{inner_w - 2}} │"
                is_heading = line and not line.startswith(" ")
                self._safe_addnstr(
                    stdscr,
                    row,
                    start_x,
                    padded,
                    term_w - start_x - 1,
                    attr_title if is_heading else curses.A_NORMAL,
                )
                row += 1

            # Rule list
            if n_rules:
                for vi in range(rule_area):
                    if row >= start_y + box_h - 2:
                        break
                    idx = scroll + vi
                    if idx < n_rules:
                        rule = self.filter_rules[idx]
                        kind = "regex" if rule.is_regex else "str  "
                        mode = rule.mode.upper()
                        marker = "▶ " if idx == cursor else "  "
                        check = "[x]" if rule.enabled else "[ ]"
                        label = f"{marker}{check} {idx + 1:>2}  {mode:<9}{kind:>7}  {rule.display}"
                        if len(label) > inner_w - 4:
                            label = label[: inner_w - 7] + "…"
                        padded = f"│  {label:<{inner_w - 4}}  │"
                        if idx == cursor:
                            self._safe_addnstr(
                                stdscr,
                                row,
                                start_x,
                                padded,
                                term_w - start_x - 1,
                                curses.A_REVERSE | curses.A_BOLD,
                            )
                        else:
                            attr = curses.A_NORMAL if rule.enabled else curses.A_DIM
                            self._safe_addnstr(
                                stdscr,
                                row,
                                start_x,
                                padded,
                                term_w - start_x - 1,
                                attr,
                            )
                    else:
                        self._safe_addnstr(
                            stdscr,
                            row,
                            start_x,
                            empty,
                            term_w - start_x - 1,
                            attr_border,
                        )
                    row += 1
            else:
                if row < start_y + box_h - 2:
                    msg = "  (no filter rules -- press 'a' to add one)"
                    padded = f"│ {msg:<{inner_w - 2}} │"
                    self._safe_addnstr(
                        stdscr,
                        row,
                        start_x,
                        padded,
                        term_w - start_x - 1,
                        curses.A_DIM,
                    )
                    row += 1

            # Examples
            for line in example_lines:
                if row >= start_y + box_h - 2:
                    break
                padded = f"│ {line:<{inner_w - 2}} │"
                is_heading = line and not line.startswith(" ")
                self._safe_addnstr(
                    stdscr,
                    row,
                    start_x,
                    padded,
                    term_w - start_x - 1,
                    attr_title if is_heading else curses.A_DIM,
                )
                row += 1

            # Fill remaining rows
            while row < start_y + box_h - 2:
                self._safe_addnstr(
                    stdscr,
                    row,
                    start_x,
                    empty,
                    term_w - start_x - 1,
                    attr_border,
                )
                row += 1

            # Footer
            padded_f = f"│ {footer:<{inner_w - 2}} │"
            self._safe_addnstr(
                stdscr,
                row,
                start_x,
                padded_f,
                term_w - start_x - 1,
                attr_border,
            )
            row += 1
            self._safe_addnstr(
                stdscr,
                row,
                start_x,
                bottom,
                term_w - start_x - 1,
                attr_border,
            )

            stdscr.refresh()

            # Input
            stdscr.timeout(-1)
            ch = stdscr.getch()
            stdscr.timeout(100)

            if ch == 27:  # Esc
                break
            elif ch in (curses.KEY_DOWN,):
                if n_rules:
                    cursor = min(cursor + 1, n_rules - 1)
            elif ch in (curses.KEY_UP,):
                if n_rules:
                    cursor = max(cursor - 1, 0)
            elif ch == ord("J") and n_rules and cursor < n_rules - 1:
                self.filter_rules[cursor], self.filter_rules[cursor + 1] = (
                    self.filter_rules[cursor + 1],
                    self.filter_rules[cursor],
                )
                cursor += 1
                self._apply_filter()
            elif ch == ord("K") and n_rules and cursor > 0:
                self.filter_rules[cursor], self.filter_rules[cursor - 1] = (
                    self.filter_rules[cursor - 1],
                    self.filter_rules[cursor],
                )
                cursor -= 1
                self._apply_filter()
            elif ch == ord("a"):
                mode = self._filter_pick_mode(stdscr)
                if mode:
                    stdscr.timeout(100)
                    pattern = self._filter_prompt_pattern(
                        stdscr,
                        f" {mode.capitalize()} pattern (prefix ~ for regex): ",
                    )
                    if pattern:
                        try:
                            rule = FilterRule(pattern, mode=mode)
                            self.filter_rules.append(rule)
                            cursor = len(self.filter_rules) - 1
                            self._apply_filter()
                        except re.error:
                            pass
            elif ch == ord("e") and n_rules:
                rule = self.filter_rules[cursor]
                stdscr.timeout(100)
                pattern = self._filter_prompt_pattern(
                    stdscr,
                    f" Edit {rule.mode} pattern: ",
                    rule.raw,
                )
                if pattern:
                    try:
                        self.filter_rules[cursor] = FilterRule(
                            pattern,
                            mode=rule.mode,
                            enabled=rule.enabled,
                        )
                        self._apply_filter()
                    except re.error:
                        pass
            elif ch == ord(" ") and n_rules:
                self.filter_rules[cursor].enabled = not self.filter_rules[
                    cursor
                ].enabled
                self._apply_filter()
            elif ch == ord("i") and n_rules:
                rule = self.filter_rules[cursor]
                new_mode = "exclude" if rule.mode == "include" else "include"
                self.filter_rules[cursor] = FilterRule(
                    rule.raw, mode=new_mode, enabled=rule.enabled
                )
                self._apply_filter()
            elif ch in (ord("d"), curses.KEY_DC) and n_rules:
                self.filter_rules.pop(cursor)
                if cursor >= len(self.filter_rules) and cursor > 0:
                    cursor -= 1
                self._apply_filter()
            elif ch == ord("c"):
                self.filter_rules.clear()
                cursor = 0
                self._apply_filter()

        n = len(self.filter_rules)
        if n:
            self.status_msg = f"{n} filter rule{'s' if n != 1 else ''} active"
        else:
            self.status_msg = "No filter rules active"
        self.status_time = time.time()

    def _filter_pick_mode(self, stdscr) -> str | None:
        """Quick 1-key prompt: include or exclude?"""
        term_h, term_w = stdscr.getmaxyx()
        prompt = " Rule type: [i]nclude  [e]xclude  Esc:cancel "
        self._safe_addnstr(
            stdscr,
            term_h - 1,
            0,
            prompt.ljust(term_w),
            term_w - 1,
            curses.A_REVERSE | curses.A_BOLD,
        )
        stdscr.refresh()
        stdscr.timeout(-1)
        ch = stdscr.getch()
        stdscr.timeout(100)
        if ch == ord("i"):
            return "include"
        elif ch == ord("e"):
            return "exclude"
        return None

    def _detail_search_prompt(self, stdscr) -> None:
        """Prompt for a regex pattern and search the detail pane content."""
        term_h, term_w = stdscr.getmaxyx()
        curses.curs_set(1)
        buf: list[str] = []
        pos = 0
        error_msg = ""

        while True:
            text = "".join(buf)
            before = text[:pos]
            after = text[pos:]
            display = "/" + before + "█" + after + error_msg
            self._safe_addnstr(
                stdscr,
                term_h - 1,
                0,
                display.ljust(term_w),
                term_w - 1,
                curses.A_REVERSE | curses.A_BOLD,
            )
            stdscr.refresh()

            ch = stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                break
            elif ch == 27:
                curses.curs_set(0)
                return
            elif ch == curses.KEY_LEFT:
                pos = max(pos - 1, 0)
            elif ch == curses.KEY_RIGHT:
                pos = min(pos + 1, len(buf))
            elif ch == curses.KEY_HOME:
                pos = 0
            elif ch == curses.KEY_END:
                pos = len(buf)
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if pos > 0:
                    buf.pop(pos - 1)
                    pos -= 1
                error_msg = ""
            elif ch == curses.KEY_DC:
                if pos < len(buf):
                    buf.pop(pos)
                error_msg = ""
            elif 32 <= ch <= 126:
                buf.insert(pos, chr(ch))
                pos += 1
                error_msg = ""
                text = "".join(buf)
                try:
                    re.compile(text, re.IGNORECASE)
                except re.error as e:
                    error_msg = f"  (invalid regex: {e})"

        curses.curs_set(0)
        pattern = "".join(buf).strip()

        if not pattern:
            self._search_pattern = ""
            self._search_re = None
            self._search_matches = []
            self._search_match_idx = -1
            self.status_msg = "Search cleared"
            self.status_time = time.time()
            return

        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            self.status_msg = f"Invalid regex: {e}"
            self.status_kind = "error"
            self.status_time = time.time()
            return

        self._search_pattern = pattern
        self._search_re = compiled
        self._rebuild_search_matches()

        if self._search_matches:
            self._search_match_idx = 0
            self._scroll_to_search_match()
            self.status_msg = f"/{pattern}  [{self._search_match_idx + 1}/{len(self._search_matches)}]"
        else:
            self._search_match_idx = -1
            self.status_msg = f"/{pattern}  [no matches]"
        self.status_time = time.time()

    def _rebuild_search_matches(self) -> None:
        """Scan detail_lines for all matches of the current search regex."""
        self._search_matches = []
        if self._search_re is None:
            return
        for line_idx, line in enumerate(self.detail_lines):
            for m in self._search_re.finditer(line):
                self._search_matches.append((line_idx, m.start(), m.end()))

    def _scroll_to_search_match(self) -> None:
        """Center the detail pane on the current search match."""
        if not self._search_matches or self._search_match_idx < 0:
            return
        line_idx, _, _ = self._search_matches[self._search_match_idx]
        # We don't know detail_h here, so estimate a generous centering.
        # _draw will clamp, but aiming for the middle works well.
        self.detail_scroll = max(0, line_idx - 5)

    def _search_next(self, reverse: bool = False) -> None:
        """Jump to the next (or previous) search match."""
        if not self._search_matches:
            if self._search_re is not None:
                self.status_msg = f"/{self._search_pattern}  [no matches]"
                self.status_time = time.time()
            return
        if reverse:
            self._search_match_idx = (self._search_match_idx - 1) % len(
                self._search_matches
            )
        else:
            self._search_match_idx = (self._search_match_idx + 1) % len(
                self._search_matches
            )
        self._scroll_to_search_match()
        self.status_msg = f"/{self._search_pattern}  [{self._search_match_idx + 1}/{len(self._search_matches)}]"
        self.status_time = time.time()

    def _show_help(self, stdscr):
        """Draw a centered help overlay showing all keyboard shortcuts."""
        help_lines = [
            "KEYBOARD SHORTCUTS",
            "",
            "AWS",
            "  l               Switch log group (overlay selector)",
            "  r               Switch AWS region (overlay selector)",
            "  F5              Refresh logs for current log group",
            "  F2              Toggle auto-refresh",
            "  F3              Set auto-refresh interval (seconds)",
            "  c               Sample auth counts (current region)",
            "  C               Sample auth counts (all regions, concurrent)",
            "",
            "View",
            "  v               Cycle view (detail -> json -> headers)",
            "  S               Cycle source view (merged -> cwl -> s3 -> waf)",
            "  m               Cycle replay mode (firefox -> chrome -> curl)",
            "",
            "Search & Filter",
            "  t               Toggle auth filter (JWTs, cookies, API keys, tokens)",
            "  b               Toggle hide BLOCK/DENY entries",
            "  w               Set window start time (relative e.g. 4h, or ISO-8601)",
            "  W               Set window end time (relative e.g. 1h, or ISO-8601)",
            "  o               Cycle list sort field (time -> method -> url)",
            "  O               Toggle sort direction (ascending / descending)",
            "  f               Open filter rules manager (add/edit/delete/reorder)",
            "  F               Clear all filters, rules & selection",
            "",
            "Selection & Replay",
            "  Space           Toggle selection on current entry",
            "  a               Select all / deselect all visible",
            "  Enter           Replay selected (or cursor if none)",
            "  e               Edit request (method, URL, headers, body)",
            "",
            "Navigation",
            "  Up/Down         Move cursor up / down",
            "  PgUp / PgDn     Jump 10 entries",
            "  Home / End      First / last entry",
            "  [ / ]           Scroll detail pane up / down",
            "  { / }           Scroll detail pane to top / bottom",
            "  ; / '           Scroll detail pane left / right",
            '  : / "           Scroll detail pane to left / right edge',
            "  /               Search detail pane (regex)",
            "  n               Jump to next search match",
            "  N               Jump to previous search match",
            "  Tab             Jump to next section in detail pane",
            "  Shift+Tab       Jump to previous section",
            "",
            "Other",
            "  h / ?           This help window",
            "  q               Quit",
            "",
            "Filter patterns: plain text = substring match (case-insensitive)",
            "                 ~pattern   = regex (IGNORECASE | MULTILINE)",
            "                 Rules applied in order, top to bottom.",
        ]

        content_w = max(len(l) for l in help_lines)
        box_w = content_w + 4  # 2 border + 1 padding each side

        term_h, term_w = stdscr.getmaxyx()
        box_w = min(box_w, term_w - 2)
        box_h = min(len(help_lines) + 2, term_h - 2)
        visible = box_h - 2  # rows available for content
        scrollable = len(help_lines) > visible
        max_scroll = max(0, len(help_lines) - visible)

        start_y = max((term_h - box_h) // 2, 0)
        start_x = max((term_w - box_w) // 2, 0)
        inner_w = box_w - 2

        attr_border = curses.A_BOLD | curses.color_pair(2)
        attr_title = curses.A_BOLD | curses.color_pair(3)
        attr_text = curses.A_NORMAL

        help_scroll = 0
        stdscr.timeout(-1)

        while True:
            # Top border
            top = "┌" + "─" * (box_w - 2) + "┐"
            self._safe_addnstr(
                stdscr, start_y, start_x, top, term_w - start_x - 1, attr_border
            )

            # Content rows
            for i in range(visible):
                y = start_y + 1 + i
                src = i + help_scroll
                if src < len(help_lines):
                    line = help_lines[src]
                    padded = f"│ {line:<{inner_w - 2}} │"
                    if src == 0 or line and not line.startswith(" "):
                        self._safe_addnstr(
                            stdscr,
                            y,
                            start_x,
                            padded,
                            term_w - start_x - 1,
                            attr_title,
                        )
                    else:
                        self._safe_addnstr(
                            stdscr,
                            y,
                            start_x,
                            padded,
                            term_w - start_x - 1,
                            attr_text,
                        )
                else:
                    empty = "│" + " " * (box_w - 2) + "│"
                    self._safe_addnstr(
                        stdscr, y, start_x, empty, term_w - start_x - 1, attr_border
                    )

            # Bottom border
            bottom = "└" + "─" * (box_w - 2) + "┘"
            self._safe_addnstr(
                stdscr,
                start_y + box_h - 1,
                start_x,
                bottom,
                term_w - start_x - 1,
                attr_border,
            )

            # Footer hint
            if scrollable:
                hint = " ↑↓/PgUp/PgDn:scroll  Esc/q:close "
            else:
                hint = " Press any key to close "
            hint_y = start_y + box_h - 1
            hint_x = start_x + max(0, (box_w - len(hint)) // 2)
            self._safe_addnstr(
                stdscr, hint_y, hint_x, hint, term_w - hint_x - 1, attr_border
            )

            stdscr.refresh()

            ch = stdscr.getch()
            if not scrollable:
                break
            if ch == curses.KEY_DOWN:
                help_scroll = min(help_scroll + 1, max_scroll)
            elif ch == curses.KEY_UP:
                help_scroll = max(help_scroll - 1, 0)
            elif ch == curses.KEY_NPAGE:
                help_scroll = min(help_scroll + visible, max_scroll)
            elif ch == curses.KEY_PPAGE:
                help_scroll = max(help_scroll - visible, 0)
            elif ch == curses.KEY_HOME:
                help_scroll = 0
            elif ch == curses.KEY_END:
                help_scroll = max_scroll
            else:
                break

        stdscr.timeout(100)

    def _overlay_select(
        self, stdscr, title: str, items: list[str], current: str = "", footer: str = ""
    ) -> str | None:
        """Generic scrollable overlay selector. Returns chosen item or None on Esc."""
        if not items:
            return None

        term_h, term_w = stdscr.getmaxyx()
        attr_border = curses.A_BOLD | curses.color_pair(2)
        attr_title = curses.A_BOLD | curses.color_pair(3)

        selector_cursor = 0
        # Pre-select current if it exists
        if current in items:
            selector_cursor = items.index(current)
        scroll = 0

        footer = footer or "↑↓:navigate  Enter:select  Esc:cancel"

        while True:
            # Box sizing
            content_w = max(
                len(title) + 2, len(footer) + 2, max((len(it) + 6) for it in items)
            )
            box_w = min(content_w + 4, term_w - 4)
            inner_w = box_w - 2
            visible_items = min(len(items), term_h - 8)
            box_h = (
                visible_items + 5
            )  # title + blank + items + blank + footer + borders

            start_y = max((term_h - box_h) // 2, 0)
            start_x = max((term_w - box_w) // 2, 0)

            # Scroll follows cursor
            scroll = min(scroll, selector_cursor)
            if selector_cursor >= scroll + visible_items:
                scroll = selector_cursor - visible_items + 1

            # Draw box
            top = "┌" + "─" * (box_w - 2) + "┐"
            empty = "│" + " " * (box_w - 2) + "│"
            bottom = "└" + "─" * (box_w - 2) + "┘"

            self._safe_addnstr(
                stdscr, start_y, start_x, top, term_w - start_x - 1, attr_border
            )

            row = start_y + 1
            # Title
            padded = f"│ {title:<{inner_w - 2}} │"
            self._safe_addnstr(
                stdscr, row, start_x, padded, term_w - start_x - 1, attr_title
            )
            row += 1
            self._safe_addnstr(
                stdscr, row, start_x, empty, term_w - start_x - 1, attr_border
            )
            row += 1

            # Item list
            for vi in range(visible_items):
                idx = scroll + vi
                if row >= start_y + box_h - 2:
                    break
                if idx < len(items):
                    item = items[idx]
                    mark = "→ " if item == current else "  "
                    label = f"{mark}{item}"
                    if len(label) > inner_w - 4:
                        label = label[: inner_w - 7] + "…"
                    padded_l = f"│  {label:<{inner_w - 4}}  │"
                    if idx == selector_cursor:
                        self._safe_addnstr(
                            stdscr,
                            row,
                            start_x,
                            padded_l,
                            term_w - start_x - 1,
                            curses.A_REVERSE | curses.A_BOLD,
                        )
                    else:
                        self._safe_addnstr(
                            stdscr,
                            row,
                            start_x,
                            padded_l,
                            term_w - start_x - 1,
                            curses.A_NORMAL,
                        )
                else:
                    self._safe_addnstr(
                        stdscr, row, start_x, empty, term_w - start_x - 1, attr_border
                    )
                row += 1

            # Footer
            self._safe_addnstr(
                stdscr, row, start_x, empty, term_w - start_x - 1, attr_border
            )
            row += 1
            padded_f = f"│ {footer:<{inner_w - 2}} │"
            self._safe_addnstr(
                stdscr, row, start_x, padded_f, term_w - start_x - 1, attr_border
            )
            row += 1
            self._safe_addnstr(
                stdscr, row, start_x, bottom, term_w - start_x - 1, attr_border
            )

            stdscr.refresh()

            stdscr.timeout(-1)
            ch = stdscr.getch()
            stdscr.timeout(100)

            if ch == 27:
                return None
            elif ch in (curses.KEY_DOWN, ord("j")):
                selector_cursor = min(selector_cursor + 1, len(items) - 1)
            elif ch in (curses.KEY_UP, ord("k")):
                selector_cursor = max(selector_cursor - 1, 0)
            elif ch == curses.KEY_NPAGE:
                selector_cursor = min(selector_cursor + 10, len(items) - 1)
            elif ch == curses.KEY_PPAGE:
                selector_cursor = max(selector_cursor - 10, 0)
            elif ch in (curses.KEY_ENTER, 10, 13):
                return items[selector_cursor]

    def _build_log_group_display(
        self, groups: list[str]
    ) -> tuple[list[str], dict[str, str]]:
        """Build display labels for log groups with cached auth counts.

        Reads from the ``selector_counts`` table populated by auth-count
        sample runs and log-group loads.
        """
        counts: dict[str, tuple[int, int]] = {}
        if self.db is not None:
            try:
                counts = storage.get_selector_counts(
                    self.db, self.log_location or "cwl"
                )
            except Exception:
                counts = {}

        decorated: list[tuple[int | None, str, str]] = []
        for g in groups:
            entry = counts.get(g)
            if entry is not None:
                auth, total = entry
                label = f"{g} ({auth:,}/{total:,})"
            else:
                auth = None
                label = g
            decorated.append((auth, g, label))

        decorated.sort(key=lambda t: (-t[0] if t[0] is not None else 1, t[1]))

        display_labels = [t[2] for t in decorated]
        display_to_raw = {t[2]: t[1] for t in decorated}
        return display_labels, display_to_raw

    def _needs_selector_counts(self) -> bool:
        """True when selector_counts is empty but source records exist."""
        if self.db is None:
            return False
        source = self.log_location or "cwl"
        try:
            if storage.get_selector_counts(self.db, source):
                return False
            return bool(storage.list_source_log_groups(self.db, source))
        except Exception:
            return False

    def _ensure_selector_counts(self) -> None:
        """Populate selector_counts from existing records if not yet cached."""
        if self.db is None:
            return
        source = self.log_location or "cwl"
        try:
            if storage.get_selector_counts(self.db, source):
                return
            groups = storage.list_source_log_groups(self.db, source)
            if not groups:
                return
            start_time = self.aws_context.get("start_time") or (
                datetime.now(UTC) - timedelta(minutes=60)
            )
            end_time = self.aws_context.get("end_time") or datetime.now(UTC)
            storage.refresh_selector_counts(
                self.db,
                source,
                int(start_time.timestamp() * 1000),
                int(end_time.timestamp() * 1000),
                self.aws_context.get("action_filter"),
            )
        except Exception:
            pass

    def _db_log_groups(self) -> list[str]:
        """Log groups known to the local database, or empty if unavailable."""
        if self.db is None:
            return []
        try:
            return storage.list_source_log_groups(self.db, self.log_location or "cwl")
        except Exception:
            return []

    def _show_log_selector(self, stdscr):
        """Show an overlay to select a log source, then reload.

        When log_location is "s3", discovers S3 buckets matching the aws-waf-logs-*
        prefix.  Otherwise discovers CloudWatch log groups.
        """
        term_h, term_w = stdscr.getmaxyx()
        if self.log_location == "s3":
            loading_msg = "  Fetching S3 buckets…  "
        else:
            loading_msg = "  Fetching log groups…  "
        self._safe_addnstr(
            stdscr,
            term_h // 2,
            2,
            loading_msg,
            term_w - 4,
            curses.A_REVERSE | curses.A_BOLD,
        )
        stdscr.refresh()

        if self.db_only:
            groups = self._db_log_groups()
        else:
            try:
                if self.log_location == "s3":
                    groups = s3_mod.discover_waf_buckets(
                        profile=self.aws_context.get("profile"),
                        region=self.aws_context.get("region"),
                    )
                else:
                    groups = fetch_waf_log_groups(
                        profile=self.aws_context.get("profile"),
                        region=self.aws_context.get("region"),
                    )
            except Exception as exc:
                groups = self._db_log_groups()
                if not groups:
                    kind = "S3 buckets" if self.log_location == "s3" else "log groups"
                    self.status_msg = f"✘ Failed to list {kind}: {exc}"
                    self.status_time = time.time()
                    return

        if not groups:
            groups = self._db_log_groups()
            if not groups:
                kind = "S3 buckets" if self.log_location == "s3" else "log groups"
                if self.db_only:
                    self.status_msg = f"No cached {kind} found in the database"
                elif self.log_location == "s3":
                    self.status_msg = "No S3 buckets matching aws-waf-logs-* found"
                else:
                    self.status_msg = "No matching log groups found in this region"
                self.status_time = time.time()
                return

        if self.log_location == "s3":
            title = "SELECT S3 BUCKET"
            current_raw = self.source_info.get("log_group", "")
            chosen = self._overlay_select(stdscr, title, groups, current_raw)
            if chosen:
                self._reload_log_group(chosen)
                self._splash_while_loading(stdscr, "Loading log records...")
        else:
            display_labels, display_to_raw = self._build_log_group_display(groups)

            current_raw = self.source_info.get("log_group", "")
            current_display = ""
            for label, raw in display_to_raw.items():
                if raw == current_raw:
                    current_display = label
                    break

            title = "SELECT LOG GROUP"
            chosen_display = self._overlay_select(
                stdscr,
                title,
                display_labels,
                current_display,
            )
            if chosen_display:
                chosen_raw = display_to_raw.get(chosen_display, chosen_display)
                self._reload_log_group(chosen_raw)
                self._splash_while_loading(stdscr, "Loading log records...")

    def _splash_while_loading(self, stdscr, label: str = "Loading...") -> None:
        """Show the splash screen while the background load thread runs."""
        from waf_fu.banner import _draw_splash

        def _wait():
            if self._load_thread is not None:
                self._load_thread.join()
            self._apply_pending_load()

        _draw_splash(stdscr, on_pause=_wait, pause_label=label)

    def _show_region_selector(self, stdscr):
        """Show an overlay to select an AWS region, then clear and show log group selector."""
        current = self.aws_context.get("region") or self.source_info.get("region") or ""
        chosen = self._overlay_select(stdscr, "SELECT AWS REGION", AWS_REGIONS, current)
        if chosen and chosen != current:
            self.aws_context["region"] = chosen
            self.source_info["region"] = chosen

            # Clear current data — new region means different log groups
            self.all_requests = []
            self.filtered = []
            self.selected.clear()
            self.cursor = 0
            self.detail_scroll = 0
            self.detail_h_offset = 0
            self.source_info["log_group"] = ""
            self.detail_lines = [
                "",
                f"  Region changed to {chosen} — select a log group",
            ]

            self.status_msg = f"Region set to {chosen}"
            self.status_time = time.time()
            self._draw(stdscr)

            # Immediately show log group selector for the new region
            self._show_log_selector(stdscr)

    def _is_loading(self) -> bool:
        return self._load_thread is not None and self._load_thread.is_alive()

    def _get_load_status(self) -> str:
        with self._load_lock:
            return self._load_status

    def _set_load_status(self, msg: str) -> None:
        with self._load_lock:
            self._load_status = msg

    def _set_pending_load(self, result: dict | None) -> None:
        with self._load_lock:
            self._pending_load = result

    def _apply_pending_load(self) -> bool:
        with self._load_lock:
            result = self._pending_load
            self._pending_load = None
        if result is None:
            return False

        if "error" in result:
            self.status_msg = result["error"]
            self.status_kind = "error"
            self.status_time = time.time()
            self._load_status = ""
            return True

        requests = result["requests"]
        log_group = result["log_group"]
        refresh = result["refresh"]

        if refresh and self.selected:
            old_sel_keys = set()
            for r in self.all_requests:
                if id(r) in self.selected:
                    old_sel_keys.add((r.timestamp, r.method, r.uri, r.client_ip))
            self.selected.clear()
            for r in requests:
                if (r.timestamp, r.method, r.uri, r.client_ip) in old_sel_keys:
                    self.selected.add(id(r))

        self.all_requests = requests
        if not refresh:
            start_time = self.aws_context.get("start_time")
            end_time = self.aws_context.get("end_time")
            if start_time and end_time:
                start_ms = int(start_time.timestamp() * 1000)
                end_ms = int(end_time.timestamp() * 1000)
                self.all_requests = [
                    r for r in self.all_requests if start_ms <= r.timestamp <= end_ms
                ]
        self.source_info["log_group"] = log_group
        if not refresh:
            self.selected.clear()
        self._reset_source_view()
        if refresh:
            self._apply_filter(preserve_cursor=True)
        else:
            self.cursor = 0
            self.detail_scroll = 0
            self.detail_h_offset = 0
            self._apply_filter()

        now = time.time()
        verb = "Refreshed" if refresh else "Loaded"
        self.status_msg = f"✔ {verb} {len(self.all_requests)} entries from {log_group}"
        self.status_time = now
        self._last_refresh_time = now
        self._load_status = ""

        DEBUG(
            "pending_load applied: %d entries, %d after filter",
            len(requests),
            len(self.filtered),
        )
        return True

    def _show_request_editor(self, stdscr):
        """Overlay editor to modify request details before replay."""
        if not self.filtered:
            return
        req = self.filtered[self.cursor]

        # Build editable field list: (label, key, value, field_type)
        # field_type: 'fixed_key' (edit value only), 'header' (deletable), 'body'
        def _rebuild_fields():
            fields = [
                ("Method", "method", req.method, "fixed_key"),
                ("Scheme", "scheme", req.scheme, "fixed_key"),
                ("Host", "host", req.host, "fixed_key"),
                ("URI", "uri", req.uri, "fixed_key"),
                ("Query", "args", req.args, "fixed_key"),
            ]
            for hname, hval in req.headers.items():
                fields.append((f"H: {hname}", hname, hval, "header"))
            fields.append(("Body", "body", req.body or "(empty)", "body"))
            return fields

        fields = _rebuild_fields()
        cursor = 0
        scroll = 0

        term_h, term_w = stdscr.getmaxyx()
        attr_border = curses.A_BOLD | curses.color_pair(2)
        attr_title = curses.A_BOLD | curses.color_pair(3)

        title = " EDIT REQUEST "
        footer = "↑↓:nav  Enter:edit value  d:delete header  n:new header  Esc:done"

        while True:
            box_w = min(term_w - 4, 100)
            inner_w = box_w - 2
            visible = min(len(fields), term_h - 8)
            box_h = visible + 5
            start_y = max((term_h - box_h) // 2, 0)
            start_x = max((term_w - box_w) // 2, 0)

            scroll = min(scroll, cursor)
            if cursor >= scroll + visible:
                scroll = cursor - visible + 1

            top = "┌" + "─" * (box_w - 2) + "┐"
            empty = "│" + " " * (box_w - 2) + "│"
            bottom = "└" + "─" * (box_w - 2) + "┘"

            self._safe_addnstr(
                stdscr, start_y, start_x, top, term_w - start_x - 1, attr_border
            )
            row = start_y + 1
            padded = f"│ {title:<{inner_w - 2}} │"
            self._safe_addnstr(
                stdscr, row, start_x, padded, term_w - start_x - 1, attr_title
            )
            row += 1
            self._safe_addnstr(
                stdscr, row, start_x, empty, term_w - start_x - 1, attr_border
            )
            row += 1

            for vi in range(visible):
                idx = scroll + vi
                if row >= start_y + box_h - 2:
                    break
                if idx < len(fields):
                    label, key, value, ftype = fields[idx]
                    # Truncate value for display
                    label_w = 16
                    val_w = inner_w - label_w - 6
                    disp_val = (
                        value if len(value) <= val_w else value[: val_w - 1] + "…"
                    )
                    line_text = f"│ {label:<{label_w}} {disp_val:<{val_w}}  │"
                    if idx == cursor:
                        self._safe_addnstr(
                            stdscr,
                            row,
                            start_x,
                            line_text,
                            term_w - start_x - 1,
                            curses.A_REVERSE | curses.A_BOLD,
                        )
                    else:
                        self._safe_addnstr(
                            stdscr,
                            row,
                            start_x,
                            line_text,
                            term_w - start_x - 1,
                            curses.A_NORMAL,
                        )
                else:
                    self._safe_addnstr(
                        stdscr, row, start_x, empty, term_w - start_x - 1, attr_border
                    )
                row += 1

            self._safe_addnstr(
                stdscr, row, start_x, empty, term_w - start_x - 1, attr_border
            )
            row += 1
            foot_trunc = footer[: inner_w - 2]
            padded_f = f"│ {foot_trunc:<{inner_w - 2}} │"
            self._safe_addnstr(
                stdscr, row, start_x, padded_f, term_w - start_x - 1, attr_border
            )
            row += 1
            self._safe_addnstr(
                stdscr, row, start_x, bottom, term_w - start_x - 1, attr_border
            )
            stdscr.refresh()

            stdscr.timeout(-1)
            ch = stdscr.getch()
            stdscr.timeout(100)

            if ch == 27:  # Esc — done editing
                break
            elif ch in (curses.KEY_DOWN, ord("j")):
                cursor = min(cursor + 1, len(fields) - 1)
            elif ch in (curses.KEY_UP, ord("k")):
                cursor = max(cursor - 1, 0)
            elif ch in (curses.KEY_ENTER, 10, 13):
                # Inline edit the value of the selected field
                label, key, old_val, ftype = fields[cursor]
                if ftype == "body" and old_val == "(empty)":
                    old_val = ""
                new_val = self._inline_edit(stdscr, f" Edit {label}: ", old_val)
                if new_val is not None:
                    self._apply_field_edit(req, key, new_val, ftype)
                    fields = _rebuild_fields()
                    req.edited = True
                    # Invalidate matchable cache
                    if hasattr(req, "_matchable_cache"):
                        del req._matchable_cache
            elif ch == ord("d"):
                # Delete header
                label, key, _val, ftype = fields[cursor]
                if ftype == "header" and key in req.headers:
                    del req.headers[key]
                    fields = _rebuild_fields()
                    cursor = min(cursor, len(fields) - 1)
                    req.edited = True
                    if hasattr(req, "_matchable_cache"):
                        del req._matchable_cache
            elif ch == ord("n"):
                # Add new header
                hname = self._inline_edit(stdscr, " Header name: ", "")
                if hname:
                    hval = self._inline_edit(stdscr, f" {hname}: ", "")
                    if hval is not None:
                        req.headers[hname] = hval
                        fields = _rebuild_fields()
                        req.edited = True
                        if hasattr(req, "_matchable_cache"):
                            del req._matchable_cache

    def _inline_edit(self, stdscr, prompt: str, initial: str) -> str | None:
        """Show an inline edit prompt at the bottom of screen. Returns new value or None."""
        term_h, term_w = stdscr.getmaxyx()
        curses.curs_set(1)
        buf = list(initial)
        # Horizontal scroll offset for long values
        h_scroll = max(0, len(buf) - (term_w - len(prompt) - 5))

        while True:
            visible_w = term_w - len(prompt) - 3
            display_start = h_scroll
            display_text = "".join(buf[display_start : display_start + visible_w])
            line = prompt + display_text + "█"
            self._safe_addnstr(
                stdscr,
                term_h - 1,
                0,
                line.ljust(term_w),
                term_w - 1,
                curses.A_REVERSE | curses.A_BOLD,
            )
            stdscr.refresh()

            ch = stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                curses.curs_set(0)
                return "".join(buf)
            elif ch == 27:
                curses.curs_set(0)
                return None
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if buf:
                    buf.pop()
                    h_scroll = max(0, len(buf) - visible_w)
            elif 32 <= ch <= 126:
                buf.append(chr(ch))
                if len(buf) - h_scroll > visible_w:
                    h_scroll = len(buf) - visible_w

    def _sort_pool(
        self, pool: list[ReconstructedRequest]
    ) -> list[ReconstructedRequest]:
        """Return a new list of `pool` ordered by `self.sort_field`/`sort_dir`."""
        if self.sort_field == "method":

            def key(r: ReconstructedRequest):
                return (r.method, r.timestamp)
        elif self.sort_field == "url":

            def key(r: ReconstructedRequest):
                return (r.uri, r.timestamp)
        else:

            def key(r: ReconstructedRequest):
                return r.timestamp

        return sorted(pool, key=key, reverse=self.sort_dir == "desc")

    def _set_sort(self, field: str, direction: str) -> None:
        self.sort_field = field
        self.sort_dir = direction
        self._save_preference("sort_field", field)
        self._save_preference("sort_dir", direction)
        saved_cursor = self.cursor
        self._apply_filter()
        self.cursor = min(saved_cursor, max(len(self.filtered) - 1, 0))

    def _set_mode(self, mode: str) -> None:
        DEBUG("set_mode: %s -> %s", self.mode, mode)
        self.mode = mode
        self._save_preference("replay_mode", mode)

    def _set_auth_filter(self, enabled: bool) -> None:
        self.auth_filter = enabled
        self._save_preference("auth_filter", "on" if enabled else "off")

    def _save_preference(self, key: str, value: str) -> None:
        if self.db is None:
            return
        try:
            storage.set_preference(self.db, key, value)
        except Exception:
            pass

    def _apply_field_edit(
        self, req: ReconstructedRequest, key: str, value: str, ftype: str
    ):
        """Apply an edited value back to the request object."""
        if key == "method":
            req.method = value.upper()
        elif key == "scheme":
            req.scheme = value.lower()
        elif key == "host":
            req.host = value
            # Also update the Host header if it exists
            for hname in list(req.headers):
                if hname.lower() == "host":
                    req.headers[hname] = value
        elif key == "uri":
            req.uri = value
        elif key == "args":
            req.args = value
            req.args_redacted = False
        elif key == "body":
            req.body = value
        elif ftype == "header":
            # key is the header name
            req.headers[key] = value
            # Update shortcut fields
            low = key.lower()
            if low == "cookie":
                req.cookies = value
            elif low == "user-agent":
                req.user_agent = value
            elif low == "authorization":
                req.authorization = value
                req.jwt_payload = decode_jwt_payload(value)
                req.jwt_exp = jwt_expiry(value)
                req.jwt_valid = jwt_is_valid(value)

    def _edit_time_window(self, stdscr, which: str) -> None:
        """Prompt for a new start/end time and, if valid, retarget the
        CloudWatch window and reload the current log group."""
        current = self.aws_context.get(f"{which}_time")
        prefill = current.isoformat() if current else ""
        result = self._inline_edit(
            stdscr, f" {which.capitalize()} time (4h, 2d, or ISO-8601): ", prefill
        )
        if result is None or not result.strip():
            return

        reference = (
            self.aws_context.get("end_time") or datetime.now(UTC)
            if which == "start"
            else datetime.now(UTC)
        )
        try:
            parsed = parse_time_arg(result.strip(), reference=reference)
        except ValueError as exc:
            self.status_msg = f"Invalid time: {exc}"
            self.status_kind = "error"
            self.status_time = time.time()
            return

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)

        prospective_start = (
            parsed if which == "start" else self.aws_context.get("start_time")
        )
        prospective_end = parsed if which == "end" else self.aws_context.get("end_time")
        if (
            prospective_start is not None
            and prospective_end is not None
            and prospective_start >= prospective_end
        ):
            self.status_msg = "Invalid time window: start must be before end"
            self.status_kind = "error"
            self.status_time = time.time()
            return

        self.aws_context[f"{which}_time"] = parsed
        log_group = self.source_info.get("log_group")
        if log_group:
            self.status_msg = f"Window {which} set to {parsed.isoformat()} -- reloading"
            self.status_time = time.time()
            self._reload_log_group(log_group, refresh=False)
        else:
            self.status_msg = f"Window {which} set to {parsed.isoformat()} -- press l to choose a log group"
            self.status_time = time.time()

    def _refresh_logs(self):
        """Re-fetch logs for the currently selected log group."""
        log_group = self.source_info.get("log_group", "")
        if not log_group:
            self.status_msg = "No log group selected -- press l to choose one"
            self.status_time = time.time()
            return
        self._reload_log_group(log_group, refresh=True)

    def _reload_log_group(self, log_group: str, refresh: bool = False):
        """Kick off a background fetch for a log group (non-blocking)."""
        if self._is_loading():
            self.status_msg = "Already loading -- please wait"
            self.status_time = time.time()
            return
        DEBUG("reload: log_group=%s refresh=%s", _redact_meta(log_group), refresh)
        verb = "Refreshing" if refresh else "Loading"
        self._set_load_status(f"{verb} {log_group}…")

        start_time = self.aws_context.get(
            "start_time", datetime.now(UTC) - timedelta(minutes=60)
        )
        if refresh:
            end_time = datetime.now(UTC)
            if self.all_requests:
                last_ts = datetime.fromtimestamp(
                    self.all_requests[-1].timestamp / 1000, tz=UTC
                )
                start_time = min(start_time, last_ts)
        else:
            end_time = self.aws_context.get("end_time", datetime.now(UTC))

        ctx = {
            "log_group": log_group,
            "refresh": refresh,
            "start_ms": int(start_time.timestamp() * 1000),
            "end_ms": int(end_time.timestamp() * 1000),
            "action_filter": self.aws_context.get("action_filter"),
            "profile": self.aws_context.get("profile"),
            "region": self.aws_context.get("region"),
            "limit": self.aws_context.get("limit", 0),
        }

        source = self.log_location or "cwl"
        if source == "s3":
            bucket, _, acl_name = log_group.partition(":")
            fetch_fn = _s3_fetch_adapter(bucket, acl_name or None)
        else:
            fetch_fn = _fetch_from_cloudwatch_ms

        def _run():
            try:
                if self.db_only and self.db is not None:
                    # --db-only: read the cache directly. Never calls fetch_fn,
                    # so no AWS request is made and no fetch-coverage row is
                    # written for the (likely huge) requested window.
                    if source == "cwl":
                        records = storage.load_merged_records(
                            self.db,
                            ctx["log_group"],
                            ctx["start_ms"],
                            ctx["end_ms"],
                            ctx["action_filter"],
                        )
                        if not records:
                            records = storage.load_source_records(
                                self.db,
                                "cwl",
                                ctx["log_group"],
                                ctx["start_ms"],
                                ctx["end_ms"],
                                ctx["action_filter"],
                            )
                    else:
                        records = storage.load_source_records(
                            self.db,
                            source,
                            ctx["log_group"],
                            ctx["start_ms"],
                            ctx["end_ms"],
                            ctx["action_filter"],
                        )
                elif self.db is not None:
                    records = storage.load_source_with_cache(
                        self.db,
                        source,
                        ctx["log_group"],
                        start_ms=ctx["start_ms"],
                        end_ms=ctx["end_ms"],
                        action_filter=ctx["action_filter"],
                        profile=ctx["profile"],
                        region=ctx["region"],
                        fetch_fn=fetch_fn,
                        refresh=ctx["refresh"],
                    )
                else:
                    records = fetch_logs_from_cloudwatch(
                        log_group=ctx["log_group"],
                        start_time=datetime.fromtimestamp(
                            ctx["start_ms"] / 1000, tz=UTC
                        ),
                        end_time=datetime.fromtimestamp(ctx["end_ms"] / 1000, tz=UTC),
                        profile=ctx["profile"],
                        region=ctx["region"],
                        action_filter=ctx["action_filter"],
                    )
            except Exception as exc:
                DEBUG("reload: FAILED: %s", exc)
                self._set_pending_load({"error": f"✘ Failed to load: {exc}"})
                return

            if not records:
                DEBUG("reload: no records in %s", ctx["log_group"])
                self._set_pending_load(
                    {
                        "requests": [],
                        "log_group": ctx["log_group"],
                        "refresh": ctx["refresh"],
                    }
                )
                return

            DEBUG("reload: %d raw records, parsing", len(records))
            self._set_load_status(f"Parsing {len(records)} records…")
            requests = parse_all(records)
            if ctx["limit"] > 0:
                requests = requests[: ctx["limit"]]

            if self.db is not None:
                storage.record_auth_counts(
                    self.db, ctx["profile"], ctx["region"], ctx["log_group"], requests
                )
                storage.refresh_selector_counts(
                    self.db,
                    source,
                    ctx["start_ms"],
                    ctx["end_ms"],
                    ctx["action_filter"],
                    log_group=ctx["log_group"],
                )

            self._set_pending_load(
                {
                    "requests": requests,
                    "log_group": ctx["log_group"],
                    "refresh": ctx["refresh"],
                }
            )

        self._load_thread = threading.Thread(target=_run, daemon=True)
        self._load_thread.start()

    def _run_auth_count_sample_bg(self, all_regions: bool = False) -> None:
        """Kick off a background auth-count sample."""
        if self._is_loading():
            self.status_msg = "Already loading -- please wait"
            self.status_time = time.time()
            return
        if self.db_only:
            self.status_msg = (
                "Auth count sample requires AWS access (incompatible with --db-only)"
            )
            self.status_kind = "error"
            self.status_time = time.time()
            return
        if self.db is None:
            self.status_msg = "No database connection"
            self.status_kind = "error"
            self.status_time = time.time()
            return

        label = "all regions" if all_regions else "current region"
        self._set_load_status(f"Starting auth count sample ({label})...")

        def _run():
            try:
                self._auth_count_sample_worker(all_regions=all_regions)
            except Exception as exc:
                DEBUG("auth_count_sample: FAILED: %s", exc)
                self._set_pending_load({"error": f"Auth count sample failed: {exc}"})

        self._load_thread = threading.Thread(target=_run, daemon=True)
        self._load_thread.start()

    def _auth_count_sample_worker(self, all_regions: bool = False) -> None:
        """Background worker: delegates to auth_sample.run_auth_count_sample."""
        from waf_fu.auth_sample import all_wafv2_regions, run_auth_count_sample

        conn = self.db
        if conn is None:
            return

        profile = self.aws_context.get("profile")
        region = self.aws_context.get("region")
        start_time = self.aws_context.get(
            "start_time", datetime.now(UTC) - timedelta(minutes=60)
        )
        end_time = self.aws_context.get("end_time", datetime.now(UTC))
        action_filter = self.aws_context.get("action_filter")

        if all_regions:
            regions = all_wafv2_regions(profile)
        else:
            regions = [region or "us-east-1"]

        def _on_progress(_phase: str, msg: str) -> None:
            self._set_load_status(msg)

        sr = run_auth_count_sample(
            conn,
            regions,
            profile,
            start_time,
            end_time,
            log_location=self.log_location or None,
            action_filter=action_filter,
            s3_region=region,
            on_progress=_on_progress,
        )

        source = self.log_location or "cwl"
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        storage.refresh_selector_counts(conn, source, start_ms, end_ms, action_filter)

        with self._load_lock:
            self._load_status = ""
        self.status_msg = sr.summary()
        self.status_time = time.time()

    # ── replay actions ──────────────────────────────────────────────────────

    def _get_replay_targets(self) -> list[ReconstructedRequest]:
        """Return selected entries if any, otherwise the cursor entry."""
        if self.selected:
            # Maintain list order for the selected items
            return [r for r in self.filtered if id(r) in self.selected]
        elif self.filtered:
            return [self.filtered[self.cursor]]
        return []

    def _ensure_browser(self, browser: str = ""):
        """Return the persistent browser driver, creating it if needed.
        browser: 'chrome' or 'firefox'. Defaults to self.mode.
        Returns (driver, error_string)."""
        browser = browser or self.mode
        if browser not in ("chrome", "firefox"):
            browser = "chrome"
        DEBUG("ensure_browser: requested=%s", browser)

        # If existing driver is alive and same browser type, reuse it
        if self._browser_driver is not None and self._browser_type == browser:
            try:
                _ = self._browser_driver.window_handles
                DEBUG("ensure_browser: reusing existing %s driver", browser)
                return self._browser_driver, ""
            except Exception:
                DEBUG("ensure_browser: existing driver dead, will relaunch")
                self._browser_driver = None
                self._browser_type = ""

        # If switching browser types, kill the old one
        if self._browser_driver is not None and self._browser_type != browser:
            DEBUG(
                "ensure_browser: switching from %s to %s", self._browser_type, browser
            )
            try:
                self._browser_driver.quit()
            except Exception:
                pass
            self._browser_driver = None
            self._browser_type = ""

        driver, err = launch_driver(
            browser,
            self.proxy,
            chromedriver_path=self.chromedriver_path,
            geckodriver_path=self.geckodriver_path,
        )
        if driver is None:
            return None, err

        self._browser_driver = driver
        self._browser_type = browser
        DEBUG("ensure_browser: %s launched successfully", browser)
        return driver, ""

    def _execute_replay(self, stdscr):
        """Execute replay for selected entries (or cursor if none selected)."""
        targets = self._get_replay_targets()
        if not targets:
            if self.selected:
                msg = "No selected entries match current filter"
                self.status_msg = f"✘ {msg} — clear selection with Esc"
            elif not self.filtered:
                msg = "No entries to replay"
                self.status_msg = f"✘ {msg}"
            else:
                msg = "No replay target"
                self.status_msg = f"✘ {msg}"
            DEBUG(
                "execute_replay: SKIPPED: %s (filtered=%d selected=%d)",
                msg,
                len(self.filtered),
                len(self.selected),
            )
            self.status_time = time.time()
            return

        count = len(targets)
        DEBUG("execute_replay: mode=%s targets=%d", self.mode, count)
        for i, t in enumerate(targets):
            DEBUG(
                "execute_replay: target %d/%d: %s %s",
                i + 1,
                count,
                t.method,
                _redact_url(t.full_url),
            )

        problems = [(req, errs) for req in targets if (errs := validate_request(req))]
        if problems:
            req, errs = problems[0]
            DEBUG("execute_replay: validation failed: %s", errs)
            self.status_msg = f"✘ Cannot replay: {errs[0]} — press e to edit"
            self.status_kind = "error"
            self.status_time = time.time()
            return

        if self.mode == "curl":
            DEBUG("execute_replay: generating %d curl command(s)", count)
            all_cmds = []
            for req in targets:
                all_cmds.append(to_curl(req, proxy=self.proxy))

            # Copy all to clipboard (joined by newlines)
            combined = "\n\n".join(all_cmds)
            copied = False
            for clip_cmd in (
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
                ["wl-copy"],
                ["pbcopy"],
            ):
                if shutil.which(clip_cmd[0]):
                    try:
                        proc = subprocess.run(
                            clip_cmd,
                            input=combined.encode(),
                            timeout=3,
                            capture_output=True,
                        )
                        if proc.returncode == 0:
                            copied = True
                            break
                    except Exception:
                        pass

            self.post_exit_output.extend(all_cmds)

            if copied:
                self.status_msg = f"✔ {count} curl cmd(s) copied to clipboard"
            else:
                self.status_msg = f"✔ {count} curl cmd(s) staged — printed on exit"
            self.status_kind = ""
            self.status_time = time.time()

        elif self.mode in ("chrome", "firefox"):
            browser_name = self.mode.title()
            self.status_msg = f"Opening {count} request(s) in {browser_name}…"
            self.status_kind = ""
            self.status_time = time.time()
            self._draw(stdscr)

            # Temporarily leave curses
            curses.endwin()

            driver, err = self._ensure_browser(self.mode)
            if err:
                stdscr.refresh()
                first_line = err.split("\n")[0]
                self.status_msg = f"✘ {first_line} (full error printed on exit)"
                self.status_time = time.time()
                self.post_exit_output.append(
                    f"\n{'─' * 60}\n{browser_name} launch error:\n{err}\n{'─' * 60}"
                )
                return

            # Determine how many tabs already exist
            try:
                existing_tabs = len(driver.window_handles)
                current = driver.current_url
            except Exception:
                existing_tabs = 0
                current = "about:blank"
            opened = 0

            errors: list[str] = []
            for i, req in enumerate(targets):
                # First request: use existing tab if it's blank, else new tab
                need_new_tab = (i > 0) or (
                    existing_tabs > 0 and current not in ("about:blank", "data:,")
                )
                try:
                    result = open_request(
                        driver, req, new_tab=need_new_tab, timeout=self.timeout
                    )
                    if result and result.startswith("ERROR:"):
                        errors.append(result)
                except TimeoutError:
                    # Browser tab stays open with whatever loaded — do not
                    # quit/close the driver, and stop rather than pressing
                    # on through the remaining targets.
                    DEBUG(
                        "execute_replay: TIMEOUT target %d/%d after %gs",
                        i + 1,
                        count,
                        self.timeout,
                    )
                    stdscr.refresh()
                    self.status_msg = f"Replay timed out after {self.timeout:g}s"
                    self.status_kind = "warn"
                    self.status_time = time.time()
                    return
                except KeyboardInterrupt:
                    # Browser tab stays with partial content — same rationale
                    # as the TimeoutError branch above.
                    DEBUG(
                        "execute_replay: CANCELLED by user at target %d/%d",
                        i + 1,
                        count,
                    )
                    stdscr.refresh()
                    self.status_msg = "Replay cancelled"
                    self.status_kind = "warn"
                    self.status_time = time.time()
                    return
                except BaseException as exc:
                    # Safety net: some other BaseException variant escaped
                    # the backend (e.g. a BaseExceptionGroup that wasn't
                    # unwrapped upstream). Recover the TUI instead of
                    # crashing with a traceback.
                    if isinstance(exc, BaseExceptionGroup):
                        kb = exc.subgroup(KeyboardInterrupt)
                        if kb is not None:
                            DEBUG(
                                "execute_replay: CANCELLED (via BaseExceptionGroup) "
                                "at target %d/%d",
                                i + 1,
                                count,
                            )
                            stdscr.refresh()
                            self.status_msg = "Replay cancelled"
                            self.status_kind = "warn"
                            self.status_time = time.time()
                            return
                    DEBUG("execute_replay: unexpected BaseException: %s", exc)
                    stdscr.refresh()
                    self.status_msg = f"Replay failed: {type(exc).__name__}"
                    self.status_kind = "error"
                    self.status_time = time.time()
                    return
                opened += 1

            # Re-enter curses
            stdscr.refresh()

            try:
                tab_count = len(driver.window_handles)
            except Exception:
                tab_count = opened
            DEBUG(
                "execute_replay: opened=%d tabs_total=%d errors=%d",
                opened,
                tab_count,
                len(errors),
            )
            if errors:
                short = errors[0].removeprefix("ERROR: ").split("\n")[0]
                self.status_msg = f"✘ {browser_name}: {short}"
                self.status_kind = "error"
            else:
                self.status_msg = f"✔ Opened {opened} tab(s) in {browser_name} ({tab_count} total tabs)"
                self.status_kind = ""
            self.status_time = time.time()

        # Clear selection after execution
        self.selected.clear()

    # ── main loop ───────────────────────────────────────────────────────────

    def run(self, stdscr):
        curses.curs_set(0)

        # Colors: pair(1)=red, pair(2)=cyan, pair(3)=cyan bold,
        #         pair(4)=yellow, pair(5)=green
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_CYAN, -1)
        curses.init_pair(3, curses.COLOR_CYAN, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_GREEN, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)  # edited entries
        curses.init_pair(7, curses.COLOR_BLUE, -1)  # matched-data entries
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_YELLOW)  # search highlight
        curses.init_pair(
            9, curses.COLOR_BLACK, curses.COLOR_GREEN
        )  # active search match

        from waf_fu.banner import _draw_splash

        if self._needs_selector_counts():
            _draw_splash(
                stdscr,
                on_pause=self._ensure_selector_counts,
                pause_label="Processing auth metrics...",
            )
        else:
            _draw_splash(stdscr)

        stdscr.timeout(100)  # 100ms — allows responsive resize

        # Auto-show log group selector if started with no data
        if self._needs_log_selection:
            self._needs_log_selection = False
            self._draw(stdscr)
            self._show_log_selector(stdscr)

        while True:
            try:
                self._draw(stdscr)
                ch = stdscr.getch()
            except KeyboardInterrupt:
                break

            if ch == -1:
                self._apply_pending_load()
                if (
                    self.auto_refresh
                    and not self._is_loading()
                    and self.source_info.get("log_group")
                    and time.time() - self._last_refresh_time
                    >= self.auto_refresh_interval
                ):
                    self._refresh_logs()
                continue

            n = len(self.filtered)
            cursor_before = self.cursor
            term_h, _ = stdscr.getmaxyx()
            detail_h, _, _ = self._layout(term_h, stdscr.getmaxyx()[1])

            # ── Navigation (list pane) ──
            # Scroll position intentionally preserved across entries
            if ch == curses.KEY_DOWN and n:
                self.cursor = min(self.cursor + 1, n - 1)

            elif ch == curses.KEY_UP and n:
                self.cursor = max(self.cursor - 1, 0)

            elif ch == curses.KEY_NPAGE and n:  # PgDn
                self.cursor = min(self.cursor + 10, n - 1)

            elif ch == curses.KEY_PPAGE and n:  # PgUp
                self.cursor = max(self.cursor - 10, 0)

            elif ch == curses.KEY_HOME and n:
                self.cursor = 0

            elif ch == curses.KEY_END and n:
                self.cursor = n - 1

            elif ch == curses.KEY_RIGHT and n:
                term_w = stdscr.getmaxyx()[1]
                avail = max(term_w - 1 - 3, 0)
                longest = max((len(r.list_line()) for r in self.filtered), default=0)
                self.h_offset = min(
                    self.h_offset + 5, max_hscroll_offset("x" * longest, avail)
                )

            elif ch == curses.KEY_LEFT:
                self.h_offset = max(0, self.h_offset - 5)

            # ── Detail pane scroll ──
            elif ch == ord("]"):  # scroll detail down
                max_scroll = max(len(self.detail_lines) - detail_h, 0)
                self.detail_scroll = min(self.detail_scroll + 3, max_scroll)

            elif ch == ord("}"):  # scroll detail to bottom
                self.detail_scroll = max(len(self.detail_lines) - detail_h, 0)

            elif ch == ord("["):  # scroll detail up
                self.detail_scroll = max(self.detail_scroll - 3, 0)

            elif ch == ord("{"):  # scroll detail to top
                self.detail_scroll = 0

            elif ch == ord("'"):  # scroll detail right
                self.detail_h_offset += 5

            elif ch == ord('"'):  # scroll detail to rightmost
                if self.detail_lines:
                    self.detail_h_offset = max(
                        (len(line) for line in self.detail_lines), default=0
                    )

            elif ch == ord(";"):  # scroll detail left
                self.detail_h_offset = max(0, self.detail_h_offset - 5)

            elif ch == ord(":"):  # scroll detail to leftmost
                self.detail_h_offset = 0

            elif ch == 9:  # Tab — jump to next section in detail
                # Find next section header after current scroll
                for i in range(self.detail_scroll + 1, len(self.detail_lines)):
                    if self.detail_lines[i].startswith("═══"):
                        self.detail_scroll = i
                        break

            elif ch == curses.KEY_BTAB:  # Shift+Tab — jump to previous section
                for i in range(self.detail_scroll - 1, -1, -1):
                    if self.detail_lines[i].startswith("═══"):
                        self.detail_scroll = i
                        break

            # ── Mode toggle ──
            elif ch == ord("m"):
                idx = self._MODES.index(self.mode)
                self._set_mode(self._MODES[(idx + 1) % len(self._MODES)])
                self.status_msg = f"Switched to {self.mode} mode"
                self.status_time = time.time()

            elif ch == ord("t"):
                self._set_auth_filter(not self.auth_filter)
                self._apply_filter()
                state = (
                    "ON — showing only replayable auth"
                    if self.auth_filter
                    else "OFF — showing all entries"
                )
                self.status_msg = f"Auth filter {state}"
                self.status_time = time.time()

            elif ch == ord("b"):
                self.hide_blocks = not self.hide_blocks
                self._apply_filter()
                state = "hidden" if self.hide_blocks else "shown"
                self.status_msg = f"BLOCK/DENY entries now {state}"
                self.status_time = time.time()

            elif ch == ord("f"):
                self._show_filter_manager(stdscr)

            elif ch == ord("w"):
                self._edit_time_window(stdscr, "start")

            elif ch == ord("W"):
                self._edit_time_window(stdscr, "end")

            elif ch == ord("o"):
                idx = self._SORT_FIELDS.index(self.sort_field)
                next_field = self._SORT_FIELDS[(idx + 1) % len(self._SORT_FIELDS)]
                self._set_sort(next_field, self.sort_dir)
                self.status_msg = f"Sort: {self.sort_field} {self.sort_dir}"
                self.status_time = time.time()

            elif ch == ord("O"):
                idx = self._SORT_DIRS.index(self.sort_dir)
                next_dir = self._SORT_DIRS[(idx + 1) % len(self._SORT_DIRS)]
                self._set_sort(self.sort_field, next_dir)
                self.status_msg = f"Sort: {self.sort_field} {self.sort_dir}"
                self.status_time = time.time()

            elif ch == ord("v"):
                idx = self._VIEW_MODES.index(self.view_mode)
                self.view_mode = self._VIEW_MODES[(idx + 1) % len(self._VIEW_MODES)]
                self.detail_scroll = 0
                self.detail_h_offset = 0
                self.status_msg = f"View: {self.view_mode}"
                self.status_time = time.time()

            elif ch == ord("l"):
                self._show_log_selector(stdscr)

            elif ch == ord("r"):
                self._show_region_selector(stdscr)

            elif ch == ord("c"):
                self._run_auth_count_sample_bg()

            elif ch == ord("C"):
                self._run_auth_count_sample_bg(all_regions=True)

            elif ch == ord("S"):
                self._cycle_source_view()

            elif ch == curses.KEY_F5:
                self._refresh_logs()

            elif ch == curses.KEY_F2:
                self.auto_refresh = not self.auto_refresh
                if self.auto_refresh:
                    self._last_refresh_time = time.time()
                    self.status_msg = f"Auto-refresh ON ({self.auto_refresh_interval}s)"
                else:
                    self.status_msg = "Auto-refresh OFF"
                self.status_time = time.time()

            elif ch == curses.KEY_F3:
                val = self._inline_edit(
                    stdscr,
                    " Auto-refresh interval (seconds): ",
                    str(self.auto_refresh_interval),
                )
                if val is not None:
                    try:
                        new_interval = int(val)
                        if new_interval < 1:
                            self.status_msg = "Interval must be at least 1 second"
                            self.status_kind = "error"
                        else:
                            self.auto_refresh_interval = new_interval
                            self.status_msg = (
                                f"Auto-refresh interval set to {new_interval}s"
                            )
                    except ValueError:
                        self.status_msg = "Invalid number"
                        self.status_kind = "error"
                    self.status_time = time.time()

            elif ch == ord("e") and n:
                self._show_request_editor(stdscr)

            # ── Selection ──
            elif ch == ord(" ") and n:  # Space — toggle selection
                req_obj = self.filtered[self.cursor]
                obj_id = id(req_obj)
                if obj_id in self.selected:
                    self.selected.discard(obj_id)
                else:
                    self.selected.add(obj_id)
                # Auto-advance cursor after toggling
                if self.cursor < n - 1:
                    self.cursor += 1

            elif ch == ord("a") and n:  # Select all visible / deselect all
                visible_ids = {id(r) for r in self.filtered}
                if visible_ids.issubset(self.selected):
                    # All visible are selected → deselect all
                    self.selected -= visible_ids
                    self.status_msg = "Deselected all"
                else:
                    self.selected |= visible_ids
                    self.status_msg = (
                        f"Selected all {len(self.filtered)} visible entries"
                    )
                self.status_time = time.time()

            elif ch in (ord("F"), 27):  # F / Escape — clear filter and selection
                changed = []
                if self.filter_rules:
                    self.filter_rules.clear()
                    changed.append("rules")
                if self.selected:
                    self.selected.clear()
                    changed.append("selection")
                if changed:
                    self._apply_filter()
                self.status_msg = f"Cleared {' & '.join(changed)}" if changed else ""
                self.status_time = time.time()

            # ── Detail search ──
            elif ch == ord("/"):
                self._detail_search_prompt(stdscr)

            elif ch == ord("n") and self._search_re is not None:
                self._search_next()

            elif ch == ord("N") and self._search_re is not None:
                self._search_next(reverse=True)

            # ── Execute ──
            elif ch in (curses.KEY_ENTER, 10, 13):
                self._execute_replay(stdscr)

            # ── Help ──
            elif ch in (ord("h"), ord("?")):
                self._show_help(stdscr)

            # ── Quit ──
            elif ch == ord("q"):
                break

            # The source view is per-record, so a different record starts merged.
            if self.cursor != cursor_before:
                self._reset_source_view()

        self._cleanup_browser()
        return self.post_exit_output

    def _cleanup_browser(self):
        if self._browser_driver is not None:
            DEBUG("cleanup_browser: quitting %s driver", self._browser_type)
            try:
                self._browser_driver.quit()
            except Exception as exc:
                DEBUG("cleanup_browser: quit failed: %s", exc)
            self._browser_driver = None
