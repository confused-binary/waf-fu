"""Tests for the detail-pane colour classifier and headers-only view.

No curses terminal is touched here: `detail_line_kind`,
`build_detail_lines` and `build_headers_lines` are pure string builders, and
that separation from curses colour initialisation is exactly what makes them
testable under headless pytest.
"""

from __future__ import annotations

import inspect

import pytest

from waf_fu.tui import (
    WafTUI,
    build_detail_lines,
    build_headers_lines,
    detail_line_kind,
)


# ── detail_line_kind colouring ────────────────────────────────────────────────


def test_detail_line_kind_section():
    assert detail_line_kind("═══ WAF DECISION ═══") == "section"


def test_detail_line_kind_ok():
    assert detail_line_kind("  ✔ User-Agent") == "ok"


def test_detail_line_kind_bad():
    assert detail_line_kind("  ✘ Host — Chrome rejects ...") == "bad"


def test_detail_line_kind_leaves_jwt_status_row_plain():
    assert detail_line_kind("  Status            ✔ VALID (not expired)") == "plain"


@pytest.mark.parametrize(
    "line",
    [
        "  ✎ EDITED",
        "  ⚠ Query string REDACTED",
        "",
    ],
)
def test_detail_line_kind_other_glyphs_stay_plain(line):
    assert detail_line_kind(line) == "plain"


def test_draw_loop_uses_detail_line_kind():
    source = inspect.getsource(WafTUI._draw)
    assert "detail_line_kind" in source


# ── headers view shows only request line, headers, cookies (TUI-05) ─


def test_headers_view_shows_only_headers_and_cookies(make_request):
    req = make_request(cookies="sid=1", body="a=b")
    lines = build_headers_lines(req)
    text = "\n".join(lines)

    assert "═══ HEADERS ═══" in text
    assert "═══ COOKIES ═══" in text

    non_empty = [line for line in lines if line.strip()]
    assert non_empty[0] == f"  {req.method} {req.full_url} {req.http_version}"

    assert "═══ REQUEST ═══" not in text
    assert "═══ BODY ═══" not in text
    assert "═══ REPLAY FIDELITY ═══" not in text
    assert "═══ REPLAY COMMAND ═══" not in text
    assert "Client:" not in text
    assert "Country:" not in text
    assert "Action:" not in text


def test_detail_views_no_stale_header_mechanisms(make_request):
    req = make_request(cookies="sid=1", body="a=b")
    for mode in ("curl", "chrome", "firefox"):
        texts = [
            "\n".join(build_detail_lines(req, mode)),
            "\n".join(build_headers_lines(req)),
        ]
        for text in texts:
            assert "injected via CDP" not in text
            assert "custom headers via fetch only" not in text
            assert "Selenium API" not in text


def test_detail_view_no_replay_sections(make_request):
    req = make_request()
    for mode in ("curl", "chrome", "firefox"):
        lines = build_detail_lines(req, mode)
        assert "═══ REPLAY FIDELITY ═══" not in lines
        assert "═══ REPLAY COMMAND ═══" not in lines
