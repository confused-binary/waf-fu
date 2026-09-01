"""Database-aware TUI paths: offline selector fallback, cache-aware
reload, and round-trip filter fidelity (DB-03, DB-04)."""

from __future__ import annotations

import curses
import inspect
import sqlite3
from datetime import timedelta

import pytest

import waf_fu.tui as tui_module
from waf_fu import storage
from waf_fu.models import FilterRule, parse_all
from waf_fu.tui import WafTUI, hscroll_window, max_hscroll_offset


class _FakeStdscr:
    """Minimal stand-in for curses' stdscr. Not a bare MagicMock, so an
    attribute typo in production code fails loudly instead of returning
    another Mock."""

    def getmaxyx(self):
        return (40, 120)

    def refresh(self):
        pass


@pytest.fixture
def fake_stdscr():
    return _FakeStdscr()


def _mute_drawing(monkeypatch, t: WafTUI):
    monkeypatch.setattr(t, "_safe_addnstr", lambda *a, **k: None)


def _reload_and_wait(t: WafTUI, log_group: str, **kwargs):
    """Call _reload_log_group and wait for the background thread to finish."""
    t._reload_log_group(log_group, **kwargs)
    if t._load_thread is not None:
        t._load_thread.join(timeout=5)
    t._apply_pending_load()


def _raise_no_creds(**kwargs):
    raise RuntimeError("no AWS credentials")


def test_offline_selector_fallback(tmp_path, waf_record, monkeypatch, fake_stdscr):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(conn, "cwl", "group-a", [waf_record(uri="/a")])
    storage.save_source_records(conn, "cwl", "group-b", [waf_record(uri="/b")])

    monkeypatch.setattr(tui_module, "fetch_waf_log_groups", _raise_no_creds)

    t = WafTUI([], db=conn)
    _mute_drawing(monkeypatch, t)

    captured: dict = {}

    def fake_overlay(stdscr, title, items, current="", footer=""):
        captured["items"] = items

    monkeypatch.setattr(t, "_overlay_select", fake_overlay)

    t._show_log_selector(fake_stdscr)

    assert set(captured["items"]) == {"group-a", "group-b"}


def test_offline_selector_empty_result_fallback(
    tmp_path, waf_record, monkeypatch, fake_stdscr
):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(conn, "cwl", "group-a", [waf_record(uri="/a")])
    storage.save_source_records(conn, "cwl", "group-b", [waf_record(uri="/b")])

    monkeypatch.setattr(tui_module, "fetch_waf_log_groups", lambda **kw: [])

    t = WafTUI([], db=conn)
    _mute_drawing(monkeypatch, t)

    captured: dict = {}

    def fake_overlay(stdscr, title, items, current="", footer=""):
        captured["items"] = items

    monkeypatch.setattr(t, "_overlay_select", fake_overlay)

    t._show_log_selector(fake_stdscr)

    assert set(captured["items"]) == {"group-a", "group-b"}


def test_offline_selector_no_db_keeps_error(monkeypatch, fake_stdscr):
    monkeypatch.setattr(tui_module, "fetch_waf_log_groups", _raise_no_creds)

    t = WafTUI([], db=None)
    _mute_drawing(monkeypatch, t)

    overlay_called = []
    monkeypatch.setattr(
        t, "_overlay_select", lambda *a, **k: overlay_called.append(1) or None
    )

    t._show_log_selector(fake_stdscr)

    assert "no AWS credentials" in t.status_msg
    assert overlay_called == []


def test_reload_uses_cache_when_db_set(tmp_path, monkeypatch, fake_stdscr):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    start_time = tui_module.datetime(2026, 1, 1, tzinfo=tui_module.UTC)
    end_time = tui_module.datetime(2026, 1, 1, 1, tzinfo=tui_module.UTC)

    t = WafTUI(
        [],
        db=conn,
        aws_context={
            "start_time": start_time,
            "end_time": end_time,
            "profile": "prof",
            "region": "us-east-1",
            "action_filter": None,
        },
    )
    _mute_drawing(monkeypatch, t)

    calls = []
    fetch_calls = []

    def fake_load_with_cache(conn_arg, source, log_group, **kwargs):
        calls.append((conn_arg, source, log_group, kwargs))
        return []

    monkeypatch.setattr(
        tui_module.storage, "load_source_with_cache", fake_load_with_cache
    )
    monkeypatch.setattr(
        tui_module,
        "fetch_logs_from_cloudwatch",
        lambda **kw: fetch_calls.append(kw) or [],
    )

    _reload_and_wait(t, "g1")

    assert len(calls) == 1
    conn_arg, source, log_group, kwargs = calls[0]
    assert conn_arg is conn
    assert source == "cwl"
    assert log_group == "g1"
    assert kwargs["start_ms"] == int(start_time.timestamp() * 1000)
    assert kwargs["end_ms"] == int(end_time.timestamp() * 1000)
    assert kwargs["refresh"] is False
    assert fetch_calls == []


def test_reload_gap_fills_then_hits_cache(
    tmp_path, monkeypatch, fake_stdscr, waf_record
):
    """End-to-end through real storage: the first switch fetches the window
    aws_context asked for -- proving _fetch_from_cloudwatch_ms converts the
    ms-int contract back to the exact datetimes -- and switching back to the
    same group makes no CloudWatch call at all."""
    conn = storage.open_db(str(tmp_path / "logs.db"))
    start_time = tui_module.datetime(2026, 1, 1, tzinfo=tui_module.UTC)
    end_time = tui_module.datetime(2026, 1, 1, 1, tzinfo=tui_module.UTC)

    t = WafTUI(
        [],
        db=conn,
        aws_context={
            "start_time": start_time,
            "end_time": end_time,
            "profile": "prof",
            "region": "us-east-1",
            "action_filter": None,
        },
    )
    _mute_drawing(monkeypatch, t)

    calls = []

    def fake_fetch(
        *,
        log_group,
        start_time,
        end_time,
        profile=None,
        region=None,
        action_filter=None,
    ):
        calls.append((log_group, start_time, end_time))
        return [
            waf_record(uri="/a", timestamp=int(start_time.timestamp() * 1000) + 1000)
        ]

    monkeypatch.setattr(tui_module, "fetch_logs_from_cloudwatch", fake_fetch)

    _reload_and_wait(t, "g1")
    assert calls == [("g1", start_time, end_time)]
    assert len(t.all_requests) == 1

    _reload_and_wait(t, "g1")
    assert len(calls) == 1
    assert len(t.all_requests) == 1


def test_reload_without_db_uses_cloudwatch(monkeypatch, fake_stdscr):
    t = WafTUI([], db=None, aws_context={"profile": "prof", "region": "us-east-1"})
    _mute_drawing(monkeypatch, t)

    load_with_cache_calls = []
    fetch_calls = []

    monkeypatch.setattr(
        tui_module.storage,
        "load_source_with_cache",
        lambda *a, **k: load_with_cache_calls.append(1) or [],
    )
    monkeypatch.setattr(
        tui_module,
        "fetch_logs_from_cloudwatch",
        lambda **kw: fetch_calls.append(kw) or [],
    )

    _reload_and_wait(t, "g1")

    assert load_with_cache_calls == []
    assert len(fetch_calls) == 1
    assert fetch_calls[0]["log_group"] == "g1"


def test_reload_survives_db_error(tmp_path, monkeypatch, fake_stdscr):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    t = WafTUI([], db=conn, aws_context={})
    _mute_drawing(monkeypatch, t)
    original_requests = t.all_requests

    def raise_db_error(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(tui_module.storage, "load_source_with_cache", raise_db_error)

    _reload_and_wait(t, "g1")

    assert t.status_msg.startswith("✘")
    assert "database is locked" in t.status_msg
    assert t.all_requests is original_requests


# ── Selector labels and background scan on SQLite (CLI-01/CLI-02) ────────


_WINDOW_START = tui_module.datetime(2026, 1, 1, tzinfo=tui_module.UTC)
_WINDOW_END = tui_module.datetime(2026, 1, 1, 1, tzinfo=tui_module.UTC)
_IN_WINDOW_MS = int(_WINDOW_START.timestamp() * 1000) + 1000


def _seed_group(conn, waf_record, group: str, auth: int, total: int, timestamp: int):
    """Seed `total` records for `group`, `auth` of which carry a Cookie header."""
    storage.save_source_records(
        conn,
        "cwl",
        group,
        [
            waf_record(
                uri=f"/{group}/{i}",
                timestamp=timestamp,
                cookies="session=abc" if i < auth else "",
            )
            for i in range(total)
        ],
    )


def _windowed_tui(conn) -> WafTUI:
    return WafTUI(
        [],
        db=conn,
        aws_context={"start_time": _WINDOW_START, "end_time": _WINDOW_END},
    )


def test_build_log_group_display_sorted_counted_first(tmp_path):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.upsert_selector_counts(conn, "cwl", {"a": (5, 1000), "c": (40, 1000)})

    t = _windowed_tui(conn)
    labels, display_to_raw = t._build_log_group_display(["a", "b", "c"])

    assert labels == ["c (40/1,000)", "a (5/1,000)", "b"]
    assert display_to_raw == {"c (40/1,000)": "c", "a (5/1,000)": "a", "b": "b"}


def test_build_log_group_display_with_no_db_returns_raw_names():
    t = WafTUI([], db=None)
    labels, display_to_raw = t._build_log_group_display(["a", "b"])

    assert labels == ["a", "b"]
    assert display_to_raw == {"a": "a", "b": "b"}


def test_build_log_group_display_reads_cached_counts(tmp_path):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.upsert_selector_counts(conn, "cwl", {"a": (3, 10)})

    t = _windowed_tui(conn)
    labels, _ = t._build_log_group_display(["a"])

    assert labels == ["a (3/10)"]


def test_build_log_group_display_comma_formats_large_numbers(tmp_path):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.upsert_selector_counts(conn, "cwl", {"a": (1234, 56789)})

    t = _windowed_tui(conn)
    labels, _ = t._build_log_group_display(["a"])

    assert labels == ["a (1,234/56,789)"]


def test_ensure_selector_counts_populates_from_existing_records(tmp_path, waf_record):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    _seed_group(conn, waf_record, "g1", 3, 10, _IN_WINDOW_MS)

    assert storage.get_selector_counts(conn, "cwl") == {}

    t = _windowed_tui(conn)
    t._ensure_selector_counts()

    result = storage.get_selector_counts(conn, "cwl")
    assert "g1" in result
    assert result["g1"] == (3, 10)


def test_ensure_selector_counts_skips_when_already_cached(tmp_path, waf_record):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.upsert_selector_counts(conn, "cwl", {"g1": (99, 100)})
    _seed_group(conn, waf_record, "g1", 3, 10, _IN_WINDOW_MS)

    t = _windowed_tui(conn)
    t._ensure_selector_counts()

    result = storage.get_selector_counts(conn, "cwl")
    assert result["g1"] == (99, 100)


def test_waftui_init_no_longer_accepts_log_counts_path():
    with pytest.raises(TypeError):
        WafTUI([], log_counts_path="x.json")


# ── Auth-count upsert on reload (CLI-02) ──────────────────────────────────


def test_reload_upserts_auth_counts_for_new_group(
    tmp_path, waf_record, monkeypatch, fake_stdscr
):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(
        conn,
        "cwl",
        "group-new",
        [
            waf_record(uri="/a", cookies="session=1"),
            waf_record(uri="/b", cookies="session=2"),
            waf_record(uri="/c"),
            waf_record(uri="/d"),
            waf_record(uri="/e"),
        ],
    )

    t = WafTUI(
        [],
        db=conn,
        aws_context={
            "profile": None,
            "region": None,
            "start_time": tui_module.datetime(2025, 1, 1, tzinfo=tui_module.UTC),
            "end_time": tui_module.datetime(2025, 1, 1, 1, tzinfo=tui_module.UTC),
        },
    )
    _mute_drawing(monkeypatch, t)

    _reload_and_wait(t, "group-new")

    assert storage.get_auth_count(conn, None, None, "group-new") == (2, 5)


def test_reload_upsert_keyed_by_new_group_not_previous(
    tmp_path, waf_record, monkeypatch, fake_stdscr
):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(
        conn, "cwl", "old-group", [waf_record(uri="/a", cookies="s=1")]
    )
    storage.save_source_records(conn, "cwl", "new-group", [waf_record(uri="/b")])

    t = WafTUI(
        [],
        db=conn,
        aws_context={
            "profile": None,
            "region": None,
            "start_time": tui_module.datetime(2025, 1, 1, tzinfo=tui_module.UTC),
            "end_time": tui_module.datetime(2025, 1, 1, 1, tzinfo=tui_module.UTC),
        },
        source_info={"log_group": "old-group"},
    )
    _mute_drawing(monkeypatch, t)

    _reload_and_wait(t, "new-group")

    assert storage.get_auth_count(conn, None, None, "new-group") == (0, 1)


def test_reload_with_no_db_does_not_raise(monkeypatch, fake_stdscr):
    t = WafTUI([], db=None, aws_context={"profile": "prof", "region": "us-east-1"})
    _mute_drawing(monkeypatch, t)

    monkeypatch.setattr(tui_module, "fetch_logs_from_cloudwatch", lambda **kw: [])

    _reload_and_wait(t, "g1")  # must not raise


def test_reload_events_scanned_reflects_post_limit_truncation(
    tmp_path, waf_record, monkeypatch, fake_stdscr
):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(
        conn,
        "cwl",
        "group-limited",
        [waf_record(uri=f"/{i}") for i in range(5)],
    )

    t = WafTUI(
        [],
        db=conn,
        aws_context={
            "profile": None,
            "region": None,
            "limit": 2,
            "start_time": tui_module.datetime(2025, 1, 1, tzinfo=tui_module.UTC),
            "end_time": tui_module.datetime(2025, 1, 1, 1, tzinfo=tui_module.UTC),
        },
    )
    _mute_drawing(monkeypatch, t)

    _reload_and_wait(t, "group-limited")

    assert len(t.all_requests) == 2
    assert storage.get_auth_count(conn, None, None, "group-limited") == (0, 2)


def test_show_log_selector_offers_db_groups_when_fetch_fails_no_file_shortcircuit(
    tmp_path, waf_record, monkeypatch, fake_stdscr
):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(conn, "cwl", "group-a", [waf_record(uri="/a")])

    monkeypatch.setattr(tui_module, "fetch_waf_log_groups", _raise_no_creds)

    t = WafTUI([], db=conn, source_info={})
    _mute_drawing(monkeypatch, t)

    captured: dict = {}

    def fake_overlay(stdscr, title, items, current="", footer=""):
        captured["items"] = items

    monkeypatch.setattr(t, "_overlay_select", fake_overlay)

    t._show_log_selector(fake_stdscr)

    assert captured["items"] == ["group-a"]


# ── Preference persistence on toggle (CLI-02) ─────────────────────────────


def test_set_mode_writes_preference(tmp_path):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    t = WafTUI([], db=conn)

    t._set_mode("curl")

    assert t.mode == "curl"
    assert storage.get_preference(conn, "replay_mode") == "curl"


def test_set_auth_filter_writes_on_off_strings(tmp_path):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    t = WafTUI([], db=conn)

    t._set_auth_filter(False)
    assert t.auth_filter is False
    assert storage.get_preference(conn, "auth_filter") == "off"

    t._set_auth_filter(True)
    assert t.auth_filter is True
    assert storage.get_preference(conn, "auth_filter") == "on"


def test_set_mode_and_auth_filter_noop_persistence_when_db_none():
    t = WafTUI([], db=None)

    t._set_mode("curl")
    t._set_auth_filter(False)

    assert t.mode == "curl"
    assert t.auth_filter is False


def test_toggled_value_survives_reopen(tmp_path):
    db_path = str(tmp_path / "logs.db")
    conn = storage.open_db(db_path)
    t = WafTUI([], db=conn)

    t._set_mode("curl")
    conn.close()

    reopened = storage.open_db(db_path)
    assert (
        storage.get_preference(reopened, "replay_mode", storage.DEFAULT_REPLAY_MODE)
        == "curl"
    )


def test_db_records_filter_identically(tmp_path, waf_record):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    records = [
        waf_record(uri="/login", action="ALLOW", headers={"Authorization": "Bearer x"}),
        waf_record(uri="/static/app.js", action="ALLOW"),
        waf_record(uri="/admin", action="BLOCK", headers={"Authorization": "Bearer y"}),
    ]
    storage.save_records(conn, "group-a", records)

    loaded = storage.load_records(conn, "group-a", 0, 1 << 62)

    t_from_db = WafTUI(parse_all(loaded))
    t_from_original = WafTUI(parse_all(records))

    for t in (t_from_db, t_from_original):
        t.auth_filter = True
        t.filter_rules = [
            FilterRule("log", mode="include"),
            FilterRule("/admin", mode="exclude"),
        ]
        t._apply_filter()

    db_lines = [r.list_line() for r in t_from_db.filtered]
    original_lines = [r.list_line() for r in t_from_original.filtered]
    assert db_lines == original_lines
    # Guard against a vacuous pass: two empty lists would also compare equal.
    assert db_lines


# ── Layout / cursor-position counter (TUI-02, TUI-04) ─────────────────────


@pytest.mark.parametrize(
    "term_h,expected_list_h",
    [(40, 10), (10, 4)],
)
def test_layout_list_pane_is_ten_rows(term_h, expected_list_h):
    t = WafTUI([])
    _detail_h, list_h, _divider_y = t._layout(term_h, 120)
    assert list_h == expected_list_h


@pytest.mark.parametrize("term_h", range(10, 61))
def test_layout_invariants_hold_across_heights(term_h):
    t = WafTUI([])
    detail_h, list_h, _divider_y = t._layout(term_h, 120)
    assert detail_h + list_h + 1 == term_h - 1
    assert detail_h >= 1


def test_draw_counter_shows_cursor_position(
    make_request, scripted_stdscr, headless_curses
):
    requests = [make_request(uri=f"/{i}") for i in range(149)]
    t = WafTUI(requests, auth_filter_default=False)
    t.cursor = 4
    stdscr = scripted_stdscr()

    t._draw(stdscr)

    assert any("5/149 entries" in line for line in stdscr.drawn)


def test_draw_counter_empty_filter_shows_zero(
    make_request, scripted_stdscr, headless_curses
):
    t = WafTUI([make_request()], auth_filter_default=False)
    t.filtered = []
    t.cursor = 0
    stdscr = scripted_stdscr()

    t._draw(stdscr)

    assert any("0/0 entries" in line for line in stdscr.drawn)
    assert not any("1/0" in line for line in stdscr.drawn)


# ── Key dispatch (TUI-03, TUI-06, TUI-07, TUI-08) ─────────────────────────


def _run_keys(t, scripted_stdscr, keys):
    """Drive t.run() with a scripted key sequence, always terminating on 'q'."""
    stdscr = scripted_stdscr(list(keys) + [ord("q")])
    t.run(stdscr)
    return stdscr


def _two_entry_tui(make_request):
    requests = [make_request(uri="/a"), make_request(uri="/b")]
    return WafTUI(requests, auth_filter_default=False)


def test_j_is_inert_in_main_list(make_request, scripted_stdscr, headless_curses):
    t = _two_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [ord("j")])
    assert t.cursor == 0


def test_arrow_down_still_moves_cursor(make_request, scripted_stdscr, headless_curses):
    t = _two_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [curses.KEY_DOWN])
    assert t.cursor == 1


def test_k_is_inert_in_main_list(make_request, scripted_stdscr, headless_curses):
    t = _two_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [curses.KEY_DOWN, ord("k")])
    assert t.cursor == 1


def test_arrow_up_still_moves_cursor(make_request, scripted_stdscr, headless_curses):
    t = _two_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [curses.KEY_DOWN, curses.KEY_UP])
    assert t.cursor == 0


def test_lowercase_b_toggles_hide_blocks(
    make_request, scripted_stdscr, headless_curses
):
    t = _two_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [ord("b")])
    assert t.hide_blocks is True


def test_uppercase_b_does_not_toggle_hide_blocks(
    make_request, scripted_stdscr, headless_curses
):
    t = _two_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [ord("B")])
    assert t.hide_blocks is False


def test_overlay_select_still_has_jk_aliases():
    source = inspect.getsource(WafTUI._overlay_select)
    assert 'ord("j")' in source
    assert 'ord("k")' in source


def test_show_request_editor_still_has_jk_aliases():
    source = inspect.getsource(WafTUI._show_request_editor)
    assert 'ord("j")' in source
    assert 'ord("k")' in source


def test_help_and_view_dispatch(
    make_request, scripted_stdscr, headless_curses, monkeypatch
):
    t = _two_entry_tui(make_request)
    calls = []
    monkeypatch.setattr(t, "_show_help", lambda stdscr: calls.append(stdscr))

    _run_keys(t, scripted_stdscr, [ord("?")])
    assert len(calls) == 1

    _run_keys(t, scripted_stdscr, [ord("h")])
    assert len(calls) == 2


def test_view_switch_resets_detail_scroll(
    make_request, scripted_stdscr, headless_curses
):
    t = _two_entry_tui(make_request)
    t.detail_scroll = 12
    _run_keys(t, scripted_stdscr, [ord("v")])
    assert t.detail_scroll == 0


def test_view_switch_advances_view_mode(make_request, scripted_stdscr, headless_curses):
    t = _two_entry_tui(make_request)
    assert t.view_mode == "detail"
    _run_keys(t, scripted_stdscr, [ord("v")])
    assert t.view_mode == "json"


def test_view_switch_cycles_back_to_detail(
    make_request, scripted_stdscr, headless_curses
):
    t = _two_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [ord("v"), ord("v"), ord("v")])
    assert t.view_mode == "detail"
    assert t.detail_scroll == 0


# ── hscroll_window / max_hscroll_offset (TUI-01) ─────────────────────────


def test_hscroll_window_short_item_unchanged():
    assert hscroll_window("short", 20, 0) == "short"


def test_hscroll_window_short_item_ignores_stale_offset():
    assert hscroll_window("short", 20, 50) == "short"


def test_hscroll_window_long_item_offset_zero():
    item = "abcdefghijklmnopqrstuvwxyz"
    result = hscroll_window(item, 10, 0)
    assert len(result) == 10
    assert result.endswith("…")
    assert not result.startswith("…")
    assert result == "abcdefghi…"


def test_hscroll_window_long_item_mid_offset():
    item = "abcdefghijklmnopqrstuvwxyz"
    result = hscroll_window(item, 10, 5)
    assert len(result) == 10
    assert result.startswith("…")
    assert result.endswith("…")
    assert "ghijklmn" in result


def test_hscroll_window_long_item_max_offset():
    item = "abcdefghijklmnopqrstuvwxyz"
    off = max_hscroll_offset(item, 10)
    result = hscroll_window(item, 10, off)
    assert len(result) == 10
    assert result.startswith("…")
    assert not result.endswith("…")
    assert result.endswith("z")


def test_hscroll_window_never_exceeds_avail():
    item = "abcdefghijklmnopqrstuvwxyz"
    for avail in (1, 2, 3, 5, 10, 26, 100):
        for off in range(0, len(item) + 10, 3):
            result = hscroll_window(item, avail, off)
            assert len(result) <= avail, (
                f"avail={avail} off={off} got len={len(result)}"
            )


def test_max_hscroll_offset_fitting_item():
    assert max_hscroll_offset("hi", 20) == 0


def test_max_hscroll_offset_long_item():
    item = "abcdefghijklmnopqrstuvwxyz"
    off = max_hscroll_offset(item, 10)
    assert off == len(item) - 10
    result = hscroll_window(item, 10, off)
    assert result.endswith("z")


def test_hscroll_window_zero_avail():
    assert hscroll_window("anything", 0, 0) == ""


def test_hscroll_window_avail_one():
    result = hscroll_window("abcdef", 1, 0)
    assert len(result) <= 1


# ── List-pane horizontal scroll (TUI-01) ──────────────────────────────────


def _long_uri():
    return "/very/long/path/that/will/definitely/exceed/terminal/width/when/combined/with/timestamps/and/metadata"


def _long_entry_tui(make_request):
    """Two entries: one with a URI long enough to overflow 80 cols, one short."""
    requests = [
        make_request(uri=_long_uri(), terminating_rule_id="long-rule-name-here"),
        make_request(uri="/b"),
    ]
    return WafTUI(requests, auth_filter_default=False)


def test_list_right_arrow_reveals_later_text(
    make_request, scripted_stdscr, headless_curses
):
    t = _long_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [curses.KEY_RIGHT])
    assert t.h_offset > 0


def test_list_many_right_shows_tail(make_request, scripted_stdscr, headless_curses):
    t = _long_entry_tui(make_request)
    keys = [curses.KEY_RIGHT] * 50
    stdscr = _run_keys(t, scripted_stdscr, keys)
    raw = t.filtered[0].list_line()
    term_w = stdscr.getmaxyx()[1]
    avail = max(term_w - 1 - 3, 0)
    assert t.h_offset == max_hscroll_offset(raw, avail)
    tail_drawn = [d for d in stdscr.drawn if "long-rule-name-here" in d]
    assert tail_drawn, "tail of long item should be visible after many right-presses"


def test_list_left_at_start_is_noop(make_request, scripted_stdscr, headless_curses):
    t = _long_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [curses.KEY_LEFT])
    assert t.h_offset == 0


def test_list_cursor_move_preserves_offset(
    make_request, scripted_stdscr, headless_curses
):
    t = _long_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [curses.KEY_RIGHT, curses.KEY_RIGHT, curses.KEY_DOWN])
    assert t.h_offset == 10
    assert t.cursor == 1


def test_list_right_then_left(make_request, scripted_stdscr, headless_curses):
    t = _long_entry_tui(make_request)
    _run_keys(t, scripted_stdscr, [curses.KEY_RIGHT, curses.KEY_RIGHT, curses.KEY_LEFT])
    assert t.h_offset == 5


def test_overlay_returns_item_on_enter(scripted_stdscr, headless_curses):
    items = ["alpha", "beta"]
    t = WafTUI([], auth_filter_default=False)

    stdscr = scripted_stdscr([curses.KEY_DOWN, 10], size=(40, 120), on_exhaust=27)
    result = t._overlay_select(stdscr, "Pick", items)
    assert result == "beta"


def test_overlay_returns_none_on_esc(scripted_stdscr, headless_curses):
    items = ["alpha", "beta"]
    t = WafTUI([], auth_filter_default=False)

    stdscr = scripted_stdscr([27], size=(40, 120), on_exhaust=27)
    result = t._overlay_select(stdscr, "Pick", items)
    assert result is None


# ── Time window hotkeys (w / W) ───────────────────────────────────────────


def _time_window_tui(make_request, log_group="g"):
    start_time = tui_module.datetime(2026, 1, 1, tzinfo=tui_module.UTC)
    end_time = tui_module.datetime(2026, 1, 1, 4, tzinfo=tui_module.UTC)
    requests = [make_request()]
    return WafTUI(
        requests,
        auth_filter_default=False,
        source_info={"log_group": log_group},
        aws_context={"start_time": start_time, "end_time": end_time},
    )


def test_w_sets_start_time_and_reloads(
    make_request, scripted_stdscr, headless_curses, monkeypatch
):
    t = _time_window_tui(make_request)
    monkeypatch.setattr(t, "_inline_edit", lambda *a, **k: "4h")
    reload_calls = []
    monkeypatch.setattr(
        t, "_reload_log_group", lambda log_group, **k: reload_calls.append(log_group)
    )

    _run_keys(t, scripted_stdscr, [ord("w")])

    assert t.aws_context["start_time"] == t.aws_context["end_time"] - timedelta(hours=4)
    assert reload_calls == ["g"]


def test_capital_w_sets_end_time(
    make_request, scripted_stdscr, headless_curses, monkeypatch
):
    t = _time_window_tui(make_request)
    new_end = tui_module.datetime(2026, 1, 1, 6, tzinfo=tui_module.UTC)
    monkeypatch.setattr(t, "_inline_edit", lambda *a, **k: new_end.isoformat())
    reload_calls = []
    monkeypatch.setattr(
        t, "_reload_log_group", lambda log_group, **k: reload_calls.append(log_group)
    )

    _run_keys(t, scripted_stdscr, [ord("W")])

    assert t.aws_context["end_time"] == new_end
    assert reload_calls == ["g"]


def test_invalid_time_string_leaves_window_unchanged(
    make_request, scripted_stdscr, headless_curses, monkeypatch
):
    t = _time_window_tui(make_request)
    orig_start = t.aws_context["start_time"]
    monkeypatch.setattr(t, "_inline_edit", lambda *a, **k: "last tuesday")
    reload_calls = []
    monkeypatch.setattr(
        t, "_reload_log_group", lambda log_group, **k: reload_calls.append(log_group)
    )

    _run_keys(t, scripted_stdscr, [ord("w")])

    assert t.aws_context["start_time"] == orig_start
    assert t.status_kind == "error"
    assert reload_calls == []


def test_start_after_end_rejected(
    make_request, scripted_stdscr, headless_curses, monkeypatch
):
    t = _time_window_tui(make_request)
    orig_start = t.aws_context["start_time"]
    later_than_end = t.aws_context["end_time"] + timedelta(hours=1)
    monkeypatch.setattr(t, "_inline_edit", lambda *a, **k: later_than_end.isoformat())
    reload_calls = []
    monkeypatch.setattr(
        t, "_reload_log_group", lambda log_group, **k: reload_calls.append(log_group)
    )

    _run_keys(t, scripted_stdscr, [ord("w")])

    assert t.aws_context["start_time"] == orig_start
    assert t.status_kind == "error"
    assert reload_calls == []


def test_time_edit_cancel_is_noop(
    make_request, scripted_stdscr, headless_curses, monkeypatch
):
    t = _time_window_tui(make_request)
    orig_start = t.aws_context["start_time"]
    monkeypatch.setattr(t, "_inline_edit", lambda *a, **k: None)
    reload_calls = []
    monkeypatch.setattr(
        t, "_reload_log_group", lambda log_group, **k: reload_calls.append(log_group)
    )

    _run_keys(t, scripted_stdscr, [ord("w")])

    assert t.aws_context["start_time"] == orig_start
    assert t.status_kind != "error"
    assert reload_calls == []


def test_time_edit_without_log_group_updates_window_only(
    make_request, scripted_stdscr, headless_curses, monkeypatch
):
    t = _time_window_tui(make_request, log_group="")
    monkeypatch.setattr(t, "_inline_edit", lambda *a, **k: "4h")
    reload_calls = []
    monkeypatch.setattr(
        t, "_reload_log_group", lambda log_group, **k: reload_calls.append(log_group)
    )

    _run_keys(t, scripted_stdscr, [ord("w")])

    assert t.aws_context["start_time"] == t.aws_context["end_time"] - timedelta(hours=4)
    assert reload_calls == []
    assert "l" in t.status_msg


# ── Sortable log list (o / O) ──────────────────────────────────────────────


def test_default_sort_is_time_ascending(make_request):
    requests = [
        make_request(uri="/c", timestamp=3000),
        make_request(uri="/a", timestamp=1000),
        make_request(uri="/b", timestamp=2000),
    ]
    t = WafTUI(requests, auth_filter_default=False)

    assert [r.uri for r in t.filtered] == ["/a", "/b", "/c"]
    assert t.sort_field == "time"
    assert t.sort_dir == "asc"


def test_o_cycles_sort_field(make_request, scripted_stdscr, headless_curses):
    t = WafTUI([make_request()], auth_filter_default=False)

    _run_keys(t, scripted_stdscr, [ord("o")])
    assert t.sort_field == "method"
    _run_keys(t, scripted_stdscr, [ord("o")])
    assert t.sort_field == "url"
    _run_keys(t, scripted_stdscr, [ord("o")])
    assert t.sort_field == "time"


def test_capital_o_toggles_direction(make_request, scripted_stdscr, headless_curses):
    t = WafTUI([make_request()], auth_filter_default=False)

    _run_keys(t, scripted_stdscr, [ord("O")])
    assert t.sort_dir == "desc"
    _run_keys(t, scripted_stdscr, [ord("O")])
    assert t.sort_dir == "asc"


def test_sort_by_method_then_url_orders_list(
    make_request, scripted_stdscr, headless_curses
):
    requests = [
        make_request(method="GET", uri="/z", timestamp=1000),
        make_request(method="POST", uri="/a", timestamp=500),
        make_request(method="GET", uri="/a", timestamp=2000),
    ]
    t = WafTUI(requests, auth_filter_default=False)

    _run_keys(t, scripted_stdscr, [ord("o")])
    assert [(r.method, r.timestamp) for r in t.filtered] == [
        ("GET", 1000),
        ("GET", 2000),
        ("POST", 500),
    ]

    _run_keys(t, scripted_stdscr, [ord("o")])
    assert [(r.uri, r.timestamp) for r in t.filtered] == [
        ("/a", 500),
        ("/a", 2000),
        ("/z", 1000),
    ]


def test_desc_reverses_order(make_request, scripted_stdscr, headless_curses):
    requests = [
        make_request(uri="/a", timestamp=1000),
        make_request(uri="/b", timestamp=2000),
    ]
    t = WafTUI(requests, auth_filter_default=False)
    assert [r.uri for r in t.filtered] == ["/a", "/b"]

    _run_keys(t, scripted_stdscr, [ord("O")])
    assert [r.uri for r in t.filtered] == ["/b", "/a"]


def test_sort_toggle_preserves_cursor_position(
    make_request, scripted_stdscr, headless_curses
):
    requests = [
        make_request(uri="/a", timestamp=1000),
        make_request(uri="/b", timestamp=2000),
        make_request(uri="/c", timestamp=3000),
        make_request(uri="/d", timestamp=4000),
        make_request(uri="/e", timestamp=5000),
    ]
    t = WafTUI(requests, auth_filter_default=False)
    t.cursor = 1
    assert t.filtered[t.cursor].uri == "/b"

    _run_keys(t, scripted_stdscr, [ord("O")])
    assert t.cursor == 1


def test_sort_preference_written_to_db(tmp_path, scripted_stdscr, headless_curses):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    t = WafTUI([], db=conn)

    _run_keys(t, scripted_stdscr, [ord("o")])
    _run_keys(t, scripted_stdscr, [ord("O")])

    assert storage.get_preference(conn, "sort_field") == "method"
    assert storage.get_preference(conn, "sort_dir") == "desc"


def test_sort_preference_survives_reopen(
    tmp_path, make_request, scripted_stdscr, headless_curses
):
    db_path = str(tmp_path / "logs.db")
    conn = storage.open_db(db_path)
    t = WafTUI([], db=conn)
    _run_keys(t, scripted_stdscr, [ord("o")])
    conn.close()

    reopened = storage.open_db(db_path)
    sort_field = storage.get_preference(
        reopened, "sort_field", storage.DEFAULT_SORT_FIELD
    )
    sort_dir = storage.get_preference(reopened, "sort_dir", storage.DEFAULT_SORT_DIR)
    assert sort_field == "method"

    requests = [
        make_request(method="GET", uri="/z"),
        make_request(method="POST", uri="/a"),
    ]
    t2 = WafTUI(
        requests,
        auth_filter_default=False,
        initial_sort_field=sort_field,
        initial_sort_dir=sort_dir,
    )
    assert [r.method for r in t2.filtered] == ["GET", "POST"]


def test_sort_noop_persistence_when_db_none(
    make_request, scripted_stdscr, headless_curses
):
    t = WafTUI([make_request()], db=None, auth_filter_default=False)
    _run_keys(t, scripted_stdscr, [ord("o"), ord("O")])  # must not raise


# ── Source view toggle (SRC-05) ───────────────────────────────────────────


def _source_tui(make_request, sources, **kwargs):
    """Single-entry TUI whose record carries `sources` provenance."""
    req = make_request(**kwargs)
    if sources is not None:
        req.raw["_sources"] = sources
    return WafTUI([req], auth_filter_default=False)


def test_source_view_default_merged(make_request):
    t = _source_tui(make_request, "cwl,waf")
    assert t._source_view == "merged"


def test_source_cycle_with_multi_source_record(
    make_request, scripted_stdscr, headless_curses
):
    t = _source_tui(make_request, "cwl,waf")

    _run_keys(t, scripted_stdscr, [ord("S")])
    assert t._source_view == "cwl"
    _run_keys(t, scripted_stdscr, [ord("S")])
    assert t._source_view == "waf"
    _run_keys(t, scripted_stdscr, [ord("S")])
    assert t._source_view == "merged"


def test_source_cycle_without_provenance_stays_merged(
    make_request, scripted_stdscr, headless_curses
):
    t = _source_tui(make_request, None)

    _run_keys(t, scripted_stdscr, [ord("S"), ord("S")])
    assert t._source_view == "merged"


def test_source_cycle_single_source(make_request, scripted_stdscr, headless_curses):
    t = _source_tui(make_request, "cwl")

    _run_keys(t, scripted_stdscr, [ord("S")])
    assert t._source_view == "cwl"
    _run_keys(t, scripted_stdscr, [ord("S")])
    assert t._source_view == "merged"


def test_source_view_resets_on_cursor_move(
    make_request, scripted_stdscr, headless_curses
):
    requests = [make_request(uri="/a"), make_request(uri="/b")]
    for r in requests:
        r.raw["_sources"] = "cwl,waf"
    t = WafTUI(requests, auth_filter_default=False)

    _run_keys(t, scripted_stdscr, [ord("S"), curses.KEY_DOWN])

    assert t.cursor == 1
    assert t._source_view == "merged"


def test_body_unavailable_waf_only(make_request):
    req = make_request(body="")
    req.raw["_sources"] = "waf"

    lines = tui_module.build_detail_lines(req, "curl")

    assert any("(body not available via WAF sampling API)" in line for line in lines)


def test_body_unavailable_not_shown_for_cwl_record(make_request):
    req = make_request(body="")
    req.raw["_sources"] = "cwl"

    lines = tui_module.build_detail_lines(req, "curl")

    assert not any("body not available" in line for line in lines)


def test_source_view_indicator_in_status_bar(
    make_request, scripted_stdscr, headless_curses
):
    t = _source_tui(make_request, "cwl,waf")
    t._source_view = "cwl"
    stdscr = scripted_stdscr()

    t._draw(stdscr)

    assert any("Source: cwl" in line for line in stdscr.drawn)


def test_merged_view_has_no_source_indicator(
    make_request, scripted_stdscr, headless_curses
):
    t = _source_tui(make_request, "cwl,waf")
    stdscr = scripted_stdscr()

    t._draw(stdscr)

    assert not any("Source:" in line for line in stdscr.drawn)


def test_detail_pane_renders_source_specific_record(tmp_path, waf_record, make_request):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(
        conn,
        "cwl",
        "g1",
        [waf_record(uri="/a", headers={"Authorization": "REDACTED"})],
    )

    merged = make_request(uri="/a", headers={"Authorization": "Bearer merged"})
    merged.raw["_sources"] = "cwl,waf"
    t = WafTUI(
        [merged],
        auth_filter_default=False,
        db=conn,
        source_info={"log_group": "g1"},
    )

    t._source_view = "cwl"
    assert t._detail_request().headers["Authorization"] == "REDACTED"

    t._reset_source_view()
    assert t._detail_request().headers["Authorization"] == "Bearer merged"


def test_detail_pane_falls_back_when_source_has_no_record(
    tmp_path, waf_record, make_request
):
    conn = storage.open_db(str(tmp_path / "logs.db"))
    storage.save_source_records(conn, "cwl", "g1", [waf_record(uri="/other")])

    merged = make_request(uri="/a")
    merged.raw["_sources"] = "cwl,waf"
    t = WafTUI(
        [merged],
        auth_filter_default=False,
        db=conn,
        source_info={"log_group": "g1"},
    )

    t._source_view = "cwl"
    assert t._detail_request() is merged


def test_source_view_normalizes_sampled_headers(tmp_path, make_request):
    """WAF sampling stores API-cased {Name,Value} headers; the source view
    must normalize them instead of rendering a header with an empty name."""
    conn = storage.open_db(str(tmp_path / "logs.db"))
    sampled = {
        "timestamp": 1735689600000,
        "action": "ALLOW",
        "httpRequest": {
            "httpMethod": "GET",
            "uri": "/a",
            "args": "",
            "clientIp": "203.0.113.7",
            "headers": [{"Name": "Authorization", "Value": "Bearer clear"}],
            "requestBody": "",
        },
    }
    storage.save_source_records(conn, "waf", "g1", [sampled])

    merged = make_request(uri="/a", headers={"Authorization": "REDACTED"})
    merged.raw["_sources"] = "cwl,waf"
    t = WafTUI(
        [merged],
        auth_filter_default=False,
        db=conn,
        source_info={"log_group": "g1"},
    )

    t._source_view = "waf"
    assert t._detail_request().headers["Authorization"] == "Bearer clear"


def test_cursor_follows_entry_across_sort_change(
    make_request, scripted_stdscr, headless_curses
):
    requests = [
        make_request(uri="/a", timestamp=1000),
        make_request(uri="/b", timestamp=2000),
        make_request(uri="/c", timestamp=3000),
    ]
    t = WafTUI(requests, auth_filter_default=False)
    t.cursor = 1
    target = t.filtered[1]

    _run_keys(t, scripted_stdscr, [ord("O")])

    assert t.filtered[t.cursor] is target
