"""WAF-FU banner for CLI help and TUI splash screen."""

from __future__ import annotations

import curses
import time
import unicodedata

# ANSI color codes for terminal output (CLI help)
_GREEN = "\033[38;5;46m"
_DIM_GREEN = "\033[38;5;34m"
_RESET = "\033[0m"
_BOLD = "\033[1m"

# The logo: WAF-FU text
_LOGO_LINES = [
    r"         __      __  ___   ___      ___  __ __",
    r"        / /\    / / /   | / __\    / __\/ // /",
    r"       / / /\  / / / /| |/ /_     / /_  / // / ",
    r"      / / /  \/ / / /_| / __/    / __/ / // /  ",
    r"     / / / /\  / / __  / /      / /   / // /___",
    r"    /_/_/ /  \/_/_/  |_\_|     /_/   /_/ \____/",
]

_TAGLINE = "AWS WAF Log Browser & Replayer"

# Shield icon for splash screen and CLI help
_ICON_LINES = [
    "                 🮣🭇🭊𜷡𜷞𜶻𜺣𜺣",
    "         𜺠🮣🮣🭈𜷋𜷡🭂𜷥🭝🭞🭜🭧🮅🭒𜷤𜷞🭑🭊🬽🮢𜺣𜺣",
    "       🮣🭋🬹𜷤𜷥🭁🮆𜵰🬎𜴂🭘 🭇🭇🮢🭻 🭣🬂🭧🭓🮆🭌🭌🭍🬹🬾🮢",
    "       🮡🮈🭌𜵊🭣  🭇🬭𜷡🭂𜷥🮆🮆🮆🮆𜷤🭍🬹🭑🬽𜺣 🭣𜶘🭌𜵊ʽ",
    "        🮇🭝𜴍🭈🭆🭁🭞𜷚🭝🭜𜺨 𜷋🬏 🭢🬊🭒𜷊🭓𜷤𜷞🬽𜴡🭒🭽",
    "    🭇🭊🭑🬭🭊🬶🭁🭞🭜𜺨🭅🭝🭗🭇🭆🭁🭌🬺𜷞𜶻🮢🭢🭒𜷀🭢🬊🭒🭍🬳𜶬🭯🬽𜺣𜺣",
    "🬭🬞𜷍𜷝🬰𜷣🬸𜷣🭌𜷊𜴼  🮡🮋🭪 🭢🬊🭓🭒🬝𜴦🭒🭐🮡🮊🭌🮠ʽ 𜵻𜷚🭌𜷠𜷠𜷝𜷝𜷝𜷝🬭🮢",
    "   🭢🭷𜴇𜴈𜷊𜵄𜶫🭌𜷞🬽𜺣🭔🭌🬼  🭢🭢𜺨🭇🭁🭡🭇🭁𜵊🮢🭈🭄🭁🭞🬎𜷘𜵎𜴀🭧🭷",
    "         🬦🬯𜵄🭓𜷤𜷥𜷚🭌🬿𜵑𜶜𜷞𜷡𜵰🭜𜷌🭁🬴𜷡🭁🭞𜵷🬶🬓",
    "         🭤🭒🭎𜺣 🭣🭧🮅🮆🭌𜷤🬹🬹🭂𜷥🭝🮅🬎🭘𜺨🭇🭃🭟𜺨",
    "          🭢🭒🭌🬝🬎🬎🬎🬬🭝🬎🬎🬎🬎🬬🬝🬎🬎🬎🭫🮆🮆𜵅",
    "           🭢𜴢🭌🬹𜵭𜴫𜴵𜵰𜴳𜶨🬹🬹𜴵🬺🬹𜷞🬹🭁𜴗",
    "            🭢🭣🭕𜷤🭑🭯𜶻🬽𜷕𜷀🬽🭊𜶻🭄🭝🭠𜺨ʽ",
    "              🭢🭣🬎🭒𜷠𜶾𜴸𜵳𜷝𜷣🭝🭜𜺨",
    "                 🭢🬂𜴦🭒🭝🬎🭘",
]


def _display_width(s: str) -> int:
    """Return the visible column width of *s*, accounting for wide chars."""
    w = 0
    for ch in s:
        eaw = unicodedata.east_asian_width(ch)
        w += 2 if eaw in ("W", "F") else 1
    return w


def banner_plain() -> str:
    """Return the icon as plain text (no ANSI colors)."""
    lines = _ICON_LINES + ["", f"  {_TAGLINE}"]
    return "\n".join(lines)


def banner_ansi(description: str = "") -> str:
    """Return the icon with ANSI color escapes, centered in the terminal."""
    import shutil

    term_w = shutil.get_terminal_size((80, 24)).columns

    # The icon lines have built-in leading spaces for internal alignment.
    # Center the whole block as a unit using the widest line's display width.
    icon_widths = [_display_width(l) for l in _ICON_LINES]
    max_icon_w = max(icon_widths)
    block_pad = max(0, (term_w - max_icon_w) // 2)

    out: list[str] = []
    for line in _ICON_LINES:
        out.append(f"{' ' * block_pad}{_BOLD}{_GREEN}{line}{_RESET}")
    out.append("")
    tag_pad = max(0, (term_w - len(_TAGLINE)) // 2)
    out.append(f"{' ' * tag_pad}{_DIM_GREEN}{_TAGLINE}{_RESET}")
    if description:
        desc_pad = max(0, (term_w - len(description)) // 2)
        out.append(f"{' ' * desc_pad}{description}")
    out.append("")
    return "\n".join(out)


def _draw_splash(stdscr, on_pause=None, pause_label: str = "") -> None:
    """Draw an animated splash screen using curses colors.

    If *on_pause* is given it runs during the post-animation hold (replacing
    the normal 1.2 s getch wait).  *pause_label* is shown below the tagline
    while *on_pause* executes; the splash image does not shift.
    """
    if not hasattr(stdscr, "bkgd"):
        return
    h, w = stdscr.getmaxyx()

    GREEN_PAIR = 10
    DIM_GREEN_PAIR = 11
    BRIGHT_GREEN_PAIR = 12

    curses.init_pair(GREEN_PAIR, curses.COLOR_GREEN, -1)
    curses.init_pair(DIM_GREEN_PAIR, curses.COLOR_GREEN, -1)
    curses.init_pair(BRIGHT_GREEN_PAIR, curses.COLOR_GREEN, -1)

    green = curses.color_pair(GREEN_PAIR)
    bright = curses.color_pair(BRIGHT_GREEN_PAIR) | curses.A_BOLD
    dim = curses.color_pair(DIM_GREEN_PAIR) | curses.A_DIM

    all_lines = _ICON_LINES + ["", _TAGLINE]
    total = len(all_lines)
    start_y = max(0, (h - total) // 2)

    max_icon_w = max(_display_width(l) for l in _ICON_LINES)
    block_pad = max(0, (w - max_icon_w) // 2)

    stdscr.erase()
    if hasattr(stdscr, "bkgd"):
        stdscr.bkgd(" ", curses.color_pair(0))

    try:
        curses.curs_set(0)
    except curses.error:
        pass

    for i, line in enumerate(all_lines):
        y = start_y + i
        if y >= h - 1:
            break
        if not line.strip():
            continue

        if i < len(_ICON_LINES):
            x = block_pad
            attr = bright
        else:
            x = max(0, (w - _display_width(line)) // 2)
            attr = dim
        try:
            stdscr.addnstr(y, x, line, w - x - 1, attr)
        except curses.error:
            pass
        stdscr.refresh()
        time.sleep(0.03)

    if on_pause is not None:
        note_y = start_y + total + 1
        if pause_label and note_y < h - 1:
            nx = max(0, (w - len(pause_label)) // 2)
            try:
                stdscr.addnstr(note_y, nx, pause_label, w - nx - 1, dim)
            except curses.error:
                pass
            stdscr.refresh()
        on_pause()
    else:
        stdscr.timeout(1200)
        stdscr.getch()
        stdscr.timeout(100)

    stdscr.erase()
    stdscr.refresh()
