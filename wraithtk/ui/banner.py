"""WraithTK banner — adaptive, no duplication, colorful sweep."""

import random
import shutil
import time

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from wraithtk._meta import __author__, __version__
from wraithtk.ui.palette import PALETTE

TAGLINE = "Speak WebSocket. See what the wire forgets."

QUOTES = [
    "Every frame is a confession.",
    "The handshake is where trust begins and ends.",
    "See the invisible. Own the wire.",
    "State is a language. Learn to speak it.",
    "A socket open is a door unlocked.",
    "Trust nothing. Verify the origin.",
    "Silence, then access.",
    "Every protocol has a blind spot.",
    "The wire remembers what the browser forgets.",
    "One frame is enough.",
]

SUBTITLE = "═══  b y   D E D S E C  ═══"
WORDMARK = "W R A I T H T K"

# ── tier 1: full ANSI Shadow banner (needs ~106 cols) ──
LOGO_FULL = [
    r"  .S     S.    .S_SSSs     .S_sSSs     .S  sdSS_SSSSSSbs   .S    S.   sdSS_SSSSSSbs   .S    S.   ",
    r" .SS     SS.  .SS~SSSSS   .SS~YS%%b   .SS  YSSS~S%SSSSSP  .SS    SS.  YSSS~S%SSSSSP  .SS    SS.  ",
    r" S%S     S%S  S%S   SSSS  S%S   `S%b  S%S       S%S       S%S    S%S       S%S       S%S    S&S  ",
    r" S%S     S%S  S%S    S%S  S%S    S%S  S%S       S%S       S%S    S%S       S%S       S%S    d*S  ",
    r" S%S     S%S  S%S SSSS%S  S%S    d*S  S&S       S&S       S%S SSSS%S       S&S       S&S   .S*S  ",
    r" S&S     S&S  S&S  SSS%S  S&S   .S*S  S&S       S&S       S&S  SSS&S       S&S       S&S_sdSSS   ",
    r" S&S     S&S  S&S    S&S  S&S_sdSSS   S&S       S&S       S&S    S&S       S&S       S&S~YSSY%b  ",
    r" S&S     S&S  S&S    S&S  S&S~YSY%b   S&S       S&S       S&S    S&S       S&S       S&S    `S%  ",
    r" S*S     S*S  S*S    S&S  S*S   `S%b  S*S       S*S       S*S    S*S       S*S       S*S     S%  ",
    r" S*S  .  S*S  S*S    S*S  S*S    S%S  S*S       S*S       S*S    S*S       S*S       S*S     S&  ",
    r" S*S_sSs_S*S  S*S    S*S  S*S    S&S  S*S       S*S       S*S    S*S       S*S       S*S     S&  ",
    r" SSS~SSS~S*S  SSS    S*S  S*S    SSS  S*S       S*S       SSS    S*S       S*S       S*S     SS  ",
    r"                     SP   SP          SP        SP               SP        SP        SP          ",
    r"                     Y    Y           Y         Y                Y         Y         Y           ",
]


# ── tier 2: medium — condensed 5-line version (~60 cols) ──
LOGO_MED = [
    r"  W  R  A  I  T  H  T  K ",
    r"  ╲  ╲ │┌─┐┌─┐ ┬ ─┬─ ┬ ┬ ",
    r"   ╲  ╲||-\|─| │  │  ├─┤ ",
    r"    ╲╱ ┴┴ ┴┴ ┴ ┴  ┴  ┴ ┴ ",
    r" WebSocket Security Toolkit",
]


# ── tier 3: tiny — two lines, wordmark only ──
LOGO_TINY = [
    r"     W R A I T H T K ",
    r"websocket security toolkit",
]


def _pick_logo(cols: int) -> tuple[list[str], bool]:
    """Return (logo_lines, show_wordmark_below).
    show_wordmark_below is False when the logo already contains the wordmark.
    """
    if cols >= 106:
        return LOGO_FULL, True
    if cols >= 45:
        return LOGO_MED, False
    return LOGO_TINY, False


def _hex_lerp(c1: str, c2: str, t: float) -> str:
    r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
    r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    r = int(r1 + (r2 - r1) * t)
    g = int(g1 + (g2 - g1) * t)
    b = int(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _glitch_wordmark() -> Text:
    wm = Text()
    for i, ch in enumerate(WORDMARK):
        if ch == " ":
            wm.append(" ")
        elif i % 3 == 0:
            wm.append(ch, style=f"bold {PALETTE['primary']}")
        elif i % 3 == 1:
            wm.append(ch, style=f"bold {PALETTE['accent']}")
        else:
            wm.append(ch, style=f"bold {PALETTE['secondary']}")
    return wm


def show_banner(console: Console | None = None, animate: bool = True) -> None:
    console = console or Console()
    cols = shutil.get_terminal_size((80, 24)).columns
    logo, show_wordmark = _pick_logo(cols)

    n = max(1, len(logo) - 1)
    colored = [
        (line, _hex_lerp(PALETTE["primary"], PALETTE["accent"], i / n))
        for i, line in enumerate(logo)
    ]

    console.print()
    if animate:
        for line, color in colored:
            console.print(Align.center(Text(line, style=f"bold {color}")))
            time.sleep(0.04)
    else:
        for line, color in colored:
            console.print(Align.center(Text(line, style=f"bold {color}")))

    console.print()
    if show_wordmark:
        console.print(Align.center(_glitch_wordmark()))
    console.print(Align.center(Text(SUBTITLE, style=PALETTE["dim"])))
    console.print()
    console.print(Align.center(Text(TAGLINE, style=PALETTE["text"])))
    console.print()
    console.print(
        Align.center(
            Text(f"version v{__version__}   ·   built by {__author__}",
                 style=PALETTE["dim"])
        )
    )
    console.print(
        Align.center(
            Text(f"\u201c{random.choice(QUOTES)}\u201d",
                 style=f"italic {PALETTE['dim']}")
        )
    )
    console.print()

    panel_body = Text.from_markup(
        f"[bold {PALETTE['danger']}]▓▒░  AUTHORIZED USE ONLY  ░▒▓[/]\n\n"
        f"[{PALETTE['text']}]WraithTK is intended for authorized security testing[/]\n"
        f"[{PALETTE['text']}]and educational purposes only. Use it exclusively against[/]\n"
        f"[{PALETTE['text']}]systems you own or have explicit written permission to test.[/]\n\n"
        f"[{PALETTE['dim']}]Unauthorized interception of traffic is illegal.[/]"
    )
    console.print(
        Align.center(
            Panel(
                panel_body,
                title=f"[bold {PALETTE['primary']}]◤ WraithTK ◢[/]",
                subtitle=f"[{PALETTE['dim']}]v{__version__} · DEDSEC[/]",
                border_style=PALETTE["primary"],
                padding=(1, 3),
                expand=False,
            )
        )
    )
    console.print()
