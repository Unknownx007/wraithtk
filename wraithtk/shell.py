"""WraithTK interactive shell."""

import asyncio
import shlex
import time
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from wraithtk.attacks.cswsh import test_cswsh
from wraithtk.attacks.injection import test_injection
from wraithtk.attacks.frame import test_frame_attacks
from wraithtk.attacks.origin import test_host_header
from wraithtk.connection.manager import fetch_handshake
from wraithtk.reporting import output as rep
from wraithtk.state import Session
from wraithtk.ui.output import console, ok, fail, warn, info, findings_table
from wraithtk.ui.palette import PALETTE


_COMMANDS = [
    "target", "handshake", "cswsh", "inject", "frames", "origin",
    "scan", "findings", "report", "probe", "clear", "help", "exit",
]


_STYLE = Style.from_dict({
    "prompt.brand": "ansibrightgreen bold",
    "prompt.target": "ansibrightcyan",
    "prompt.arrow": "ansibrightgreen bold",
})


def _prompt(s: Session):
    return [
        ("class:prompt.brand", "wraith"),
        ("class:prompt.target", f" [{s.target or 'no-target'}]"),
        ("class:prompt.arrow", " > "),
    ]


def _hist():
    return str(Path.home() / ".wraithtk_history")


def _async(coro):
    """Run a coroutine. Creates a fresh loop each call — safe in sync shell."""
    return asyncio.run(coro)


def _progress_ctx():
    return Progress(
        SpinnerColumn(style=PALETTE["primary"]),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style=PALETTE["primary"]),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )


def cmd_target(s: Session, args: list[str]) -> None:
    if not args:
        warn("usage: target <ws://host:port/path>")
        return
    raw = args[0]
    # Normalize schemes
    if raw.startswith("https://"):
        raw = "wss://" + raw[len("https://"):]
        info("auto-converted https:// → wss://")
    elif raw.startswith("http://"):
        raw = "ws://" + raw[len("http://"):]
        info("auto-converted http:// → ws://")
    elif not (raw.startswith("ws://") or raw.startswith("wss://")):
        raw = "wss://" + raw
        info("auto-prepended wss://")

    # Strip trailing slash, add /ws if no path
    from urllib.parse import urlparse
    p = urlparse(raw)
    if not p.path or p.path == "/":
        raw = raw.rstrip("/") + "/ws"
        info("auto-appended /ws (default WS path — adjust if your target differs)")

    s.target = raw
    ok(f"target = {s.target}")
    info("tip: run 'handshake' first — if HTTP != 101, the path is wrong")


def cmd_handshake(s: Session, args: list[str]) -> None:
    if not s.target:
        fail("no target set — use: target ws://...")
        return
    with console.status(f"[{PALETTE['primary']}]analyzing handshake..."):
        r = _async(fetch_handshake(s.target, cookies=s.cookies))
    s.last_handshake = r
    if r.get("accepted"):
        ok(f"HTTP {r['status']} — upgrade accepted")
        console.print(f"  [dim]subprotocol:[/] {r.get('subprotocol') or '(none)'}")
        for k, v in r.get("headers", {}).items():
            if k.lower().startswith("sec-websocket") or k.lower() in ("server", "upgrade"):
                console.print(f"  [dim]{k}:[/] {v}")
    else:
        warn(f"HTTP {r.get('status')} — not upgraded")
        if r.get("error"):
            console.print(f"  [dim]{r['error']}[/]")


def cmd_cswsh(s: Session, args: list[str]) -> None:
    if not s.target:
        fail("no target")
        return
    with _progress_ctx() as prog:
        tid = prog.add_task("[cyan]testing CSWSH...", total=100)
        def on_progress(done, total, origin):
            prog.update(tid, completed=done, total=total)
        with console.status(""):
            pass
        # The actual call is async; we wrap with a progress callback but since
        # the callback is synchronous, we pass a simple lambda that updates.
        findings = _async(test_cswsh(s.target, cookies=s.cookies, progress=on_progress))
    for f in findings:
        s.findings.append(f)
    console.print(findings_table(findings))


def cmd_inject(s: Session, args: list[str]) -> None:
    if not s.target:
        fail("no target")
        return
    template = '{"input":"__INJ__"}'
    if args:
        template = args[0]
    console.print(f"[dim]template: {template}[/]")
    total_classes = 7
    with _progress_ctx() as prog:
        tid = prog.add_task("[cyan]fuzzing...", total=100)
        def on_progress(done, total, label):
            prog.update(tid, completed=done, total=total, description=f"[cyan]{label}")
        findings = _async(test_injection(s.target, field_template=template,
                                          cookies=s.cookies, progress=on_progress))
    for f in findings:
        s.findings.append(f)
    console.print(findings_table(findings))


def cmd_frames(s: Session, args: list[str]) -> None:
    if not s.target:
        fail("no target")
        return
    with console.status(f"[{PALETTE['primary']}]raw frame attacks..."):
        findings = _async(test_frame_attacks(s.target, cookies=s.cookies))
    for f in findings:
        s.findings.append(f)
    console.print(findings_table(findings))


def cmd_origin(s: Session, args: list[str]) -> None:
    if not s.target:
        fail("no target")
        return
    with console.status(f"[{PALETTE['primary']}]host header variations..."):
        findings = _async(test_host_header(s.target, cookies=s.cookies))
    for f in findings:
        s.findings.append(f)
    console.print(findings_table(findings))


def cmd_scan(s: Session, args: list[str]) -> None:
    if not s.target:
        fail("no target")
        return
    cmd_handshake(s, [])
    cmd_cswsh(s, [])
    cmd_origin(s, [])
    cmd_inject(s, [])
    cmd_frames(s, [])
    console.print()
    console.print(findings_table(s.findings))


def cmd_findings(s: Session, args: list[str]) -> None:
    if not s.findings:
        info("no findings yet")
        return
    console.print(findings_table(s.findings))


def cmd_report(s: Session, args: list[str]) -> None:
    if not s.findings:
        info("no findings — run scan first")
        return
    fmt = args[0] if args else "all"
    if fmt in ("json", "all"):
        p = rep.write_json(s)
        ok(f"json: {p}")
    if fmt in ("html", "all"):
        p = rep.write_html(s)
        ok(f"html: {p}")


def cmd_probe(s: Session, args: list[str]) -> None:
    """Probe common WebSocket paths on the target host."""
    if not s.target:
        fail("set target first (hostname works — the tool will use wss://)")
        return
    console.print(f"[dim]probing {len(__import__('wraithtk.connection.manager', fromlist=['COMMON_WS_PATHS']).COMMON_WS_PATHS)} common paths...[/dim]")
    from wraithtk.connection.manager import probe_paths
    with console.status(f"[{PALETTE['primary']}]probing..."):
        results = _async(probe_paths(s.target, cookies=s.cookies))
    if not results:
        warn("no reachable WebSocket endpoints found")
        info("find the path in browser DevTools → Network → WS filter")
        return
    ok(f"found {len(results)} endpoint(s)")
    from rich.table import Table
    t = Table(border_style=PALETTE["border"], header_style=f"bold {PALETTE['accent']}")
    t.add_column("URL", style=PALETTE["primary"])
    t.add_column("Subprotocol", style=PALETTE["dim"])
    for r in results:
        t.add_row(r["url"], r.get("subprotocol") or "-")
    console.print(t)
    if len(results) == 1:
        s.target = results[0]["url"]
        ok(f"auto-set target: {s.target}")


def cmd_clear(s: Session, args: list[str]) -> None:
    console.clear()


def cmd_help(s: Session, args: list[str]) -> None:
    console.print(f"[bold {PALETTE['primary']}]commands[/]")
    for line in [
        "target <ws://...>               set the WebSocket endpoint",
        "handshake                        analyze upgrade handshake",
        "cswsh                            cross-site WebSocket hijacking test",
        "inject [json_template]           injection fuzzing (template: '{\"input\":\"{}\"}')",
        "frames                           raw frame-level attacks",
        "origin                           origin / host-header variations",
        "scan                             run all attacks",
        "findings                         show all findings so far",
        "report [json|html|all]           write report file(s)",
        "probe                            probe common WS paths on target host",
        "clear / exit / help",
    ]:
        console.print(f"  [{PALETTE['accent']}]{line}[/]")


def cmd_exit(s: Session, args: list[str]) -> None:
    s.running = False


COMMANDS = {
    "target": cmd_target, "handshake": cmd_handshake,
    "cswsh": cmd_cswsh, "inject": cmd_inject,
    "frames": cmd_frames, "origin": cmd_origin,
    "scan": cmd_scan, "findings": cmd_findings,
    "report": cmd_report, "probe": cmd_probe, "clear": cmd_clear,
    "help": cmd_help, "exit": cmd_exit, "quit": cmd_exit,
}


def run(state: Session) -> None:
    session = PromptSession(
        history=FileHistory(_hist()),
        completer=WordCompleter(_COMMANDS, ignore_case=True),
        complete_while_typing=True,
        style=_STYLE,
    )
    console.print(f"[dim]type [bold]help[/bold] for commands, [bold]exit[/bold] to quit[/dim]\n")
    while state.running:
        try:
            line = session.prompt(_prompt(state))
        except (KeyboardInterrupt, EOFError):
            console.print()
            break
        try:
            parts = shlex.split(line)
        except ValueError as e:
            fail(f"parse error: {e}")
            continue
        if not parts:
            continue
        name, args = parts[0].lower(), parts[1:]
        fn = COMMANDS.get(name)
        if not fn:
            fail(f"unknown command: {name}")
            continue
        try:
            fn(state, args)
        except Exception as e:
            fail(f"error: {e}")
    console.print("[dim]goodbye[/dim]")
