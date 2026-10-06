from rich.console import Console
from rich.markup import escape
from rich.table import Table

from wraithtk.ui.palette import PALETTE, sev_color

console = Console()
err = Console(stderr=True)


def ok(msg):    console.print(f"[{PALETTE['success']}][+][/] {msg}")
def fail(msg):  console.print(f"[{PALETTE['danger']}][-][/] {msg}")
def warn(msg):  console.print(f"[{PALETTE['warning']}][!][/] {msg}")
def info(msg):  console.print(f"[{PALETTE['dim']}][*][/] [{PALETTE['dim']}]{escape(msg)}[/]")


def findings_table(findings: list[dict]) -> Table:
    t = Table(
        title=f"[bold {PALETTE['primary']}]◤ FINDINGS ◢[/]",
        header_style=f"bold {PALETTE['accent']}",
        border_style=PALETTE["border"],
    )
    t.add_column("#", width=3, justify="right", style="dim")
    t.add_column("Severity", width=10)
    t.add_column("Type", style=PALETTE["text"], no_wrap=True)
    t.add_column("Detail", style=PALETTE["text"])
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        t.add_row(
            str(i),
            f"[bold {sev_color(sev)}]{sev.upper()}[/]",
            f.get("type", "-"),
            f.get("detail", "-")[:70],
        )
    return t
