"""WraithTK CLI entry point."""

import argparse
import sys

from wraithtk._meta import __author__, __version__
from wraithtk.ui.banner import show_banner
from wraithtk.ui.output import console
from wraithtk.state import Session
from wraithtk.shell import run

HELP = f"""
[bold]WraithTK {__version__}[/bold] — WebSocket security toolkit. By {__author__}.

[bold]Usage:[/bold]
  wraithtk                        interactive shell
  wraithtk lab                    start vulnerable test server
  wraithtk --version
  wraithtk --help
"""


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])

    if "--version" in argv or "-V" in argv:
        console.print(f"WraithTK {__version__} — by {__author__}")
        return 0
    if "--help" in argv or "-h" in argv:
        console.print(HELP)
        return 0

    if argv and argv[0] == "lab":
        from wraithtk.lab.server import run as lab_run
        # strip "lab" and pass remaining args
        sys.argv = ["wraithtk-lab"] + argv[1:]
        lab_run()
        return 0

    no_banner = "--no-banner" in argv
    no_anim = "--no-anim" in argv

    if not no_banner:
        show_banner(console, animate=not no_anim)

    run(Session())
    return 0


if __name__ == "__main__":
    sys.exit(main())
