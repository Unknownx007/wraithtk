"""JSON and HTML report writers."""

import json
import time
from pathlib import Path

from wraithtk.ui.palette import PALETTE, sev_color


def write_json(session, path: str | None = None) -> str:
    if not path:
        path = f"wraithtk-report-{time.strftime('%Y%m%d-%H%M%S')}.json"
    data = {
        "tool": "WraithTK",
        "version": "0.1.0",
        "author": "DEDSEC",
        "target": session.target,
        "subprotocol": session.subprotocol,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "finding_count": len(session.findings),
        "findings": session.findings,
    }
    Path(path).write_text(json.dumps(data, indent=2))
    return path


def write_html(session, path: str | None = None) -> str:
    if not path:
        path = f"wraithtk-report-{time.strftime('%Y%m%d-%H%M%S')}.html"

    rows = []
    for f in session.findings:
        sev = f.get("severity", "info")
        color = sev_color(sev)
        rows.append(
            f"<tr>"
            f"<td style='color:{color};font-weight:bold'>{sev.upper()}</td>"
            f"<td><code>{f.get('type', '-')}</code></td>"
            f"<td>{_esc(f.get('detail', '-'))}</td>"
            f"<td><pre>{_esc(f.get('evidence', ''))[:500]}</pre></td>"
            f"</tr>"
        )

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WraithTK report — {_esc(session.target)}</title>
<style>
  body {{ background:#000; color:#d0d0d0; font-family:monospace; padding:2em; }}
  h1 {{ color:{PALETTE['primary']}; }}
  h2 {{ color:{PALETTE['accent']}; border-bottom:1px solid #333; padding-bottom:.3em; }}
  table {{ border-collapse:collapse; width:100%; margin-top:1em; }}
  th,td {{ border:1px solid #222; padding:.5em .8em; text-align:left; vertical-align:top; }}
  th {{ background:#111; color:{PALETTE['primary']}; }}
  tr:nth-child(even) {{ background:#0a0a0a; }}
  code,pre {{ color:#e8e8e8; }}
  .meta {{ color:#666; font-size:.9em; }}
  .brand {{ color:{PALETTE['primary']}; font-weight:bold; }}
</style>
</head>
<body>
  <h1><span class="brand">WraithTK</span> — WebSocket Security Report</h1>
  <p class="meta">
    Target: <code>{_esc(session.target)}</code><br>
    Subprotocol: <code>{_esc(session.subprotocol or '(none)')}</code><br>
    Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}<br>
    Findings: {len(session.findings)}
  </p>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>Detail</th><th>Evidence</th></tr></thead>
    <tbody>
      {''.join(rows) or '<tr><td colspan=4>no findings</td></tr>'}
    </tbody>
  </table>
  <p class="meta" style="margin-top:3em">
    WraithTK v0.1.0 · by DEDSEC · authorized testing only
  </p>
</body>
</html>
"""
    Path(path).write_text(html)
    return path


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;"))
