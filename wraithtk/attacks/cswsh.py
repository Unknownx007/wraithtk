"""Cross-Site WebSocket Hijacking detection."""

from wraithtk.connection.manager import try_connect
from wraithtk.fuzz.payloads import CSWSH_ORIGINS


async def test_cswsh(url: str, cookies: dict | None = None,
                     progress=None) -> list[dict]:
    """Test if the server validates the Origin header during upgrade.

    A vulnerable server accepts a WebSocket upgrade from ANY Origin,
    which lets attacker.com hijack the authenticated session.
    """
    findings = []

    # First — baseline with no origin
    baseline = await try_connect(url, cookies=cookies)
    if not baseline.get("connected"):
        return [{
            "type": "cswsh",
            "severity": "info",
            "detail": "baseline connection failed — check target URL and path",
            "evidence": baseline.get("error", "")[:150],
        }]

    # Now try attacker origins
    vuln_origins = []
    for i, origin_tpl in enumerate(CSWSH_ORIGINS):
        origin = origin_tpl.replace("{target}", _extract_host(url))
        r = await try_connect(url, origin=origin, cookies=cookies)
        if r.get("connected"):
            vuln_origins.append(origin)
        if progress:
            progress(i + 1, len(CSWSH_ORIGINS), origin)

    if vuln_origins:
        findings.append({
            "type": "cswsh",
            "severity": "critical",
            "detail": f"server accepts {len(vuln_origins)} foreign origin(s)",
            "evidence": "accepted: " + ", ".join(vuln_origins[:5]),
        })
    else:
        findings.append({
            "type": "cswsh",
            "severity": "info",
            "detail": "origin header is validated",
            "evidence": f"tried {len(CSWSH_ORIGINS)} origins, none accepted",
        })

    return findings


def _extract_host(url: str) -> str:
    import re
    m = re.match(r"wss?://([^/:]+)", url)
    return m.group(1) if m else "localhost"
