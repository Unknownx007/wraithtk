"""Origin / host header manipulation testing."""

from wraithtk.connection.manager import try_connect


HOST_HEADER_TESTS = [
    "attacker.com",
    "localhost",
    "127.0.0.1",
    "",
    "a" * 200,
    "target.com/../evil.com",
    "target.com@evil.com",
    "target.com:80@evil.com",
]


async def test_host_header(url: str, cookies: dict | None = None) -> list[dict]:
    """Probe variations of the Origin header alongside missing ones."""
    findings = []

    # Test with no Origin header at all
    r = await try_connect(url, origin="", cookies=cookies)
    if r.get("connected"):
        findings.append({
            "type": "origin_missing",
            "severity": "low",
            "detail": "connection succeeds with no Origin header (may be acceptable)",
            "evidence": "handshake OK",
        })

    # Test with mangled origins
    accepted = []
    for origin in HOST_HEADER_TESTS:
        r = await try_connect(url, origin=origin, cookies=cookies)
        if r.get("connected"):
            accepted.append(repr(origin))

    if accepted:
        findings.append({
            "type": "origin_bypass",
            "severity": "high",
            "detail": f"server accepts {len(accepted)} malformed Origin value(s)",
            "evidence": "accepted: " + ", ".join(accepted),
        })

    return findings
