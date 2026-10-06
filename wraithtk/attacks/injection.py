"""Injection testing via WebSocket messages."""

import json

from wraithtk.connection.manager import send_and_receive
from wraithtk.fuzz.payloads import INJECTION_PAYLOADS
from wraithtk.fuzz.detectors import (
    detect_injection, detect_reflection,
    detect_boolean_differential, detect_any_error,
)


async def test_injection(url: str,
                          field_template: str = '{"input":"__INJ__"}',
                          cookies: dict | None = None,
                          classes: list[str] | None = None,
                          progress=None) -> list[dict]:
    """Send injection payloads in WS messages, detect via multiple oracles:

      1. Known error signatures (error-based)
      2. DB error markers (sqlite3, OperationalError, etc.)
      3. Boolean differential (response differs from baseline)
      4. Reflection (for XSS)
    """
    findings = []
    classes = classes or list(INJECTION_PAYLOADS.keys())

    # ── Baseline ─────────────────────────────────────────────
    benign_msg = field_template.replace("__INJ__", "benign_value_xyz")
    baseline = await send_and_receive(url, benign_msg, cookies=cookies)
    baseline_resp = "\n".join(baseline.get("responses", []))

    if not baseline.get("ok"):
        return [{
            "type": "injection",
            "severity": "info",
            "detail": "baseline send failed — is the target up?",
            "evidence": baseline.get("error", "")[:150],
        }]

    total = sum(len(INJECTION_PAYLOADS[c]) for c in classes)
    done = 0
    seen_types: set[str] = set()

    for cls in classes:
        for payload in INJECTION_PAYLOADS[cls]:
            msg = field_template.replace("__INJ__", payload)

            r = await send_and_receive(url, msg, cookies=cookies)
            responses = r.get("responses", [])
            joined = "\n".join(responses)

            # Oracle 1 — known error signatures
            det = detect_injection(cls, payload, responses)
            if det.get("found") and f"{cls}_sig" not in seen_types:
                seen_types.add(f"{cls}_sig")
                findings.append({
                    "type": f"{cls}_injection",
                    "severity": det["severity"],
                    "detail": f"{cls} error signature '{det['signature']}' triggered",
                    "evidence": det["evidence"],
                })

            # Oracle 2 — generic DB error markers
            err = detect_any_error(joined)
            if err.get("found") and f"{cls}_err" not in seen_types:
                seen_types.add(f"{cls}_err")
                findings.append({
                    "type": f"{cls}_injection",
                    "severity": "high",
                    "detail": f"{cls}: DB error marker '{err['marker']}' in response",
                    "evidence": joined[:200],
                })

            # Oracle 3 — boolean differential (skips XSS/XXE which don't change data)
            if cls in ("sqli", "ldap", "ssrf", "traversal", "cmdi"):
                diff = detect_boolean_differential(baseline_resp, joined)
                if diff.get("found") and f"{cls}_diff" not in seen_types:
                    seen_types.add(f"{cls}_diff")
                    findings.append({
                        "type": f"{cls}_injection",
                        "severity": "high",
                        "detail": f"{cls}: {diff['reason']}",
                        "evidence": f"baseline {len(baseline_resp)}b → response {len(joined)}b: {joined[:180]}",
                    })

            # Oracle 4 — reflection (for XSS)
            if cls == "xss":
                refl = detect_reflection(payload, responses)
                if refl.get("found") and "xss_refl" not in seen_types:
                    seen_types.add("xss_refl")
                    findings.append({
                        "type": "xss_reflection",
                        "severity": "high",
                        "detail": f"payload reflected unescaped: {payload[:40]}",
                        "evidence": refl.get("evidence", ""),
                    })

            done += 1
            if progress:
                progress(done, total, f"{cls}: {payload[:30]}")

    if not findings:
        findings.append({
            "type": "injection",
            "severity": "info",
            "detail": f"no injection across {total} payloads",
            "evidence": f"baseline {len(baseline_resp)}b",
        })
    return findings
