"""Response differ + oracle detection for injection."""

import re

from wraithtk.fuzz.payloads import ERROR_SIGNATURES


def detect_injection(payload_class: str, payload: str,
                     responses: list[str]) -> dict:
    """Check if responses contain error signatures for a given payload class."""
    joined = "\n".join(responses)
    for sig in ERROR_SIGNATURES.get(payload_class, []):
        if sig in joined:
            return {
                "found": True,
                "signature": sig,
                "severity": "high" if payload_class in ("sqli", "cmdi", "xxe") else "medium",
                "evidence": _context(joined, sig),
            }
    return {"found": False}


def _context(text: str, needle: str, span: int = 60) -> str:
    i = text.find(needle)
    if i < 0:
        return ""
    return text[max(0, i - span):i + span].replace("\n", " ")


def detect_reflection(payload: str, responses: list[str]) -> dict:
    """Detect if the payload is reflected unescaped in responses."""
    joined = "\n".join(responses)
    if payload in joined:
        # check if it's literally reflected (XSS candidate)
        if payload_class_xss(payload):
            return {
                "found": True,
                "severity": "high",
                "evidence": _context(joined, payload),
            }
    return {"found": False}


def payload_class_xss(payload: str) -> bool:
    lowered = payload.lower()
    return any(m in lowered for m in ("<script", "onerror=", "onload=", "javascript:"))


def diff_responses(baseline: str, mutated: str, threshold: float = 0.30) -> dict:
    """Simple response differ. Returns change ratio and whether it's meaningful."""
    if not baseline and not mutated:
        return {"changed": False, "ratio": 0.0}
    if not baseline or not mutated:
        return {"changed": True, "ratio": 1.0, "reason": "length difference"}
    min_len = min(len(baseline), len(mutated))
    max_len = max(len(baseline), len(mutated))
    if max_len == 0:
        return {"changed": False, "ratio": 0.0}
    same = sum(1 for i in range(min_len) if baseline[i] == mutated[i])
    ratio = 1.0 - (same / max_len)
    return {"changed": ratio > threshold, "ratio": round(ratio, 3)}

# SQLite and other DB error markers we care about
DB_ERROR_MARKERS = [
    "sqlite3", "OperationalError", "no such column", "no such table",
    "syntax error", "unrecognized token", "SQL logic error",
    "mysql", "mysqli", "PostgreSQL", "pg_query", "ORA-", "SQLSTATE",
]


def detect_boolean_differential(baseline: str, response: str) -> dict:
    """Detect injection by comparing baseline response to payload response.

    A SQLi payload that changes the WHERE clause will produce a
    different dataset, even without raising an error.
    """
    if not baseline or not response:
        return {"found": False}

    # Length change
    bl, rl = len(baseline), len(response)
    if bl == 0 and rl > 0:
        return {"found": True, "reason": "empty baseline, non-empty response",
                "delta": rl - bl}
    if bl == 0:
        return {"found": False}

    delta_pct = abs(rl - bl) / bl

    # Content change
    content_same = baseline.strip() == response.strip()

    # Large length difference OR large content difference
    if delta_pct > 0.4 and not content_same:
        return {"found": True, "reason": f"length delta {delta_pct:.0%}",
                "delta": rl - bl}

    return {"found": False, "reason": f"delta {delta_pct:.0%}, same={content_same}"}


def detect_any_error(response: str) -> dict:
    """Look for any DB error marker in the response."""
    for marker in DB_ERROR_MARKERS:
        if marker.lower() in response.lower():
            return {"found": True, "marker": marker}
    return {"found": False}

