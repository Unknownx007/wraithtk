"""Smoke tests — no network needed."""
import pytest
from wraithtk.fuzz.detectors import detect_injection, diff_responses
from wraithtk.fuzz.payloads import INJECTION_PAYLOADS, CSWSH_ORIGINS


def test_payloads_nonempty():
    assert len(CSWSH_ORIGINS) >= 10
    for cls, lst in INJECTION_PAYLOADS.items():
        assert lst, f"{cls} has no payloads"


def test_detect_sqli_signature():
    r = detect_injection("sqli", "'", ["SQL syntax error near"])
    assert r["found"] is True
    assert r["severity"] == "high"


def test_detect_no_signature():
    r = detect_injection("sqli", "'", ["hello world"])
    assert r["found"] is False


def test_diff_responses_identical():
    r = diff_responses("hello", "hello")
    assert r["changed"] is False


def test_diff_responses_different():
    r = diff_responses("hello", "world!!!")
    assert r["changed"] is True
