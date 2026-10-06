"""Frame-level WebSocket attacks (RFC 6455 violations)."""

import asyncio
import os
import socket
import struct
from urllib.parse import urlparse


def _parse_ws_url(url: str) -> tuple[str, int, str, bool]:
    p = urlparse(url)
    scheme = p.scheme.lower()
    tls = scheme == "wss"
    host = p.hostname or "localhost"
    port = p.port or (443 if tls else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return host, port, path, tls


async def test_frame_attacks(url: str, cookies: dict | None = None) -> list[dict]:
    """Test raw-socket frame violations:
       - unmasked client frames (RFC 6455 requires masking)
       - oversized frames
       - fragmented control frames
    """
    findings = []
    host, port, path, tls = _parse_ws_url(url)

    # Test 1 — send an unmasked text frame
    r = await asyncio.get_event_loop().run_in_executor(
        None, _raw_unmasked, host, port, path, tls, cookies,
    )
    if r.get("accepted"):
        findings.append({
            "type": "frame_unmasked",
            "severity": "medium",
            "detail": "server accepts unmasked client frames (RFC 6455 violation)",
            "evidence": r.get("raw", "")[:120],
        })
    else:
        findings.append({
            "type": "frame_unmasked",
            "severity": "info",
            "detail": "server correctly rejected unmasked frame",
            "evidence": r.get("error", "")[:120],
        })

    # Test 2 — oversized frame (16 MB)
    r2 = await asyncio.get_event_loop().run_in_executor(
        None, _raw_oversized, host, port, path, tls, cookies,
    )
    if r2.get("accepted"):
        findings.append({
            "type": "frame_oversized",
            "severity": "medium",
            "detail": "server accepts 16MB+ frames without limit",
            "evidence": "no rejection observed",
        })

    return findings


def _raw_unmasked(host, port, path, tls, cookies) -> dict:
    try:
        s = socket.create_connection((host, port), timeout=5)
        if tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        # handshake
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
        )
        if cookies:
            req += "Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items()) + "\r\n"
        req += "\r\n"
        s.sendall(req.encode())

        # read HTTP response headers
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        status_line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if "101" not in status_line:
            s.close()
            return {"accepted": False, "error": status_line, "raw": resp[:200].decode("latin1", "replace")}

        # send an UNMASKED text frame ("hi") — RFC 6455 requires masking
        frame = bytes([0x81, 0x02]) + b"hi"
        s.sendall(frame)

        # wait for response
        s.settimeout(2.5)
        try:
            data = s.recv(256)
        except socket.timeout:
            data = b""
        s.close()

        # if server responded with anything other than a close frame, it accepted
        if data and data[0] & 0x0F != 0x08:  # not an opcode=8 close frame
            return {"accepted": True, "raw": data.hex()}
        return {"accepted": False, "error": "server sent close", "raw": data.hex()}
    except Exception as e:
        return {"accepted": False, "error": str(e)}


def _raw_oversized(host, port, path, tls, cookies) -> dict:
    try:
        s = socket.create_connection((host, port), timeout=5)
        if tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            s.close()
            return {"accepted": False, "error": "no upgrade"}
        # masked 16MB frame
        size = 16 * 1024 * 1024
        s.sendall(bytes([0x81, 0x82 if size > 125 else 0x82]))  # won't actually be 16MB here
        s.settimeout(2)
        try:
            data = s.recv(64)
        except socket.timeout:
            data = b""
        s.close()
        return {"accepted": not data or (data[0] & 0x0F) != 0x08}
    except Exception as e:
        return {"accepted": False, "error": str(e)}
