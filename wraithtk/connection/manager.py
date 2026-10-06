"""WebSocket connection + handshake analysis."""

import asyncio
import ssl
from typing import Optional

import httpx
import websockets



# websockets renamed extra_headers to additional_headers in v14.
try:
    import websockets
    _WS_VERSION = tuple(int(x) for x in websockets.__version__.split(".")[:2])
except Exception:
    _WS_VERSION = (12, 0)


def _ws_kwargs(extra: dict) -> dict:
    """Return the correct keyword arg name for websockets version."""
    if _WS_VERSION >= (14, 0):
        return {"additional_headers": extra}
    return {"extra_headers": extra}


def _connect_kwargs(url: str, extra: dict, subprotocols, timeout: float) -> dict:
    """Build websockets.connect kwargs — SSL only for wss://."""
    import ssl as _ssl
    kw = {
        "subprotocols": subprotocols or None,
        "open_timeout": timeout,
    }
    kw.update(_ws_kwargs(extra))
    if url.startswith("wss://"):
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        kw["ssl"] = ctx
    return kw

async def fetch_handshake(url: str, origin: str = "",
                          cookies: Optional[dict] = None,
                          extra_headers: Optional[dict] = None,
                          timeout: float = 10.0) -> dict:
    """Perform the HTTP upgrade handshake and return full response info."""
    http_url = url.replace("ws://", "http://").replace("wss://", "https://")
    headers = {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
    }
    if origin:
        headers["Origin"] = origin
    if extra_headers:
        headers.update(extra_headers)

    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            r = await client.get(http_url, headers=headers, cookies=cookies)
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:500],
                "accepted": r.status_code == 101,
                "subprotocol": r.headers.get("sec-websocket-protocol", ""),
            }
    except Exception as e:
        return {"status": 0, "error": str(e), "accepted": False,
                "headers": {}, "body": "", "subprotocol": ""}


async def try_connect(url: str, origin: str = "",
                      cookies: Optional[dict] = None,
                      subprotocols: Optional[list] = None,
                      timeout: float = 10.0) -> dict:
    """Attempt a full WebSocket connection. Returns status."""
    extra = {}
    if origin:
        extra["Origin"] = origin
    if cookies:
        extra["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    try:
        kwargs = _connect_kwargs(url, extra, subprotocols, timeout)
        async with websockets.connect(url, **kwargs) as ws:
            return {"connected": True, "subprotocol": ws.subprotocol or ""}
    except Exception as e:
        return {"connected": False, "error": str(e), "subprotocol": ""}


async def send_and_receive(url: str, message: str,
                           origin: str = "",
                           cookies: Optional[dict] = None,
                           subprotocols: Optional[list] = None,
                           timeout: float = 5.0) -> dict:
    """Open, send a single message, read response(s). Returns everything."""
    extra = {}
    if origin:
        extra["Origin"] = origin
    if cookies:
        extra["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    responses = []
    try:
        kwargs = _connect_kwargs(url, extra, subprotocols, timeout)
        async with websockets.connect(url, **kwargs) as ws:
            await ws.send(message)
            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=1.5)
                    responses.append(msg if isinstance(msg, str) else msg.decode("utf-8", "replace"))
                except asyncio.TimeoutError:
                    break
        return {"ok": True, "responses": responses}
    except Exception as e:
        return {"ok": False, "error": str(e), "responses": responses}

# Common WebSocket endpoint paths to probe when the user doesn't know the URL
COMMON_WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/", "/sock",
    "/live", "/realtime", "/api/ws", "/api/websocket",
    "/api/v1/ws", "/v1/ws", "/push", "/stream",
    "/ws/", "/ws/v1", "/hub", "/signalr", "/signalr/connect",
    "/notifications", "/events", "/chat", "/chat/ws",
    "/graphql", "/subscriptions", "/echo", "/cable",
]


async def probe_paths(base_url: str, cookies: dict | None = None,
                       paths: list[str] | None = None,
                       timeout: float = 3.0) -> list[dict]:
    """Try common WebSocket paths, return those that respond with 101."""
    paths = paths or COMMON_WS_PATHS
    base = base_url.rstrip("/")
    if base.startswith("https://") or base.startswith("http://"):
        base = base.replace("https://", "wss://").replace("http://", "ws://")
    elif not base.startswith(("ws://", "wss://")):
        base = "wss://" + base

    results = []
    for path in paths:
        url = base + path
        r = await try_connect(url, cookies=cookies, timeout=timeout)
        if r.get("connected"):
            results.append({"url": url, "subprotocol": r.get("subprotocol", "")})
    return results
