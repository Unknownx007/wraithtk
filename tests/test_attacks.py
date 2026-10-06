"""Integration tests — spin up lab server, attack it."""
import asyncio
import pytest

from wraithtk.lab import server as lab_server
from wraithtk.attacks.cswsh import test_cswsh
from wraithtk.attacks.injection import test_injection


LAB_URL = "ws://127.0.0.1:8766/ws"


@pytest.fixture(scope="module")
def lab():
    """Start lab server in a background thread."""
    import threading
    import asyncio as aio
    loop = aio.new_event_loop()
    stop = [False]

    def run():
        aio.set_event_loop(loop)
        lab_server.init_db()
        async def serve():
            import websockets
            async with websockets.serve(lab_server.handler, "127.0.0.1", 8766):
                while not stop[0]:
                    await aio.sleep(0.1)
        loop.run_until_complete(serve())

    t = threading.Thread(target=run, daemon=True)
    t.start()
    import time
    time.sleep(1.0)
    yield
    stop[0] = True
    time.sleep(0.3)


def test_cswsh_finds_vulnerability(lab):
    findings = asyncio.get_event_loop().run_until_complete(test_cswsh(LAB_URL))
    severities = [f["severity"] for f in findings]
    assert "critical" in severities, f"expected CSWSH critical, got {findings}"


def test_injection_finds_sqli(lab):
    findings = asyncio.get_event_loop().run_until_complete(
        test_injection(LAB_URL, classes=["sqli"])
    )
    types = [f["type"] for f in findings if f["severity"] == "high"]
    assert any("sqli" in t for t in types), f"expected sqli finding, got {findings}"
