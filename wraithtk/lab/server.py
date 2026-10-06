"""Vulnerable WebSocket lab server for testing WraithTK.

Run: python -m wraithtk.lab.server --port 8765
"""

import argparse
import asyncio
import json
import sqlite3

import websockets


# Intentional vulnerabilities:
#   1. CSWSH — origin not validated
#   2. SQLi — user-controlled string concatenated into query
#   3. XSS — reflected without encoding
#   4. Unmasked frames accepted (websockets default)

DB = sqlite3.connect(":memory:", check_same_thread=False)


def init_db():
    cur = DB.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, name TEXT, secret TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'alice', 'flag{alice_secret}')")
    cur.execute("INSERT INTO users VALUES (2, 'bob', 'flag{bob_secret}')")
    DB.commit()


def handle_message(msg: str) -> str:
    try:
        data = json.loads(msg)
    except Exception:
        return json.dumps({"error": "invalid json"})

    if "input" in data:
        value = str(data["input"])
        # VULN: SQLi — string concat
        try:
            cur = DB.cursor()
            cur.execute(f"SELECT name, secret FROM users WHERE name = '{value}'")
            rows = cur.fetchall()
            if rows:
                return json.dumps({"result": rows})
        except Exception as e:
            # VULN: leak the error
            return json.dumps({"error": f"SQL error: {e}"})
        # VULN: XSS reflection
        return json.dumps({"echo": value})

    if data.get("action") == "ping":
        return json.dumps({"pong": True})
    if data.get("action") == "info":
        return json.dumps({"server": "wraithtk-lab", "version": "0.1.0", "vulnerable": True})
    return json.dumps({"error": "unknown"})


async def handler(ws):
    try:
        async for msg in ws:
            if isinstance(msg, bytes):
                msg = msg.decode("utf-8", "replace")
            resp = handle_message(msg)
            await ws.send(resp)
    except websockets.ConnectionClosed:
        pass


async def main(host: str, port: int):
    init_db()
    print(f"[+] WraithTK lab running on ws://{host}:{port}/ws")
    print(f"[+] Intentionally vulnerable — CSWSH, SQLi, XSS")
    async with websockets.serve(handler, host, port):
        await asyncio.Future()


def run():
    ap = argparse.ArgumentParser(description="WraithTK lab server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    try:
        asyncio.run(main(args.host, args.port))
    except KeyboardInterrupt:
        print("\n[+] lab stopped")


if __name__ == "__main__":
    run()
