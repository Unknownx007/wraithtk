<div align="center">

```
  .S     S.    .S_SSSs     .S_sSSs     .S  sdSS_SSSSSSbs   .S    S.   sdSS_SSSSSSbs   .S    S.
 .SS     SS.  .SS~SSSSS   .SS~YS%%b   .SS  YSSS~S%SSSSSP  .SS    SS.  YSSS~S%SSSSSP  .SS    SS.
 S%S     S%S  S%S   SSSS  S%S   `S%b  S%S       S%S       S%S    S%S       S%S       S%S    S&S
 S%S     S%S  S%S    S%S  S%S    S%S  S%S       S%S       S%S    S%S       S%S       S%S    d*S
 S%S     S%S  S%S SSSS%S  S%S    d*S  S&S       S&S       S%S SSSS%S       S&S       S&S   .S*S
 S&S     S&S  S&S  SSS%S  S&S   .S*S  S&S       S&S       S&S  SSS&S       S&S       S&S_sdSSS
 S&S     S&S  S&S    S&S  S&S_sdSSS   S&S       S&S       S&S    S&S       S&S       S&S~YSSY%b
 S&S     S&S  S&S    S&S  S&S~YSY%b   S&S       S&S       S&S    S&S       S&S       S&S    `S%
 S*S     S*S  S*S    S&S  S*S   `S%b  S*S       S*S       S*S    S*S       S*S       S*S     S%
 S*S  .  S*S  S*S    S*S  S*S    S%S  S*S       S*S       S*S    S*S       S*S       S*S     S&
 S*S_sSs_S*S  S*S    S*S  S*S    S&S  S*S       S*S       S*S    S*S       S*S       S*S     S&
 SSS~SSS~S*S  SSS    S*S  S*S    SSS  S*S       S*S       SSS    S*S       S*S       S*S     SS
                     SP   SP          SP        SP               SP        SP        SP
                     Y    Y           Y         Y                Y         Y         Y

```

# WraithTK

**WebSocket security toolkit — by DEDSEC.**

*Speak WebSocket. See what the wire forgets.*

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-00ff41?style=for-the-badge&labelColor=000000)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.1.0-00ff41?style=for-the-badge&labelColor=000000)](https://github.com/Unknownx007/WraithTK/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-4d9fff?style=for-the-badge&labelColor=000000)](https://www.python.org/downloads/)
[![CI](https://github.com/Unknownx007/WraithTK/actions/workflows/ci.yml/badge.svg)](https://github.com/Unknownx007/WraithTK/actions/workflows/ci.yml)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20only-ff0844?style=for-the-badge&labelColor=000000)](#-legal-disclaimer)

`Linux` · `macOS` · `Windows` · `CSWSH` · `injection` · `frame attacks`

</div>

---

## ⚠️ Legal disclaimer

> **WraithTK is intended for authorized security testing and educational purposes only.**

Use it exclusively against WebSocket endpoints you **own** or have **explicit written permission** to test. Unauthorized testing of systems is a criminal offense under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws worldwide.

The author (**DEDSEC**) assumes no liability for misuse.

**If you do not have written authorization, do not run this.**

---

## What is WraithTK

A focused security scanner for WebSocket endpoints. It finds the vulnerabilities that generic HTTP tools miss — the WebSocket-specific classes (CSWSH, frame-level attacks) plus every injection class that flows through a WS message.

- **Interactive shell** — `target`, `scan`, `report`, done
- **Handshake analyzer** — parses upgrade response, subprotocol negotiation
- **6 attack categories** — CSWSH, injection, frames, origin, subprotocol, custom
- **Multi-oracle detection** — error signatures, DB markers, boolean differential, reflection
- **Self-contained lab** — vulnerable target on `localhost:8765`, no external setup
- **JSON + HTML reports** — client-ready output
- **Zero external binaries** — pure Python

## What it is not

- **Not an HTTP scanner.** WebSocket endpoints only. Use Burp/ZAP for HTTP.
- **Not a proxy.** Speaks WebSocket directly; doesn't sit between browser and server.
- **Not an exploit framework.** Finds and proves vulnerabilities; doesn't auto-exploit.

---

## Install

```bash
git clone https://github.com/Unknownx007/wraithtk
cd wraithtk
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows
pip install -e .
wraithtk && wraithtk
```

Requires **Python 3.10+**. Dependencies (`websockets`, `httpx`, `rich`, `prompt_toolkit`) install automatically.

Verify:

```bash
wraithtk && wraithtk --version
```

---

## Quick start for testing own pre maded lab

### Terminal 1 — start the lab

```bash
python -m wraithtk.lab.server --port 8765
```

```
[+] WraithTK lab running on ws://127.0.0.1:8765/ws
[+] Intentionally vulnerable — CSWSH, SQLi, XSS
```

### Terminal 2 — run WraithTK

```bash
wraithtk && wraithtk
```

```
wraith [no-target] > target ws://127.0.0.1:8765/ws
[+] target = ws://127.0.0.1:8765/ws

wraith [ws://127.0.0.1:8765/ws] > scan
```

Expected — 10 findings including **1 CRITICAL** (CSWSH), **5 HIGH** (SQLi, XSS, CMDi, SSRF, origin bypass), **1 MEDIUM** (frame size).

---

## Command reference

| Command | What it does |
|---|---|
| `target <url>` | Set the endpoint. Auto-normalizes schemes and appends `/ws` if no path. |
| `handshake` | Analyze upgrade handshake. Auto-probes on non-101. |
| `probe` | Force-probe 30 common WS paths (`/socket.io/`, `/graphql`, `/cable`, `/signalr`, ...). |
| `cswsh` | Cross-Site WebSocket Hijacking — 30+ origin payloads. |
| `inject [template]` | Injection fuzzing. Default: `{"input":"__INJ__"}`. |
| `frames` | Raw frame attacks (unmasked, oversized). |
| `origin` | Origin / host-header manipulation. |
| `scan` | Run all attacks in sequence. |
| `findings` | Show everything collected this session. |
| `report [json\|html\|all]` | Write report file(s). |
| `clear` / `help` / `exit` | Self-explanatory. |

---

## Attack reference

| Attack | Command | Severity | What it detects |
|---|---|---|---|
| **CSWSH** | `cswsh` | CRITICAL | Server accepts foreign `Origin` — session hijack possible |
| **SQLi** | `inject` | HIGH | Error signatures + boolean differential |
| **XSS reflection** | `inject` | HIGH | Payload echoed unescaped |
| **CMDi** | `inject` | HIGH | Command output in response |
| **SSRF** | `inject` | HIGH | Metadata endpoint reachable via WS |
| **SSTI** | `inject` | HIGH | Template evaluation |
| **Path traversal** | `inject` | HIGH | `/etc/passwd` content leak |
| **LDAP / XXE** | `inject` | HIGH | Parse errors + content leak |
| **Origin bypass** | `origin` | HIGH | Malformed Origin accepted |
| **Oversized frames** | `frames` | MEDIUM | No size limit → DoS vector |
| **Unmasked frames** | `frames` | MEDIUM | RFC 6455 violation |

---

## Against real targets

**You must have written authorization.**

WebSocket paths aren't discoverable by port scan — they're application-specific. To find one:

1. Open the target in a browser
2. **F12** → **Network** tab → **WS** filter
3. Reload the page
4. Click any WS connection → **Headers** → copy **Request URL**
5. Paste into WraithTK:

```
wraith [no-target] > target wss://target.com/socket.io/?EIO=4&transport=websocket
wraith [...] > scan
```

### Auto-discovery

Give a hostname and let WraithTK probe common paths:

```
wraith [no-target] > target rc.example.com
wraith [...] > probe
```

30 common paths tested. Unique hit → target auto-set.

### Example session

```
wraith [no-target] > target rc.bisebwp.pk
[*] auto-prepended wss://
[*] auto-appended /ws
[+] target = wss://rc.bisebwp.pk/ws

wraith [...] > scan
[!] HTTP 404 — not upgraded
[*] no WS at this path — auto-probing 30 common endpoints...
[+] found 1 endpoint
    wss://rc.bisebwp.pk/socket.io/  (subprotocol: none)
[+] auto-set target → wss://rc.bisebwp.pk/socket.io/

...scanning...
```

---

## Self-contained lab

The lab is a real, intentionally vulnerable WebSocket server. Run it on localhost and test every attack without any external target.

```bash
python -m wraithtk.lab.server --port 8765
```

**Injected vulnerabilities:**

- CSWSH — no `Origin` validation
- SQLi — string-concatenated query + leaked error
- XSS — unsanitized reflection
- Oversized frames accepted

Every attack in WraithTK is verified against this lab. If the lab is running and WraithTK works, you'll get the same findings every time.

---

## Reports

```bash
wraith [...] > scan
wraith [...] > report all
```

Produces:

- `wraithtk-report-<timestamp>.json` — machine-readable for pipelines
- `wraithtk-report-<timestamp>.html` — self-contained, browser-openable, severity color-coded

The HTML report is what you hand to a client. Every finding includes severity, type, detail line, and the raw evidence excerpt.

---

## Verified scope

Every attack in v0.1.0 has been reproduced against the lab:

| Finding | Severity | Result |
|---|---|---|
| CSWSH — 23 foreign origins accepted | CRITICAL | ✅ |
| Origin bypass — 8 malformed headers | HIGH | ✅ |
| SQL injection — length delta 164% | HIGH | ✅ |
| XSS reflection — payload echoed | HIGH | ✅ |
| Command injection — length delta 43% | HIGH | ✅ |
| SSRF — length delta 86% | HIGH | ✅ |
| Oversized frame accepted | MEDIUM | ✅ |
| Unmasked frame correctly rejected | INFO | ✅ |

**Not yet implemented (v0.2):**

- Blind time-based injection
- Authenticated sessions in the shell (Python API supports it)
- Subprotocol-specific playbooks (GraphQL-WS, Socket.IO, STOMP)
- Stateful message fuzzing
- MCP server wrapper (v0.3, DEDSEC.AI integration)

---

## Troubleshooting

**Baseline connection fails against lab**
```bash
# check the lab is up
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
     -H "Sec-WebSocket-Version: 13" \
     http://127.0.0.1:8765/ws
```
Should return `HTTP/1.1 101 Switching Protocols`.

**`HTTP 404` on a real target**  
Path is wrong. Use `probe`, or copy the URL from browser DevTools.

**`HTTP 200` on a real target**  
You pointed at an HTTP page. Same fix — DevTools → WS filter.

**`probe` finds nothing**  
The site probably doesn't use WebSockets. Check DevTools → Network → WS after reload. Empty list = no WS to test.

---

## Contributing

Focused PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

Rules:

- No external binaries — pure Python only
- Every new attack needs a matching vulnerability in `wraithtk/lab/server.py`
- Every attack needs a test in `tests/`
- Every finding must include verifiable evidence

Run tests:

```bash
pip install -e ".[dev]"
pytest -v
```

---

## Security policy

Found a vulnerability **in WraithTK**? Use GitHub's private [security advisory](../../security/advisories/new) — do not open a public issue. See [SECURITY.md](SECURITY.md).

---

## License

**AGPL-3.0-or-later.** See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Under Section 5 of the AGPL, the original author credit **DEDSEC** must be preserved in any copy, fork, or derivative work.

---

## Credits

**Built by DEDSEC.**

If you use WraithTK in a talk, write-up, or course, credit:

`https://github.com/Unknownx007/wraithtk`

<div align="center">
  <sub>WraithTK v0.1.0 · AGPL-3.0-or-later · authorized testing only</sub>
</div>
