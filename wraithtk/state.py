from dataclasses import dataclass, field
from typing import Any


@dataclass
class Session:
    target: str = ""
    subprotocol: str = ""
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    last_handshake: dict = field(default_factory=dict)
    running: bool = True

    def add_finding(self, ftype: str, severity: str, detail: str, evidence: str = ""):
        self.findings.append({
            "type": ftype,
            "severity": severity,
            "detail": detail,
            "evidence": evidence,
            "target": self.target,
        })
