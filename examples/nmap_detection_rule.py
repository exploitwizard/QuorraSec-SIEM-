# ═══════════════════════════════════════════════════════════════════════════
# EXAMPLE: Nmap Port Scan Detection Rule
#
# Copy one of the versions below into Rules Builder → Level 3 (Python DSL).
#
# VERSION 1 requires: Settings → Security → Python DSL Sandbox = DISABLED
# VERSION 2 works with the sandbox ON (no imports)
# VERSION 3 is a YAML/JSON rule (Level 2, any sandbox setting)
# ═══════════════════════════════════════════════════════════════════════════


# ───────────────────────────────────────────────────────────────────────────
# VERSION 1 — Full regex detection  (Sandbox OFF required)
# Settings → Security → Python DSL Sandbox → Disable
# ───────────────────────────────────────────────────────────────────────────
def rule(event):  # noqa: F811
    import re

    payload = str(event.get("payload", "") or "")
    ua      = str(event.get("user_agent", "") or "")
    attack  = str(event.get("attack_type", "") or "")
    text    = (payload + " " + ua + " " + attack).lower()

    # Nmap NSE User-Agent and common log signatures
    nmap_patterns = [
        r"nmap",
        r"scripting engine",
        r"-s[sStTuUaAnN]\b",      # scan type flags: -sS -sT -sU -sA -sN
        r"-s[vVcCpP]\b",          # service/version/ping scan flags
        r"syn[\s_-]scan",
        r"port[\s_-]scan",
        r"service[\s_-]detect",
        r"os[\s_-]detect",
        r"stealth[\s_-]scan",
    ]
    for pattern in nmap_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # SYN-only TCP (nmap -sS fingerprint in structured logs)
    protocol  = str(event.get("protocol", "") or "").lower()
    tcp_flags = str(event.get("tcp_flags", "") or "").lower()
    if protocol == "tcp" and tcp_flags.strip() == "s":
        return True

    return False


# ───────────────────────────────────────────────────────────────────────────
# VERSION 2 — Substring matching only  (works with Sandbox ON)
# ───────────────────────────────────────────────────────────────────────────
def rule(event):  # noqa: F811
    ua      = (event.get("user_agent")  or "").lower()
    attack  = (event.get("attack_type") or "").lower()
    payload = (event.get("payload")     or "").lower()

    # Nmap NSE User-Agent fingerprint
    if "nmap" in ua or "scripting engine" in ua:
        return True

    # Attack type already labelled as a scan by an upstream sensor / WAF
    for kw in ("nmap", "port_scan", "port scan", "network_scan", "network scan"):
        if kw in attack:
            return True

    # Nmap service-detection probe strings in payload
    for sig in ("nmap", "nmapscript", "scripting engine", "-ss ", "-st ", "-su "):
        if sig in payload:
            return True

    return False


# ───────────────────────────────────────────────────────────────────────────
# VERSION 3 — YAML / JSON DSL  (Level 2, any sandbox setting)
#
# Paste the JSON below into the Rule Definition field (Level 2).
# ───────────────────────────────────────────────────────────────────────────
YAML_DSL_VERSION = """
rule_name: Nmap Scan Detection
logic: OR
conditions:
  - field: user_agent
    operator: contains
    value: nmap
  - field: user_agent
    operator: contains
    value: scripting engine
  - field: attack_type
    operator: contains
    value: nmap
  - field: attack_type
    operator: contains
    value: port_scan
  - field: attack_type
    operator: contains
    value: network_scan
  - field: payload
    operator: contains
    value: nmap
  - field: payload
    operator: contains
    value: -sS
  - field: payload
    operator: contains
    value: -sT
  - field: payload
    operator: contains
    value: -sU
"""

JSON_DSL_VERSION = {
    "rule_name": "Nmap Scan Detection",
    "logic": "OR",
    "conditions": [
        {"field": "user_agent",  "operator": "contains", "value": "nmap"},
        {"field": "user_agent",  "operator": "contains", "value": "scripting engine"},
        {"field": "attack_type", "operator": "contains", "value": "nmap"},
        {"field": "attack_type", "operator": "contains", "value": "port_scan"},
        {"field": "attack_type", "operator": "contains", "value": "network_scan"},
        {"field": "payload",     "operator": "contains", "value": "nmap"},
        {"field": "payload",     "operator": "contains", "value": "-sS"},
        {"field": "payload",     "operator": "contains", "value": "-sT"},
        {"field": "payload",     "operator": "contains", "value": "-sU"},
    ],
}
