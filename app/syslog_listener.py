# app/syslog_listener.py
"""
Cross-platform syslog receiver for Quorra SIEM.

Listens on UDP (and optionally TCP) for RFC 3164 / RFC 5424 syslog messages
and converts them to LogEntry records in the database.

Default ports are 5140 (UDP) and 5141 (TCP) — no root/admin privileges needed.
Override with SYSLOG_UDP_PORT / SYSLOG_TCP_PORT environment variables.

Enable by setting SYSLOG_LISTENER_ENABLED=true.
"""

import re
import json
import socket
import socketserver
import threading
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# RFC 3164 priority/facility mapping
SEVERITY_MAP = {
    0: "critical",   # Emergency
    1: "critical",   # Alert
    2: "critical",   # Critical
    3: "high",       # Error
    4: "high",       # Warning
    5: "medium",     # Notice
    6: "low",        # Informational
    7: "info",       # Debug
}

# Pattern matches <PRI>TIMESTAMP HOSTNAME TAG: MSG
_RFC3164 = re.compile(
    r"^<(\d{1,3})>"                          # priority
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # timestamp
    r"\s+(\S+)"                              # hostname
    r"\s+([^:]+):\s*(.*)"                   # tag + message
)

# Simpler fallback: <PRI> followed by anything
_RFC3164_SIMPLE = re.compile(r"^<(\d{1,3})>\s*(.*)")


def _parse_syslog(raw: str) -> dict:
    """Parse a syslog line into a normalised dict."""
    raw = raw.strip()

    m = _RFC3164.match(raw)
    if m:
        priority  = int(m.group(1))
        severity  = SEVERITY_MAP.get(priority & 0x07, "medium")
        hostname  = m.group(3)
        tag       = m.group(4).strip()
        message   = m.group(5).strip()
        return {
            "severity":    severity,
            "ip_address":  hostname,
            "attack_type": f"syslog:{tag}",
            "endpoint":    tag,
            "payload":     message,
            "raw":         raw,
        }

    m = _RFC3164_SIMPLE.match(raw)
    if m:
        priority = int(m.group(1))
        severity = SEVERITY_MAP.get(priority & 0x07, "medium")
        return {
            "severity":    severity,
            "ip_address":  "syslog-source",
            "attack_type": "syslog",
            "endpoint":    "syslog",
            "payload":     m.group(2).strip(),
            "raw":         raw,
        }

    return {
        "severity":    "info",
        "ip_address":  "syslog-source",
        "attack_type": "syslog",
        "endpoint":    "syslog",
        "payload":     raw[:1000],
        "raw":         raw,
    }


def _store_syslog_event(flask_app, parsed: dict) -> None:
    """Persist a parsed syslog event as a LogEntry (runs inside app context)."""
    try:
        from app.database import db
        from app.models import LogEntry
        with flask_app.app_context():
            entry = LogEntry(
                ip_address  = parsed.get("ip_address", "syslog-source")[:45],
                attack_type = parsed.get("attack_type", "syslog")[:100],
                endpoint    = parsed.get("endpoint",    "syslog")[:500],
                payload     = parsed.get("payload",     "")[:1000],
                severity    = parsed.get("severity",    "info"),
                timestamp   = datetime.utcnow(),
                raw_data    = json.dumps({"source": "syslog", "raw": parsed.get("raw", "")}),
            )
            db.session.add(entry)
            db.session.commit()
    except Exception as e:
        logger.error("syslog_listener: failed to store event: %s", e)


# ---------------------------------------------------------------------------
# UDP handler
# ---------------------------------------------------------------------------

class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data  = self.request[0].decode("utf-8", errors="replace")
            parsed = _parse_syslog(data)
            _store_syslog_event(self.server.flask_app, parsed)
        except Exception as e:
            logger.debug("UDP syslog handler error: %s", e)


class _ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads      = True


# ---------------------------------------------------------------------------
# TCP handler
# ---------------------------------------------------------------------------

class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            for line in self.rfile:
                text   = line.decode("utf-8", errors="replace").strip()
                if text:
                    parsed = _parse_syslog(text)
                    _store_syslog_event(self.server.flask_app, parsed)
        except Exception as e:
            logger.debug("TCP syslog handler error: %s", e)


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


# ---------------------------------------------------------------------------
# Public start function
# ---------------------------------------------------------------------------

def start_syslog_listeners(flask_app) -> None:
    """
    Start UDP and TCP syslog listeners in daemon background threads.
    Safe to call multiple times — will not start if already running.
    Called by main.py when Config.SYSLOG_LISTENER_ENABLED is True.
    """
    from app.config import Config

    udp_port = Config.SYSLOG_UDP_PORT
    tcp_port = Config.SYSLOG_TCP_PORT
    host     = Config.SYSLOG_HOST

    # --- UDP ---
    try:
        udp_server = _ThreadedUDPServer((host, udp_port), _UDPHandler)
        udp_server.flask_app = flask_app
        t = threading.Thread(target=udp_server.serve_forever, daemon=True,
                             name="syslog-udp")
        t.start()
        logger.info("Syslog UDP listener started on %s:%d", host, udp_port)
        print(f"Syslog UDP listener on {host}:{udp_port}")
    except OSError as e:
        logger.warning("Could not start syslog UDP listener on port %d: %s", udp_port, e)
        print(f"Warning: Syslog UDP listener could not bind to {host}:{udp_port} — {e}")

    # --- TCP ---
    try:
        tcp_server = _ThreadedTCPServer((host, tcp_port), _TCPHandler)
        tcp_server.flask_app = flask_app
        t = threading.Thread(target=tcp_server.serve_forever, daemon=True,
                             name="syslog-tcp")
        t.start()
        logger.info("Syslog TCP listener started on %s:%d", host, tcp_port)
        print(f"Syslog TCP listener on {host}:{tcp_port}")
    except OSError as e:
        logger.warning("Could not start syslog TCP listener on port %d: %s", tcp_port, e)
        print(f"Warning: Syslog TCP listener could not bind to {host}:{tcp_port} — {e}")
