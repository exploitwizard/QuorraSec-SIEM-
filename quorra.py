#!/usr/bin/env python3
"""
Quorra SIEM Tool - Main Entry Point
Cross-platform CLI for Block Fortress integration.
Supports Windows, Linux, and macOS.
"""

import sys
import os
import signal
import socket
import argparse
import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler


# ---------------------------------------------------------------------------
# Logging setup (before importing the app so Flask's startup messages use it)
# ---------------------------------------------------------------------------

def _setup_logging(log_level: str = "INFO", log_file=None):
    """Configure root logger with rotating file + console handlers."""
    if log_file is None:
        # Platform-aware log directory
        if sys.platform == "win32":
            log_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "QuorraSIEM" / "logs"
        elif sys.platform == "darwin":
            log_dir = Path.home() / "Library" / "Logs" / "QuorraSIEM"
        else:
            log_dir = Path.home() / ".local" / "share" / "quorra" / "logs"

        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = str(log_dir / "quorra.log")

    level = getattr(logging, log_level.upper(), logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    # Rotating file handler — 10 MB x 5 files (Windows-safe: no locks held on closed files)
    try:
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5,
                                 encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as e:
        print(f"Warning: Could not open log file {log_file}: {e}")

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    return log_file


# ---------------------------------------------------------------------------
# Port discovery
# ---------------------------------------------------------------------------

def _kill_port_processes(port_range):
    """Kill any processes holding ports in the given range (Unix/macOS)."""
    if sys.platform not in ("darwin", "linux"):
        return
    import subprocess
    for port in range(port_range[0], port_range[1] + 1):
        try:
            result = subprocess.run(
                ["lsof", "-ti", f":{port}"],
                capture_output=True, text=True
            )
            if result.stdout.strip():
                pids = result.stdout.strip().split("\n")
                for pid in pids:
                    try:
                        subprocess.run(["kill", "-9", pid], capture_output=True)
                        print(f"Killed lingering process on port {port} (PID: {pid})")
                    except Exception:
                        pass
        except Exception:
            pass


def find_free_port(start=5001, end=5020):
    """Return the first free TCP port in the given range."""
    import time
    _kill_port_processes((start, end))
    for port in range(start, end + 1):
        for attempt in range(3):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("127.0.0.1", port))
                    return port
            except OSError:
                if attempt < 2:
                    time.sleep(0.3)
                continue
    return start


# ---------------------------------------------------------------------------
# Browser open (with OS-specific fallbacks)
# ---------------------------------------------------------------------------

def open_browser(url):
    import webbrowser
    import subprocess

    try:
        webbrowser.open(url)
        return
    except Exception:
        pass

    # Fallback per platform
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", url])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", url])
        elif sys.platform == "win32":
            subprocess.Popen(["cmd", "/c", "start", url], shell=False)
    except Exception as e:
        print(f"Could not open browser automatically: {e}")
        print(f"Please open manually: {url}")


# ---------------------------------------------------------------------------
# Signal handling (cross-platform)
# ---------------------------------------------------------------------------

def _setup_signals():
    """Register graceful shutdown handlers for all platforms."""
    def _handler(sig, frame):
        print("\n\nShutting down Quorra SIEM...")
        sys.exit(0)

    signal.signal(signal.SIGINT, _handler)

    # SIGTERM — Unix/Linux/macOS process manager termination
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)

    # SIGBREAK — Windows Ctrl+Break
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _handler)


# ---------------------------------------------------------------------------
# TLS helper (optional self-signed cert for local HTTPS)
# ---------------------------------------------------------------------------

def _ensure_tls_cert(cert_file, key_file):
    """
    Generate a self-signed TLS certificate if it does not exist.
    Returns True if TLS is ready, False on failure.
    """
    cert_path = Path(cert_file)
    key_path  = Path(key_file)

    if cert_path.exists() and key_path.exists():
        return True

    cert_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Try trustme (lightweight, cross-platform)
        import trustme
        ca  = trustme.CA()
        srv = ca.issue_cert("localhost", "127.0.0.1")
        ca.cert_pem.write_to_path(str(cert_path))
        srv.private_key_pem.write_to_path(str(key_path))
        print(f"Self-signed TLS certificate generated: {cert_path}")
        return True
    except ImportError:
        pass

    try:
        # Fallback: use openssl via subprocess
        import subprocess
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out",    str(cert_path),
            "-days",   "365",
            "-nodes",
            "-subj",   "/CN=localhost",
        ], check=True, capture_output=True)
        print(f"Self-signed TLS certificate generated via openssl: {cert_path}")
        return True
    except Exception as e:
        print(f"Warning: Could not generate TLS certificate: {e}")
        return False


# ---------------------------------------------------------------------------
# Production WSGI server selection (cross-platform)
# ---------------------------------------------------------------------------

def _run_server(flask_app, host, port, tls, cert_file, key_file):
    """
    Choose the best available WSGI server for the current platform.

    Priority:
      1. waitress  — cross-platform, no C build deps, works on Windows
      2. gunicorn  — Linux/macOS only
      3. Flask dev server — last resort (not for production)
    """
    ssl_context = None
    if tls and _ensure_tls_cert(cert_file, key_file):
        ssl_context = (cert_file, key_file)

    # --- waitress (preferred on all platforms) ---
    try:
        from waitress import serve
        scheme = "https" if ssl_context else "http"
        print(f"Production server: waitress  ({scheme}://{host}:{port})")

        if ssl_context:
            # waitress doesn't natively support TLS — wrap with ssl module
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*ssl_context)
            serve(flask_app, host=host, port=port, threads=8,
                  channel_timeout=30, url_scheme="https",
                  _ssl_context=ctx)
        else:
            serve(flask_app, host=host, port=port, threads=8, channel_timeout=30)
        return
    except ImportError:
        pass

    # --- gunicorn (Linux/macOS) ---
    if sys.platform != "win32":
        try:
            from gunicorn.app.base import BaseApplication

            class _GunicornApp(BaseApplication):
                def __init__(self, application, options=None):
                    self.options     = options or {}
                    self.application = application
                    super().__init__()

                def load_config(self):
                    for k, v in self.options.items():
                        if k in self.cfg.settings and v is not None:
                            self.cfg.set(k.lower(), v)

                def load(self):
                    return self.application

            opts = {
                "bind":    f"{host}:{port}",
                "workers": 2,
                "threads": 4,
                "timeout": 60,
            }
            if ssl_context:
                opts["certfile"] = ssl_context[0]
                opts["keyfile"]  = ssl_context[1]

            print(f"Production server: gunicorn  ({host}:{port})")
            _GunicornApp(flask_app, opts).run()
            return
        except ImportError:
            pass

    # --- Fallback: Flask dev server ---
    print("Warning: Neither waitress nor gunicorn found. Using Flask development server.")
    print("         Install waitress for production: pip install waitress")
    ssl_ctx = ssl_context if ssl_context else None
    flask_app.run(host=host, port=port, debug=False, use_reloader=False,
                  ssl_context=ssl_ctx)


# ---------------------------------------------------------------------------
# Service installer
# ---------------------------------------------------------------------------

def install_service():
    """Install Quorra as a system service (systemd / launchd / Windows SCM)."""
    script = Path(__file__).resolve()

    if sys.platform == "win32":
        _install_windows_service(script)
    elif sys.platform == "darwin":
        _install_launchd_service(script)
    else:
        _install_systemd_service(script)


def _install_systemd_service(script):
    user      = os.environ.get("USER", "quorra")
    work_dir  = script.parent
    exec_path = f"{sys.executable} {script} --no-browser"

    unit = f"""[Unit]
Description=Quorra SIEM
After=network.target

[Service]
Type=simple
User={user}
WorkingDirectory={work_dir}
ExecStart={exec_path}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    dest = Path("/etc/systemd/system/quorra.service")
    try:
        dest.write_text(unit)
        print(f"systemd service written to {dest}")
        print("Enable with: sudo systemctl enable --now quorra")
    except PermissionError:
        print("Permission denied writing to /etc/systemd/system/")
        print("Run this command as root or with sudo.")
        print("\nService file content:")
        print(unit)


def _install_launchd_service(script):
    work_dir = script.parent
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.quorra.siem</string>
  <key>ProgramArguments</key>
  <array>
    <string>{sys.executable}</string>
    <string>{script}</string>
    <string>--no-browser</string>
  </array>
  <key>WorkingDirectory</key>  <string>{work_dir}</string>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>StandardOutPath</key>   <string>{work_dir}/logs/quorra.stdout.log</string>
  <key>StandardErrorPath</key> <string>{work_dir}/logs/quorra.stderr.log</string>
</dict>
</plist>
"""
    dest = Path.home() / "Library" / "LaunchAgents" / "com.quorra.siem.plist"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(plist)
    print(f"launchd plist written to {dest}")
    print(f"Load with: launchctl load {dest}")


def _install_windows_service(script):
    print("Windows Service Installation:")
    print("  Option 1 - NSSM (recommended):")
    print("    nssm install QuorraSIEM")
    print(f"    Application: {sys.executable}")
    print(f"    Arguments: {script} --no-browser")
    print("")
    print("  Option 2 - Task Scheduler:")
    print("    schtasks /create /sc ONSTART /tn QuorraSIEM \\")
    print(f"      /tr \"\\\"{sys.executable}\\\" \\\"{script}\\\" --no-browser\"")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="quorra",
        description="Quorra SIEM - Block Fortress Security Integration",
    )
    p.add_argument("--port",       type=int,  default=0,
                   help="Port to listen on (default: auto-select 5001-5020)")
    p.add_argument("--host",       default="0.0.0.0",
                   help="Host/interface to bind (default: 0.0.0.0)")
    p.add_argument("--no-browser", action="store_true",
                   help="Do not open a browser window on startup")
    p.add_argument("--log-level",  default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                   help="Logging verbosity (default: INFO)")
    p.add_argument("--log-file",   default=None,
                   help="Path to log file (default: platform data directory)")
    p.add_argument("--db-path",    default=None,
                   help="Path to SQLite database file (overrides DB_PATH env var)")
    p.add_argument("--tls",        action="store_true",
                   help="Enable HTTPS with a self-signed certificate")
    p.add_argument("--install-service", action="store_true",
                   help="Install Quorra as a system service and exit")
    return p


def main():
    args = build_parser().parse_args()

    # Handle --install-service before importing the app
    if args.install_service:
        install_service()
        return

    # Override DB path before app import resolves Config
    if args.db_path:
        os.environ["DB_PATH"] = str(Path(args.db_path).resolve())

    log_file = _setup_logging(args.log_level, args.log_file)
    _setup_signals()

    print("""
    +---------------------------------------+
    |          QUORRA SIEM v2.0             |
    |      Block Fortress Integration       |
    |   Windows / Linux / macOS             |
    +---------------------------------------+
    """)

    # Import app after env vars are set
    from app.main import app
    from app.config import Config

    port = args.port if args.port else find_free_port()
    scheme = "https" if (args.tls or Config.TLS_ENABLED) else "http"
    url    = f"{scheme}://localhost:{port}"

    os.environ.setdefault("QUORRA_PORT", str(port))
    os.environ.setdefault("BLOCK_FORTRESS_URL", Config.BLOCK_FORTRESS_URL)

    print(f"Log file         : {log_file}")
    print(f"Database         : {Config.SQLALCHEMY_DATABASE_URI}")
    print(f"Listening on     : {url}")
    print(f"Block Fortress   : {Config.BLOCK_FORTRESS_URL}")
    print(f"Syslog listener  : {'enabled (UDP:{} TCP:{})'.format(Config.SYSLOG_UDP_PORT, Config.SYSLOG_TCP_PORT) if Config.SYSLOG_LISTENER_ENABLED else 'disabled'}")
    print(f"Prometheus       : {'enabled (/metrics)' if Config.METRICS_ENABLED else 'disabled'}")
    print()
    print("Detection Rules Active:")
    print("  1. Brute Force (10 failed logins in 2 mins)")
    print("  2. Geo-velocity (impossible travel)")
    print("  3. Admin privilege escalation")
    print("  4. OS Command Injection")
    print("  5. Blocked IP detection")
    print()
    print("Press Ctrl+C to stop\n")

    if not args.no_browser:
        # Delay slightly to let the server bind before opening the browser
        import threading
        def _open():
            import time
            time.sleep(1.2)
            open_browser(f"{url}/login")
        threading.Thread(target=_open, daemon=True).start()

    _run_server(
        app,
        host=args.host,
        port=port,
        tls=args.tls or Config.TLS_ENABLED,
        cert_file=Config.TLS_CERT_FILE,
        key_file=Config.TLS_KEY_FILE,
    )


if __name__ == "__main__":
    main()
