# app/config.py
import os
import sys
import secrets
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Platform-aware user data directory
# Uses platformdirs when available; falls back to BASE_DIR-relative paths.
# ---------------------------------------------------------------------------
def _get_platform_data_dir() -> Path:
    try:
        from platformdirs import user_data_dir
        d = Path(user_data_dir("CourraSec", "CourraSec"))
        d.mkdir(parents=True, exist_ok=True)
        return d
    except ImportError:
        return BASE_DIR / "data"

def _get_platform_log_dir() -> Path:
    try:
        from platformdirs import user_log_dir
        d = Path(user_log_dir("CourraSec", "CourraSec"))
        d.mkdir(parents=True, exist_ok=True)
        return d
    except ImportError:
        return BASE_DIR / "logs"

# ---------------------------------------------------------------------------
# Persistent SECRET_KEY
# Order: env var → .courra-sec-secret file in data dir → generate + persist
# This ensures sessions survive restarts without requiring manual config.
# ---------------------------------------------------------------------------
def _get_or_create_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key:
        return env_key

    data_dir = BASE_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    secret_file = data_dir / ".courra-sec-secret"

    if secret_file.exists():
        key = secret_file.read_text().strip()
        if len(key) >= 32:
            return key

    key = secrets.token_hex(32)
    try:
        secret_file.write_text(key)
        # Restrict read permissions on Unix
        if sys.platform != "win32":
            secret_file.chmod(0o600)
    except OSError:
        print("Warning: Could not persist SECRET_KEY to disk. Sessions will not survive restarts.")
    return key


_secret_key = _get_or_create_secret_key()


class Config:
    """Application configuration — all settings overridable via environment variables."""

    # -----------------------------------------------------------------------
    # Core Flask
    # -----------------------------------------------------------------------
    SECRET_KEY = _secret_key
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # -----------------------------------------------------------------------
    # Database
    # DB_PATH env var overrides the default (useful on Windows where
    # C:\Program Files is read-only).
    # -----------------------------------------------------------------------
    _db_path = os.environ.get("DB_PATH") or str(BASE_DIR / "data" / "courra-sec.db")
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{_db_path}"

    # Enable WAL mode for better concurrency on all platforms
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {"check_same_thread": False},
        "pool_pre_ping": True,
    }

    # -----------------------------------------------------------------------
    # Ingest API key — MUST be set via environment variable.
    # If empty, only localhost connections are accepted (see main.py).
    # -----------------------------------------------------------------------
    INGEST_API_KEY = os.environ.get("INGEST_API_KEY", "")

    # -----------------------------------------------------------------------
    # Session
    # -----------------------------------------------------------------------
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------
    COURRA_SEC_USERNAME = os.environ.get("COURRA_SEC_USERNAME", "user-courra-sec")
    COURRA_SEC_PASSWORD = os.environ.get("COURRA_SEC_PASSWORD", "courra-sec@1000")

    # Force a password change on the first login for the default account.
    # Set to "false" to disable (not recommended for production).
    FORCE_PASSWORD_CHANGE = os.environ.get("FORCE_PASSWORD_CHANGE", "true").lower() == "true"

    # -----------------------------------------------------------------------
    # TOTP / 2FA
    # -----------------------------------------------------------------------
    TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "CourraSec")
    TOTP_ENABLED_DEFAULT = False   # Users opt-in via the UI

    # -----------------------------------------------------------------------
    # Block Fortress integration
    # -----------------------------------------------------------------------
    BLOCK_FORTRESS_URL = os.environ.get("BLOCK_FORTRESS_URL", "http://localhost:5000")
    BLOCK_FORTRESS_WS_URL = os.environ.get(
        "BLOCK_FORTRESS_WS_URL", "ws://localhost:5000/api/ws/logs"
    )
    # Optional: admin credentials for authenticated API pull from Block Fortress
    BLOCK_FORTRESS_ADMIN_USER = os.environ.get("BLOCK_FORTRESS_ADMIN_USER", "admin")
    BLOCK_FORTRESS_ADMIN_PASS = os.environ.get("BLOCK_FORTRESS_ADMIN_PASS", "")

    # -----------------------------------------------------------------------
    # Detection thresholds
    # -----------------------------------------------------------------------
    BRUTEFORCE_THRESHOLD = int(os.environ.get("BRUTEFORCE_THRESHOLD", "10"))
    BRUTEFORCE_WINDOW = int(os.environ.get("BRUTEFORCE_WINDOW", "120"))   # seconds
    GEO_VELOCITY_THRESHOLD = int(os.environ.get("GEO_VELOCITY_THRESHOLD", "300"))  # km
    MULTI_ATTACK_THRESHOLD = int(os.environ.get("MULTI_ATTACK_THRESHOLD", "3"))

    # -----------------------------------------------------------------------
    # Alerts
    # -----------------------------------------------------------------------
    ALERT_RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", "30"))
    EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "false").lower() == "true"

    # Slack incoming webhook URL (set to enable Slack alerts)
    SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

    # Generic outbound webhook URL (receives JSON POST on every high/critical alert)
    ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")

    # Microsoft Teams incoming webhook URL
    TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")

    # -----------------------------------------------------------------------
    # Monitoring / WebSocket reconnect
    # -----------------------------------------------------------------------
    MONITORING_INTERVAL = int(os.environ.get("MONITORING_INTERVAL", "5"))
    WS_RECONNECT_DELAY = int(os.environ.get("WS_RECONNECT_DELAY", "5"))

    # -----------------------------------------------------------------------
    # Rate limiting (Flask-Limiter)
    # -----------------------------------------------------------------------
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_INGEST = os.environ.get("RATELIMIT_INGEST", "200 per minute")
    RATELIMIT_LOGIN = os.environ.get("RATELIMIT_LOGIN", "20 per minute")

    # -----------------------------------------------------------------------
    # Syslog UDP/TCP listener
    # -----------------------------------------------------------------------
    SYSLOG_LISTENER_ENABLED = os.environ.get("SYSLOG_LISTENER_ENABLED", "false").lower() == "true"
    SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "0.0.0.0")
    SYSLOG_UDP_PORT = int(os.environ.get("SYSLOG_UDP_PORT", "5140"))   # 514 needs root; 5140 does not
    SYSLOG_TCP_PORT = int(os.environ.get("SYSLOG_TCP_PORT", "5141"))

    # -----------------------------------------------------------------------
    # Prometheus metrics
    # -----------------------------------------------------------------------
    METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "true").lower() == "true"
    # Optional bearer token to protect /metrics — leave empty for open access
    METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")

    # -----------------------------------------------------------------------
    # HTTPS / TLS (self-signed cert for local use)
    # Set TLS_ENABLED=true + TLS_CERT_FILE + TLS_KEY_FILE to enable
    # -----------------------------------------------------------------------
    TLS_ENABLED = os.environ.get("TLS_ENABLED", "false").lower() == "true"
    TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE", str(BASE_DIR / "data" / "tls" / "cert.pem"))
    TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE", str(BASE_DIR / "data" / "tls" / "key.pem"))

    # -----------------------------------------------------------------------
    # File paths (all resolved relative to BASE_DIR for portability)
    # -----------------------------------------------------------------------
    DATA_DIR = str(BASE_DIR / "data")
    LOGS_DIR = str(BASE_DIR / "logs")
    TEMPLATES_DIR = str(BASE_DIR / "app" / "templates")

    GEOIP_DB_PATH = str(BASE_DIR / "data" / "geolite" / "GeoLite2-City.mmdb")

    # MaxMind license key for automatic GeoLite2 download (set to enable)
    MAXMIND_LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "")

    # -----------------------------------------------------------------------
    # Email — Resend (team invitations)
    # Set RESEND_API_KEY to enable email delivery.
    # If unset, invitations still create the user but no email is sent.
    # Supervisor example:
    #   environment=RESEND_API_KEY="re_xxxxxxxx",APP_BASE_URL="https://siem.example.com",RESEND_FROM_EMAIL="noreply@yourdomain.com"
    # -----------------------------------------------------------------------
    RESEND_API_KEY    = os.environ.get("RESEND_API_KEY", "")
    RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "noreply@yourdomain.com")
    APP_BASE_URL      = os.environ.get("APP_BASE_URL", "http://localhost:8080")
