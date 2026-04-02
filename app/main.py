# app/main.py
import time
import json
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone as _tz
from functools import wraps
from pathlib import Path
from threading import Thread

import websocket
from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, session, send_from_directory, Response,
)
from flask_cors import CORS
from flask_sock import Sock

from app.config import Config
from app.database import init_db, db
from app.rules_engine import RulesEngine
from app.log_collector import LogCollector
from app.alert_system import AlertSystem
from app.models import LogEntry, Alert, Attack, IPBlocklist, QuorraUser
from app.metrics import (
    PROMETHEUS_AVAILABLE,
    HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION,
    INGEST_EVENTS_TOTAL, INGEST_ERRORS_TOTAL,
    RULES_TRIGGERED_TOTAL, ALERTS_CREATED_TOTAL, ML_ANOMALIES_TOTAL,
    LOGS_IN_DB, ATTACKS_IN_DB, BLOCKED_IPS, WS_CONNECTED,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Flask App
# =============================================================================
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY
CORS(app)
sock = Sock(app)

# =============================================================================
# Rate limiting
# =============================================================================
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=Config.RATELIMIT_STORAGE_URI,
        default_limits=[],       # No blanket limits — only explicit per-route
    )
    LIMITER_AVAILABLE = True
except ImportError:
    limiter = None
    LIMITER_AVAILABLE = False
    logger.warning("flask-limiter not installed — rate limiting disabled")

# =============================================================================
# Database
# =============================================================================
with app.app_context():
    init_db(app)

# =============================================================================
# Security headers
# =============================================================================
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    # Content-Security-Policy — allow Bootstrap/FA CDN used by templates
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:;"
    )
    return response

# =============================================================================
# Request instrumentation (Prometheus)
# =============================================================================
@app.before_request
def _before_request():
    request._start_time = time.monotonic()

@app.after_request
def _after_request(response):
    if hasattr(request, "_start_time"):
        duration = time.monotonic() - request._start_time
        endpoint = request.endpoint or "unknown"
        HTTP_REQUESTS_TOTAL.labels(
            method=request.method,
            endpoint=endpoint,
            status_code=str(response.status_code),
        ).inc()
        HTTP_REQUEST_DURATION.labels(
            method=request.method,
            endpoint=endpoint,
        ).observe(duration)
    return response

# =============================================================================
# Components
# =============================================================================
rules_engine  = RulesEngine()
log_collector = LogCollector()
alert_system  = AlertSystem()

# =============================================================================
# ML Pipeline (optional — works without models)
# =============================================================================
ml_pipeline = None
try:
    from app.ml import MLPipeline
    ml_pipeline = MLPipeline()
    ml_pipeline.load()
    print("ML pipeline loaded")
except Exception as e:
    print(f"Warning: ML pipeline not available: {e}")

# =============================================================================
# State
# =============================================================================
monitoring_active = True
ws_connected      = False
_geo_cache: dict  = {}
MAX_GEO_CACHE     = 1000

# =============================================================================
# Auth helpers
# =============================================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def _get_current_user() -> QuorraUser | None:
    username = session.get("user")
    if not username:
        return None
    return QuorraUser.query.filter_by(username=username, is_active=True).first()


# =============================================================================
# AUTH ROUTES
# =============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if LIMITER_AVAILABLE and limiter:
        # Apply login rate limit dynamically
        try:
            limiter.limit(Config.RATELIMIT_LOGIN)(lambda: None)()
        except Exception:
            pass

    # --- Step 2: TOTP verification ---
    if request.method == "POST" and request.form.get("totp_step"):
        pending_user = session.get("totp_pending_user")
        if not pending_user:
            return render_template("login.html", error="Session expired. Please log in again.")
        code = request.form.get("totp_code", "").strip()
        user = QuorraUser.query.filter_by(username=pending_user, is_active=True).first()
        if user and user.verify_totp(code):
            session.pop("totp_pending_user", None)
            session["user"] = user.username
            user.last_login = datetime.utcnow()
            db.session.commit()
            if user.password_change_required:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))
        return render_template("login.html", totp_step=True,
                               error="Invalid authenticator code. Try again.")

    # --- Step 1: Username + password ---
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = QuorraUser.query.filter_by(username=username, is_active=True).first()

        if user and user.check_password(password):
            if user.totp_enabled:
                # Store pending user and show TOTP form
                session["totp_pending_user"] = user.username
                return render_template("login.html", totp_step=True)

            session["user"] = user.username
            user.last_login = datetime.utcnow()
            db.session.commit()

            if user.password_change_required:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = _get_current_user()
    if not user:
        return redirect(url_for("logout"))

    if request.method == "POST":
        current  = request.form.get("current_password", "")
        new_pw   = request.form.get("new_password", "")
        confirm  = request.form.get("confirm_password", "")

        if not user.check_password(current):
            return render_template("change_password.html",
                                   error="Current password is incorrect.",
                                   username=user.username)
        if len(new_pw) < 8:
            return render_template("change_password.html",
                                   error="Password must be at least 8 characters.",
                                   username=user.username)
        if new_pw != confirm:
            return render_template("change_password.html",
                                   error="Passwords do not match.",
                                   username=user.username)
        if new_pw == request.form.get("current_password"):
            return render_template("change_password.html",
                                   error="New password must differ from the current one.",
                                   username=user.username)

        user.set_password(new_pw)
        user.password_change_required = False
        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template("change_password.html", username=user.username,
                           required=user.password_change_required)

# =============================================================================
# TOTP ROUTES
# =============================================================================

@app.route("/api/totp/setup", methods=["POST"])
@login_required
def api_totp_setup():
    """Generate a TOTP secret and return the provisioning URI + QR data URL."""
    user = _get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    try:
        import pyotp, qrcode, io, base64
        secret = user.generate_totp_secret()
        db.session.commit()
        uri = user.get_totp_uri()
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_data = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
        return jsonify({"ok": True, "secret": secret, "uri": uri, "qr": qr_data})
    except ImportError:
        # qrcode not installed — return URI only
        secret = user.generate_totp_secret()
        db.session.commit()
        uri = user.get_totp_uri()
        return jsonify({"ok": True, "secret": secret, "uri": uri, "qr": None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/totp/enable", methods=["POST"])
@login_required
def api_totp_enable():
    """Verify a TOTP code and enable 2FA for the current user."""
    user = _get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    code = (request.get_json(force=True, silent=True) or {}).get("code", "")
    if not user.verify_totp(code):
        return jsonify({"ok": False, "error": "Invalid code — check your authenticator app"}), 400
    user.totp_enabled = True
    db.session.commit()
    return jsonify({"ok": True, "message": "2FA enabled successfully"})


@app.route("/api/totp/disable", methods=["POST"])
@login_required
def api_totp_disable():
    """Disable TOTP for the current user after verifying their password."""
    user = _get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    data     = request.get_json(force=True, silent=True) or {}
    password = data.get("password", "")
    if not user.check_password(password):
        return jsonify({"ok": False, "error": "Incorrect password"}), 403
    user.totp_enabled = False
    user.totp_secret  = None
    db.session.commit()
    return jsonify({"ok": True, "message": "2FA disabled"})

# =============================================================================
# UI ROUTES
# =============================================================================

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=session["user"],
        logs=LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(10).all(),
        alerts=Alert.query.order_by(Alert.created_at.desc()).limit(10).all(),
        attacks=Attack.query.order_by(Attack.detected_at.desc()).limit(10).all(),
        blocked_ips=IPBlocklist.query.count(),
    )


@app.route("/logs")
@login_required
def logs_view():
    return render_template("logs.html", username=session["user"])


@app.route("/attacks")
@login_required
def attacks_view():
    return render_template(
        "attacks.html",
        attacks=Attack.query.order_by(Attack.detected_at.desc()).all(),
        username=session["user"],
    )


@app.route("/alerts")
@login_required
def alerts_view():
    return render_template("alerts.html", alerts=Alert.query.all(), username=session["user"])


@app.route("/blocklist")
@login_required
def blocklist_view():
    return render_template(
        "blocklist.html",
        blocked_ips=IPBlocklist.query.all(),
        username=session["user"],
    )


@app.route("/ml-dashboard")
@login_required
def ml_dashboard():
    summary = ml_pipeline.get_ml_summary() if ml_pipeline else {}
    return render_template("ml_dashboard.html", summary=summary, username=session["user"])

# =============================================================================
# HEALTH CHECK  (no auth — required by Docker/k8s probes)
# =============================================================================

@app.route("/health")
def health():
    """Lightweight liveness/readiness probe."""
    try:
        db_ok = bool(db.session.execute(db.text("SELECT 1")).scalar())
    except Exception:
        db_ok = False

    status = "healthy" if db_ok else "degraded"
    return jsonify({
        "status":       status,
        "version":      "2.0.0",
        "db":           "ok" if db_ok else "error",
        "ml":           ml_pipeline is not None,
        "monitoring":   monitoring_active,
        "ws_connected": ws_connected,
        "timestamp":    datetime.utcnow().isoformat() + "Z",
    }), 200 if db_ok else 503

# =============================================================================
# PROMETHEUS METRICS  (optional bearer-token auth)
# =============================================================================

@app.route("/metrics")
def metrics():
    """Expose Prometheus metrics in text format."""
    if not Config.METRICS_ENABLED:
        return jsonify({"error": "metrics disabled"}), 404

    # Optional bearer token protection
    if Config.METRICS_TOKEN:
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {Config.METRICS_TOKEN}":
            return Response("Unauthorized", status=401,
                            headers={"WWW-Authenticate": "Bearer"})

    if not PROMETHEUS_AVAILABLE:
        return jsonify({"error": "prometheus-client not installed"}), 503

    # Refresh gauges with live DB values
    try:
        LOGS_IN_DB.set(LogEntry.query.count())
        ATTACKS_IN_DB.set(Attack.query.count())
        BLOCKED_IPS.set(IPBlocklist.query.count())
        WS_CONNECTED.set(1 if ws_connected else 0)
    except Exception:
        pass

    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

# =============================================================================
# API — STATS
# =============================================================================

@app.route("/api/stats")
@login_required
def api_stats():
    last_24h = datetime.utcnow() - timedelta(hours=24)

    attack_type_rows = (
        db.session.query(Attack.attack_type, db.func.count(Attack.id))
        .group_by(Attack.attack_type).all()
    )
    attack_types = {row[0]: row[1] for row in attack_type_rows}

    hourly: dict = defaultdict(int)
    recent_attacks = Attack.query.filter(Attack.detected_at >= last_24h).all()
    for a in recent_attacks:
        hourly[a.detected_at.strftime("%H:00")] += 1
    hourly_distribution = dict(sorted(hourly.items()))

    return jsonify({
        "total_logs":          LogEntry.query.count(),
        "total_alerts":        Alert.query.count(),
        "total_attacks":       Attack.query.count(),
        "blocked_ips":         IPBlocklist.query.count(),
        "monitoring_active":   monitoring_active,
        "ws_connected":        ws_connected,
        "recent_attacks":      len(recent_attacks),
        "attack_types":        attack_types,
        "hourly_distribution": hourly_distribution,
        "active_monitoring":   monitoring_active,
        "ml_available":        ml_pipeline is not None,
    })

# =============================================================================
# API — LOGS
# =============================================================================

@app.route("/api/logs")
@login_required
def api_logs():
    page        = int(request.args.get("page", 1))
    per_page    = int(request.args.get("per_page", 20))
    severity    = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    ip_address  = request.args.get("ip_address")

    query = LogEntry.query
    if severity:    query = query.filter(LogEntry.severity == severity)
    if attack_type: query = query.filter(LogEntry.attack_type.ilike(f"%{attack_type}%"))
    if ip_address:  query = query.filter(LogEntry.ip_address.ilike(f"%{ip_address}%"))

    pag = query.order_by(LogEntry.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "items": [
            {
                "id":          l.id,
                "ip_address":  l.ip_address,
                "attack_type": l.attack_type,
                "endpoint":    l.endpoint,
                "payload":     l.payload,
                "user_agent":  l.user_agent,
                "severity":    l.severity,
                "timestamp":   l.timestamp.isoformat() + "Z" if l.timestamp else None,
                "raw_data":    l.raw_data,
            }
            for l in pag.items
        ],
        "total":    pag.total,
        "pages":    pag.pages,
        "page":     page,
        "per_page": per_page,
    })


@app.route("/api/logs/export")
@login_required
def api_logs_export():
    fmt  = request.args.get("format", "json")
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(10000).all()

    if fmt == "json":
        data = json.dumps([
            {
                "id": l.id, "ip_address": l.ip_address,
                "attack_type": l.attack_type, "endpoint": l.endpoint,
                "severity": l.severity,
                "timestamp": l.timestamp.isoformat() + "Z" if l.timestamp else None,
                "payload": l.payload,
            }
            for l in logs
        ], indent=2)
        return app.response_class(
            data, mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=quorra_logs.json"},
        )

    if fmt == "cef":
        lines = [
            f"CEF:0|Quorra|SIEM|2.0|{l.attack_type}|{l.attack_type}|"
            f"{'10' if l.severity == 'critical' else '7' if l.severity == 'high' else '5'}|"
            f"src={l.ip_address} request={l.endpoint} "
            f"msg={l.payload[:100] if l.payload else ''}"
            for l in logs
        ]
        return app.response_class(
            "\n".join(lines), mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=quorra_logs.cef"},
        )

    if fmt == "syslog":
        lines = [
            f"<134>{l.timestamp.strftime('%b %d %H:%M:%S') if l.timestamp else 'Jan 01 00:00:00'} "
            f"quorra-siem[{l.id}]: [{l.severity.upper()}] {l.attack_type} from {l.ip_address} "
            f"at {l.endpoint}"
            for l in logs
        ]
        return app.response_class(
            "\n".join(lines), mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=quorra_logs.log"},
        )

    return jsonify({"error": "unsupported format"}), 400

# =============================================================================
# API — ATTACKS
# =============================================================================

@app.route("/api/attacks")
@login_required
def api_attacks():
    attacks = Attack.query.order_by(Attack.detected_at.desc()).limit(500).all()
    return jsonify([
        {
            "id":          a.id,
            "attack_type": a.attack_type,
            "ip_address":  a.ip_address,
            "severity":    a.severity,
            "detected_at": a.detected_at.isoformat() + "Z" if a.detected_at else None,
            "details":     a.details,
        }
        for a in attacks
    ])

# =============================================================================
# API — ALERTS
# =============================================================================

@app.route("/api/alerts")
@login_required
def api_alerts():
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(500).all()
    return jsonify([
        {
            "id":           a.id,
            "message":      a.message,
            "alert_type":   a.alert_type,
            "severity":     a.severity,
            "details":      a.details,
            "created_at":   a.created_at.isoformat() + "Z" if a.created_at else None,
            "acknowledged": a.acknowledged,
            "read":         a.is_read,
            "is_read":      a.is_read,
        }
        for a in alerts
    ])


@app.route("/api/acknowledge_alert/<int:alert_id>", methods=["POST"])
@login_required
def acknowledge_alert(alert_id):
    ok = alert_system.acknowledge_alert(alert_id)
    ALERTS_CREATED_TOTAL.labels(severity="acknowledged", alert_type="ack").inc()
    return jsonify({"success": ok})


@app.route("/api/mark_read/<int:alert_id>", methods=["POST"])
@login_required
def mark_read(alert_id):
    ok = alert_system.mark_as_read(alert_id)
    return jsonify({"success": ok})

# =============================================================================
# API — BLOCKLIST
# =============================================================================

@app.route("/api/blocklist")
@login_required
def api_blocklist():
    items = IPBlocklist.query.order_by(IPBlocklist.blocked_at.desc()).all()
    return jsonify([
        {
            "id":         b.id,
            "ip_address": b.ip_address,
            "reason":     b.reason,
            "blocked_by": b.blocked_by,
            "blocked_at": b.blocked_at.isoformat() + "Z" if b.blocked_at else None,
        }
        for b in items
    ])


@app.route("/api/block_ip", methods=["POST"])
@login_required
def block_ip():
    data       = request.get_json(force=True, silent=True) or {}
    ip_address = data.get("ip_address", "").strip()
    reason     = data.get("reason", "Manual block")

    if not ip_address:
        return jsonify({"success": False, "message": "IP address required"}), 400

    existing = IPBlocklist.query.filter_by(ip_address=ip_address).first()
    if existing:
        return jsonify({"success": False, "message": f"{ip_address} is already blocked"})

    entry = IPBlocklist(
        ip_address=ip_address,
        reason=reason,
        blocked_by=session.get("user", "system"),
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"success": True, "message": f"IP {ip_address} blocked successfully"})


@app.route("/api/unblock_ip/<int:block_id>", methods=["DELETE"])
@login_required
def unblock_ip(block_id):
    entry = db.session.get(IPBlocklist, block_id)
    if not entry:
        return jsonify({"success": False, "message": "Not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"success": True, "message": f"IP {entry.ip_address} unblocked"})

# =============================================================================
# API — MONITORING CONTROLS
# =============================================================================

@app.route("/api/start_monitoring", methods=["POST"])
@login_required
def start_monitoring():
    global monitoring_active
    monitoring_active = True
    return jsonify({"success": True, "message": "Monitoring started"})


@app.route("/api/stop_monitoring", methods=["POST"])
@login_required
def stop_monitoring():
    global monitoring_active
    monitoring_active = False
    return jsonify({"success": True, "message": "Monitoring paused"})

# =============================================================================
# API — GEOIP
# =============================================================================

def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_global and not addr.is_private and not addr.is_loopback
                and not addr.is_link_local and not addr.is_multicast
                and not addr.is_reserved and not addr.is_unspecified)
    except ValueError:
        return False


@app.route("/api/geoip/<path:ip_address>")
@login_required
def api_geoip(ip_address):
    if not _is_public_ip(ip_address):
        return jsonify({"ip": ip_address, "error": "Not a public IP address", "source": None})

    if ip_address in _geo_cache:
        return jsonify(_geo_cache[ip_address])

    result = {"ip": ip_address, "source": None}

    if rules_engine.geoip_reader:
        try:
            resp = rules_engine.geoip_reader.city(ip_address)
            result.update({
                "country":      resp.country.name,
                "country_code": resp.country.iso_code,
                "city":         resp.city.name,
                "lat":          resp.location.latitude,
                "lon":          resp.location.longitude,
                "source":       "GeoLite2",
            })
            if len(_geo_cache) >= MAX_GEO_CACHE:
                _geo_cache.pop(next(iter(_geo_cache)))
            _geo_cache[ip_address] = result
            return jsonify(result)
        except Exception:
            pass

    try:
        import requests as _req
        r = _req.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result.update({
                    "country":      data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region":       data.get("regionName"),
                    "city":         data.get("city"),
                    "lat":          data.get("lat"),
                    "lon":          data.get("lon"),
                    "isp":          data.get("isp"),
                    "org":          data.get("org"),
                    "timezone":     data.get("timezone"),
                    "source":       "ip-api.com",
                })
                if len(_geo_cache) >= MAX_GEO_CACHE:
                    _geo_cache.pop(next(iter(_geo_cache)))
                _geo_cache[ip_address] = result
            else:
                result["error"] = data.get("message", "Private or reserved IP")
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)

# =============================================================================
# API — ML
# =============================================================================

@app.route("/api/ml/summary")
@login_required
def api_ml_summary():
    if not ml_pipeline:
        return jsonify({"error": "ML pipeline not available"}), 503
    return jsonify(ml_pipeline.get_ml_summary())


@app.route("/api/ml/entity/<entity_id>")
@login_required
def api_ml_entity(entity_id):
    if not ml_pipeline:
        return jsonify({"error": "ML pipeline not available"}), 503
    profile = ml_pipeline.ueba.get_profile(entity_id)
    history = ml_pipeline.risk.get_entity_history(entity_id)
    graph   = ml_pipeline.graph.get_entity_graph(entity_id)
    return jsonify({"profile": profile, "history": history, "graph": graph})

# =============================================================================
# INGEST  (rate-limited)
# =============================================================================

def _auth_ingest(api_key: str, client_ip: str) -> bool:
    expected = getattr(Config, "INGEST_API_KEY", "") or ""
    if expected:
        return api_key == expected
    return client_ip in ("127.0.0.1", "::1", "localhost")


def _process_ingest(data: dict) -> None:
    """Parse, persist, and analyse one ingest event. Shared by HTTP and WS."""
    ip_addr     = data.get("ipAddress") or (data.get("request") or {}).get("ip") or "unknown"
    endpoint    = data.get("endpoint")  or (data.get("request") or {}).get("path") or "unknown"
    attack_type = data.get("attackType") or data.get("event_type") or "unknown"
    payload     = data.get("payload")
    if payload is None:
        payload = json.dumps(data.get("details") or {})

    ts = data.get("timestamp")
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else datetime.utcnow()
        # Normalize to naive UTC so SQLite always stores a plain UTC value
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(_tz.utc).replace(tzinfo=None)
        timestamp = parsed
    except Exception:
        timestamp = datetime.utcnow()

    log = LogEntry(
        ip_address=ip_addr,
        attack_type=attack_type,
        endpoint=endpoint,
        payload=str(payload)[:1000],
        user_agent=data.get("userAgent") or (data.get("request") or {}).get("user_agent"),
        severity=data.get("severity", "medium"),
        timestamp=timestamp,
        raw_data=json.dumps(data),
    )
    db.session.add(log)
    db.session.commit()

    # Rules engine
    with app.app_context():
        rule_result = rules_engine.check_rules(log)
        if rule_result["triggered"]:
            db.session.add(Attack(
                attack_type=rule_result["rule"],
                ip_address=ip_addr,
                details=json.dumps(rule_result["details"]),
                severity=rule_result["severity"],
            ))
            RULES_TRIGGERED_TOTAL.labels(
                rule_name=rule_result["rule"],
                severity=rule_result["severity"],
            ).inc()

            if rule_result.get("block_ip"):
                if not IPBlocklist.query.filter_by(ip_address=ip_addr).first():
                    db.session.add(IPBlocklist(
                        ip_address=ip_addr,
                        reason=f"Auto-blocked: {rule_result['rule']}",
                        blocked_by="system",
                    ))

            alert_system.create_alert(
                message=f"Rule triggered: {rule_result['rule']} from {ip_addr}",
                alert_type=rule_result["rule"],
                severity=rule_result["severity"],
                details=rule_result["details"],
            )
            ALERTS_CREATED_TOTAL.labels(
                severity=rule_result["severity"],
                alert_type=rule_result["rule"],
            ).inc()
            db.session.commit()

    # ML pipeline
    if ml_pipeline:
        try:
            ml_result = ml_pipeline.analyze({
                "source_ip": ip_addr, "ip_address": ip_addr,
                "path": endpoint, "endpoint": endpoint,
                "event_type": attack_type, "attack_type": attack_type,
                "payload": str(payload)[:500], "body": str(payload)[:500],
                "user_agent": data.get("userAgent", ""),
                "status_code": data.get("statusCode", 0),
                "request_size": data.get("requestSize", 0),
                "response_size": data.get("responseSize", 0),
                "severity": data.get("severity", "medium"),
                "timestamp": timestamp.isoformat() + "Z",
                "message": str(payload)[:200],
            })
            if ml_result["severity"] in ("high", "critical"):
                with app.app_context():
                    alert_system.create_ml_alert(ml_result, log_entry=log)
                ML_ANOMALIES_TOTAL.labels(severity=ml_result["severity"]).inc()
        except Exception as ml_err:
            print(f"ML analysis error: {ml_err}")


def _apply_ingest_rate_limit():
    """Apply ingest rate limit if flask-limiter is available."""
    if LIMITER_AVAILABLE and limiter:
        try:
            limiter.limit(Config.RATELIMIT_INGEST)(lambda: None)()
        except Exception:
            raise


@app.route("/ingest", methods=["POST"])
def ingest():
    try:
        api_key   = request.headers.get("X-Quorra-Key", "")
        client_ip = request.remote_addr or ""
        if not _auth_ingest(api_key, client_ip):
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        data = request.get_json(force=True, silent=False)
        _process_ingest(data)
        INGEST_EVENTS_TOTAL.labels(transport="http").inc()
        return jsonify({"ok": True}), 200

    except Exception as e:
        INGEST_ERRORS_TOTAL.inc()
        logger.error("Ingest error: %s", e)
        return jsonify({"ok": False, "error": "Internal server error"}), 500


# Apply rate limit decorator to ingest if available
if LIMITER_AVAILABLE and limiter:
    ingest = limiter.limit(Config.RATELIMIT_INGEST)(ingest)


@sock.route("/ws/ingest")
def ws_ingest(ws):
    """WebSocket ingest — SDK connects here for persistent low-latency delivery."""
    api_key   = request.args.get("key", "")
    client_ip = request.remote_addr or ""
    if not _auth_ingest(api_key, client_ip):
        ws.close(message=b"unauthorized")
        return

    while True:
        try:
            message = ws.receive()
            if message is None:
                break
            data = json.loads(message)
            with app.app_context():
                _process_ingest(data)
            INGEST_EVENTS_TOTAL.labels(transport="websocket").inc()
        except Exception as e:
            logger.error("WS ingest error: %s", e)
            break

# =============================================================================
# RULE BUILDER API
# =============================================================================

from app.rule_builder import (
    evaluator as _rule_evaluator,
    dsl_runner as _dsl_runner,
    AVAILABLE_FIELDS, SIMPLE_OPERATORS, TEMPORAL_OPERATORS, MITRE_TACTICS,
    RuleEvaluator,
)


@app.route("/rules")
@login_required
def rules_view():
    return render_template("rules.html", username=session["user"])


@app.route("/api/rules/schema")
@login_required
def api_rules_schema():
    return jsonify({
        "fields":            AVAILABLE_FIELDS,
        "simple_operators":  SIMPLE_OPERATORS,
        "temporal_operators": TEMPORAL_OPERATORS,
        "mitre_tactics":     MITRE_TACTICS,
        "severities":        ["info", "low", "medium", "high", "critical"],
        "actions":           ["alert", "block", "alert_and_block"],
        "dsl_template":      _dsl_runner.template,
        "restricted_python_available": __import__(
            'app.rule_builder', fromlist=['RESTRICTED_PYTHON']
        ).RESTRICTED_PYTHON,
    })


@app.route("/api/rules")
@login_required
def api_rules_list():
    from app.models import CustomRule
    rules = CustomRule.query.order_by(CustomRule.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rules])


@app.route("/api/rules", methods=["POST"])
@login_required
def api_rules_create():
    from app.models import CustomRule
    data = request.get_json(force=True, silent=True) or {}

    level       = int(data.get("level", 2))
    name        = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()

    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    if level not in (1, 2, 3):
        return jsonify({"ok": False, "error": "level must be 1, 2, or 3"}), 400

    rule = CustomRule(
        name=name, description=description, level=level,
        severity=data.get("severity", "medium"),
        mitre_tactic=data.get("mitre_tactic"),
        action=data.get("action", "alert"),
        block_ip=bool(data.get("block_ip", False)),
        enabled=True,
        created_by=session.get("user", "unknown"),
    )

    if level in (1, 2):
        raw = data.get("rule_definition") or ""
        if isinstance(raw, dict):
            rule_def, error = raw, None
        else:
            rule_def, error = _rule_evaluator.parse_yaml(raw)
        if error:
            return jsonify({"ok": False, "error": f"Parse error: {error}"}), 400
        ok, err = _rule_evaluator.validate(rule_def)
        if not ok:
            return jsonify({"ok": False, "error": err}), 400
        rule_def.setdefault("rule_name", name)
        rule.rule_definition = json.dumps(rule_def)

    elif level == 3:
        code = data.get("rule_python") or ""
        ok, err = _dsl_runner.validate(code)
        if not ok:
            return jsonify({"ok": False, "error": err}), 400
        rule.rule_python = code

    db.session.add(rule)
    db.session.commit()
    return jsonify({"ok": True, "rule": rule.to_dict()}), 201


@app.route("/api/rules/<int:rule_id>", methods=["PUT"])
@login_required
def api_rules_update(rule_id):
    from app.models import CustomRule
    rule = db.session.get(CustomRule, rule_id)
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404

    data = request.get_json(force=True, silent=True) or {}

    for field in ("name", "description", "severity", "mitre_tactic", "action"):
        if field in data:
            setattr(rule, field, data[field])
    if "block_ip" in data: rule.block_ip = bool(data["block_ip"])
    if "enabled"  in data: rule.enabled  = bool(data["enabled"])

    if rule.level in (1, 2) and "rule_definition" in data:
        raw = data["rule_definition"]
        rule_def, error = (raw, None) if isinstance(raw, dict) else _rule_evaluator.parse_yaml(raw)
        if error:
            return jsonify({"ok": False, "error": f"Parse error: {error}"}), 400
        ok, err = _rule_evaluator.validate(rule_def)
        if not ok:
            return jsonify({"ok": False, "error": err}), 400
        rule.rule_definition = json.dumps(rule_def)

    if rule.level == 3 and "rule_python" in data:
        ok, err = _dsl_runner.validate(data["rule_python"])
        if not ok:
            return jsonify({"ok": False, "error": err}), 400
        rule.rule_python = data["rule_python"]

    rule.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "rule": rule.to_dict()})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@login_required
def api_rules_delete(rule_id):
    from app.models import CustomRule
    rule = db.session.get(CustomRule, rule_id)
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def api_rules_toggle(rule_id):
    from app.models import CustomRule
    rule = db.session.get(CustomRule, rule_id)
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    rule.enabled = not rule.enabled
    db.session.commit()
    return jsonify({"ok": True, "enabled": rule.enabled})


@app.route("/api/rules/<int:rule_id>/test", methods=["POST"])
@login_required
def api_rules_test(rule_id):
    from app.models import CustomRule
    rule = db.session.get(CustomRule, rule_id)
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404

    data   = request.get_json(force=True, silent=True) or {}
    sample = data.get("event")

    if not sample:
        recent = LogEntry.query.order_by(LogEntry.timestamp.desc()).first()
        sample = {
            "ip_address":  recent.ip_address   if recent else "1.2.3.4",
            "attack_type": recent.attack_type  if recent else "SQL Injection Attempt",
            "endpoint":    recent.endpoint     if recent else "/api/login",
            "payload":     recent.payload      if recent else "' OR 1=1 --",
            "severity":    recent.severity     if recent else "high",
            "user_agent":  recent.user_agent   if recent else "Mozilla/5.0",
        }

    triggered = False
    error     = None

    if rule.level in (1, 2) and rule.rule_definition:
        try:
            triggered = RuleEvaluator().evaluate(json.loads(rule.rule_definition), sample)
        except Exception as e:
            error = str(e)
    elif rule.level == 3 and rule.rule_python:
        triggered, error = _dsl_runner.execute(rule.rule_python, sample)

    return jsonify({"ok": True, "triggered": triggered, "error": error, "event": sample})

# =============================================================================
# SDK
# =============================================================================

_SDK_DIR = str(Path(__file__).resolve().parent.parent / "sdk")


@app.route("/quorra-sdk.js")
def serve_sdk():
    return send_from_directory(_SDK_DIR, "quorra-sdk.js", mimetype="application/javascript")


@app.route("/sdk")
@login_required
def sdk_view():
    return render_template("sdk.html", username=session["user"])

# =============================================================================
# WebSocket connector to Block Fortress
# =============================================================================

def on_ws_message(_ws, message):
    try:
        data = json.loads(message)
        with app.app_context():
            log = LogEntry(
                ip_address  = data.get("ipAddress",  "unknown"),
                attack_type = data.get("attackType", "unknown"),
                endpoint    = data.get("endpoint",   "unknown"),
                payload     = str(data.get("payload", ""))[:1000],
                severity    = data.get("severity",   "medium"),
                raw_data    = json.dumps(data),
                timestamp   = datetime.utcnow(),
            )
            db.session.add(log)
            db.session.commit()
    except Exception as e:
        logger.error("WS message error: %s", e)


def connect_websocket():
    global ws_connected
    delay     = Config.WS_RECONNECT_DELAY
    max_delay = 60
    jitter    = 0
    while monitoring_active:
        try:
            def on_open(_ws):
                global ws_connected
                ws_connected = True
                WS_CONNECTED.set(1)

            api_key = getattr(Config, "INGEST_API_KEY", "") or ""
            ws_headers = {"x-quorra-key": api_key} if api_key else {}
            ws = websocket.WebSocketApp(
                Config.BLOCK_FORTRESS_WS_URL,
                on_message=on_ws_message,
                on_open=on_open,
                header=ws_headers,
            )
            delay = Config.WS_RECONNECT_DELAY
            ws.run_forever()
        except Exception:
            pass
        ws_connected = False
        WS_CONNECTED.set(0)
        import random
        sleep_time = min(delay + random.uniform(0, 1), max_delay)
        time.sleep(sleep_time)
        delay = min(delay * 2, max_delay)


Thread(target=connect_websocket, daemon=True).start()

# =============================================================================
# Syslog listener (optional)
# =============================================================================
if Config.SYSLOG_LISTENER_ENABLED:
    try:
        from app.syslog_listener import start_syslog_listeners
        start_syslog_listeners(app)
    except Exception as e:
        print(f"Warning: Could not start syslog listener: {e}")

# =============================================================================
# Startup warnings
# =============================================================================
if not getattr(Config, "INGEST_API_KEY", ""):
    print("Warning: INGEST_API_KEY not set — /ingest only accepts localhost connections. "
          "Set the INGEST_API_KEY environment variable to accept external events.")

print("Quorra SIEM v2.0.0 ready")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
