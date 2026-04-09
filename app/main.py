# app/main.py  — Courra-Sec v2.0 — Multi-tenant SaaS
import os
import re
import time
import json
import secrets
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone as _tz
from functools import wraps
from pathlib import Path
from threading import Thread

import websocket
from flask import (
    Flask, render_template, jsonify, request, g,
    redirect, url_for, session, send_from_directory, Response, make_response,
)
from flask_cors import CORS
from flask_sock import Sock

from app.config import Config
from app.database import init_db, db
from app.rules_engine import RulesEngine
from app.log_collector import LogCollector
from app.alert_system import AlertSystem
from app.correlation_engine import correlation_engine
from app.playbook_engine import playbook_engine
from app.log_normalizer import normalize, normalize_severity, compute_dedup_hash, is_duplicate
from app.models import (
    Organisation, CourraSecUser, LogEntry, Alert, Attack,
    IPBlocklist, CustomRule, SoarAction, ApiKeyUsage,
)
from app.metrics import (
    PROMETHEUS_AVAILABLE,
    HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION,
    INGEST_EVENTS_TOTAL, INGEST_ERRORS_TOTAL,
    RULES_TRIGGERED_TOTAL, ALERTS_CREATED_TOTAL, ML_ANOMALIES_TOTAL,
    LOGS_IN_DB, ATTACKS_IN_DB, BLOCKED_IPS, WS_CONNECTED,
)

logger = logging.getLogger(__name__)

SUPERADMIN_USERNAME = os.environ.get("SUPERADMIN_USERNAME", "superadmin")

# =============================================================================
# Flask App
# =============================================================================
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# CORS: open only on /ingest
CORS(app, resources={r"/ingest": {"origins": "*"},
                     r"/ws/ingest": {"origins": "*"}})
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
        default_limits=[],
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
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:;"
    )
    return response

# =============================================================================
# Jinja2 custom filters
# =============================================================================
import json as _json_mod

@app.template_filter('from_json')
def _from_json(s):
    try:
        return _json_mod.loads(s or '[]')
    except Exception:
        return []

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
# ML Pipeline (per-org lazy registry)
# =============================================================================
_pipelines: dict = {}
ml_pipeline = None   # legacy fallback

try:
    from app.ml import MLPipeline
    _global_ml = MLPipeline()
    _global_ml.load()
    ml_pipeline = _global_ml
    print("ML pipeline loaded")
except Exception as e:
    print(f"Warning: ML pipeline not available: {e}")


def get_pipeline(org_id: int):
    """Return (or create) a per-org ML pipeline."""
    if not _pipelines.get(org_id):
        try:
            from app.ml import MLPipeline
            p = MLPipeline()
            p.load()
            _pipelines[org_id] = p
        except Exception:
            _pipelines[org_id] = ml_pipeline  # fallback to global
    return _pipelines.get(org_id)

# =============================================================================
# State
# =============================================================================
monitoring_active = True
ws_connected      = False
_geo_cache: dict  = {}
MAX_GEO_CACHE     = 1000

# =============================================================================
# Auth / Tenant helpers
# =============================================================================

def require_auth(f):
    """Ensure the user is authenticated and load g.user / g.org."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id = session.get("user_id")
        org_id  = session.get("organisation_id")
        if not user_id or not org_id:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))

        user = CourraSecUser.query.filter_by(id=user_id, is_active=True).first()
        org  = Organisation.query.filter_by(id=org_id, status='active').first()

        if not user or not org or user.organisation_id != org_id:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))

        g.user = user
        g.org  = org
        g.user_id = user.id
        g.org_id  = org.id
        return f(*args, **kwargs)
    return wrapper


def require_role(*roles):
    """Decorator: require g.user.role in allowed roles."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not hasattr(g, 'user'):
                return jsonify({"error": "Authentication required"}), 401
            if g.user.role not in roles:
                return jsonify({"error": f"Insufficient permissions — requires: {', '.join(roles)}"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_superadmin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not hasattr(g, 'user') or g.user.username != SUPERADMIN_USERNAME:
            return jsonify({"error": "Superadmin access required"}), 403
        return f(*args, **kwargs)
    return wrapper


def _make_slug(name: str, max_len: int = 60) -> str:
    s = re.sub(r'[^a-z0-9\s-]', '', name.lower())
    s = re.sub(r'[\s-]+', '-', s).strip('-')
    return s[:max_len] or 'org'


def _unique_slug(base: str) -> str:
    slug = base
    n = 1
    while Organisation.query.filter_by(slug=slug).first():
        slug = f"{base}-{n}"
        n += 1
    return slug


def _inject_nav_context():
    """Inject common template vars from g into kwargs."""
    kwargs = {}
    if hasattr(g, 'user'):
        kwargs['g_username']    = g.user.username
        kwargs['g_role']        = g.user.role
        kwargs['g_user_id']     = g.user.id
        kwargs['g_org_name']    = g.org.name
        kwargs['g_org_slug']    = g.org.slug
        kwargs['is_superadmin'] = (g.user.username == SUPERADMIN_USERNAME)
    return kwargs


# =============================================================================
# LANDING PAGE
# =============================================================================

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


# =============================================================================
# REGISTRATION
# =============================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("register.html", form={})

    # Collect fields
    org_name  = request.form.get("org_name",  "").strip()
    full_name = request.form.get("full_name", "").strip()
    email     = request.form.get("email",     "").strip().lower()
    username  = request.form.get("username",  "").strip().lower()
    password  = request.form.get("password",  "")
    confirm   = request.form.get("confirm_password", "")
    terms     = request.form.get("terms")

    form = {"org_name": org_name, "full_name": full_name,
            "email": email, "username": username}

    def err(msg):
        return render_template("register.html", error=msg, form=form)

    if not all([org_name, full_name, email, username, password, confirm]):
        return err("All fields are required.")
    if not terms:
        return err("You must accept the Terms of Service.")
    if len(password) < 8:
        return err("Password must be at least 8 characters.")
    if password != confirm:
        return err("Passwords do not match.")
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
        return err("Invalid email address.")
    if Organisation.query.filter_by(owner_email=email).first():
        return err("An organisation is already registered with this email.")

    # Generate slug + API key
    slug    = _unique_slug(_make_slug(org_name))
    api_key = 'qrr_live_' + secrets.token_urlsafe(32)

    org = Organisation(
        name=org_name,
        slug=slug,
        api_key=api_key,
        api_key_prefix='qrr_live_',
        owner_email=email,
        plan='free',
        status='active',
    )
    db.session.add(org)
    db.session.flush()  # get org.id

    # Check username uniqueness within org (trivial for new org)
    owner = CourraSecUser(
        organisation_id=org.id,
        username=username,
        email=email,
        full_name=full_name,
        role='owner',
        is_admin=True,
        must_change_password=False,
        password_change_required=False,
    )
    owner.set_password(password)
    db.session.add(owner)
    db.session.commit()

    # Auto-login
    session["user_id"]        = owner.id
    session["organisation_id"] = org.id
    session.permanent          = True
    return redirect(url_for("onboarding"))


# =============================================================================
# ONBOARDING
# =============================================================================

@app.route("/onboarding")
@require_auth
def onboarding():
    siem_url = request.host_url.rstrip('/')
    return render_template(
        "onboarding.html",
        org=g.org,
        siem_url=siem_url,
        **_inject_nav_context(),
    )


# =============================================================================
# AUTH ROUTES
# =============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    # --- Step 2: TOTP verification ---
    if request.method == "POST" and request.form.get("totp_step"):
        pending_user_id = session.get("totp_pending_user_id")
        if not pending_user_id:
            return render_template("login.html", error="Session expired. Please log in again.")
        code = request.form.get("totp_code", "").strip()
        user = CourraSecUser.query.filter_by(id=pending_user_id, is_active=True).first()
        if user and user.verify_totp(code):
            session.pop("totp_pending_user_id", None)
            session["user_id"]          = user.id
            session["organisation_id"]  = user.organisation_id
            session.permanent           = True
            user.last_login = datetime.utcnow()
            db.session.commit()
            if user.must_change_password or user.password_change_required:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))
        return render_template("login.html", totp_step=True,
                               error="Invalid authenticator code. Try again.")

    # --- Step 1: Username/email + password ---
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password   = request.form.get("password", "")

        # Look up by username OR email (global — user can be in any org)
        user = (CourraSecUser.query.filter_by(username=identifier, is_active=True).first() or
                CourraSecUser.query.filter_by(email=identifier,    is_active=True).first())

        if user and user.check_password(password):
            # Check org is active
            org = Organisation.query.filter_by(
                id=user.organisation_id, status='active'
            ).first()
            if not org:
                return render_template("login.html",
                                       error="Your organisation has been suspended. Contact support.")

            if user.totp_enabled:
                session["totp_pending_user_id"] = user.id
                return render_template("login.html", totp_step=True)

            session["user_id"]          = user.id
            session["organisation_id"]  = user.organisation_id
            session.permanent           = True
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Audit: login
            from app.audit import audit_log, Actions
            audit_log(Actions.LOGIN, org_id=user.organisation_id,
                      user_id=user.id, username=user.username,
                      ip=request.headers.get('X-Forwarded-For','').split(',')[0].strip() or request.remote_addr)

            if user.must_change_password or user.password_change_required:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))

        # Audit: failed login
        try:
            from app.audit import audit_log, Actions
            audit_log(Actions.LOGIN_FAILED, username=identifier,
                      ip=request.headers.get('X-Forwarded-For','').split(',')[0].strip() or request.remote_addr)
        except Exception:
            pass

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@require_auth
def change_password():
    user = g.user

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

        user.set_password(new_pw)
        user.must_change_password      = False
        user.password_change_required  = False
        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template("change_password.html",
                           username=user.username,
                           required=user.must_change_password)


# =============================================================================
# TOTP ROUTES
# =============================================================================

@app.route("/api/totp/setup", methods=["POST"])
@require_auth
def api_totp_setup():
    user = g.user
    try:
        import pyotp, qrcode, io, base64
        secret  = user.generate_totp_secret()
        db.session.commit()
        uri     = user.get_totp_uri()
        img     = qrcode.make(uri)
        buf     = io.BytesIO()
        img.save(buf, format="PNG")
        qr_data = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
        return jsonify({"ok": True, "secret": secret, "uri": uri, "qr": qr_data})
    except ImportError:
        secret = user.generate_totp_secret()
        db.session.commit()
        uri    = user.get_totp_uri()
        return jsonify({"ok": True, "secret": secret, "uri": uri, "qr": None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/totp/enable", methods=["POST"])
@require_auth
def api_totp_enable():
    user = g.user
    code = (request.get_json(force=True, silent=True) or {}).get("code", "")
    if not user.verify_totp(code):
        return jsonify({"ok": False, "error": "Invalid code"}), 400
    user.totp_enabled = True
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/totp/disable", methods=["POST"])
@require_auth
def api_totp_disable():
    user = g.user
    data = request.get_json(force=True, silent=True) or {}
    if not user.check_password(data.get("password", "")):
        return jsonify({"ok": False, "error": "Incorrect password"}), 403
    user.totp_enabled = False
    user.totp_secret  = None
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# UI ROUTES
# =============================================================================

@app.route("/dashboard")
@require_auth
def dashboard():
    org_id = g.org.id
    return render_template(
        "dashboard.html",
        username=g.user.username,
        logs=LogEntry.query.filter_by(organisation_id=org_id)
                     .order_by(LogEntry.timestamp.desc()).limit(10).all(),
        alerts=Alert.query.filter_by(organisation_id=org_id)
                    .order_by(Alert.created_at.desc()).limit(10).all(),
        attacks=Attack.query.filter_by(organisation_id=org_id)
                      .order_by(Attack.detected_at.desc()).limit(10).all(),
        blocked_ips=IPBlocklist.query.filter_by(organisation_id=org_id).count(),
        **_inject_nav_context(),
    )


@app.route("/logs")
@require_auth
def logs_view():
    return render_template("logs.html",
                           username=g.user.username, **_inject_nav_context())


@app.route("/attacks")
@require_auth
def attacks_view():
    org_id = g.org.id
    return render_template(
        "attacks.html",
        attacks=Attack.query.filter_by(organisation_id=org_id)
                      .order_by(Attack.detected_at.desc()).all(),
        username=g.user.username,
        **_inject_nav_context(),
    )


@app.route("/alerts")
@require_auth
def alerts_view():
    org_id = g.org.id
    return render_template(
        "alerts.html",
        alerts=Alert.query.filter_by(organisation_id=org_id).all(),
        username=g.user.username,
        **_inject_nav_context(),
    )


@app.route("/blocklist")
@require_auth
def blocklist_view():
    org_id = g.org.id
    return render_template(
        "blocklist.html",
        blocked_ips=IPBlocklist.query.filter_by(organisation_id=org_id).all(),
        username=g.user.username,
        **_inject_nav_context(),
    )


@app.route("/ml-dashboard")
@require_auth
def ml_dashboard():
    pipeline = get_pipeline(g.org.id)
    summary  = pipeline.get_ml_summary() if pipeline else {}
    return render_template("ml_dashboard.html",
                           summary=summary, username=g.user.username,
                           **_inject_nav_context())


@app.route("/rules")
@require_auth
def rules_view():
    return render_template("rules.html",
                           username=g.user.username, **_inject_nav_context())


@app.route("/sdk")
@require_auth
def sdk_view():
    return render_template("sdk.html",
                           username=g.user.username, **_inject_nav_context())


@app.route("/demo")
def demo():
    # Redirect to dashboard if logged in, otherwise to register
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("register"))


# =============================================================================
# SETTINGS ROUTES
# =============================================================================

@app.route("/settings/team")
@require_auth
def settings_team():
    org_id = g.org.id
    users  = CourraSecUser.query.filter_by(organisation_id=org_id).all()
    return render_template(
        "settings/team.html",
        org=g.org, users=users,
        **_inject_nav_context(),
    )


@app.route("/settings/organisation")
@require_auth
def settings_organisation():
    from app.models import ApiKeyUsage
    org    = g.org
    org_id = org.id
    today  = datetime.utcnow().date()

    # Build masked key
    key = org.api_key
    masked = key[:12] + '...' + key[-4:] if len(key) > 16 else key

    usage_today = 0
    usage_row   = ApiKeyUsage.query.filter_by(organisation_id=org_id, date=today).first()
    if usage_row:
        usage_today = usage_row.log_count

    total_logs  = LogEntry.query.filter_by(organisation_id=org_id).count()
    active_users = CourraSecUser.query.filter_by(organisation_id=org_id, is_active=True).count()

    return render_template(
        "settings/organisation.html",
        org=org,
        masked_key=masked,
        usage_today=usage_today,
        total_logs=total_logs,
        active_users=active_users,
        **_inject_nav_context(),
    )


# =============================================================================
# TEAM API
# =============================================================================

@app.route("/api/team/invite", methods=["POST"])
@require_auth
@require_role('owner', 'admin')
def api_team_invite():
    from app.limits import check_limit
    allowed, msg = check_limit(g.org, 'max_users')
    if not allowed:
        return jsonify({"ok": False, "error": msg}), 429

    data      = request.get_json(force=True, silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    username  = (data.get("username")  or "").strip().lower()
    email     = (data.get("email")     or "").strip().lower()
    role      = data.get("role", "analyst")
    password  = data.get("password") or None

    if not all([username, email]):
        return jsonify({"ok": False, "error": "username and email are required"}), 400
    if role not in ('admin', 'analyst', 'readonly'):
        return jsonify({"ok": False, "error": "invalid role"}), 400

    if CourraSecUser.query.filter_by(organisation_id=g.org.id, username=username).first():
        return jsonify({"ok": False, "error": f"Username '{username}' already exists"}), 400
    if CourraSecUser.query.filter_by(organisation_id=g.org.id, email=email).first():
        return jsonify({"ok": False, "error": f"Email already registered in this organisation"}), 400

    temp_password = password or secrets.token_urlsafe(12)
    user = CourraSecUser(
        organisation_id=g.org.id,
        username=username,
        email=email,
        full_name=full_name,
        role=role,
        must_change_password=True,
        password_change_required=True,
    )
    user.set_password(temp_password)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "ok": True,
        "username": username,
        "temp_password": temp_password,
        "message": f"User '{username}' created with role '{role}'",
    })


@app.route("/api/team/deactivate/<int:user_id>", methods=["POST"])
@require_auth
@require_role('owner', 'admin')
def api_team_deactivate(user_id):
    user = CourraSecUser.query.filter_by(id=user_id, organisation_id=g.org.id).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if user.id == g.user.id:
        return jsonify({"ok": False, "error": "Cannot deactivate yourself"}), 400
    user.is_active = False
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/team/activate/<int:user_id>", methods=["POST"])
@require_auth
@require_role('owner', 'admin')
def api_team_activate(user_id):
    user = CourraSecUser.query.filter_by(id=user_id, organisation_id=g.org.id).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    user.is_active = True
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/team/change-role/<int:user_id>", methods=["POST"])
@require_auth
@require_role('owner')
def api_team_change_role(user_id):
    user = CourraSecUser.query.filter_by(id=user_id, organisation_id=g.org.id).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if user.id == g.user.id:
        return jsonify({"ok": False, "error": "Cannot change your own role"}), 400
    data = request.get_json(force=True, silent=True) or {}
    new_role = data.get("role", "")
    if new_role not in ('owner', 'admin', 'analyst', 'readonly'):
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    user.role = new_role
    db.session.commit()
    return jsonify({"ok": True, "role": new_role})


@app.route("/api/team/remove/<int:user_id>", methods=["DELETE"])
@require_auth
@require_role('owner')
def api_team_remove(user_id):
    user = CourraSecUser.query.filter_by(id=user_id, organisation_id=g.org.id).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if user.id == g.user.id:
        return jsonify({"ok": False, "error": "Cannot remove yourself"}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# ORGANISATION SETTINGS API
# =============================================================================

@app.route("/api/org/update", methods=["POST"])
@require_auth
@require_role('owner', 'admin')
def api_org_update():
    data = request.form or (request.get_json(force=True, silent=True) or {})
    if data.get("name"):
        g.org.name = data["name"].strip()
    if data.get("owner_email") and g.user.role == 'owner':
        g.org.owner_email = data["owner_email"].strip().lower()
    db.session.commit()
    return redirect(url_for("settings_organisation") + "?message=Saved")


@app.route("/api/org/reveal-key")
@require_auth
def api_org_reveal_key():
    return jsonify({"ok": True, "api_key": g.org.api_key})


@app.route("/api/org/regenerate-key", methods=["POST"])
@require_auth
@require_role('owner')
def api_org_regenerate_key():
    new_key       = 'qrr_live_' + secrets.token_urlsafe(32)
    g.org.api_key = new_key
    db.session.commit()
    return jsonify({"ok": True, "api_key": new_key})


@app.route("/api/org/log-count")
@require_auth
def api_org_log_count():
    today = datetime.utcnow().date()
    usage = ApiKeyUsage.query.filter_by(
        organisation_id=g.org.id, date=today
    ).first()
    return jsonify({
        "today": usage.log_count if usage else 0,
        "limit": g.org.max_logs_per_day,
    })


@app.route("/api/org/delete", methods=["DELETE"])
@require_auth
@require_role('owner')
def api_org_delete():
    org_id = g.org.id
    org    = g.org

    # Hard delete all related data
    from app.models import Case, CaseItem
    # Delete CaseItems for all org cases first (no ORM cascade on bulk delete)
    org_case_ids = [c.id for c in Case.query.filter_by(organisation_id=org_id).with_entities(Case.id)]
    if org_case_ids:
        CaseItem.query.filter(CaseItem.case_id.in_(org_case_ids)).delete(synchronize_session=False)
    Case.query.filter_by(organisation_id=org_id).delete()
    for model in [LogEntry, Alert, Attack, IPBlocklist, CustomRule,
                  SoarAction, ApiKeyUsage]:
        model.query.filter_by(organisation_id=org_id).delete()
    CourraSecUser.query.filter_by(organisation_id=org_id).delete()
    db.session.delete(org)
    db.session.commit()
    session.clear()
    return jsonify({"ok": True})


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.route("/api/integration/status")
@require_auth
def api_integration_status():
    """Diagnostic endpoint: shows Block Fortress connection state and ingest stats."""
    import requests as _req
    bf_reachable = False
    bf_error = None
    try:
        r = _req.get(f"{Config.BLOCK_FORTRESS_URL}/api/products", timeout=3)
        bf_reachable = r.status_code == 200
    except Exception as e:
        bf_error = str(e)

    default_org = Organisation.query.filter_by(slug='default', status='active').first()
    total_logs  = LogEntry.query.filter_by(organisation_id=g.org.id).count() if hasattr(g, 'org') else 0

    return jsonify({
        "ws_connected":        ws_connected,
        "block_fortress_url":  Config.BLOCK_FORTRESS_URL,
        "block_fortress_ws":   Config.BLOCK_FORTRESS_WS_URL,
        "block_fortress_up":   bf_reachable,
        "block_fortress_error": bf_error,
        "default_org_exists":  default_org is not None,
        "default_org_api_key": (default_org.api_key[:12] + "...") if default_org else None,
        "total_logs_in_db":    total_logs,
        "ingest_endpoint":     "/ingest",
        "localhost_bypass":    "enabled",
    })


@app.route("/health")
def health():
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
# PROMETHEUS METRICS
# =============================================================================

@app.route("/metrics")
def metrics():
    if not Config.METRICS_ENABLED:
        return jsonify({"error": "metrics disabled"}), 404

    if Config.METRICS_TOKEN:
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {Config.METRICS_TOKEN}":
            return Response("Unauthorized", status=401,
                            headers={"WWW-Authenticate": "Bearer"})

    if not PROMETHEUS_AVAILABLE:
        return jsonify({"error": "prometheus-client not installed"}), 503

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
# API — STATS (tenant-scoped)
# =============================================================================

@app.route("/api/stats")
@require_auth
def api_stats():
    org_id   = g.org.id
    last_24h = datetime.utcnow() - timedelta(hours=24)

    attack_type_rows = (
        db.session.query(Attack.attack_type, db.func.count(Attack.id))
        .filter_by(organisation_id=org_id)
        .group_by(Attack.attack_type).all()
    )
    attack_types = {row[0]: row[1] for row in attack_type_rows}

    hourly: dict = defaultdict(int)
    recent_attacks = (Attack.query
                      .filter_by(organisation_id=org_id)
                      .filter(Attack.detected_at >= last_24h).all())
    for a in recent_attacks:
        hourly[a.detected_at.strftime("%H:00")] += 1
    hourly_distribution = dict(sorted(hourly.items()))

    today = datetime.utcnow().date()
    usage = ApiKeyUsage.query.filter_by(organisation_id=org_id, date=today).first()

    return jsonify({
        "total_logs":          LogEntry.query.filter_by(organisation_id=org_id).count(),
        "total_alerts":        Alert.query.filter_by(organisation_id=org_id).count(),
        "total_attacks":       Attack.query.filter_by(organisation_id=org_id).count(),
        "blocked_ips":         IPBlocklist.query.filter_by(organisation_id=org_id).count(),
        "monitoring_active":   monitoring_active,
        "ws_connected":        ws_connected,
        "recent_attacks":      len(recent_attacks),
        "attack_types":        attack_types,
        "hourly_distribution": hourly_distribution,
        "active_monitoring":   monitoring_active,
        "ml_available":        ml_pipeline is not None,
        "logs_today":          usage.log_count if usage else 0,
        "logs_limit":          g.org.max_logs_per_day,
    })


# =============================================================================
# API — LOGS (tenant-scoped)
# =============================================================================

@app.route("/api/logs")
@require_auth
def api_logs():
    org_id      = g.org.id
    page        = int(request.args.get("page", 1))
    per_page    = int(request.args.get("per_page", 20))
    severity    = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    ip_address  = request.args.get("ip_address")

    show_suppressed = request.args.get("suppressed", "false").lower() == "true"

    query = LogEntry.query.filter_by(organisation_id=org_id)
    if not show_suppressed:
        query = query.filter(
            (LogEntry.suppressed == False) | (LogEntry.suppressed == None)  # noqa: E712
        )
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
                "suppressed":  bool(l.suppressed),
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
@require_auth
def api_logs_export():
    org_id = g.org.id
    fmt    = request.args.get("format", "json")
    logs   = (LogEntry.query.filter_by(organisation_id=org_id)
              .order_by(LogEntry.timestamp.desc()).limit(10000).all())

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
            headers={"Content-Disposition": "attachment;filename=courra-sec_logs.json"},
        )

    _CEF_SEV = {'critical': '10', 'high': '7', 'medium': '5', 'low': '3', 'info': '1'}
    if fmt == "cef":
        lines = [
            f"CEF:0|Courra-Sec|SIEM|2.0|{l.attack_type}|{l.attack_type}|"
            f"{_CEF_SEV.get(l.severity, '5')}|"
            f"src={l.ip_address} request={l.endpoint} "
            f"msg={l.payload[:100] if l.payload else ''}"
            for l in logs
        ]
        return app.response_class(
            "\n".join(lines), mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=courra-sec_logs.cef"},
        )

    if fmt == "syslog":
        lines = [
            f"<134>{l.timestamp.strftime('%b %d %H:%M:%S') if l.timestamp else 'Jan 01 00:00:00'} "
            f"courra-sec[{l.id}]: [{l.severity.upper()}] {l.attack_type} from {l.ip_address} "
            f"at {l.endpoint}"
            for l in logs
        ]
        return app.response_class(
            "\n".join(lines), mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=courra-sec_logs.log"},
        )

    return jsonify({"error": "unsupported format"}), 400


# =============================================================================
# API — ATTACKS (tenant-scoped)
# =============================================================================

@app.route("/api/attacks")
@require_auth
def api_attacks():
    org_id  = g.org.id
    attacks = (Attack.query.filter_by(organisation_id=org_id)
               .order_by(Attack.detected_at.desc()).limit(500).all())
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
# API — ALERTS (tenant-scoped)
# =============================================================================

@app.route("/api/alerts")
@require_auth
def api_alerts():
    org_id = g.org.id
    alerts = (Alert.query.filter_by(organisation_id=org_id)
              .order_by(Alert.created_at.desc()).limit(500).all())
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
@require_auth
def acknowledge_alert(alert_id):
    alert = Alert.query.filter_by(id=alert_id, organisation_id=g.org.id).first()
    if not alert:
        return jsonify({"success": False}), 404
    alert.acknowledged = True
    db.session.commit()
    ALERTS_CREATED_TOTAL.labels(severity="acknowledged", alert_type="ack").inc()
    return jsonify({"success": True})


@app.route("/api/mark_read/<int:alert_id>", methods=["POST"])
@require_auth
def mark_read(alert_id):
    alert = Alert.query.filter_by(id=alert_id, organisation_id=g.org.id).first()
    if not alert:
        return jsonify({"success": False}), 404
    alert.is_read = True
    db.session.commit()
    return jsonify({"success": True})


# =============================================================================
# API — BLOCKLIST (tenant-scoped)
# =============================================================================

@app.route("/api/blocklist")
@require_auth
def api_blocklist():
    org_id = g.org.id
    items  = (IPBlocklist.query.filter_by(organisation_id=org_id)
              .order_by(IPBlocklist.blocked_at.desc()).all())
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
@require_auth
@require_role('owner', 'admin', 'analyst')
def block_ip():
    from app.limits import check_limit
    allowed, msg = check_limit(g.org, 'max_blocklist')
    if not allowed:
        return jsonify({"success": False, "message": msg}), 429

    data       = request.get_json(force=True, silent=True) or {}
    ip_address = data.get("ip_address", "").strip()
    reason     = data.get("reason", "Manual block")

    if not ip_address:
        return jsonify({"success": False, "message": "IP address required"}), 400

    existing = IPBlocklist.query.filter_by(
        organisation_id=g.org.id, ip_address=ip_address
    ).first()
    if existing:
        return jsonify({"success": False, "message": f"{ip_address} is already blocked"})

    entry = IPBlocklist(
        organisation_id=g.org.id,
        ip_address=ip_address,
        reason=reason,
        blocked_by=g.user.username,
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"success": True, "message": f"IP {ip_address} blocked successfully"})


@app.route("/api/unblock_ip/<int:block_id>", methods=["DELETE"])
@require_auth
@require_role('owner', 'admin', 'analyst')
def unblock_ip(block_id):
    entry = IPBlocklist.query.filter_by(
        id=block_id, organisation_id=g.org.id
    ).first()
    if not entry:
        return jsonify({"success": False, "message": "Not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"success": True, "message": f"IP {entry.ip_address} unblocked"})


# =============================================================================
# API — MONITORING CONTROLS
# =============================================================================

@app.route("/api/start_monitoring", methods=["POST"])
@require_auth
def start_monitoring():
    global monitoring_active
    monitoring_active = True
    return jsonify({"success": True, "message": "Monitoring started"})


@app.route("/api/stop_monitoring", methods=["POST"])
@require_auth
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
@require_auth
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
# API — ML (tenant-scoped)
# =============================================================================

@app.route("/api/ml/summary")
@require_auth
def api_ml_summary():
    pipeline = get_pipeline(g.org.id)
    if not pipeline:
        return jsonify({"error": "ML pipeline not available"}), 503
    return jsonify(pipeline.get_ml_summary())


@app.route("/api/ml/entity/<entity_id>")
@require_auth
def api_ml_entity(entity_id):
    pipeline = get_pipeline(g.org.id)
    if not pipeline:
        return jsonify({"error": "ML pipeline not available"}), 503
    profile = pipeline.ueba.get_profile(entity_id)
    history = pipeline.risk.get_entity_history(entity_id)
    graph   = pipeline.graph.get_entity_graph(entity_id)
    return jsonify({"profile": profile, "history": history, "graph": graph})


# =============================================================================
# INGEST  — API key authenticated, CORS open
# =============================================================================

def _lookup_org_by_api_key(api_key: str):
    """Return active Organisation matching the API key, or None."""
    if not api_key:
        return None
    return Organisation.query.filter_by(api_key=api_key, status='active').first()


def _check_daily_limit(org) -> bool:
    """Return True if org is within its daily log limit, False if over."""
    today = datetime.utcnow().date()
    usage = ApiKeyUsage.query.filter_by(organisation_id=org.id, date=today).first()
    return not (usage and usage.log_count >= org.max_logs_per_day)


def _increment_usage(org):
    today = datetime.utcnow().date()
    usage = ApiKeyUsage.query.filter_by(organisation_id=org.id, date=today).first()
    if not usage:
        usage = ApiKeyUsage(organisation_id=org.id, date=today, log_count=0)
        db.session.add(usage)
    usage.log_count += 1
    org.last_active  = datetime.utcnow()


def _is_suppressed(log_fields: dict, org_id: int) -> bool:
    """Return True if any active SuppressionRule matches the given log fields."""
    try:
        from app.models import SuppressionRule
        now = datetime.utcnow()
        rules = SuppressionRule.query.filter_by(
            organisation_id=org_id, enabled=True
        ).all()
        for rule in rules:
            # Skip expired rules
            if rule.expires_at and rule.expires_at < now:
                continue
            # Parse conditions
            try:
                conditions = json.loads(rule.conditions or '[]')
            except Exception:
                conditions = []
            # No conditions = suppress all
            if not conditions:
                rule.hit_count = (rule.hit_count or 0) + 1
                db.session.commit()
                return True
            # All conditions must match
            matched = True
            for cond in conditions:
                field = cond.get('field', '')
                op    = cond.get('op', 'eq')
                val   = str(cond.get('value', ''))
                actual = str(log_fields.get(field, '') or '')
                if op == 'eq':
                    if actual.lower() != val.lower():
                        matched = False; break
                elif op == 'contains':
                    if val.lower() not in actual.lower():
                        matched = False; break
                elif op == 'starts_with':
                    if not actual.lower().startswith(val.lower()):
                        matched = False; break
                elif op == 'regex':
                    if not re.search(val, actual, re.I):
                        matched = False; break
            if matched:
                rule.hit_count = (rule.hit_count or 0) + 1
                db.session.commit()
                return True
    except Exception:
        pass
    return False


def _process_ingest(data: dict, org_id: int) -> None:
    """Parse, normalise, deduplicate, suppress and analyse one ingest event. Tenant-scoped."""
    # ------------------------------------------------------------------ #
    # 1. Extract raw string for normalisation                             #
    # ------------------------------------------------------------------ #
    raw_str = data.get("raw") or data.get("message") or data.get("payload") or ""
    if not raw_str and isinstance(data, dict):
        raw_str = json.dumps(data)

    source_hint = data.get("source") or data.get("source_tag")

    # ------------------------------------------------------------------ #
    # 2. Normalise — structured fields take precedence over raw parse     #
    # ------------------------------------------------------------------ #
    norm = normalize(raw_str, source_hint=source_hint)

    # Explicit fields in the ingest payload always win over parsed ones
    ip_addr     = (data.get("ipAddress") or (data.get("request") or {}).get("ip")
                   or norm['ip_address'] or "unknown")
    endpoint    = (data.get("endpoint")  or (data.get("request") or {}).get("path")
                   or norm['endpoint']   or "unknown")
    attack_type = (data.get("attackType") or data.get("event_type")
                   or norm['attack_type'] or "unknown")
    user_agent  = (data.get("userAgent") or (data.get("request") or {}).get("user_agent")
                   or norm['user_agent'])
    severity    = normalize_severity(data.get("severity") or norm['severity'] or "medium")
    payload     = data.get("payload") or norm['payload'] or json.dumps(data.get("details") or {})

    ts = data.get("timestamp")
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else datetime.utcnow()
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(_tz.utc).replace(tzinfo=None)
        timestamp = parsed
    except Exception:
        timestamp = datetime.utcnow()

    # ------------------------------------------------------------------ #
    # 3. Deduplication — skip identical events within 60 s               #
    # ------------------------------------------------------------------ #
    dedup_hash = compute_dedup_hash(ip_addr, attack_type, endpoint, str(payload), org_id)
    if is_duplicate(dedup_hash, window_secs=60):
        return  # silently drop duplicate

    # ------------------------------------------------------------------ #
    # 4. Suppression — check SuppressionRule records                     #
    # ------------------------------------------------------------------ #
    log_fields_for_suppression = {
        'ip_address':  ip_addr,
        'attack_type': attack_type,
        'endpoint':    endpoint,
        'severity':    severity,
        'user_agent':  user_agent or '',
    }
    if _is_suppressed(log_fields_for_suppression, org_id):
        # Still persist the raw log but mark it suppressed; don't fire alerts
        log = LogEntry(
            organisation_id=org_id,
            ip_address=ip_addr,
            attack_type=attack_type,
            endpoint=endpoint,
            payload=str(payload)[:1000],
            user_agent=user_agent,
            severity=severity,
            timestamp=timestamp,
            raw_data=json.dumps(data),
            suppressed=True,
        )
        db.session.add(log)
        db.session.commit()
        return

    # ------------------------------------------------------------------ #
    # 5. Persist log entry                                                #
    # ------------------------------------------------------------------ #
    log = LogEntry(
        organisation_id=org_id,
        ip_address=ip_addr,
        attack_type=attack_type,
        endpoint=endpoint,
        payload=str(payload)[:1000],
        user_agent=user_agent,
        severity=severity,
        timestamp=timestamp,
        raw_data=json.dumps(data),
    )
    db.session.add(log)
    db.session.commit()

    # Rules engine — runs in the same app context as the caller
    rule_result = rules_engine.check_rules(log)
    if rule_result["triggered"]:
        db.session.add(Attack(
            organisation_id=org_id,
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
            try:
                existing_block = IPBlocklist.query.filter_by(
                    organisation_id=org_id, ip_address=ip_addr
                ).first()
                if not existing_block:
                    db.session.add(IPBlocklist(
                        organisation_id=org_id,
                        ip_address=ip_addr,
                        reason=f"Auto-blocked: {rule_result['rule']}",
                        blocked_by="system",
                    ))
                    db.session.flush()
            except Exception as block_err:
                db.session.rollback()
                logger.warning("Auto-block failed for %s: %s", ip_addr, block_err)

        # Create tenant-scoped alert
        alert = Alert(
            organisation_id=org_id,
            message=f"Rule triggered: {rule_result['rule']} from {ip_addr}",
            alert_type=rule_result["rule"],
            severity=rule_result["severity"],
            details=json.dumps(rule_result["details"]),
        )
        db.session.add(alert)
        ALERTS_CREATED_TOTAL.labels(
            severity=rule_result["severity"],
            alert_type=rule_result["rule"],
        ).inc()
        db.session.commit()
        # Fire external alert channels
        try:
            alert_system.send_alert(
                message=f"Rule triggered: {rule_result['rule']} from {ip_addr}",
                severity=rule_result["severity"],
                details=rule_result["details"],
            )
        except Exception:
            pass
        # Run playbooks for this alert
        try:
            playbook_engine.run_for_alert(alert, org_id)
        except Exception:
            pass

    # Correlation engine
    try:
        fired_correlations = correlation_engine.evaluate(log, org_id)
        for fired in fired_correlations:
            corr_alert = correlation_engine.create_alert_for_correlation(fired, org_id)
            if corr_alert:
                # Run playbooks for correlation alerts
                try:
                    playbook_engine.run_for_alert(corr_alert, org_id)
                except Exception:
                    pass
    except Exception as corr_err:
        logger.debug("Correlation engine error: %s", corr_err)

    # Threat intel enrichment
    try:
        from app.threat_intel import enrich_log_entry
        ioc_matches = enrich_log_entry(log, org_id)
        if ioc_matches:
            ioc_alert = Alert(
                organisation_id=org_id,
                message=f"IOC match: {log.ip_address} matched {len(ioc_matches)} threat indicator(s)",
                alert_type="threat_intel_match",
                severity="high",
                details=json.dumps({"matches": ioc_matches, "ip": log.ip_address}),
            )
            db.session.add(ioc_alert)
            db.session.commit()
            try:
                playbook_engine.run_for_alert(ioc_alert, org_id)
            except Exception:
                pass
    except Exception as ti_err:
        logger.debug("Threat intel enrichment error: %s", ti_err)

    # Playbooks for rule-triggered alerts (handled above in the rule block)

    # ML pipeline (per-org)
    pipeline = get_pipeline(org_id)
    if pipeline:
        try:
            ml_result = pipeline.analyze({
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
                ml_alert = Alert(
                    organisation_id=org_id,
                    message=f"ML anomaly detected from {ip_addr}",
                    alert_type="ml_anomaly",
                    severity=ml_result["severity"],
                    details=json.dumps(ml_result),
                )
                db.session.add(ml_alert)
                db.session.commit()
                ML_ANOMALIES_TOTAL.labels(severity=ml_result["severity"]).inc()
        except Exception as ml_err:
            logger.debug("ML analysis error: %s", ml_err)


@app.route("/ingest", methods=["POST", "OPTIONS"])
def ingest():
    # CORS preflight
    if request.method == "OPTIONS":
        response = make_response()
        response.headers['Access-Control-Allow-Origin']  = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key, X-Quorra-Key, X-Courra-Sec-Key, Authorization, ngrok-skip-browser-warning'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return response, 200

    try:
        # Extract API key
        api_key = (request.headers.get("X-API-Key") or
                   request.headers.get("X-Courra-Sec-Key") or
                   request.headers.get("X-Quorra-Key") or
                   request.headers.get("Authorization", "").replace("Bearer ", "") or
                   request.args.get("api_key", ""))

        org = _lookup_org_by_api_key(api_key)
        if not org:
            # Localhost bypass: allow Block Fortress (same machine) without an API key
            # Mirrors the pattern used in Block Fortress's own WS upgrade handler.
            client_ip = (request.headers.get("X-Forwarded-For", "") or
                         request.remote_addr or "").split(",")[0].strip()
            _LOCAL_IPS = {"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"}
            if client_ip in _LOCAL_IPS and not api_key:
                org = Organisation.query.filter_by(slug='default', status='active').first()
        if not org:
            return jsonify({"ok": False, "error": "Invalid or missing API key"}), 401

        if not _check_daily_limit(org):
            return jsonify({
                "ok": False,
                "error": "Daily log limit reached",
                "limit": org.max_logs_per_day,
            }), 429

        data = request.get_json(force=True, silent=False)
        if not data:
            return jsonify({"ok": False, "error": "Empty or invalid JSON body"}), 400

        _process_ingest(data, org.id)
        _increment_usage(org)
        db.session.commit()
        INGEST_EVENTS_TOTAL.labels(transport="http").inc()

        response = jsonify({"ok": True, "org": org.slug})
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response, 200

    except Exception as e:
        INGEST_ERRORS_TOTAL.inc()
        logger.error("Ingest error: %s", e)
        return jsonify({"ok": False, "error": "Internal server error"}), 500


if LIMITER_AVAILABLE and limiter:
    ingest = limiter.limit(Config.RATELIMIT_INGEST)(ingest)


@sock.route("/ws/ingest")
def ws_ingest(ws):
    """WebSocket ingest — authenticated by API key in query string or localhost bypass."""
    api_key = (request.args.get("key", "") or
               request.args.get("api_key", "") or
               request.headers.get("X-API-Key", "") or
               request.headers.get("X-Quorra-Key", ""))
    org = _lookup_org_by_api_key(api_key)
    if not org:
        # Localhost bypass — same rule as /ingest
        client_ip = (request.headers.get("X-Forwarded-For", "") or
                     request.remote_addr or "").split(",")[0].strip()
        _LOCAL_IPS = {"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"}
        if client_ip in _LOCAL_IPS and not api_key:
            org = Organisation.query.filter_by(slug='default', status='active').first()
    if not org:
        ws.close(message=b"unauthorized")
        return

    while True:
        try:
            message = ws.receive()
            if message is None:
                break
            data = json.loads(message)
            if not _check_daily_limit(org):
                ws.send(json.dumps({"ok": False, "error": "daily limit reached"}))
                continue
            with app.app_context():
                _process_ingest(data, org.id)
                _increment_usage(org)
                db.session.commit()
            INGEST_EVENTS_TOTAL.labels(transport="websocket").inc()
        except Exception as e:
            logger.error("WS ingest error: %s", e)
            break


# =============================================================================
# RULE BUILDER API (tenant-scoped)
# =============================================================================

from app.rule_builder import (
    evaluator as _rule_evaluator,
    dsl_runner as _dsl_runner,
    AVAILABLE_FIELDS, SIMPLE_OPERATORS, TEMPORAL_OPERATORS, MITRE_TACTICS,
    RuleEvaluator,
)


@app.route("/api/rules/schema")
@require_auth
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
@require_auth
def api_rules_list():
    rules = CustomRule.query.filter_by(
        organisation_id=g.org.id
    ).order_by(CustomRule.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rules])


@app.route("/api/rules", methods=["POST"])
@require_auth
@require_role('owner', 'admin', 'analyst')
def api_rules_create():
    from app.limits import check_limit
    allowed, msg = check_limit(g.org, 'max_rules')
    if not allowed:
        return jsonify({"ok": False, "error": msg}), 429

    data        = request.get_json(force=True, silent=True) or {}
    level       = int(data.get("level", 2))
    name        = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()

    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    if level not in (1, 2, 3):
        return jsonify({"ok": False, "error": "level must be 1, 2, or 3"}), 400

    rule = CustomRule(
        organisation_id=g.org.id,
        name=name, description=description, level=level,
        severity=data.get("severity", "medium"),
        mitre_tactic=data.get("mitre_tactic"),
        action=data.get("action", "alert"),
        block_ip=bool(data.get("block_ip", False)),
        enabled=True,
        created_by=g.user.username,
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
@require_auth
@require_role('owner', 'admin', 'analyst')
def api_rules_update(rule_id):
    rule = CustomRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
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
@require_auth
@require_role('owner', 'admin', 'analyst')
def api_rules_delete(rule_id):
    rule = CustomRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@require_auth
@require_role('owner', 'admin', 'analyst')
def api_rules_toggle(rule_id):
    rule = CustomRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    rule.enabled = not rule.enabled
    db.session.commit()
    return jsonify({"ok": True, "enabled": rule.enabled})


@app.route("/api/rules/<int:rule_id>/test", methods=["POST"])
@require_auth
def api_rules_test(rule_id):
    rule = CustomRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404

    data   = request.get_json(force=True, silent=True) or {}
    sample = data.get("event")

    if not sample:
        recent = LogEntry.query.filter_by(
            organisation_id=g.org.id
        ).order_by(LogEntry.timestamp.desc()).first()
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
# SEARCH
# =============================================================================

@app.route("/search")
@require_auth
def search_view():
    return render_template("search.html", username=g.user.username, **_inject_nav_context())


@app.route("/api/search/logs")
@require_auth
def api_search_logs():
    from app.search import search_logs
    q        = request.args.get("q", "")
    page     = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    sort     = request.args.get("sort", "timestamp")
    order    = request.args.get("order", "desc")
    pag      = search_logs(g.org.id, q, page=page, per_page=per_page, sort=sort, order=order)
    return jsonify({
        "items": [
            {
                "id":          l.id,
                "ip_address":  l.ip_address,
                "attack_type": l.attack_type,
                "endpoint":    l.endpoint,
                "severity":    l.severity,
                "user_agent":  l.user_agent,
                "payload":     (l.payload or "")[:300],
                "timestamp":   l.timestamp.isoformat() + "Z" if l.timestamp else None,
            }
            for l in pag.items
        ],
        "total":    pag.total,
        "pages":    pag.pages,
        "page":     page,
        "per_page": per_page,
        "query":    q,
    })


@app.route("/api/search/alerts")
@require_auth
def api_search_alerts():
    from app.search import search_alerts
    q        = request.args.get("q", "")
    page     = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    pag      = search_alerts(g.org.id, q, page=page, per_page=per_page)
    return jsonify({
        "items": [a.to_dict() for a in pag.items],
        "total": pag.total, "pages": pag.pages, "page": page,
    })


@app.route("/api/search/unified")
@require_auth
def api_search_unified():
    from app.search import unified_search
    q      = request.args.get("q", "")
    limit  = min(int(request.args.get("limit", 20)), 100)
    return jsonify(unified_search(g.org.id, q, limit=limit))


# =============================================================================
# CASES (Investigation management)
# =============================================================================

from app.models import Case, CaseItem

@app.route("/cases")
@require_auth
def cases_view():
    org_id = g.org.id
    cases  = Case.query.filter_by(organisation_id=org_id).order_by(Case.created_at.desc()).all()
    return render_template("cases.html", cases=cases, username=g.user.username,
                           **_inject_nav_context())


@app.route("/cases/<int:case_id>")
@require_auth
def case_detail(case_id):
    case = Case.query.filter_by(id=case_id, organisation_id=g.org.id).first_or_404()
    users = CourraSecUser.query.filter_by(organisation_id=g.org.id, is_active=True).all()
    return render_template("cases/detail.html", case=case, users=users,
                           username=g.user.username, **_inject_nav_context())


@app.route("/api/cases", methods=["GET"])
@require_auth
def api_cases_list():
    org_id  = g.org.id
    status  = request.args.get("status")
    q       = Case.query.filter_by(organisation_id=org_id)
    if status:
        q = q.filter(Case.status == status)
    cases = q.order_by(Case.created_at.desc()).all()
    return jsonify([c.to_dict() for c in cases])


@app.route("/api/cases", methods=["POST"])
@require_auth
def api_cases_create():
    from app.audit import audit_log, Actions
    data     = request.get_json(force=True, silent=True) or {}
    title    = (data.get("title") or "").strip()
    if not title:
        return jsonify({"ok": False, "error": "title is required"}), 400
    case = Case(
        organisation_id=g.org.id,
        title=title,
        description=data.get("description", ""),
        priority=data.get("priority", "medium"),
        status="open",
        created_by_id=g.user.id,
        tags=json.dumps(data.get("tags", [])),
        mitre_tactic=data.get("mitre_tactic"),
    )
    db.session.add(case)
    db.session.commit()
    audit_log(Actions.CASE_CREATED, resource_type='case', resource_id=case.id,
              details={"title": title})
    return jsonify({"ok": True, "case": case.to_dict()}), 201


@app.route("/api/cases/<int:case_id>", methods=["PUT"])
@require_auth
def api_cases_update(case_id):
    from app.audit import audit_log, Actions
    case = Case.query.filter_by(id=case_id, organisation_id=g.org.id).first()
    if not case:
        return jsonify({"ok": False, "error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    for f in ("title", "description", "status", "priority", "mitre_tactic"):
        if f in data:
            setattr(case, f, data[f])
    if "assigned_to_id" in data:
        case.assigned_to_id = data["assigned_to_id"]
    if data.get("status") in ("resolved", "closed") and not case.closed_at:
        case.closed_at = datetime.utcnow()
    case.updated_at = datetime.utcnow()
    db.session.commit()
    audit_log(Actions.CASE_UPDATED, resource_type='case', resource_id=case_id)
    return jsonify({"ok": True, "case": case.to_dict()})


@app.route("/api/cases/<int:case_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin")
def api_cases_delete(case_id):
    case = Case.query.filter_by(id=case_id, organisation_id=g.org.id).first()
    if not case:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(case)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/cases/<int:case_id>/items", methods=["POST"])
@require_auth
def api_case_add_item(case_id):
    case = Case.query.filter_by(id=case_id, organisation_id=g.org.id).first()
    if not case:
        return jsonify({"ok": False, "error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    item = CaseItem(
        case_id=case_id,
        item_type=data.get("item_type", "note"),
        item_id=data.get("item_id"),
        note=data.get("note", ""),
        added_by=g.user.username,
    )
    db.session.add(item)
    case.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "item_id": item.id}), 201


@app.route("/api/cases/<int:case_id>/items/<int:item_id>", methods=["DELETE"])
@require_auth
def api_case_remove_item(case_id, item_id):
    item = CaseItem.query.filter_by(id=item_id, case_id=case_id).first()
    if not item:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(item)
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# CORRELATION RULES
# =============================================================================

from app.models import CorrelationRule
from app.correlation_engine import correlation_engine

@app.route("/correlation")
@require_auth
def correlation_view():
    return render_template("correlation.html", username=g.user.username,
                           **_inject_nav_context())


@app.route("/api/correlation", methods=["GET"])
@require_auth
def api_correlation_list():
    rules = CorrelationRule.query.filter_by(
        organisation_id=g.org.id
    ).order_by(CorrelationRule.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rules])


@app.route("/api/correlation", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_correlation_create():
    from app.audit import audit_log, Actions
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    rule = CorrelationRule(
        organisation_id=g.org.id,
        name=name,
        description=data.get("description", ""),
        conditions=json.dumps(data.get("conditions", [])),
        group_by=data.get("group_by", "ip_address"),
        time_window=int(data.get("time_window", 300)),
        min_events=int(data.get("min_events", 2)),
        severity=data.get("severity", "high"),
        mitre_tactic=data.get("mitre_tactic"),
        action=data.get("action", "alert"),
        enabled=True,
        created_by=g.user.username,
    )
    db.session.add(rule)
    db.session.commit()
    audit_log(Actions.CORRELATION_CREATED, resource_type='correlation_rule', resource_id=rule.id)
    return jsonify({"ok": True, "rule": rule.to_dict()}), 201


@app.route("/api/correlation/<int:rule_id>", methods=["PUT"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_correlation_update(rule_id):
    rule = CorrelationRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    for f in ("name", "description", "group_by", "severity", "mitre_tactic", "action"):
        if f in data:
            setattr(rule, f, data[f])
    if "conditions" in data:
        rule.conditions = json.dumps(data["conditions"])
    if "time_window" in data:
        rule.time_window = int(data["time_window"])
    if "min_events" in data:
        rule.min_events = int(data["min_events"])
    if "enabled" in data:
        rule.enabled = bool(data["enabled"])
    rule.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "rule": rule.to_dict()})


@app.route("/api/correlation/<int:rule_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin")
def api_correlation_delete(rule_id):
    from app.audit import audit_log, Actions
    rule = CorrelationRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(rule)
    db.session.commit()
    audit_log(Actions.CORRELATION_DELETED, resource_type='correlation_rule', resource_id=rule_id)
    return jsonify({"ok": True})


@app.route("/api/correlation/<int:rule_id>/toggle", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_correlation_toggle(rule_id):
    rule = CorrelationRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    rule.enabled = not rule.enabled
    db.session.commit()
    return jsonify({"ok": True, "enabled": rule.enabled})


# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

from app.models import ThreatIndicator

@app.route("/threat-intel")
@require_auth
def threat_intel_view():
    from app.threat_intel import get_stats
    stats = get_stats(g.org.id)
    return render_template("threat_intel.html", stats=stats,
                           username=g.user.username, **_inject_nav_context())


@app.route("/api/threat-intel/indicators", methods=["GET"])
@require_auth
def api_ioc_list():
    org_id = g.org.id
    itype  = request.args.get("type")
    page   = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    q = ThreatIndicator.query.filter_by(organisation_id=org_id, is_active=True)
    if itype:
        q = q.filter(ThreatIndicator.indicator_type == itype)
    pag = q.order_by(ThreatIndicator.last_seen.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        "items":    [i.to_dict() for i in pag.items],
        "total":    pag.total,
        "pages":    pag.pages,
        "page":     page,
    })


@app.route("/api/threat-intel/indicators", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_ioc_create():
    from app.threat_intel import _upsert_indicator
    data = request.get_json(force=True, silent=True) or {}
    itype = (data.get("indicator_type") or "").strip().lower()
    value = (data.get("value") or "").strip()
    if not itype or not value:
        return jsonify({"ok": False, "error": "indicator_type and value required"}), 400
    if itype not in ("ip", "domain", "hash", "url", "email"):
        return jsonify({"ok": False, "error": "invalid indicator_type"}), 400
    _upsert_indicator(
        org_id=g.org.id,
        indicator_type=itype,
        value=value,
        source=data.get("source", "manual"),
        confidence=int(data.get("confidence", 70)),
        description=data.get("description", ""),
        tags=data.get("tags", ""),
    )
    db.session.commit()
    return jsonify({"ok": True}), 201


@app.route("/api/threat-intel/indicators/<int:ioc_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_ioc_delete(ioc_id):
    ioc = ThreatIndicator.query.filter_by(id=ioc_id, organisation_id=g.org.id).first()
    if not ioc:
        return jsonify({"ok": False, "error": "not found"}), 404
    ioc.is_active = False
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/threat-intel/import", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_ioc_import():
    from app.threat_intel import import_indicators_csv, import_plain_list
    from app.audit import audit_log, Actions

    if "file" in request.files:
        f       = request.files["file"]
        content = f.read().decode("utf-8", errors="ignore")
        imported, errors = import_indicators_csv(g.org.id, content)
    else:
        data       = request.get_json(force=True, silent=True) or {}
        text       = data.get("text", "")
        itype      = data.get("indicator_type", "ip")
        confidence = int(data.get("confidence", 60))
        imported   = import_plain_list(g.org.id, text, itype, confidence=confidence)
        errors     = []

    audit_log(Actions.IOC_IMPORTED, details={"count": imported})
    return jsonify({"ok": True, "imported": imported, "errors": errors})


@app.route("/api/threat-intel/sync/otx", methods=["POST"])
@require_auth
@require_role("owner", "admin")
def api_ioc_sync_otx():
    from app.threat_intel import fetch_otx_indicators
    from app.audit import audit_log, Actions
    api_key  = request.get_json(force=True, silent=True).get("api_key", "") or os.environ.get("OTX_API_KEY", "")
    if not api_key:
        return jsonify({"ok": False, "error": "OTX_API_KEY not configured"}), 400
    imported = fetch_otx_indicators(api_key, g.org.id)
    audit_log(Actions.FEED_SYNCED, details={"feed": "OTX", "imported": imported})
    return jsonify({"ok": True, "imported": imported})


@app.route("/api/threat-intel/lookup/virustotal", methods=["POST"])
@require_auth
def api_vt_lookup():
    from app.threat_intel import lookup_virustotal_ip, lookup_virustotal_hash
    data    = request.get_json(force=True, silent=True) or {}
    api_key = data.get("api_key") or os.environ.get("VT_API_KEY", "")
    if not api_key:
        return jsonify({"ok": False, "error": "VT_API_KEY not configured"}), 400
    ip   = data.get("ip")
    hash_ = data.get("hash")
    if ip:
        return jsonify(lookup_virustotal_ip(ip, api_key))
    if hash_:
        return jsonify(lookup_virustotal_hash(hash_, api_key))
    return jsonify({"ok": False, "error": "ip or hash required"}), 400


@app.route("/api/threat-intel/stats")
@require_auth
def api_ioc_stats():
    from app.threat_intel import get_stats
    return jsonify(get_stats(g.org.id))


# =============================================================================
# PLAYBOOKS
# =============================================================================

from app.models import Playbook, PlaybookRun
from app.playbook_engine import playbook_engine

@app.route("/playbooks")
@require_auth
def playbooks_view():
    playbooks = Playbook.query.filter_by(organisation_id=g.org.id).order_by(Playbook.created_at.desc()).all()
    return render_template("playbooks.html", playbooks=playbooks,
                           username=g.user.username, **_inject_nav_context())


@app.route("/api/playbooks", methods=["GET"])
@require_auth
def api_playbooks_list():
    pbs = Playbook.query.filter_by(organisation_id=g.org.id).order_by(Playbook.created_at.desc()).all()
    return jsonify([p.to_dict() for p in pbs])


@app.route("/api/playbooks", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_playbooks_create():
    from app.audit import audit_log, Actions
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    pb = Playbook(
        organisation_id=g.org.id,
        name=name,
        description=data.get("description", ""),
        trigger_on=json.dumps(data.get("trigger_on", {})),
        actions=json.dumps(data.get("actions", [])),
        enabled=True,
        created_by=g.user.username,
    )
    db.session.add(pb)
    db.session.commit()
    audit_log(Actions.PLAYBOOK_CREATED, resource_type='playbook', resource_id=pb.id)
    return jsonify({"ok": True, "playbook": pb.to_dict()}), 201


@app.route("/api/playbooks/<int:pb_id>", methods=["PUT"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_playbooks_update(pb_id):
    pb = Playbook.query.filter_by(id=pb_id, organisation_id=g.org.id).first()
    if not pb:
        return jsonify({"ok": False, "error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    for f in ("name", "description"):
        if f in data:
            setattr(pb, f, data[f])
    if "trigger_on" in data:
        pb.trigger_on = json.dumps(data["trigger_on"])
    if "actions" in data:
        pb.actions = json.dumps(data["actions"])
    if "enabled" in data:
        pb.enabled = bool(data["enabled"])
    pb.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "playbook": pb.to_dict()})


@app.route("/api/playbooks/<int:pb_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin")
def api_playbooks_delete(pb_id):
    from app.audit import audit_log, Actions
    pb = Playbook.query.filter_by(id=pb_id, organisation_id=g.org.id).first()
    if not pb:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(pb)
    db.session.commit()
    audit_log(Actions.PLAYBOOK_DELETED, resource_type='playbook', resource_id=pb_id)
    return jsonify({"ok": True})


@app.route("/api/playbooks/<int:pb_id>/toggle", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_playbooks_toggle(pb_id):
    pb = Playbook.query.filter_by(id=pb_id, organisation_id=g.org.id).first()
    if not pb:
        return jsonify({"ok": False, "error": "not found"}), 404
    pb.enabled = not pb.enabled
    db.session.commit()
    return jsonify({"ok": True, "enabled": pb.enabled})


@app.route("/api/playbooks/<int:pb_id>/runs", methods=["GET"])
@require_auth
def api_playbooks_runs(pb_id):
    runs = PlaybookRun.query.filter_by(
        playbook_id=pb_id, organisation_id=g.org.id
    ).order_by(PlaybookRun.started_at.desc()).limit(50).all()
    return jsonify([r.to_dict() for r in runs])


# =============================================================================
# ASSETS
# =============================================================================

from app.models import Asset

@app.route("/assets")
@require_auth
def assets_view():
    assets = Asset.query.filter_by(organisation_id=g.org.id, is_active=True).order_by(Asset.hostname).all()
    return render_template("assets.html", assets=assets,
                           username=g.user.username, **_inject_nav_context())


@app.route("/api/assets", methods=["GET"])
@require_auth
def api_assets_list():
    q = Asset.query.filter_by(organisation_id=g.org.id, is_active=True)
    atype = request.args.get("type")
    if atype:
        q = q.filter(Asset.asset_type == atype)
    return jsonify([a.to_dict() for a in q.order_by(Asset.hostname).all()])


@app.route("/api/assets", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_assets_create():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("hostname") and not data.get("ip_address"):
        return jsonify({"ok": False, "error": "hostname or ip_address required"}), 400
    asset = Asset(
        organisation_id=g.org.id,
        hostname=data.get("hostname", ""),
        ip_address=data.get("ip_address", ""),
        mac_address=data.get("mac_address", ""),
        asset_type=data.get("asset_type", "server"),
        os=data.get("os", ""),
        os_version=data.get("os_version", ""),
        owner=data.get("owner", ""),
        department=data.get("department", ""),
        criticality=data.get("criticality", "medium"),
        tags=json.dumps(data.get("tags", [])),
        notes=data.get("notes", ""),
        is_active=True,
    )
    db.session.add(asset)
    db.session.commit()
    return jsonify({"ok": True, "asset": asset.to_dict()}), 201


@app.route("/api/assets/<int:asset_id>", methods=["PUT"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_assets_update(asset_id):
    asset = Asset.query.filter_by(id=asset_id, organisation_id=g.org.id).first()
    if not asset:
        return jsonify({"ok": False, "error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    for f in ("hostname", "ip_address", "mac_address", "asset_type", "os",
              "os_version", "owner", "department", "criticality", "notes"):
        if f in data:
            setattr(asset, f, data[f])
    if "tags" in data:
        asset.tags = json.dumps(data["tags"])
    asset.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "asset": asset.to_dict()})


@app.route("/api/assets/<int:asset_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin")
def api_assets_delete(asset_id):
    asset = Asset.query.filter_by(id=asset_id, organisation_id=g.org.id).first()
    if not asset:
        return jsonify({"ok": False, "error": "not found"}), 404
    asset.is_active = False
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# REPORTS & COMPLIANCE
# =============================================================================

from app.models import ScheduledReport

@app.route("/reports")
@require_auth
def reports_view():
    from app.report_engine import executive_summary
    scheduled = ScheduledReport.query.filter_by(organisation_id=g.org.id).all()
    summary   = executive_summary(g.org.id, days=7)
    return render_template("reports.html", scheduled=scheduled, summary=summary,
                           username=g.user.username, **_inject_nav_context())


@app.route("/reports/compliance")
@require_auth
def reports_compliance():
    from app.report_engine import compliance_report
    framework = request.args.get("framework", "PCI-DSS")
    report    = compliance_report(g.org.id, framework)
    frameworks = ["PCI-DSS", "HIPAA", "SOC2", "ISO27001"]
    return render_template("reports/compliance.html", report=report,
                           framework=framework, frameworks=frameworks,
                           username=g.user.username, **_inject_nav_context())


@app.route("/api/reports/export/<entity>")
@require_auth
def api_reports_export(entity):
    from app.report_engine import export_logs_csv, export_alerts_csv, export_attacks_csv, export_audit_csv, export_json
    from app.audit import audit_log, Actions

    fmt    = request.args.get("format", "csv")
    after  = None
    before = None
    if request.args.get("after"):
        try:
            after = datetime.fromisoformat(request.args["after"])
        except ValueError:
            pass
    if request.args.get("before"):
        try:
            before = datetime.fromisoformat(request.args["before"])
        except ValueError:
            pass

    audit_log(Actions.REPORT_EXPORTED, details={"entity": entity, "format": fmt})

    if fmt == "json":
        content   = export_json(g.org.id, entity, after=after, before=before)
        mime      = "application/json"
        filename  = f"courra-sec_{entity}.json"
    else:
        if entity == "logs":
            content = export_logs_csv(g.org.id, after=after, before=before)
        elif entity == "alerts":
            content = export_alerts_csv(g.org.id, after=after, before=before)
        elif entity == "attacks":
            content = export_attacks_csv(g.org.id, after=after, before=before)
        elif entity == "audit":
            content = export_audit_csv(g.org.id, after=after, before=before)
        else:
            return jsonify({"error": "unknown entity"}), 400
        mime     = "text/csv"
        filename = f"courra-sec_{entity}.csv"

    return app.response_class(
        content, mimetype=mime,
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


@app.route("/api/reports/compliance/<framework>")
@require_auth
def api_reports_compliance(framework):
    from app.report_engine import compliance_report
    return jsonify(compliance_report(g.org.id, framework))


@app.route("/api/reports/executive-summary")
@require_auth
def api_reports_executive():
    from app.report_engine import executive_summary
    days = int(request.args.get("days", 7))
    return jsonify(executive_summary(g.org.id, days=days))


@app.route("/api/reports/scheduled", methods=["GET"])
@require_auth
def api_scheduled_reports_list():
    reports = ScheduledReport.query.filter_by(organisation_id=g.org.id).all()
    return jsonify([r.to_dict() for r in reports])


@app.route("/api/reports/scheduled", methods=["POST"])
@require_auth
@require_role("owner", "admin")
def api_scheduled_reports_create():
    data = request.get_json(force=True, silent=True) or {}
    sr   = ScheduledReport(
        organisation_id=g.org.id,
        name=data.get("name", "Untitled Report"),
        report_type=data.get("report_type", "executive_summary"),
        schedule=data.get("schedule", "weekly"),
        format=data.get("format", "csv"),
        recipients=json.dumps(data.get("recipients", [])),
        enabled=True,
        created_by=g.user.username,
        next_run=datetime.utcnow() + timedelta(days=1),
    )
    db.session.add(sr)
    db.session.commit()
    return jsonify({"ok": True, "report": sr.to_dict()}), 201


@app.route("/api/reports/scheduled/<int:sr_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin")
def api_scheduled_reports_delete(sr_id):
    sr = ScheduledReport.query.filter_by(id=sr_id, organisation_id=g.org.id).first()
    if not sr:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(sr)
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# AUDIT LOG
# =============================================================================

from app.models import AuditLog as AuditLogModel

@app.route("/audit")
@require_auth
@require_role("owner", "admin")
def audit_view():
    return render_template("audit.html", username=g.user.username, **_inject_nav_context())


@app.route("/api/audit", methods=["GET"])
@require_auth
@require_role("owner", "admin")
def api_audit_list():
    from app.audit import get_audit_logs
    page      = int(request.args.get("page", 1))
    per_page  = min(int(request.args.get("per_page", 50)), 200)
    action    = request.args.get("action")
    username  = request.args.get("username")
    pag       = get_audit_logs(g.org.id, page=page, per_page=per_page,
                               action=action, username=username)
    return jsonify({
        "items":    [e.to_dict() for e in pag.items],
        "total":    pag.total,
        "pages":    pag.pages,
        "page":     page,
    })


# =============================================================================
# SUPPRESSION RULES
# =============================================================================

from app.models import SuppressionRule

@app.route("/suppression")
@require_auth
def suppression_view():
    rules = SuppressionRule.query.filter_by(organisation_id=g.org.id).order_by(SuppressionRule.created_at.desc()).all()
    return render_template("suppression.html", rules=rules,
                           username=g.user.username, **_inject_nav_context())


@app.route("/api/suppression", methods=["GET"])
@require_auth
def api_suppression_list():
    rules = SuppressionRule.query.filter_by(organisation_id=g.org.id).all()
    return jsonify([r.to_dict() for r in rules])


@app.route("/api/suppression", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_suppression_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    expires_at = None
    if data.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(data["expires_at"])
        except ValueError:
            pass
    rule = SuppressionRule(
        organisation_id=g.org.id,
        name=name,
        description=data.get("description", ""),
        conditions=json.dumps(data.get("conditions", [])),
        enabled=True,
        expires_at=expires_at,
        created_by=g.user.username,
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify({"ok": True, "rule": rule.to_dict()}), 201


@app.route("/api/suppression/<int:rule_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_suppression_delete(rule_id):
    rule = SuppressionRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/suppression/<int:rule_id>/toggle", methods=["POST"])
@require_auth
@require_role("owner", "admin", "analyst")
def api_suppression_toggle(rule_id):
    rule = SuppressionRule.query.filter_by(id=rule_id, organisation_id=g.org.id).first()
    if not rule:
        return jsonify({"ok": False, "error": "not found"}), 404
    rule.enabled = not rule.enabled
    db.session.commit()
    return jsonify({"ok": True, "enabled": rule.enabled})


# =============================================================================
# IP ALLOWLIST
# =============================================================================

from app.models import OrgIPAllowlist

@app.route("/api/allowlist", methods=["GET"])
@require_auth
@require_role("owner", "admin")
def api_allowlist_list():
    entries = OrgIPAllowlist.query.filter_by(organisation_id=g.org.id).all()
    return jsonify([e.to_dict() for e in entries])


@app.route("/api/allowlist", methods=["POST"])
@require_auth
@require_role("owner", "admin")
def api_allowlist_add():
    data   = request.get_json(force=True, silent=True) or {}
    ip_cidr = (data.get("ip_cidr") or "").strip()
    if not ip_cidr:
        return jsonify({"ok": False, "error": "ip_cidr required"}), 400
    try:
        import ipaddress as _ipa
        _ipa.ip_network(ip_cidr, strict=False)
    except ValueError:
        return jsonify({"ok": False, "error": "invalid IP/CIDR"}), 400
    existing = OrgIPAllowlist.query.filter_by(organisation_id=g.org.id, ip_cidr=ip_cidr).first()
    if existing:
        return jsonify({"ok": False, "error": "already in allowlist"}), 400
    entry = OrgIPAllowlist(
        organisation_id=g.org.id,
        ip_cidr=ip_cidr,
        description=data.get("description", ""),
        created_by=g.user.username,
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"ok": True, "entry": entry.to_dict()}), 201


@app.route("/api/allowlist/<int:entry_id>", methods=["DELETE"])
@require_auth
@require_role("owner", "admin")
def api_allowlist_delete(entry_id):
    entry = OrgIPAllowlist.query.filter_by(id=entry_id, organisation_id=g.org.id).first()
    if not entry:
        return jsonify({"ok": False, "error": "not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# ALERT TRIAGE (escalate / close)
# =============================================================================

@app.route("/api/alerts/<int:alert_id>/escalate", methods=["POST"])
@require_auth
def api_alert_escalate(alert_id):
    from app.audit import audit_log
    alert = Alert.query.filter_by(id=alert_id, organisation_id=g.org.id).first()
    if not alert:
        return jsonify({"ok": False, "error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    note = data.get("note", "")
    # Create a case for this alert
    case = Case(
        organisation_id=g.org.id,
        title=f"Escalated: {alert.alert_type} [{alert.severity}]",
        description=f"Alert #{alert_id} escalated.\n\n{note}",
        priority=alert.severity if alert.severity in ("critical", "high", "medium", "low") else "high",
        status="open",
        created_by_id=g.user.id,
    )
    db.session.add(case)
    db.session.flush()
    item = CaseItem(case_id=case.id, item_type="alert", item_id=alert_id,
                    note=note, added_by=g.user.username)
    db.session.add(item)
    alert.acknowledged = True
    db.session.commit()
    audit_log("alert_escalated", resource_type="alert", resource_id=alert_id,
              details={"case_id": case.id})
    return jsonify({"ok": True, "case_id": case.id})


@app.route("/api/alerts/<int:alert_id>/close", methods=["POST"])
@require_auth
def api_alert_close(alert_id):
    alert = Alert.query.filter_by(id=alert_id, organisation_id=g.org.id).first()
    if not alert:
        return jsonify({"ok": False, "error": "not found"}), 404
    alert.acknowledged = True
    alert.is_read      = True
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# SUPERADMIN
# =============================================================================

@app.route("/superadmin")
@require_auth
@require_superadmin
def superadmin_dashboard():
    from app.models import ApiKeyUsage
    today = datetime.utcnow().date()

    orgs_raw = Organisation.query.order_by(Organisation.created_at.desc()).all()
    orgs_data = []
    for o in orgs_raw:
        usage = ApiKeyUsage.query.filter_by(organisation_id=o.id, date=today).first()
        orgs_data.append({
            "id":          o.id,
            "name":        o.name,
            "slug":        o.slug,
            "owner_email": o.owner_email,
            "plan":        o.plan,
            "status":      o.status,
            "created_at":  o.created_at,
            "max_users":   o.max_users,
            "user_count":  CourraSecUser.query.filter_by(organisation_id=o.id).count(),
            "logs_today":  usage.log_count if usage else 0,
        })

    # Make orgs iterable in template as objects
    class OrgRow:
        pass

    org_objects = []
    for d in orgs_data:
        o = OrgRow()
        for k, v in d.items():
            setattr(o, k, v)
        org_objects.append(o)

    total_logs_today = sum(d["logs_today"] for d in orgs_data)

    return render_template(
        "superadmin/dashboard.html",
        orgs=org_objects,
        total_orgs=len(orgs_data),
        total_users=CourraSecUser.query.count(),
        total_logs_today=total_logs_today,
        active_orgs=sum(1 for d in orgs_data if d["status"] == "active"),
        **_inject_nav_context(),
    )


@app.route("/api/superadmin/orgs")
@require_auth
@require_superadmin
def api_superadmin_orgs():
    orgs = Organisation.query.all()
    return jsonify([{
        "id": o.id, "name": o.name, "slug": o.slug,
        "owner_email": o.owner_email, "status": o.status, "plan": o.plan,
    } for o in orgs])


@app.route("/api/superadmin/suspend/<int:org_id>", methods=["POST"])
@require_auth
@require_superadmin
def api_superadmin_suspend(org_id):
    org = db.session.get(Organisation, org_id)
    if not org:
        return jsonify({"ok": False, "error": "Not found"}), 404
    org.status = 'suspended'
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/superadmin/activate/<int:org_id>", methods=["POST"])
@require_auth
@require_superadmin
def api_superadmin_activate(org_id):
    org = db.session.get(Organisation, org_id)
    if not org:
        return jsonify({"ok": False, "error": "Not found"}), 404
    org.status = 'active'
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/superadmin/impersonate/<int:org_id>", methods=["POST"])
@require_auth
@require_superadmin
def api_superadmin_impersonate(org_id):
    org = db.session.get(Organisation, org_id)
    if not org:
        return jsonify({"ok": False, "error": "Not found"}), 404
    # Find the owner
    owner = CourraSecUser.query.filter_by(
        organisation_id=org_id, role='owner'
    ).first() or CourraSecUser.query.filter_by(organisation_id=org_id).first()
    if not owner:
        return jsonify({"ok": False, "error": "No users in this organisation"}), 404
    session["user_id"]          = owner.id
    session["organisation_id"]  = org_id
    session["impersonating"]    = True
    return jsonify({"ok": True})


@app.route("/api/superadmin/orgs/<int:org_id>", methods=["DELETE"])
@require_auth
@require_superadmin
def api_superadmin_delete_org(org_id):
    org = db.session.get(Organisation, org_id)
    if not org:
        return jsonify({"ok": False, "error": "Not found"}), 404
    from app.models import Case, CaseItem
    org_case_ids = [c.id for c in Case.query.filter_by(organisation_id=org_id).with_entities(Case.id)]
    if org_case_ids:
        CaseItem.query.filter(CaseItem.case_id.in_(org_case_ids)).delete(synchronize_session=False)
    Case.query.filter_by(organisation_id=org_id).delete()
    for model in [LogEntry, Alert, Attack, IPBlocklist, CustomRule,
                  SoarAction, ApiKeyUsage]:
        model.query.filter_by(organisation_id=org_id).delete()
    CourraSecUser.query.filter_by(organisation_id=org_id).delete()
    db.session.delete(org)
    db.session.commit()
    return jsonify({"ok": True})


# =============================================================================
# SDK
# =============================================================================

_SDK_DIR = str(Path(__file__).resolve().parent.parent / "sdk")


@app.route("/courra-sec-sdk.js")
def serve_sdk():
    return send_from_directory(_SDK_DIR, "courra-sec-sdk.js", mimetype="application/javascript")


# =============================================================================
# Upload Logs — examine external log files
# =============================================================================

def _parse_uploaded_logs(content: str, fmt: str) -> list[dict]:
    """Parse uploaded log content into a list of ingest-compatible dicts."""
    events = []
    if fmt == "json":
        parsed = json.loads(content)
        if isinstance(parsed, list):
            events = parsed
        elif isinstance(parsed, dict):
            events = [parsed]
    elif fmt in ("cef", "syslog"):
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            events.append({"raw": line, "source": fmt})
    else:
        # Auto-detect: try JSON first, then treat as raw lines
        try:
            parsed = json.loads(content)
            events = parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, ValueError):
            for line in content.splitlines():
                line = line.strip()
                if line:
                    events.append({"raw": line, "source": "upload"})
    return events


@app.route("/api/logs/upload", methods=["POST"])
@require_auth
def api_logs_upload():
    """Accept an uploaded log file, parse it, and ingest events into the tenant's org."""
    org_id = g.org.id

    # Accept either a multipart file upload or raw JSON body
    if request.files.get("file"):
        f = request.files["file"]
        try:
            content = f.read().decode("utf-8", errors="replace")
        except Exception:
            return jsonify({"ok": False, "error": "Could not read file"}), 400
        filename = f.filename or ""
        if filename.endswith(".json"):
            fmt = "json"
        elif filename.endswith(".log") or filename.endswith(".txt"):
            fmt = "auto"
        else:
            fmt = request.form.get("format", "auto")
    else:
        body = request.get_json(force=True, silent=True) or {}
        content = body.get("content", "")
        fmt = body.get("format", "auto")
        if not content:
            return jsonify({"ok": False, "error": "No file or content provided"}), 400

    try:
        events = _parse_uploaded_logs(content, fmt)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Parse error: {e}"}), 400

    if not events:
        return jsonify({"ok": False, "error": "No events found in uploaded file"}), 400

    MAX_UPLOAD_EVENTS = 5000
    if len(events) > MAX_UPLOAD_EVENTS:
        return jsonify({
            "ok": False,
            "error": f"Too many events ({len(events)}). Max is {MAX_UPLOAD_EVENTS} per upload."
        }), 400

    ingested = 0
    errors = 0
    for event in events:
        try:
            if not isinstance(event, dict):
                event = {"raw": str(event), "source": "upload"}
            event.setdefault("source", "upload")
            _process_ingest(event, org_id)
            ingested += 1
        except Exception:
            errors += 1

    if ingested:
        db.session.commit()

    return jsonify({
        "ok": True,
        "ingested": ingested,
        "errors": errors,
        "total": len(events),
    })


# =============================================================================
# WebSocket connector to Block Fortress (legacy)
# =============================================================================

def on_ws_message(_ws, message):
    """Ingest messages from Block Fortress into the default organisation."""
    try:
        data = json.loads(message)
        with app.app_context():
            default_org = Organisation.query.filter_by(slug='default', status='active').first()
            if default_org:
                _process_ingest(data, default_org.id)
                db.session.commit()
            else:
                logger.warning("WS ingest: default org not found")
    except Exception as e:
        logger.error("WS message error: %s", e, exc_info=True)


def on_ws_error(_ws, error):
    logger.warning("Block Fortress WS error: %s", error)


def on_ws_close(_ws, close_status_code, close_msg):
    global ws_connected
    ws_connected = False
    WS_CONNECTED.set(0)
    logger.info("Block Fortress WS closed: %s %s", close_status_code, close_msg)


def _on_ws_open(_ws):
    global ws_connected
    ws_connected = True
    WS_CONNECTED.set(1)
    logger.info("Connected to Block Fortress WebSocket: %s", Config.BLOCK_FORTRESS_WS_URL)


def connect_websocket():
    global ws_connected
    import random
    delay     = Config.WS_RECONNECT_DELAY
    max_delay = 60
    while monitoring_active:
        try:
            api_key    = getattr(Config, "INGEST_API_KEY", "") or ""
            ws_headers = {"x-quorra-key": api_key} if api_key else {}
            ws = websocket.WebSocketApp(
                Config.BLOCK_FORTRESS_WS_URL,
                on_message=on_ws_message,
                on_open=_on_ws_open,
                on_error=on_ws_error,
                on_close=on_ws_close,
                header=ws_headers,
            )
            delay = Config.WS_RECONNECT_DELAY
            ws.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as e:
            logger.warning("Block Fortress WS connect failed: %s — retrying in %ds", e, delay)
        ws_connected = False
        WS_CONNECTED.set(0)
        time.sleep(min(delay + random.uniform(0, 1), max_delay))
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
# PlaybookRun retention cleanup (background thread)
# =============================================================================
_PLAYBOOK_RUN_RETENTION_DAYS = int(os.environ.get("PLAYBOOK_RUN_RETENTION_DAYS", "30"))

def _playbook_run_cleanup_loop():
    """Delete PlaybookRun records older than PLAYBOOK_RUN_RETENTION_DAYS once per day."""
    while True:
        time.sleep(86400)  # 24 hours
        try:
            from app.models import PlaybookRun
            cutoff = datetime.utcnow() - timedelta(days=_PLAYBOOK_RUN_RETENTION_DAYS)
            with app.app_context():
                deleted = PlaybookRun.query.filter(PlaybookRun.started_at < cutoff).delete()
                db.session.commit()
                if deleted:
                    logger.info("PlaybookRun retention: purged %d runs older than %d days",
                                deleted, _PLAYBOOK_RUN_RETENTION_DAYS)
        except Exception as exc:
            logger.warning("PlaybookRun cleanup error: %s", exc)

Thread(target=_playbook_run_cleanup_loop, daemon=True).start()

# =============================================================================
# Startup
# =============================================================================
print("Courra-Sec v2.0 — Multi-tenant SaaS mode ready")
print(f"Superadmin username: {SUPERADMIN_USERNAME}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
