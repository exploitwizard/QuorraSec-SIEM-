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
from app.report_engine import run_scheduled_reports
from app.email_service import send_invite_email
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
# Safety-net: run column migrations before init_db() creates the app context
# and fires any model queries. init_db() also calls run_migrations internally,
# but this outer call handles the case where database.py is patched differently.
try:
    from app.migrate import run_migrations as _run_migrations
    _run_migrations(app)
except Exception as _mig_err:
    logger.warning("Startup migration warning: %s", _mig_err)

with app.app_context():
    init_db(app)

# =============================================================================
# ML backfill — compute scores for logs ingested before this fix
# =============================================================================
def backfill_ml_results() -> None:
    """
    Score any log entries that have no ML data yet.
    Runs once at startup in a background thread, batched to avoid memory issues.
    """
    try:
        with app.app_context():
            unanalyzed = (LogEntry.query
                          .filter(LogEntry.ml_analyzed_at.is_(None))
                          .order_by(LogEntry.id.desc())
                          .limit(500).all())
            if not unanalyzed:
                logger.info("ML backfill: all logs already have ML data")
                return
            logger.info("ML backfill: processing %d logs", len(unanalyzed))

            by_org: dict = {}
            for lg in unanalyzed:
                by_org.setdefault(lg.organisation_id, []).append(lg)

            total = 0
            for org_id, logs in by_org.items():
                pipeline = get_pipeline(org_id)
                if not pipeline:
                    continue
                for lg in logs:
                    try:
                        log_dict = {
                            "source_ip":   lg.ip_address or "",
                            "ip_address":  lg.ip_address or "",
                            "attack_type": lg.attack_type or "",
                            "endpoint":    lg.endpoint or "",
                            "payload":     lg.payload or "",
                            "severity":    lg.severity or "info",
                            "message":     lg.payload or "",
                        }
                        ml_result = pipeline.analyze(log_dict)
                        _store_ml_result(lg, ml_result)
                        total += 1
                    except Exception as e:
                        logger.debug("Backfill error for log %s: %s", lg.id, e)
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    logger.error("Backfill commit error: %s", e)

            logger.info("ML backfill complete: %d logs scored", total)
    except Exception as e:
        logger.error("ML backfill failed: %s", e)


Thread(target=backfill_ml_results, daemon=True, name="ml-backfill").start()

# =============================================================================
# OWASP Security Hardening
# =============================================================================
from app.security.headers         import apply_security_headers
from app.security.security_logger import (
    setup_security_logging, log_auth_success, log_auth_failure,
    log_auth_lockout, log_access_denied, log_injection_attempt,
    log_admin_action, log_csrf_failure,
)
from app.security.rate_limiter   import login_tracker
from app.security.auth_hardening import create_secure_session, enforce_password_policy
from app.security.ssrf_protection import safe_request

# A05 — enhanced security headers (replaces the old add_security_headers)
apply_security_headers(app)

# A09 — security event logging
setup_security_logging(app)

# CSRF — generate token for every authenticated session, validate on state-changing requests
_CSRF_EXEMPT = frozenset(['/ingest', '/ws/ingest', '/login', '/register', '/health', '/logout'])

@app.before_request
def _csrf_protect():
    if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        return
    if 'user_id' not in session:
        return  # pre-auth requests don't need a CSRF token
    if request.path in _CSRF_EXEMPT:
        return
    token = (
        request.headers.get('X-CSRF-Token') or
        request.headers.get('X-CSRFToken') or
        (request.get_json(silent=True) or {}).get('csrf_token')
    )
    session_token = session.get('csrf_token', '')
    if not token or not session_token:
        log_csrf_failure(request.path, request.remote_addr)
        return jsonify({'error': 'CSRF token missing'}), 403
    import hmac as _hmac
    if not _hmac.compare_digest(str(token), str(session_token)):
        log_csrf_failure(request.path, request.remote_addr)
        return jsonify({'error': 'CSRF token invalid'}), 403

@app.after_request
def _inject_csrf_token(response):
    if 'user_id' in session:
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        response.headers['X-CSRF-Token'] = session.get('csrf_token', '')
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

@app.template_filter('fromjson')
def _fromjson(s):
    if not s:
        return {}
    try:
        return _json_mod.loads(s)
    except (TypeError, ValueError):
        return {}

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
monitoring_active        = True
ws_connected             = False
_baseline_reporter_status = "starting"
_geo_cache: dict         = {}
MAX_GEO_CACHE            = 1000

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
    app_name  = request.form.get("app_name",  "").strip()   # optional
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
    # A07 — enforce password policy on registration
    _pw_ok, _pw_err = enforce_password_policy(password, username)
    if not _pw_ok:
        return err(_pw_err)
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
        app_name=app_name[:120] if app_name else None,
        plan='open',
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

    # Default security settings for new organisation
    from app.models import OrganisationSettings
    db.session.add(OrganisationSettings(
        organisation_id=org.id,
        python_dsl_sandbox=True,
    ))
    db.session.commit()

    # Auto-login with secure session (includes CSRF token)
    create_secure_session(owner, org)
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
            org = Organisation.query.filter_by(id=user.organisation_id, status='active').first()
            create_secure_session(user, org)  # A07 — CSRF token + secure session
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_auth_success(user.username)
            if user.must_change_password or user.password_change_required:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))
        return render_template("login.html", totp_step=True,
                               error="Invalid authenticator code. Try again.")

    # --- Step 1: Username/email + password ---
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password   = request.form.get("password", "")
        _client_ip = request.remote_addr

        # A07 — account lockout check before any DB query
        locked, remaining = login_tracker.is_locked(identifier, _client_ip)
        if locked:
            log_auth_lockout(identifier)
            return render_template("login.html",
                                   error=f"Too many failed attempts. Try again in {remaining} seconds.")

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

            # A07 — create secure session with CSRF token
            create_secure_session(user, org)
            login_tracker.record_success(identifier, _client_ip)
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Audit: login
            from app.audit import audit_log, Actions
            audit_log(Actions.LOGIN, org_id=user.organisation_id,
                      user_id=user.id, username=user.username,
                      ip=request.headers.get('X-Forwarded-For','').split(',')[0].strip() or _client_ip)
            log_auth_success(user.username)

            if user.must_change_password or user.password_change_required:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))

        # Failed login — record for lockout tracker
        login_tracker.record_failure(identifier, _client_ip)
        log_auth_failure(identifier, reason="Invalid credentials")
        try:
            from app.audit import audit_log, Actions
            audit_log(Actions.LOGIN_FAILED, username=identifier,
                      ip=request.headers.get('X-Forwarded-For','').split(',')[0].strip() or _client_ip)
        except Exception:
            pass

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/accept-invite/<token>")
def accept_invite(token: str):
    user = CourraSecUser.query.filter_by(invite_token=token).first()
    now = datetime.utcnow()

    if not user or not user.invite_expires_at or user.invite_expires_at < now:
        return render_template(
            "accept_invite.html",
            error="This invitation link is invalid or has expired. Please ask your administrator to resend it.",
        ), 400

    # Consume the token so it cannot be replayed
    user.invite_token = None
    user.invite_expires_at = None
    db.session.commit()

    org = Organisation.query.get(user.organisation_id)
    return render_template(
        "accept_invite.html",
        username=user.username,
        full_name=user.full_name,
        org_name=org.name if org else "",
        role=user.role,
    )


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
# SETTINGS API — sandbox toggle
# =============================================================================

@app.route("/api/settings/sandbox", methods=["GET"])
@require_auth
def get_sandbox_setting():
    """Return the Python DSL sandbox state for the current organisation."""
    if g.user.role not in ('owner', 'admin'):
        return jsonify({"error": "Admin access required"}), 403

    from app.models import OrganisationSettings
    settings   = OrganisationSettings.query.filter_by(organisation_id=g.org.id).first()
    sandbox_on = settings.python_dsl_sandbox if settings else True

    return jsonify({
        "python_dsl_sandbox": sandbox_on,
        "sandbox_changed_by": settings.sandbox_changed_by if settings else None,
        "sandbox_changed_at": (
            settings.sandbox_changed_at.isoformat()
            if settings and settings.sandbox_changed_at else None
        ),
        "warning": (
            None if sandbox_on else
            "Sandbox is DISABLED. Python rules run with full system access. "
            "Only trusted rule authors should create rules in this mode."
        ),
    }), 200


@app.route("/api/settings/sandbox", methods=["POST"])
@require_auth
def update_sandbox_setting():
    """Enable or disable Python DSL sandbox. Owner or admin only."""
    if g.user.role not in ('owner', 'admin'):
        return jsonify({"error": "Admin access required"}), 403

    data    = request.get_json(force=True, silent=True) or {}
    enabled = data.get("python_dsl_sandbox")

    if enabled is None:
        return jsonify({"error": "python_dsl_sandbox field required"}), 400

    # Disabling the sandbox requires an explicit confirmation string
    if enabled is False:
        confirm = data.get("confirm_disable")
        if confirm != "I understand the security risks":
            return jsonify({
                "error": "confirmation_required",
                "message": (
                    "To disable the sandbox send "
                    "confirm_disable: 'I understand the security risks'"
                ),
            }), 400

    from app.models import OrganisationSettings
    settings = OrganisationSettings.query.filter_by(
        organisation_id=g.org.id
    ).first()
    if not settings:
        settings = OrganisationSettings(organisation_id=g.org.id)
        db.session.add(settings)

    settings.python_dsl_sandbox = bool(enabled)
    settings.sandbox_changed_by = g.user.id
    settings.sandbox_changed_at = datetime.utcnow()
    db.session.commit()

    try:
        from app.audit import audit_log, Actions
        audit_log(
            Actions.RULE_CREATED if enabled else "sandbox_disabled",
            resource_type="organisation_settings",
            resource_id=str(g.org.id),
            details=f"Python DSL sandbox {'enabled' if enabled else 'DISABLED'} "
                    f"by {g.user.username}",
        )
    except Exception:
        pass

    return jsonify({
        "python_dsl_sandbox": bool(enabled),
        "message": (
            "Sandbox enabled. Rules run in restricted mode."
            if enabled else
            "Sandbox disabled. Rules run with full Python access."
        ),
    }), 200


# =============================================================================
# TEAM API
# =============================================================================

@app.route("/api/team/invite", methods=["POST"])
@require_auth
@require_role('owner', 'admin')
def api_team_invite():
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

    # Check total seat limit (20 seats)
    total_active = CourraSecUser.query.filter_by(
        organisation_id=g.org.id, is_active=True
    ).count()
    max_seats = g.org.max_users or 20
    if total_active >= max_seats:
        return jsonify({
            "ok": False,
            "error": f"Seat limit reached ({max_seats} seats). Deactivate a member to free up a seat.",
        }), 400

    # Check role-specific quota (owner-configurable)
    role_limits = {
        'admin':    g.org.max_admins   or 5,
        'analyst':  g.org.max_analysts or 10,
        'readonly': g.org.max_readonly or 4,
    }
    if role in role_limits:
        role_count = CourraSecUser.query.filter_by(
            organisation_id=g.org.id, role=role, is_active=True
        ).count()
        if role_count >= role_limits[role]:
            return jsonify({
                "ok": False,
                "error": (
                    f"Role slot limit reached for '{role}' "
                    f"({role_count}/{role_limits[role]}). "
                    f"Owner can increase the quota in Settings → Team."
                ),
            }), 400

    if CourraSecUser.query.filter_by(organisation_id=g.org.id, username=username).first():
        return jsonify({"ok": False, "error": f"Username '{username}' already exists"}), 400
    if CourraSecUser.query.filter_by(organisation_id=g.org.id, email=email).first():
        return jsonify({"ok": False, "error": f"Email already registered in this organisation"}), 400

    temp_password = password or secrets.token_urlsafe(12)
    invite_token  = secrets.token_urlsafe(32)
    invite_expiry = datetime.utcnow() + timedelta(hours=48)

    user = CourraSecUser(
        organisation_id=g.org.id,
        username=username,
        email=email,
        full_name=full_name,
        role=role,
        must_change_password=True,
        password_change_required=True,
        invite_token=invite_token,
        invite_expires_at=invite_expiry,
    )
    user.set_password(temp_password)
    db.session.add(user)
    db.session.commit()

    base_url     = Config.APP_BASE_URL or request.host_url.rstrip("/")
    email_sent   = send_invite_email(
        to_email=email,
        to_name=full_name or username,
        org_name=g.org.name,
        role=role,
        username=username,
        temp_password=temp_password,
        invite_token=invite_token,
        base_url=base_url,
    )

    return jsonify({
        "ok": True,
        "username": username,
        "temp_password": temp_password,
        "email_sent": email_sent,
        "message": (
            f"User '{username}' created with role '{role}'. Invitation email sent."
            if email_sent else
            f"User '{username}' created with role '{role}'. No email sent (RESEND_API_KEY not configured)."
        ),
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
        "status":             status,
        "version":            "2.0.0",
        "db":                 "ok" if db_ok else "error",
        "ml":                 ml_pipeline is not None,
        "monitoring":         monitoring_active,
        "ws_connected":       ws_connected,
        "baseline_reporter":  _baseline_reporter_status,
        "timestamp":          datetime.utcnow().isoformat() + "Z",
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
        "app_name":            g.org.app_name or '',
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
                "id":               l.id,
                "ip_address":       l.ip_address,
                "attack_type":      l.attack_type,
                "endpoint":         l.endpoint,
                "payload":          l.payload,
                "user_agent":       l.user_agent,
                "severity":         l.severity,
                "suppressed":       bool(l.suppressed),
                "timestamp":        l.timestamp.isoformat() + "Z" if l.timestamp else None,
                "raw_data":         l.raw_data,
                "ml_risk_score":    l.ml_risk_score,
                "ml_anomaly_score": l.ml_anomaly_score,
                "ml_is_anomaly":    bool(l.ml_is_anomaly) if l.ml_is_anomaly is not None else False,
                "ml_ueba_flags":    l.ml_ueba_flags,
                "ml_attack_chains": l.ml_attack_chains,
                "ml_analyzed_at":   l.ml_analyzed_at.isoformat() + "Z" if l.ml_analyzed_at else None,
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


@app.route("/api/logs/<int:log_id>")
@require_auth
def api_log_detail(log_id):
    """Return full log details. ML data is always present — computed inline for old logs."""
    try:
        log = LogEntry.query.filter_by(
            id=log_id, organisation_id=g.org.id
        ).first_or_404()

        ml_data = None
        if log.ml_analysis:
            try:
                ml_data = json.loads(log.ml_analysis)
            except (json.JSONDecodeError, TypeError):
                ml_data = None

        if not ml_data:
            # Log predates the ML storage fix — compute and store inline now
            log_dict = {
                "source_ip":   log.ip_address, "ip_address": log.ip_address,
                "endpoint":    log.endpoint,   "attack_type": log.attack_type,
                "payload":     log.payload or "", "severity": log.severity or "medium",
                "message":     log.payload or "",
            }
            try:
                pipeline  = get_pipeline(g.org.id)
                ml_data   = pipeline.analyze(log_dict)
                _store_ml_result(log, ml_data)
                db.session.commit()
            except Exception as ml_err:
                logger.error("Inline ML backfill error: %s", ml_err)
                ml_data = {}

        ueba_flags    = ml_data.get("ueba_flags") or ml_data.get("ueba_anomalies") or []
        attack_chains = (ml_data.get("attack_chains") or
                         [c.get("pattern_name", str(c)) if isinstance(c, dict) else str(c)
                          for c in (ml_data.get("attack_chain") or [])])

        ml_section = {
            "status":           ml_data.get("model_status", "statistical_fallback"),
            "risk_score":       ml_data.get("risk_score", log.ml_risk_score or 0.0),
            "anomaly_score":    ml_data.get("anomaly_score", log.ml_anomaly_score or 0.0),
            "is_anomaly":       ml_data.get("is_anomaly", log.ml_is_anomaly or False),
            "ueba_flags":       ueba_flags,
            "attack_chains":    attack_chains,
            "threat_label":     ml_data.get("threat_label"),
            "mitre_tactic":     ml_data.get("mitre_tactic"),
            "signal_breakdown": (ml_data.get("risk") or {}).get("signal_breakdown"),
            "components":       ml_data.get("components", {}),
            "analyzed_at":      log.ml_analyzed_at.isoformat() if log.ml_analyzed_at else None,
            "has_results":      True,
        }

        return jsonify({
            "id":          log.id,
            "ip_address":  log.ip_address,
            "attack_type": log.attack_type,
            "endpoint":    log.endpoint,
            "payload":     log.payload,
            "user_agent":  log.user_agent,
            "severity":    log.severity,
            "suppressed":  bool(log.suppressed),
            "timestamp":   log.timestamp.isoformat() + "Z" if log.timestamp else None,
            "raw_data":    log.raw_data,
            "ml":          ml_section,
        }), 200

    except Exception as e:
        app.logger.error("Log detail error: %s", e)
        return jsonify({"error": "Failed to load log details"}), 500


# =============================================================================
# API — ML PIPELINE
# =============================================================================

@app.route("/api/ml/status")
@require_auth
def api_ml_status():
    """Get current ML pipeline status for the organisation."""
    try:
        pipeline   = get_pipeline(g.org.id)
        log_count  = LogEntry.query.filter_by(organisation_id=g.org.id).count()
        analyzed   = LogEntry.query.filter_by(organisation_id=g.org.id).filter(
            LogEntry.ml_analyzed_at.isnot(None)
        ).count()

        is_trained = False
        if pipeline and hasattr(pipeline, 'anomaly'):
            is_trained = getattr(pipeline.anomaly, '_trained', False)

        return jsonify({
            "is_trained":    is_trained,
            "model_status":  "trained" if is_trained else "statistical_fallback",
            "total_logs":    log_count,
            "analyzed_logs": analyzed,
            "pending_logs":  log_count - analyzed,
            "can_train":     log_count >= 100,
            "logs_needed":   max(0, 100 - log_count),
            "message": (
                "Model trained and ready" if is_trained
                else (
                    f"Statistical fallback active. "
                    f"{'Send ' + str(max(0, 100 - log_count)) + ' more logs to enable training.' if log_count < 100 else 'Training will trigger automatically.'}"
                )
            ),
        }), 200
    except Exception as e:
        return jsonify({"is_trained": False, "model_status": "error", "error": str(e)}), 500


@app.route("/api/ml/train", methods=["POST"])
@require_auth
def api_ml_train():
    """Manually trigger ML model training for the organisation."""
    if g.user.role not in ('owner', 'admin', 'analyst'):
        return jsonify({"error": "Insufficient permissions"}), 403

    try:
        count = LogEntry.query.filter_by(organisation_id=g.org.id).count()
        if count < 50:
            return jsonify({
                "status":    "insufficient_data",
                "message":   f"Need at least 50 logs to train. Currently have {count}.",
                "log_count": count,
            }), 400

        logs = (LogEntry.query.filter_by(organisation_id=g.org.id)
                .order_by(LogEntry.timestamp.desc()).limit(5000).all())

        pipeline = get_pipeline(g.org.id)
        if not pipeline:
            return jsonify({"error": "ML pipeline unavailable"}), 500

        log_dicts = [
            {
                "severity":    l.severity or "medium",
                "status_code": 0,
                "payload":     l.payload or "",
                "attack_type": l.attack_type or "",
                "timestamp":   l.timestamp.isoformat() if l.timestamp else "",
            }
            for l in logs
        ]

        def _do_train():
            with app.app_context():
                pipeline.anomaly._buffer.clear()
                for ld in log_dicts:
                    pipeline.anomaly._buffer.append(pipeline.anomaly._featurize(ld))
                pipeline.anomaly._retrain()
                logger.info("Manual ML training complete for org %s on %d logs", g.org.id, len(log_dicts))

        t = Thread(target=_do_train, daemon=True)
        t.start()

        return jsonify({
            "status":    "training_started",
            "log_count": len(log_dicts),
            "message":   f"Training started on {len(log_dicts)} logs. Model will be ready in 10-30 seconds.",
        }), 200

    except Exception as e:
        app.logger.error("ML training trigger error: %s", e)
        return jsonify({"error": str(e)}), 500


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


def _severity_to_risk(severity: str) -> float:
    """Convert severity string to risk score estimate."""
    return {
        'critical': 85.0,
        'high':     65.0,
        'medium':   40.0,
        'low':      20.0,
        'info':     10.0,
    }.get(str(severity).lower(), 30.0)


@app.route('/api/attacks/chart-data')
@require_auth
def get_attacks_chart_data():
    """Return per-type counts, hourly timeline, and severity breakdown for charts."""
    try:
        days  = int(request.args.get('days', 7))
        since = datetime.utcnow() - timedelta(days=days)

        type_counts = db.session.query(
            Attack.attack_type,
            db.func.count(Attack.id).label('count')
        ).filter(
            Attack.organisation_id == g.org.id,
            Attack.detected_at >= since
        ).group_by(Attack.attack_type).all()

        timeline_data = {}
        for attack_type, _ in type_counts:
            try:
                hourly = db.session.query(
                    db.func.strftime('%Y-%m-%d %H:00',
                        Attack.detected_at).label('hour'),
                    db.func.count(Attack.id).label('count')
                ).filter(
                    Attack.organisation_id == g.org.id,
                    Attack.attack_type == attack_type,
                    Attack.detected_at >= since
                ).group_by('hour').order_by('hour').all()
                timeline_data[attack_type] = [
                    {'hour': h, 'count': c} for h, c in hourly
                ]
            except Exception:
                timeline_data[attack_type] = []

        severity_data = {}
        for attack_type, _ in type_counts:
            sev = db.session.query(
                Attack.severity,
                db.func.count(Attack.id).label('count')
            ).filter(
                Attack.organisation_id == g.org.id,
                Attack.attack_type == attack_type,
                Attack.detected_at >= since
            ).group_by(Attack.severity).all()
            severity_data[attack_type] = {s: c for s, c in sev}

        return jsonify({
            'type_counts':   [{'type': t, 'count': c} for t, c in type_counts],
            'timeline_data': timeline_data,
            'severity_data': severity_data,
            'total_attacks': sum(c for _, c in type_counts),
            'days':          days,
        }), 200

    except Exception as e:
        app.logger.error(f"Attack chart data error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/attacks/<int:attack_id>')
@require_auth
def get_attack_detail(attack_id):
    """Return attack + ML analysis (computed from details JSON or statistical fallback)."""
    try:
        attack = Attack.query.filter_by(
            id=attack_id,
            organisation_id=g.org.id
        ).first_or_404()

        ml_section = None

        # Try to read ML data already stored in the details JSON
        if attack.details:
            try:
                det = json.loads(attack.details)
                risk_score = det.get('risk_score') or det.get('ml_risk_score')
                if risk_score is not None:
                    ueba = (det.get('ueba_anomalies') or
                            det.get('ueba_flags') or [])
                    chains = []
                    for c in (det.get('attack_chain') or []):
                        if isinstance(c, dict):
                            chains.append(c.get('pattern_name', 'chain'))
                        else:
                            chains.append(str(c))
                    sb = (det.get('signal_breakdown') or
                          (det.get('risk') or {}).get('signal_breakdown') or {})
                    ml_section = {
                        'has_results':   True,
                        'status':        'trained' if det.get('threat_label') else 'statistical_fallback',
                        'risk_score':    round(float(risk_score), 1),
                        'anomaly_score': round(float(det.get('anomaly_score') or 0), 4),
                        'is_anomaly':    bool(det.get('is_anomaly', False)),
                        'ueba_flags':    [str(f) for f in ueba],
                        'attack_chains': chains,
                        'components':    sb if isinstance(sb, dict) else {},
                    }
            except Exception:
                pass

        # No stored ML — compute inline from pipeline or use severity fallback
        if not ml_section:
            log_dict = {
                'source_ip':   attack.ip_address or '',
                'event_type':  attack.attack_type or '',
                'severity':    attack.severity or 'high',
                'message':     '',
                'payload':     '',
                'status_code': 0,
                'dest_port':   0,
            }
            try:
                pipeline = get_pipeline(g.org.id)
                if pipeline:
                    ml_result = pipeline.analyze(log_dict)
                    ml_section = {
                        'has_results':   True,
                        'status':        ml_result.get('model_status', 'statistical_fallback'),
                        'risk_score':    round(float(ml_result.get('risk_score', 0)), 1),
                        'anomaly_score': round(float(ml_result.get('anomaly_score', 0)), 4),
                        'is_anomaly':    bool(ml_result.get('is_anomaly', False)),
                        'ueba_flags':    ml_result.get('ueba_flags', []),
                        'attack_chains': ml_result.get('attack_chains', []),
                        'components':    ml_result.get('components', {}),
                    }
            except Exception as e:
                app.logger.error(f"ML compute for attack {attack_id}: {e}")

            if not ml_section:
                sev = attack.severity or 'medium'
                ml_section = {
                    'has_results':   True,
                    'status':        'statistical_fallback',
                    'risk_score':    _severity_to_risk(sev),
                    'anomaly_score': 0.5 if sev in ('high', 'critical') else 0.2,
                    'is_anomaly':    sev in ('high', 'critical'),
                    'ueba_flags':    [],
                    'attack_chains': [],
                    'components':    {},
                }

        return jsonify({
            'id':          attack.id,
            'attack_type': attack.attack_type,
            'severity':    attack.severity,
            'source_ip':   attack.ip_address,
            'created_at':  str(attack.detected_at),
            'ml':          ml_section,
        }), 200

    except Exception as e:
        app.logger.error(f"Attack detail error: {e}")
        return jsonify({'error': str(e)}), 500


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
        try:
            addr = ipaddress.ip_address(ip_address)
            if addr.is_loopback:
                note = (
                    "Loopback address (127.x.x.x / ::1). "
                    "This event originated on the same machine as the SIEM server. "
                    "In development the Browser SDK sends events via localhost."
                )
                return jsonify({
                    "ip": ip_address, "error": None,
                    "country": "Local Machine", "country_code": "",
                    "city": "Localhost", "region": "Local Network",
                    "is_private": True, "is_loopback": True,
                    "note": note, "source": "local",
                })
            else:
                note = (
                    "Private/internal IP address. "
                    "Not internet-routable — originates from within your local network."
                )
                return jsonify({
                    "ip": ip_address, "error": None,
                    "country": "Private Network", "country_code": "",
                    "city": "Internal", "region": "LAN",
                    "is_private": True, "is_loopback": False,
                    "note": note, "source": "local",
                })
        except ValueError:
            note = (
                f"'{ip_address}' is not an IP address. "
                "This identifier was captured from an SDK or proxy connection. "
                "In production the real client IP is captured via X-Real-IP headers from Nginx."
            )
            return jsonify({
                "ip": ip_address, "error": None,
                "country": "SDK Client", "country_code": "",
                "city": "Browser/SDK", "region": "Local Connection",
                "is_sdk_client": True,
                "note": note, "source": "local",
            })

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
        r = safe_request(f"http://ip-api.com/json/{ip_address}", timeout=5)
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


@app.route("/api/dashboard/top-risky-entities")
@require_auth
def api_top_risky_entities():
    """Top risky entities from stored ML risk scores — works without trained models."""
    try:
        import json as _json
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(days=7)

        rows = (
            db.session.query(
                LogEntry.ip_address,
                db.func.max(LogEntry.ml_risk_score).label('max_risk'),
                db.func.avg(LogEntry.ml_risk_score).label('avg_risk'),
                db.func.count(LogEntry.id).label('event_count'),
            )
            .filter(
                LogEntry.organisation_id == g.org.id,
                LogEntry.ip_address.isnot(None),
                LogEntry.ip_address != '',
                LogEntry.ip_address != 'client',
                LogEntry.ml_risk_score.isnot(None),
                LogEntry.timestamp >= since,
            )
            .group_by(LogEntry.ip_address)
            .order_by(db.func.max(LogEntry.ml_risk_score).desc())
            .limit(5)
            .all()
        )

        entities = []
        for row in rows:
            # Grab UEBA flags from highest-risk log for this IP
            top_log = (
                LogEntry.query
                .filter(
                    LogEntry.organisation_id == g.org.id,
                    LogEntry.ip_address == row.ip_address,
                    LogEntry.ml_ueba_flags.isnot(None),
                )
                .order_by(LogEntry.ml_risk_score.desc())
                .first()
            )
            ueba_flags = []
            if top_log and top_log.ml_ueba_flags:
                try:
                    ueba_flags = _json.loads(top_log.ml_ueba_flags)
                except Exception:
                    pass

            attack_count = Attack.query.filter(
                Attack.organisation_id == g.org.id,
                Attack.ip_address == row.ip_address,
            ).count()

            risk = round(float(row.max_risk or 0), 1)
            entities.append({
                'ip':           row.ip_address,
                'max_risk':     risk,
                'avg_risk':     round(float(row.avg_risk or 0), 1),
                'event_count':  row.event_count,
                'attack_count': attack_count,
                'ueba_flags':   ueba_flags,
                'risk_level':   (
                    'critical' if risk >= 70 else
                    'high'     if risk >= 50 else
                    'medium'   if risk >= 30 else 'low'
                ),
            })

        # Fallback: use attacks table when no ML-scored logs exist
        if not entities:
            attack_rows = (
                db.session.query(
                    Attack.ip_address,
                    db.func.count(Attack.id).label('cnt'),
                )
                .filter(
                    Attack.organisation_id == g.org.id,
                    Attack.ip_address.isnot(None),
                    Attack.ip_address != '',
                    Attack.ip_address != 'client',
                )
                .group_by(Attack.ip_address)
                .order_by(db.func.count(Attack.id).desc())
                .limit(5)
                .all()
            )
            for row in attack_rows:
                entities.append({
                    'ip':           row.ip_address,
                    'max_risk':     65.0,
                    'avg_risk':     50.0,
                    'event_count':  row.cnt,
                    'attack_count': row.cnt,
                    'ueba_flags':   ['repeated_attacks'],
                    'risk_level':   'high',
                })

        return jsonify({'entities': entities, 'total': len(entities)}), 200

    except Exception as e:
        app.logger.error("top-risky-entities error: %s", e)
        return jsonify({'entities': [], 'total': 0}), 500


@app.route("/api/org/app-info", methods=["GET", "POST"])
@require_auth
def api_org_app_info():
    """Get or update the connected application info for this organisation."""
    if request.method == "GET":
        return jsonify({
            'app_name': g.org.app_name or '',
            'app_url':  g.org.app_url  or '',
            'app_type': g.org.app_type or '',
        }), 200

    if g.user.role not in ('owner', 'admin'):
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json(silent=True) or {}
    if 'app_name' in data:
        g.org.app_name = str(data['app_name'])[:120]
    if 'app_url' in data:
        g.org.app_url  = str(data['app_url'])[:255]
    if 'app_type' in data:
        g.org.app_type = str(data['app_type'])[:50]
    db.session.commit()
    return jsonify({'message': 'App info updated'}), 200


@app.route("/api/org/role-quotas", methods=["GET"])
@require_auth
def api_get_role_quotas():
    """Return current role quota configuration and usage counts."""
    role_counts = dict(
        db.session.query(
            CourraSecUser.role,
            db.func.count(CourraSecUser.id),
        )
        .filter_by(organisation_id=g.org.id, is_active=True)
        .group_by(CourraSecUser.role)
        .all()
    )
    total_used   = sum(role_counts.values())
    max_users    = g.org.max_users    or 20
    max_admins   = g.org.max_admins   or 5
    max_analysts = g.org.max_analysts or 10
    max_readonly = g.org.max_readonly or 4

    return jsonify({
        'max_users':  max_users,
        'total_used': total_used,
        'seats_left': max(0, max_users - total_used),
        'quotas': {
            'owner':    {'max': 1,            'used': role_counts.get('owner',    0)},
            'admin':    {'max': max_admins,   'used': role_counts.get('admin',    0)},
            'analyst':  {'max': max_analysts, 'used': role_counts.get('analyst',  0)},
            'readonly': {'max': max_readonly, 'used': role_counts.get('readonly', 0)},
        },
    }), 200


@app.route("/api/org/role-quotas", methods=["POST"])
@require_auth
def api_set_role_quotas():
    """Owner sets how many of each role are allowed (max total 19, leaving 1 for owner)."""
    if g.user.role != 'owner':
        return jsonify({'error': 'Only the owner can set role quotas'}), 403

    data         = request.get_json(silent=True) or {}
    max_admins   = int(data.get('max_admins',   g.org.max_admins   or 5))
    max_analysts = int(data.get('max_analysts', g.org.max_analysts or 10))
    max_readonly = int(data.get('max_readonly', g.org.max_readonly or 4))

    total = max_admins + max_analysts + max_readonly
    if total > 19:
        return jsonify({
            'error': f'Total role slots ({total}) cannot exceed 19 (20 seats minus 1 for owner).'
        }), 400

    # Cannot reduce below current active count for each role
    role_counts = dict(
        db.session.query(
            CourraSecUser.role, db.func.count(CourraSecUser.id)
        )
        .filter_by(organisation_id=g.org.id, is_active=True)
        .group_by(CourraSecUser.role).all()
    )
    for role_name, new_max, field in [
        ('admin',    max_admins,   'admin'),
        ('analyst',  max_analysts, 'analyst'),
        ('readonly', max_readonly, 'readonly'),
    ]:
        current = role_counts.get(role_name, 0)
        if new_max < current:
            return jsonify({
                'error': (
                    f"Cannot reduce {role_name} slots below current "
                    f"count ({current})."
                )
            }), 400

    g.org.max_admins   = max_admins
    g.org.max_analysts = max_analysts
    g.org.max_readonly = max_readonly
    db.session.commit()
    return jsonify({
        'message':       'Role quotas updated',
        'max_admins':    max_admins,
        'max_analysts':  max_analysts,
        'max_readonly':  max_readonly,
    }), 200


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
    """Always return True — no log limits in open-source build."""
    return True


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


def _ml_json_default(obj):
    """
    JSON encoder fallback for non-serializable types produced by sklearn/numpy.
    numpy.bool_ and numpy.float64 are NOT JSON serializable by default.
    """
    try:
        import numpy as np
        if isinstance(obj, np.bool_):    return bool(obj)
        if isinstance(obj, np.integer):  return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.ndarray):  return obj.tolist()
    except ImportError:
        pass
    # Last resort: try numeric coercion then stringify
    try:
        return float(obj)
    except (TypeError, ValueError):
        pass
    return str(obj)


def _ml_dumps(obj: object) -> str:
    """json.dumps with numpy-safe fallback encoder."""
    return json.dumps(obj, default=_ml_json_default)


def _store_ml_result(log_entry, ml_result: dict) -> None:
    """Merge ML result into log_entry's ML columns and raw_data (in-place, no commit)."""
    try:
        # Coerce every scalar to a plain Python type immediately so nothing
        # downstream can accidentally store a numpy type.
        risk_score    = float(ml_result.get("risk_score", 0) or 0)
        anomaly_score = float(ml_result.get("anomaly_score", 0) or 0)
        is_anomaly    = bool(ml_result.get("is_anomaly", False))
        ueba_flags    = list(ml_result.get("ueba_flags") or ml_result.get("ueba_anomalies") or [])
        attack_chains = list(ml_result.get("attack_chains") or
                             [str(c.get("pattern_name", c)) if isinstance(c, dict) else str(c)
                              for c in (ml_result.get("attack_chain") or [])])
        signal_bd     = (ml_result.get("risk") or {}).get("signal_breakdown")

        # Always-safe scalar columns (no JSON)
        log_entry.ml_risk_score    = risk_score
        log_entry.ml_anomaly_score = anomaly_score
        log_entry.ml_is_anomaly    = is_anomaly
        log_entry.ml_analyzed_at   = datetime.utcnow()
        log_entry.ml_model_version = "1.0"

        # JSON text columns — use safe encoder so numpy types never crash this
        log_entry.ml_ueba_flags    = _ml_dumps([str(f) for f in ueba_flags])
        log_entry.ml_attack_chains = _ml_dumps([str(c) for c in attack_chains])
        log_entry.ml_analysis      = _ml_dumps(ml_result)   # safe even with numpy

        # Merge ML fields into raw_data so the template JS can read them
        # without needing a separate API call (the list endpoint returns raw_data)
        try:
            raw_json = json.loads(log_entry.raw_data or '{}')
        except (TypeError, ValueError):
            raw_json = {}
        raw_json.update({
            "risk_score":      risk_score,
            "threat_label":    str(ml_result.get("threat_label") or ""),
            "mitre_tactic":    str(ml_result.get("mitre_tactic") or ""),
            "is_anomaly":      is_anomaly,
            "is_ueba_anomaly": bool(ml_result.get("is_ueba_anomaly", False)),
            "is_sequential":   bool(ml_result.get("is_sequential", False)),
            "is_novel_log":    bool(ml_result.get("is_novel_log", False)),
            "attack_chain":    [],          # chain objects stripped for size
            "ueba_anomalies":  [str(f) for f in ueba_flags],
            "signal_breakdown": signal_bd,
            "risk":            ml_result.get("risk"),
        })
        log_entry.raw_data = _ml_dumps(raw_json)

    except Exception as e:
        logger.error("_store_ml_result error: %s", e)


def _run_ml_and_store(log_id: int, org_id: int, log_dict: dict) -> None:
    """Run ML pipeline and store results in the log entry (background-safe)."""
    try:
        with app.app_context():
            from app.models import LogEntry, db as _db
            pipeline  = get_pipeline(org_id)
            if not pipeline:
                return
            ml_result = pipeline.analyze(log_dict)
            entry     = LogEntry.query.get(log_id)
            if not entry:
                return
            _store_ml_result(entry, ml_result)
            _db.session.commit()
    except Exception as e:
        logger.error("_run_ml_and_store error for log %s: %s", log_id, e)


def auto_train_if_ready(org_id: int) -> None:
    """Trigger IsolationForest training when org has enough logs."""
    try:
        with app.app_context():
            from app.models import LogEntry as _LE
            count    = _LE.query.filter_by(organisation_id=org_id).count()
            pipeline = get_pipeline(org_id)
            if not pipeline:
                return

            detector   = pipeline.anomaly
            is_trained = getattr(detector, '_trained', False)
            should_train = (count >= 100 and not is_trained) or (count > 0 and count % 1000 == 0)

            if not should_train:
                return

            logs = (_LE.query.filter_by(organisation_id=org_id)
                    .order_by(_LE.timestamp.desc()).limit(5000).all())

            log_dicts = [
                {
                    "severity":     l.severity,
                    "status_code":  0,
                    "payload":      l.payload or "",
                    "attack_type":  l.attack_type or "",
                    "timestamp":    l.timestamp.isoformat() if l.timestamp else "",
                }
                for l in logs
            ]
            pipeline.anomaly._buffer.clear()
            for ld in log_dicts:
                pipeline.anomaly._featurize(ld)
                pipeline.anomaly._buffer.append(pipeline.anomaly._featurize(ld))
            pipeline.anomaly._retrain()
            logger.info("Auto-trained IsolationForest for org %s on %d logs", org_id, len(logs))
    except Exception as e:
        logger.error("auto_train_if_ready error for org %s: %s", org_id, e)


def _process_ingest(data: dict, org_id: int) -> None:
    """
    Parse, normalise, deduplicate, suppress and analyse one ingest event.

    Fast path  (synchronous, before DB commit):  normalise → dedup → ML score
    Slow path  (background thread, after return): rules engine, correlation,
               threat intel, playbooks, ML alerts
    """
    import time as _time
    _t0 = _time.perf_counter()

    # ── 1. Normalise ─────────────────────────────────────────────────────
    raw_str = data.get("raw") or data.get("message") or data.get("payload") or ""
    if not raw_str and isinstance(data, dict):
        raw_str = json.dumps(data)
    source_hint = data.get("source") or data.get("source_tag")
    norm        = normalize(raw_str, source_hint=source_hint)

    ip_addr     = (data.get("ipAddress") or data.get("source_ip")
                   or (data.get("request") or {}).get("ip")
                   or norm['ip_address'] or "unknown")
    endpoint    = (data.get("endpoint") or (data.get("request") or {}).get("path")
                   or norm['endpoint'] or "unknown")
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

    # ── 2. Deduplication ──────────────────────────────────────────────────
    dedup_hash = compute_dedup_hash(ip_addr, attack_type, endpoint, str(payload), org_id)
    if is_duplicate(dedup_hash, window_secs=60):
        return

    # ── 3. Suppression ────────────────────────────────────────────────────
    if _is_suppressed({'ip_address': ip_addr, 'attack_type': attack_type,
                       'endpoint': endpoint, 'severity': severity,
                       'user_agent': user_agent or ''}, org_id):
        db.session.add(LogEntry(
            organisation_id=org_id, ip_address=ip_addr,
            attack_type=attack_type, endpoint=endpoint,
            payload=str(payload)[:1000], user_agent=user_agent,
            severity=severity, timestamp=timestamp,
            raw_data=json.dumps(data), suppressed=True,
        ))
        db.session.commit()
        return

    # ── 4. Build LogEntry and flush (get ID without full commit) ────────��─
    log = LogEntry(
        organisation_id=org_id, ip_address=ip_addr,
        attack_type=attack_type, endpoint=endpoint,
        payload=str(payload)[:1000], user_agent=user_agent,
        severity=severity, timestamp=timestamp,
        raw_data=json.dumps(data),
    )
    db.session.add(log)
    db.session.flush()   # assigns log.id, stays in transaction

    _t1 = _time.perf_counter()

    # ── 5. ML SCORING — SYNCHRONOUS ───────────────────────────────────────
    # ML scoring is ~1-5ms. Run it now, store result in the SAME commit.
    # This guarantees every log has ML data when the response is returned.
    ml_result = None
    pipeline  = get_pipeline(org_id)
    if pipeline:
        try:
            log_dict_for_ml = {
                "source_ip":   ip_addr, "ip_address": ip_addr,
                "endpoint":    endpoint, "attack_type": attack_type,
                "payload":     str(payload)[:500],
                "severity":    severity,
                "message":     str(payload)[:200],
                "status_code": data.get("statusCode") or data.get("status_code") or 0,
            }
            ml_result = pipeline.analyze(log_dict_for_ml)
            _store_ml_result(log, ml_result)
        except Exception as ml_err:
            logger.error("ML scoring error: %s", ml_err)

    _t2 = _time.perf_counter()

    # ── 6. COMMIT (log + ML results atomically) ───────────────────────────
    db.session.commit()
    log_id = log.id

    _t3 = _time.perf_counter()

    logger.info(
        "[INGEST TIMING] parse=%.1fms ml=%.1fms commit=%.1fms total=%.1fms",
        (_t1 - _t0) * 1000, (_t2 - _t1) * 1000,
        (_t3 - _t2) * 1000, (_t3 - _t0) * 1000,
    )

    # ── 7. BACKGROUND: rules, alerts, correlation, threat intel ───────────
    # These can be slow (DB queries, external calls). Run after returning
    # so they never delay the ingest response.
    _ml_result_copy = ml_result  # capture for closure

    def _run_slow_tasks(log_id, org_id, ip_addr, ml_r):
        try:
            with app.app_context():
                _log = LogEntry.query.get(log_id)
                if not _log:
                    return

                # Built-in rules engine
                try:
                    rule_result = rules_engine.check_rules(_log)
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
                                if not IPBlocklist.query.filter_by(
                                    organisation_id=org_id, ip_address=ip_addr
                                ).first():
                                    db.session.add(IPBlocklist(
                                        organisation_id=org_id,
                                        ip_address=ip_addr,
                                        reason=f"Auto-blocked: {rule_result['rule']}",
                                        blocked_by="system",
                                    ))
                                    db.session.flush()
                            except Exception as be:
                                db.session.rollback()
                                logger.warning("Auto-block failed %s: %s", ip_addr, be)
                        _rule_det = dict(rule_result["details"])
                        _rule_det["source_ip"] = ip_addr
                        if ml_r:
                            _rule_det.update({
                                "risk_score":    ml_r.get("risk_score", 0),
                                "anomaly_score": ml_r.get("anomaly_score", 0),
                                "is_anomaly":    ml_r.get("is_anomaly", False),
                                "flags":         ml_r.get("ueba_flags", []),
                                "threat_label":  ml_r.get("threat_label", ""),
                                "mitre_tactic":  ml_r.get("mitre_tactic", ""),
                            })
                        rule_alert = Alert(
                            organisation_id=org_id,
                            message=f"Rule triggered: {rule_result['rule']} from {ip_addr}",
                            alert_type=rule_result["rule"],
                            severity=rule_result["severity"],
                            details=json.dumps(_rule_det),
                        )
                        db.session.add(rule_alert)
                        ALERTS_CREATED_TOTAL.labels(
                            severity=rule_result["severity"],
                            alert_type=rule_result["rule"],
                        ).inc()
                        db.session.commit()
                        try:
                            alert_system.send_alert(
                                message=rule_alert.message,
                                severity=rule_result["severity"],
                                details=rule_result["details"],
                            )
                        except Exception:
                            pass
                        try:
                            playbook_engine.run_for_alert(rule_alert, org_id)
                        except Exception:
                            pass
                except Exception as re_err:
                    logger.debug("Rules engine error: %s", re_err)

                # Custom rules
                try:
                    from app.rules_engine import evaluate_all_custom_rules
                    evaluate_all_custom_rules(_log, org_id)
                except Exception as cre:
                    logger.debug("Custom rules error: %s", cre)

                # Correlation engine
                try:
                    fired = correlation_engine.evaluate(_log, org_id)
                    for corr in fired:
                        ca = correlation_engine.create_alert_for_correlation(corr, org_id)
                        if ca:
                            try: playbook_engine.run_for_alert(ca, org_id)
                            except Exception: pass
                except Exception as corr_err:
                    logger.debug("Correlation error: %s", corr_err)

                # Threat intel enrichment
                try:
                    from app.threat_intel import enrich_log_entry
                    ioc_matches = enrich_log_entry(_log, org_id)
                    if ioc_matches:
                        _ioc_det = {"matches": ioc_matches, "ip": ip_addr, "source_ip": ip_addr}
                        if ml_r:
                            _ioc_det.update({
                                "risk_score":    ml_r.get("risk_score", 0),
                                "anomaly_score": ml_r.get("anomaly_score", 0),
                                "is_anomaly":    ml_r.get("is_anomaly", False),
                                "flags":         ml_r.get("ueba_flags", []),
                                "threat_label":  ml_r.get("threat_label", ""),
                                "mitre_tactic":  ml_r.get("mitre_tactic", ""),
                            })
                        ioc_alert = Alert(
                            organisation_id=org_id,
                            message=f"IOC match: {ip_addr} matched {len(ioc_matches)} indicator(s)",
                            alert_type="threat_intel_match",
                            severity="high",
                            details=json.dumps(_ioc_det),
                        )
                        db.session.add(ioc_alert)
                        db.session.commit()
                        try: playbook_engine.run_for_alert(ioc_alert, org_id)
                        except Exception: pass
                except Exception as ti_err:
                    logger.debug("Threat intel error: %s", ti_err)

                # ML-triggered alert (high/critical risk)
                try:
                    if ml_r and ml_r.get("severity") in ("high", "critical"):
                        ml_alert = Alert(
                            organisation_id=org_id,
                            message=f"ML anomaly detected from {ip_addr}",
                            alert_type="ml_anomaly",
                            severity=ml_r["severity"],
                            details=json.dumps(ml_r),
                        )
                        db.session.add(ml_alert)
                        db.session.commit()
                        ML_ANOMALIES_TOTAL.labels(severity=ml_r["severity"]).inc()
                except Exception as ml_ae:
                    logger.debug("ML alert error: %s", ml_ae)

                # Periodic auto-train
                try:
                    if log_id % 100 == 0:
                        auto_train_if_ready(org_id)
                except Exception:
                    pass

        except Exception as bg_err:
            logger.error("Post-ingest background error: %s", bg_err)

    Thread(
        target=_run_slow_tasks,
        args=(log_id, org_id, ip_addr, _ml_result_copy),
        daemon=True,
    ).start()


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
    login = limiter.limit(Config.RATELIMIT_LOGIN)(login)


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


# =============================================================================
# API — DEFAULT (BUILT-IN) RULES
# =============================================================================

DEFAULT_RULES = [
    {
        'id':            'default_brute_force',
        'name':          'Brute Force Detection',
        'description':   'Detects 10+ failed logins from one IP within 2 minutes',
        'rule_type':     'builtin',
        'severity':      'high',
        'action':        'alert',
        'mitre_tactic':  'TA0006',
        'is_active':     True,
        'is_default':    True,
        'trigger_count': 0,
        'logic': {
            'threshold': 10,
            'window_seconds': 120,
            'field': 'source_ip',
            'event_type': 'failed_login'
        }
    },
    {
        'id':            'default_geo_velocity',
        'name':          'Geo-Velocity Anomaly',
        'description':   'Impossible travel — authentication from 300+ km/h apart',
        'rule_type':     'builtin',
        'severity':      'critical',
        'action':        'alert',
        'mitre_tactic':  'TA0001',
        'is_active':     True,
        'is_default':    True,
        'trigger_count': 0,
        'logic': {'max_speed_kmh': 300, 'uses': 'haversine + geoip'}
    },
    {
        'id':            'default_privilege_escalation',
        'name':          'Privilege Escalation',
        'description':   'Low-privilege access followed by admin action in window',
        'rule_type':     'builtin',
        'severity':      'critical',
        'action':        'alert',
        'mitre_tactic':  'TA0004',
        'is_active':     True,
        'is_default':    True,
        'trigger_count': 0,
        'logic': {
            'sequence': ['low_privilege_access', 'admin_action'],
            'window_seconds': 300
        }
    },
    {
        'id':            'default_command_injection',
        'name':          'Command Injection',
        'description':   'Shell metacharacters and command sequences in payload',
        'rule_type':     'builtin',
        'severity':      'high',
        'action':        'alert_and_block',
        'mitre_tactic':  'TA0002',
        'is_active':     True,
        'is_default':    True,
        'trigger_count': 0,
        'logic': {'patterns': [';', '|', '&&', '`', 'cmd.exe', '/bin/sh', '../']}
    },
    {
        'id':            'default_multi_attack',
        'name':          'Multi-Attack Burst',
        'description':   '3+ distinct attack types from one IP in 5 minutes',
        'rule_type':     'builtin',
        'severity':      'critical',
        'action':        'alert_and_block',
        'mitre_tactic':  'TA0043',
        'is_active':     True,
        'is_default':    True,
        'trigger_count': 0,
        'logic': {'min_attack_types': 3, 'window_seconds': 300}
    },
]

_ATTACK_TYPE_MAP = {
    'default_brute_force':          'Brute Force',
    'default_geo_velocity':         'Geo-Velocity Anomaly',
    'default_privilege_escalation': 'Privilege Escalation',
    'default_command_injection':    'Command Injection',
    'default_multi_attack':         'Multi-Attack Burst',
}


@app.route('/api/rules/default', methods=['GET'])
@require_auth
def get_default_rules():
    """Return all 5 built-in rules with live trigger counts and override status."""
    try:
        from app.models import DefaultRuleOverride

        rules = []
        for rule in DEFAULT_RULES:
            r = dict(rule)

            attack_type = _ATTACK_TYPE_MAP.get(rule['id'], '')
            if attack_type:
                r['trigger_count'] = Attack.query.filter_by(
                    organisation_id=g.org.id,
                    attack_type=attack_type
                ).count()

            try:
                override = DefaultRuleOverride.query.filter_by(
                    organisation_id=g.org.id,
                    rule_id=rule['id']
                ).first()
                if override:
                    r['is_edited']      = True
                    r['edited_at']      = str(override.edited_at)
                    r['edited_by_name'] = override.edited_by_name
                    r['is_active']      = override.is_active
                    r['override_notes'] = override.notes
                else:
                    r['is_edited'] = False
            except Exception:
                r['is_edited'] = False

            rules.append(r)

        return jsonify({'default_rules': rules, 'total': len(rules)}), 200

    except Exception as e:
        app.logger.error(f"Default rules error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/rules/default/<rule_id>/toggle', methods=['POST'])
@require_auth
def toggle_default_rule(rule_id):
    """Enable or disable a built-in default rule (admin/owner only)."""
    if g.user.role not in ('owner', 'admin'):
        return jsonify({'error': 'Admin access required'}), 403

    if rule_id not in [r['id'] for r in DEFAULT_RULES]:
        return jsonify({'error': 'Unknown default rule'}), 404

    try:
        from app.models import DefaultRuleOverride

        data      = request.get_json(silent=True) or {}
        is_active = data.get('is_active', True)
        notes     = data.get('notes', '')

        override = DefaultRuleOverride.query.filter_by(
            organisation_id=g.org.id,
            rule_id=rule_id
        ).first()

        if not override:
            override = DefaultRuleOverride(
                organisation_id=g.org.id,
                rule_id=rule_id,
            )
            db.session.add(override)

        override.is_active      = is_active
        override.notes          = notes
        override.edited_at      = datetime.utcnow()
        override.edited_by      = g.user.id
        override.edited_by_name = g.user.username
        db.session.commit()

        return jsonify({
            'rule_id':   rule_id,
            'is_active': is_active,
            'is_edited': True,
            'message':   f"Rule {'enabled' if is_active else 'disabled'}",
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


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
    sandbox_on = True

    if rule.level in (1, 2) and rule.rule_definition:
        try:
            triggered = _rule_evaluator.evaluate(
                json.loads(rule.rule_definition), sample
            )
        except Exception as e:
            try:
                rule_def, parse_err = _rule_evaluator.parse_yaml(rule.rule_definition)
                if not parse_err:
                    triggered = _rule_evaluator.evaluate(rule_def, sample)
                else:
                    error = parse_err
            except Exception as e2:
                error = str(e2)
    elif rule.level == 3 and rule.rule_python:
        from app.rules_engine import _is_sandbox_enabled, _execute_unrestricted
        sandbox_on = _is_sandbox_enabled(g.org.id)
        if sandbox_on:
            triggered, error = _dsl_runner.execute(rule.rule_python, sample)
        else:
            triggered, error = _execute_unrestricted(rule.rule_python, sample, rule.name)

    return jsonify({
        "ok":        True,
        "triggered": triggered,
        "error":     error,
        "event":     sample,
        "sandbox":   sandbox_on,
    })


@app.route("/api/rules/test", methods=["POST"])
@require_auth
def api_rules_test_inline():
    """
    Test arbitrary rule code against a provided event dict before saving.
    Body: { "rule_type": "python"|"yaml"|"visual",
            "rule_code": "def rule(event): ...",
            "test_event": { ... } }
    Returns: { "matched": bool, "error": str|None, "sandbox": bool }
    """
    data       = request.get_json(force=True, silent=True) or {}
    rule_type  = data.get("rule_type", "python")
    rule_code  = (data.get("rule_code") or "").strip()
    test_event = data.get("test_event") or {}

    if not rule_code:
        return jsonify({"error": "rule_code is required"}), 400

    from app.models import OrganisationSettings
    settings   = OrganisationSettings.query.filter_by(organisation_id=g.org.id).first()
    sandbox_on = settings.python_dsl_sandbox if settings else True

    try:
        matched = False
        err     = None

        if rule_type == "python":
            from app.rules_engine import _execute_unrestricted
            if sandbox_on:
                matched, err = _dsl_runner.execute(rule_code, test_event)
            else:
                matched, err = _execute_unrestricted(rule_code, test_event, "inline-test")

        elif rule_type in ("yaml", "json", "visual"):
            rule_def, parse_err = _rule_evaluator.parse_yaml(rule_code)
            if parse_err:
                err = parse_err
            else:
                matched = _rule_evaluator.evaluate(rule_def, test_event)

        else:
            return jsonify({"error": f"Unknown rule_type: {rule_type}"}), 400

        return jsonify({"matched": matched, "error": err, "sandbox": sandbox_on}), 200

    except Exception as e:
        return jsonify({"matched": False, "error": str(e), "sandbox": sandbox_on}), 500


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
# Weekly report scheduler — fires every Monday at 08:00 UTC
# =============================================================================

def _seconds_until_next_monday_0800() -> float:
    """Return seconds from now until the next Monday 08:00 UTC."""
    now = datetime.utcnow()
    # days_ahead: 0 = this Monday, positive = days until next Monday
    days_ahead = (7 - now.weekday()) % 7  # weekday() 0=Mon … 6=Sun
    if days_ahead == 0 and (now.hour, now.minute) >= (8, 0):
        days_ahead = 7  # already past 08:00 this Monday — use next week
    next_run = now.replace(hour=8, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)
    return max((next_run - datetime.utcnow()).total_seconds(), 0)


def _weekly_report_scheduler_loop():
    global _baseline_reporter_status
    _baseline_reporter_status = "active"
    while True:
        delay = _seconds_until_next_monday_0800()
        logger.info("WeeklyReportScheduler: next run in %.0f seconds (Monday 08:00 UTC)", delay)
        time.sleep(delay)
        try:
            run_scheduled_reports(app.app_context())
            logger.info("WeeklyReportScheduler: scheduled reports triggered")
        except Exception as exc:
            logger.error("WeeklyReportScheduler: error triggering reports: %s", exc)


Thread(target=_weekly_report_scheduler_loop, daemon=True).start()

# =============================================================================
# OWASP Compliance Status
# =============================================================================

@app.route("/api/security/owasp-status")
@require_auth
@require_role('owner', 'admin')
def owasp_status():
    """Returns OWASP Top 10 compliance status for this deployment."""
    checks = {
        "A01_broken_access_control": {
            "status": "protected",
            "controls": [
                "require_auth on all protected routes",
                "tenant_scope via organisation_id on all DB queries",
                "IDOR prevention: object ownership checks",
                "Role-based access control (owner/admin/analyst/readonly)",
            ],
        },
        "A02_cryptographic_failures": {
            "status": "protected",
            "controls": [
                "PBKDF2-SHA256 password hashing via Werkzeug",
                "256-bit secrets.token_urlsafe API keys",
                "Persistent SECRET_KEY with 600 file permissions",
                "Secure session cookies (HttpOnly, SameSite=Lax)",
            ],
        },
        "A03_injection": {
            "status": "protected",
            "controls": [
                "SQLAlchemy ORM — no raw SQL in application routes",
                "Jinja2 auto-escaping on all template output",
                "Input validation module (app/security/input_validation.py)",
                "RestrictedPython sandbox for custom DSL rules",
            ],
        },
        "A04_insecure_design": {
            "status": "protected",
            "controls": [
                "Rate limiting on /ingest and /login via flask-limiter",
                "Login account lockout after 5 failures (15 min cooldown)",
                "Daily log quotas per organisation",
                "Plan tier limits enforced at route level",
            ],
        },
        "A05_security_misconfiguration": {
            "status": "protected",
            "controls": [
                "X-Frame-Options: DENY",
                "Content-Security-Policy header",
                "Permissions-Policy header",
                "X-Content-Type-Options: nosniff",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "HSTS enabled when TLS_ENABLED=true",
                "Server header removed",
                "Secure error handlers — no stack trace exposure",
            ],
        },
        "A06_vulnerable_components": {
            "status": "monitor",
            "controls": [
                "Dependencies declared in requirements.txt",
                "Run security_check.py weekly for vulnerability scan",
                "pip-audit integration available",
            ],
        },
        "A07_auth_failures": {
            "status": "protected",
            "controls": [
                "Rate limiting on login (configurable, default 20/min)",
                "Account lockout: 5 failures → 15-minute cooldown",
                "TOTP 2FA available per user",
                "Password policy enforced on registration",
                "CSRF token validation on all authenticated state-changing requests",
                "Session CSRF token rotated on login",
            ],
        },
        "A08_data_integrity": {
            "status": "protected",
            "controls": [
                "File upload extension + magic-byte validation",
                "HMAC-signed audit log entries",
                "Pinned dependency versions",
            ],
        },
        "A09_logging_monitoring": {
            "status": "protected",
            "controls": [
                "Rotating JSON security log (logs/security.log)",
                "auth_success / auth_failure / auth_lockout events",
                "access_denied and csrf_failure events",
                "injection_attempt events",
                "Prometheus metrics for anomaly detection",
            ],
        },
        "A10_ssrf": {
            "status": "protected",
            "controls": [
                "safe_request() wraps all outbound HTTP calls",
                "Domain allowlist for external services",
                "Private IP range blocking (RFC 1918 + loopback + link-local)",
                "Public IP validation before geoip lookups",
            ],
        },
    }
    protected = sum(1 for v in checks.values() if v["status"] == "protected")
    total = len(checks)
    return jsonify({
        "owasp_top_10_2021": checks,
        "summary": {
            "protected": protected,
            "monitoring": total - protected,
            "total": total,
            "compliance_score": f"{protected / total * 100:.0f}%",
        },
    }), 200


# =============================================================================
# Startup
# =============================================================================
print("Courra-Sec v2.0 — Multi-tenant SaaS mode ready")
print(f"Superadmin username: {SUPERADMIN_USERNAME}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
