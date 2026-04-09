# app/audit.py — Courra-Sec audit logging
"""
Records all security-relevant admin actions to the AuditLog table.

Usage:
    from app.audit import audit_log

    # In a route (requires g.user to be set):
    audit_log('user_invited', resource_type='user', resource_id=str(new_user.id),
              details={'invited_username': 'alice'})

    # As a decorator (logs entry + exit of a route function):
    @audit_action('rule_deleted')
    @require_auth
    def delete_rule(rule_id):
        ...
"""
import json
from datetime import datetime
from functools import wraps

from flask import g, request

from app.database import db
from app.models import AuditLog


# ---------------------------------------------------------------------------
# Core write function
# ---------------------------------------------------------------------------

def audit_log(action: str, resource_type: str = None, resource_id: str = None,
              details: dict = None, org_id: int = None, username: str = None,
              user_id: int = None, ip: str = None):
    """
    Persist an audit log entry. Safe to call from any context; silently
    swallows all errors so audit failures never break the application.
    """
    try:
        # Pull from Flask g when inside a request context
        _org_id   = org_id   or (g.org_id  if hasattr(g, 'org_id')  else None)
        _user_id  = user_id  or (g.user_id if hasattr(g, 'user_id') else None)
        _username = username or (g.user.username if hasattr(g, 'user') else None)
        _ip       = ip       or _get_request_ip()

        entry = AuditLog(
            organisation_id=_org_id,
            user_id=_user_id,
            username=_username,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            details=json.dumps(details) if details else None,
            ip_address=_ip,
            created_at=datetime.utcnow(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        # Never raise — audit must not break the calling code
        print(f'[Audit] WARNING: could not write audit log ({action}): {e}')


def _get_request_ip() -> str:
    try:
        return (
            request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            or request.remote_addr
            or ''
        )
    except RuntimeError:
        return ''


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def audit_action(action: str, resource_type: str = None):
    """
    Decorator that logs an audit entry when the wrapped route is called.

    Example:
        @app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
        @require_auth
        @audit_action('rule_deleted', resource_type='custom_rule')
        def delete_rule(rule_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Extract resource_id from kwargs if possible
            rid = (
                kwargs.get('rule_id') or kwargs.get('user_id') or
                kwargs.get('case_id') or kwargs.get('playbook_id') or
                kwargs.get('id')
            )
            result = f(*args, **kwargs)
            audit_log(
                action=action,
                resource_type=resource_type,
                resource_id=str(rid) if rid is not None else None,
            )
            return result
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_audit_logs(org_id: int, page: int = 1, per_page: int = 50,
                   action: str = None, username: str = None):
    """Paginated audit log query for an org."""
    q = AuditLog.query.filter_by(organisation_id=org_id)
    if action:
        q = q.filter(AuditLog.action.ilike(f'%{action}%'))
    if username:
        q = q.filter(AuditLog.username.ilike(f'%{username}%'))
    return q.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )


# ---------------------------------------------------------------------------
# Well-known action constants
# ---------------------------------------------------------------------------

class Actions:
    # Auth
    LOGIN          = 'login'
    LOGOUT         = 'logout'
    LOGIN_FAILED   = 'login_failed'
    TOTP_ENABLED   = 'totp_enabled'
    TOTP_DISABLED  = 'totp_disabled'
    PASSWORD_CHANGED = 'password_changed'

    # Users
    USER_INVITED   = 'user_invited'
    USER_REMOVED   = 'user_removed'
    USER_ACTIVATED = 'user_activated'
    USER_DEACTIVATED = 'user_deactivated'
    ROLE_CHANGED   = 'role_changed'

    # Rules
    RULE_CREATED   = 'rule_created'
    RULE_UPDATED   = 'rule_updated'
    RULE_DELETED   = 'rule_deleted'

    # Correlation
    CORRELATION_CREATED = 'correlation_rule_created'
    CORRELATION_DELETED = 'correlation_rule_deleted'

    # Blocklist
    IP_BLOCKED     = 'ip_blocked'
    IP_UNBLOCKED   = 'ip_unblocked'

    # Cases
    CASE_CREATED   = 'case_created'
    CASE_UPDATED   = 'case_updated'
    CASE_CLOSED    = 'case_closed'

    # Playbooks
    PLAYBOOK_CREATED = 'playbook_created'
    PLAYBOOK_DELETED = 'playbook_deleted'
    PLAYBOOK_RUN     = 'playbook_executed'

    # Org
    ORG_UPDATED     = 'org_updated'
    API_KEY_REGEN   = 'api_key_regenerated'
    ORG_DELETED     = 'org_deleted'

    # Reports
    REPORT_GENERATED = 'report_generated'
    REPORT_EXPORTED  = 'report_exported'

    # Threat Intel
    IOC_IMPORTED    = 'ioc_imported'
    FEED_SYNCED     = 'threat_feed_synced'
