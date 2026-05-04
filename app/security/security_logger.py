# app/security/security_logger.py — OWASP A09: Security Logging & Monitoring
import logging
import logging.handlers
import json
import os
from datetime import datetime

security_logger = logging.getLogger('courra.security')
_configured = False


def setup_security_logging(app):
    global _configured
    if _configured:
        return
    _configured = True

    logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        os.path.join(logs_dir, 'security.log'),
        maxBytes=50 * 1024 * 1024,
        backupCount=10,
    )
    handler.setLevel(logging.INFO)

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            entry = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'level': record.levelname,
                'event': record.getMessage(),
            }
            if hasattr(record, 'sec'):
                entry.update(record.sec)
            return json.dumps(entry)

    handler.setFormatter(_JsonFormatter())
    security_logger.addHandler(handler)
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False

    if os.environ.get('FLASK_ENV') != 'production':
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        security_logger.addHandler(ch)


def _emit(event_type: str, severity: str, **kwargs):
    try:
        from flask import request, g
        ip = request.remote_addr if request else 'unknown'
        path = request.path if request else 'unknown'
        user_id = getattr(getattr(g, 'user', None), 'id', None)
        org_id = getattr(getattr(g, 'org', None), 'id', None)
    except RuntimeError:
        ip = path = 'unknown'
        user_id = org_id = None

    payload = {
        'event_type': event_type, 'severity': severity,
        'ip': ip, 'path': path,
        'user_id': user_id, 'org_id': org_id,
        **kwargs,
    }
    level = {'critical': 50, 'high': 40, 'warning': 30, 'info': 20}.get(severity, 20)
    record = security_logger.makeRecord(
        'courra.security', level, '', 0,
        f"[{event_type}]", (), None,
    )
    record.sec = payload
    security_logger.handle(record)


def log_auth_success(username: str):
    _emit('auth_success', 'info', username=username)


def log_auth_failure(username: str, reason: str = ''):
    _emit('auth_failure', 'warning', username=username, reason=reason)


def log_auth_lockout(username: str):
    _emit('auth_lockout', 'high', username=username)


def log_access_denied(resource: str, reason: str = ''):
    _emit('access_denied', 'warning', resource=resource, reason=reason)


def log_injection_attempt(attack_type: str, payload_snippet: str = ''):
    _emit('injection_attempt', 'high', attack_type=attack_type, payload=payload_snippet[:200])


def log_admin_action(action: str, target: str = ''):
    _emit('admin_action', 'info', action=action, target=target)


def log_suspicious_activity(description: str, details: dict = None):
    _emit('suspicious_activity', 'high', description=description, details=details or {})


def log_csrf_failure(path: str, ip: str):
    _emit('csrf_failure', 'warning', attempted_path=path, source_ip=ip)
