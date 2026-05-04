# app/security/auth_hardening.py — OWASP A07: Auth Failures
import secrets
import logging
from flask import session, request

logger = logging.getLogger(__name__)

_COMMON_PASSWORDS = frozenset([
    'password', '12345678', 'qwerty123', 'admin123', 'letmein',
    'welcome1', 'courrasec', 'siem1234', 'password1', 'iloveyou',
])


def create_secure_session(user, org):
    """Set up a hardened session after successful login."""
    session['user_id'] = user.id
    session['organisation_id'] = user.organisation_id
    session['csrf_token'] = secrets.token_hex(32)
    session['role'] = user.role
    session.permanent = True


def enforce_password_policy(password: str, username: str = '') -> tuple:
    """Returns (is_valid, error_message)."""
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in password):
        errors.append("one uppercase letter")
    if not any(c.islower() for c in password):
        errors.append("one lowercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("one number")
    if username and username.lower() in password.lower():
        errors.append("password must not contain username")
    if password.lower() in _COMMON_PASSWORDS:
        errors.append("password is too common")
    if errors:
        return False, f"Password must include: {', '.join(errors)}"
    return True, ""
