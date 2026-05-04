# app/security/crypto.py — OWASP A02: Cryptographic Failures
import os
import hashlib
import secrets
import hmac


def generate_api_key(prefix='crr_live_'):
    """Generate a cryptographically secure API key (256 bits)."""
    return f"{prefix}{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage using HMAC-SHA256."""
    secret = os.environ.get('API_KEY_HMAC_SECRET', '').encode()
    if not secret:
        return hashlib.sha256(api_key.encode()).hexdigest()
    return hmac.new(secret, api_key.encode(), hashlib.sha256).hexdigest()


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return hmac.compare_digest(hash_api_key(provided_key), stored_hash)


def generate_secure_token(length: int = 32) -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)


def verify_password_strength(password: str) -> tuple:
    """Returns (is_valid, error_message)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, ""
