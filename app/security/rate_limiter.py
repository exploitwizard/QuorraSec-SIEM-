# app/security/rate_limiter.py — OWASP A04: Insecure Design (login lockout)
import time
import threading
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class LoginAttemptTracker:
    """Track failed login attempts per username+IP and lock after threshold."""
    _attempts: dict = defaultdict(list)
    _locked: dict = {}
    _lock = threading.Lock()
    LOCKOUT_THRESHOLD = 5
    LOCKOUT_DURATION = 900  # 15 minutes

    @classmethod
    def record_failure(cls, username: str, ip: str):
        with cls._lock:
            now = time.time()
            key = f"{username}:{ip}"
            cls._attempts[key].append(now)
            cls._attempts[key] = [t for t in cls._attempts[key] if now - t < cls.LOCKOUT_DURATION]
            if len(cls._attempts[key]) >= cls.LOCKOUT_THRESHOLD:
                cls._locked[key] = now + cls.LOCKOUT_DURATION
                logger.warning("Account locked: username=%s ip=%s after %d failures",
                               username, ip, cls.LOCKOUT_THRESHOLD)

    @classmethod
    def is_locked(cls, username: str, ip: str) -> tuple:
        """Returns (is_locked, seconds_remaining)."""
        with cls._lock:
            key = f"{username}:{ip}"
            if key in cls._locked:
                remaining = cls._locked[key] - time.time()
                if remaining > 0:
                    return True, int(remaining)
                del cls._locked[key]
                cls._attempts[key] = []
            return False, 0

    @classmethod
    def record_success(cls, username: str, ip: str):
        with cls._lock:
            key = f"{username}:{ip}"
            cls._attempts[key] = []
            cls._locked.pop(key, None)


login_tracker = LoginAttemptTracker()
