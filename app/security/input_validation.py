# app/security/input_validation.py — OWASP A03: Injection Prevention
import re
import html
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class InputValidator:
    SQL_PATTERNS = [
        r'(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bUNION\b)',
        r'(--|;|\/\*|\*\/|xp_|EXEC\b|EXECUTE\b)',
        r'(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)',
        r'(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)',
    ]

    XSS_PATTERNS = [
        r'<script[^>]*>',
        r'javascript\s*:',
        r'on\w+\s*=',
        r'<\s*iframe',
        r'<\s*object',
        r'expression\s*\(',
        r'vbscript\s*:',
    ]

    CMD_PATTERNS = [
        r';\s*(ls|cat|wget|curl|nc|bash|sh|python|perl|ruby)\b',
        r'\|\s*(ls|cat|wget|curl|nc|bash|sh)\b',
        r'\$\([^)]+\)',
        r'`[^`]+`',
    ]

    PATH_TRAVERSAL = [
        r'\.\.[/\\]',
        r'%2e%2e',
        r'\.\.%2f',
        r'%252e',
    ]

    @classmethod
    def sanitise_string(cls, value: Any, max_length: int = 1000, allow_html: bool = False) -> str:
        if value is None:
            return ''
        value = str(value).replace('\x00', '').replace('\r\n', '\n')
        value = value[:max_length]
        if not allow_html:
            value = html.escape(value)
        return value.strip()

    @classmethod
    def validate_ip(cls, ip: str) -> bool:
        if not ip:
            return False
        ipv4 = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        ipv6 = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
        return bool(ipv4.match(ip) or ipv6.match(ip))

    @classmethod
    def validate_email(cls, email: str) -> bool:
        pattern = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
        return bool(pattern.match(str(email or '')))

    @classmethod
    def validate_username(cls, username: str) -> tuple:
        if not username:
            return False, "Username is required"
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 50:
            return False, "Username must be at most 50 characters"
        if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
            return False, "Username may only contain letters, numbers, _ and -"
        return True, ""

    @classmethod
    def detect_sql_injection(cls, value: str) -> bool:
        value_upper = str(value).upper()
        for pattern in cls.SQL_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                return True
        return False

    @classmethod
    def detect_xss(cls, value: str) -> bool:
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, str(value), re.IGNORECASE):
                return True
        return False

    @classmethod
    def detect_command_injection(cls, value: str) -> bool:
        for pattern in cls.CMD_PATTERNS:
            if re.search(pattern, str(value), re.IGNORECASE):
                return True
        return False

    @classmethod
    def detect_path_traversal(cls, value: str) -> bool:
        for pattern in cls.PATH_TRAVERSAL:
            if re.search(pattern, str(value), re.IGNORECASE):
                return True
        return False

    @classmethod
    def validate_json_payload(cls, data: dict, required_fields: list = None, max_depth: int = 10) -> tuple:
        if not isinstance(data, dict):
            return False, "Payload must be a JSON object"
        if required_fields:
            missing = [f for f in required_fields if f not in data]
            if missing:
                return False, f"Missing required fields: {', '.join(missing)}"

        def get_depth(obj, current=0):
            if current > max_depth:
                return current
            if isinstance(obj, dict):
                return max((get_depth(v, current + 1) for v in obj.values()), default=current)
            if isinstance(obj, list):
                return max((get_depth(i, current + 1) for i in obj), default=current)
            return current

        if get_depth(data) > max_depth:
            return False, f"JSON nesting too deep (max {max_depth})"
        return True, ""


validator = InputValidator()
