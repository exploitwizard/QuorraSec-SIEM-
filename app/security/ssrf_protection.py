# app/security/ssrf_protection.py — OWASP A10: SSRF Prevention
import re
import socket
import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ALLOWED_DOMAINS = {
    'otx.alienvault.com',
    'www.virustotal.com',
    'api.virustotal.com',
    'api.abuseipdb.com',
    'api.pwnedpasswords.com',
    'slack.com',
    'hooks.slack.com',
    'outlook.office.com',
    'api.pagerduty.com',
    'ip-api.com',
}

_BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('240.0.0.0/4'),
]


def validate_url(url: str, require_https: bool = False) -> tuple:
    if not url:
        return False, "URL is required"
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"
    if require_https and parsed.scheme != 'https':
        return False, "Only HTTPS URLs are allowed"
    if parsed.scheme not in ('http', 'https'):
        return False, f"URL scheme '{parsed.scheme}' not allowed"
    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname"
    if hostname not in ALLOWED_DOMAINS and not any(
        hostname.endswith('.' + d) for d in ALLOWED_DOMAINS
    ):
        logger.warning("SSRF blocked: hostname=%s url=%.100s", hostname, url)
        return False, f"Domain '{hostname}' not in allowlist"
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        for blocked in _BLOCKED_RANGES:
            if ip in blocked:
                logger.warning("SSRF blocked private IP: hostname=%s ip=%s", hostname, ip_str)
                return False, f"URL resolves to private IP {ip_str}"
    except socket.gaierror as e:
        return False, f"Cannot resolve hostname: {e}"
    return True, ""


def safe_request(url: str, method: str = 'GET', timeout: int = 5, **kwargs):
    """Make a validated outbound HTTP request (SSRF-protected)."""
    import requests
    valid, error = validate_url(url)
    if not valid:
        raise ValueError(f"SSRF protection blocked request to {url}: {error}")
    kwargs['timeout'] = min(timeout, 10)
    kwargs['allow_redirects'] = False
    return requests.request(method, url, **kwargs)
