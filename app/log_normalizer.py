# app/log_normalizer.py — Courra-Sec log normalization and field extraction
"""
Normalizes raw log payloads into structured fields before storing.

Features:
  - Grok-style named regex patterns for common log formats
  - JSON payload auto-extraction
  - Log deduplication via content hash
  - Log source tagging (web, syslog, firewall, auth, etc.)
  - Severity normalization
"""
import hashlib
import json
import re
from datetime import datetime


# ---------------------------------------------------------------------------
# Severity normalization map
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    # numeric syslog levels → normalized
    '0': 'critical', '1': 'critical', '2': 'critical',
    '3': 'high',
    '4': 'medium',   '5': 'medium',
    '6': 'low',      '7': 'low',
    # text variants
    'emerg': 'critical', 'alert': 'critical', 'crit': 'critical', 'panic': 'critical',
    'err': 'high',    'error': 'high',
    'warn': 'medium', 'warning': 'medium', 'notice': 'medium',
    'info': 'low',    'debug': 'low', 'trace': 'low',
    # pass-through normalized names
    'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
}

VALID_SEVERITIES = {'critical', 'high', 'medium', 'low'}


def normalize_severity(raw: str) -> str:
    if not raw:
        return 'low'
    return _SEVERITY_MAP.get(str(raw).strip().lower(), 'low')


# ---------------------------------------------------------------------------
# Grok-style pattern library
# ---------------------------------------------------------------------------

_PATTERNS = {
    'COMBINEDLOG': (
        r'(?P<ip_address>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+\S+"\s+(?P<status>\d+)\s+\S+'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    ),
    'COMMONLOG': (
        r'(?P<ip_address>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+\S+"\s+(?P<status>\d+)\s+\S+'
    ),
    'SYSLOG': (
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+'
        r'(?P<program>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)'
    ),
    'AUTH_LOG': (
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(?:sshd|su|sudo|pam)'
        r'[^:]*:\s+(?P<message>.+?)'
        r'(?:from\s+(?P<ip_address>\d{1,3}(?:\.\d{1,3}){3}))?'
    ),
    'FIREWALL_IPTABLES': (
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?'
        r'SRC=(?P<ip_address>\S+)\s+DST=(?P<dst_ip>\S+).*?'
        r'PROTO=(?P<protocol>\S+)\s+SPT=(?P<src_port>\d+)\s+DPT=(?P<endpoint>\d+)'
    ),
    'JSON': r'^\s*\{.*\}\s*$',
    'CEF': (
        r'CEF:(?P<cef_version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|'
        r'(?P<version>[^|]*)\|(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|'
        r'(?P<extensions>.*)'
    ),
    'LEEF': r'LEEF:(?P<leef_version>[^|]*)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|',
}

_COMPILED = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in _PATTERNS.items()}


# ---------------------------------------------------------------------------
# Source tagger
# ---------------------------------------------------------------------------

_SOURCE_PATTERNS = [
    ('web',      re.compile(r'(nginx|apache|httpd|iis|express|django|flask|rails)', re.I)),
    ('auth',     re.compile(r'(sshd|login|pam_unix|su|sudo|krb|kerberos|ldap)', re.I)),
    ('firewall', re.compile(r'(iptables|pf|ufw|nftables|checkpoint|palo.alto|cisco.asa)', re.I)),
    ('endpoint', re.compile(r'(windows|eventlog|sysmon|defender|crowdstrike|carbon.black)', re.I)),
    ('database', re.compile(r'(mysql|postgres|oracle|mssql|mongodb|redis)', re.I)),
    ('cloud',    re.compile(r'(aws|gcp|azure|cloudtrail|stackdriver|activity.log)', re.I)),
    ('mail',     re.compile(r'(postfix|sendmail|exim|exchange|smtp|imap)', re.I)),
    ('dns',      re.compile(r'(bind|named|unbound|dnsmasq|dns)', re.I)),
]


def detect_source(raw: str) -> str:
    if not raw:
        return 'unknown'
    for tag, pattern in _SOURCE_PATTERNS:
        if pattern.search(raw):
            return tag
    return 'generic'


# ---------------------------------------------------------------------------
# CEF extension parser
# ---------------------------------------------------------------------------

def _parse_cef_extensions(ext_str: str) -> dict:
    result = {}
    for token in re.finditer(r'(\w+)=((?:[^\\= ]+|\\.)*)', ext_str):
        result[token.group(1)] = token.group(2).replace('\\=', '=').replace('\\n', '\n')
    return result


# ---------------------------------------------------------------------------
# JSON log extractor
# ---------------------------------------------------------------------------

def _extract_json(raw: str) -> dict:
    """Try to parse raw as JSON and extract known fields."""
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}

        field_map = {
            'ip_address': ['ip', 'ip_address', 'src_ip', 'source_ip', 'clientip',
                           'remote_addr', 'ipAddress', 'client_ip'],
            'endpoint':   ['url', 'endpoint', 'path', 'request', 'uri', 'requestUri'],
            'user_agent': ['user_agent', 'userAgent', 'ua', 'http_user_agent'],
            'attack_type':['type', 'attack_type', 'event_type', 'category', 'eventType'],
            'severity':   ['severity', 'level', 'priority', 'sev'],
            'payload':    ['payload', 'body', 'data', 'message', 'msg'],
        }

        extracted = {}
        for target, sources in field_map.items():
            for src in sources:
                val = data.get(src)
                if val is not None:
                    extracted[target] = str(val)
                    break

        return extracted
    except (json.JSONDecodeError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# Main normalization entry point
# ---------------------------------------------------------------------------

def normalize(raw: str, source_hint: str = None) -> dict:
    """
    Takes a raw log string. Returns a normalized dict with these keys:
      ip_address, attack_type, endpoint, user_agent, severity, payload,
      raw_data, source_tag, log_format, extracted_fields (dict)
    """
    result = {
        'ip_address':       'unknown',
        'attack_type':      None,
        'endpoint':         None,
        'user_agent':       None,
        'severity':         'low',
        'payload':          raw[:2000] if raw else None,
        'raw_data':         raw[:5000] if raw else None,
        'source_tag':       source_hint or detect_source(raw or ''),
        'log_format':       'raw',
        'extracted_fields': {},
    }

    if not raw:
        return result

    raw = raw.strip()

    # 1. Try JSON
    if raw.startswith('{') or raw.startswith('['):
        extracted = _extract_json(raw)
        if extracted:
            result['log_format'] = 'json'
            _merge(result, extracted)
            result['extracted_fields'] = extracted
            result['severity'] = normalize_severity(result.get('severity', 'low'))
            return result

    # 2. CEF
    m = _COMPILED['CEF'].match(raw)
    if m:
        result['log_format'] = 'cef'
        exts = _parse_cef_extensions(m.group('extensions'))
        result['ip_address']  = exts.get('src', result['ip_address'])
        result['endpoint']    = exts.get('request', result['endpoint'])
        result['user_agent']  = exts.get('requestClientApplication', result['user_agent'])
        result['attack_type'] = m.group('name')
        result['severity']    = normalize_severity(m.group('severity'))
        result['extracted_fields'] = {**m.groupdict(), **exts}
        return result

    # 3. Combined / Common log
    for fmt in ('COMBINEDLOG', 'COMMONLOG'):
        m = _COMPILED[fmt].match(raw)
        if m:
            gd = m.groupdict()
            result['log_format']  = fmt.lower()
            result['ip_address']  = gd.get('ip_address', result['ip_address'])
            result['endpoint']    = gd.get('endpoint', result['endpoint'])
            result['user_agent']  = gd.get('user_agent', result['user_agent'])
            result['attack_type'] = _classify_http_status(gd.get('status', ''))
            result['extracted_fields'] = gd
            return result

    # 4. Auth log
    m = _COMPILED['AUTH_LOG'].match(raw)
    if m:
        gd = m.groupdict()
        result['log_format'] = 'auth_log'
        result['ip_address'] = gd.get('ip_address') or result['ip_address']
        result['payload']    = gd.get('message', raw[:500])
        result['attack_type'] = _classify_auth_message(gd.get('message', ''))
        if result['attack_type']:
            result['severity'] = 'high'
        result['extracted_fields'] = gd
        return result

    # 5. Syslog
    m = _COMPILED['SYSLOG'].match(raw)
    if m:
        gd = m.groupdict()
        result['log_format'] = 'syslog'
        result['payload']    = gd.get('message', raw[:500])
        result['extracted_fields'] = gd
        return result

    return result


def _merge(target: dict, extracted: dict):
    for k, v in extracted.items():
        if k in target and v:
            target[k] = v


def _classify_http_status(status: str) -> str:
    try:
        code = int(status)
        if code == 401: return 'Unauthorized Access Attempt'
        if code == 403: return 'Forbidden Access'
        if code == 404: return 'Not Found'
        if code == 429: return 'Rate Limit Exceeded'
        if code >= 500: return 'Server Error'
        if code >= 400: return 'Client Error'
    except (ValueError, TypeError):
        pass
    return None


def _classify_auth_message(msg: str) -> str:
    msg = (msg or '').lower()
    if 'failed password' in msg or 'authentication failure' in msg:
        return 'Brute Force Attempt'
    if 'accepted password' in msg or 'accepted publickey' in msg:
        return 'Successful Authentication'
    if 'invalid user' in msg:
        return 'Invalid User Attempt'
    if 'connection closed' in msg:
        return 'Connection Closed'
    return None


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

_DEDUP_CACHE: dict = {}
_DEDUP_MAX   = 10000


def compute_dedup_hash(ip: str, attack_type: str, endpoint: str, payload: str,
                       org_id: int = 0) -> str:
    """SHA-256 of (org_id + ip + attack_type + endpoint + first_500_chars_of_payload).
    org_id is scoped so identical events from different tenants are never cross-deduplicated."""
    key = '|'.join([
        str(org_id),
        (ip or ''),
        (attack_type or ''),
        (endpoint or ''),
        (payload or '')[:500],
    ])
    return hashlib.sha256(key.encode()).hexdigest()


def is_duplicate(dedup_hash: str, window_secs: int = 60) -> bool:
    """
    Returns True if this exact event was already seen within window_secs.
    Uses an in-memory LRU-style cache.
    """
    now = datetime.utcnow().timestamp()
    if dedup_hash in _DEDUP_CACHE:
        ts = _DEDUP_CACHE[dedup_hash]
        if now - ts < window_secs:
            return True
    # Prune if over limit
    if len(_DEDUP_CACHE) >= _DEDUP_MAX:
        oldest = sorted(_DEDUP_CACHE.items(), key=lambda x: x[1])
        for k, _ in oldest[:_DEDUP_MAX // 4]:
            del _DEDUP_CACHE[k]
    _DEDUP_CACHE[dedup_hash] = now
    return False
