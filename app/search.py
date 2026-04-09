# app/search.py — Courra-Sec log search engine with KQL-like query syntax
"""
Supports queries like:
  ip:1.2.3.4
  severity:high
  endpoint:/admin
  attack:sql
  after:2026-01-01
  before:2026-04-01
  ua:python
  payload:union
  1.2.3.4              (bare value → full-text match across all text fields)

Multiple terms are ANDed. Quoted phrases: endpoint:"/api/login"
"""
import re
from datetime import datetime, timedelta
from app.database import db
from app.models import LogEntry, Alert, Attack


# ---------------------------------------------------------------------------
# Query parser
# ---------------------------------------------------------------------------

_FIELD_ALIASES = {
    'ip':        'ip_address',
    'src':       'ip_address',
    'source':    'ip_address',
    'sev':       'severity',
    'type':      'attack_type',
    'attack':    'attack_type',
    'url':       'endpoint',
    'path':      'endpoint',
    'ua':        'user_agent',
    'agent':     'user_agent',
    'payload':   'payload',
    'data':      'payload',
    'raw':       'raw_data',
}

_SORTABLE = {
    'timestamp', 'severity', 'ip_address', 'attack_type', 'endpoint',
}

_TOKEN_RE = re.compile(
    r'(?P<field>[a-zA-Z_]+):(?P<quoted>"[^"]*"|\'[^\']*\'|[^\s]+)'
    r'|(?P<freetext>"[^"]*"|\'[^\']*\'|\S+)'
)


def parse_query(q: str) -> dict:
    """
    Returns a dict with keys:
        filters  — list of (field, value) for known fields
        freetext — list of bare text terms
        after    — datetime or None
        before   — datetime or None
    """
    filters  = []
    freetext = []
    after    = None
    before   = None

    for m in _TOKEN_RE.finditer(q or ''):
        if m.group('field'):
            field = m.group('field').lower()
            value = m.group('quoted').strip('"\'')

            if field in ('after', 'since'):
                after = _parse_date(value)
            elif field in ('before', 'until'):
                before = _parse_date(value)
            elif field in ('last',):
                after = _parse_relative(value)
            else:
                canonical = _FIELD_ALIASES.get(field, field)
                filters.append((canonical, value))
        else:
            freetext.append(m.group('freetext').strip('"\''))

    return {'filters': filters, 'freetext': freetext, 'after': after, 'before': before}


def _parse_date(s: str):
    for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y/%m/%d'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _parse_relative(s: str):
    """Parse '24h', '7d', '30m' relative time expressions."""
    m = re.match(r'^(\d+)(m|h|d|w)$', s.lower())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    delta = {'m': timedelta(minutes=n), 'h': timedelta(hours=n),
             'd': timedelta(days=n),    'w': timedelta(weeks=n)}[unit]
    return datetime.utcnow() - delta


# ---------------------------------------------------------------------------
# Log search
# ---------------------------------------------------------------------------

def search_logs(org_id: int, q: str, page: int = 1, per_page: int = 50,
                sort: str = 'timestamp', order: str = 'desc'):
    parsed = parse_query(q)
    query  = LogEntry.query.filter_by(organisation_id=org_id)

    # Field filters
    for field, value in parsed['filters']:
        col = getattr(LogEntry, field, None)
        if col is not None:
            query = query.filter(col.ilike(f'%{value}%'))

    # Date range
    if parsed['after']:
        query = query.filter(LogEntry.timestamp >= parsed['after'])
    if parsed['before']:
        query = query.filter(LogEntry.timestamp <= parsed['before'])

    # Full-text: match any of the freetext terms across all text fields
    for term in parsed['freetext']:
        like = f'%{term}%'
        query = query.filter(
            db.or_(
                LogEntry.ip_address.ilike(like),
                LogEntry.attack_type.ilike(like),
                LogEntry.endpoint.ilike(like),
                LogEntry.payload.ilike(like),
                LogEntry.user_agent.ilike(like),
                LogEntry.raw_data.ilike(like),
            )
        )

    # Sort
    sort_col = getattr(LogEntry, sort if sort in _SORTABLE else 'timestamp')
    query = query.order_by(sort_col.desc() if order == 'desc' else sort_col.asc())

    pag = query.paginate(page=page, per_page=per_page, error_out=False)
    return pag


# ---------------------------------------------------------------------------
# Alert search
# ---------------------------------------------------------------------------

def search_alerts(org_id: int, q: str, page: int = 1, per_page: int = 50):
    parsed = parse_query(q)
    query  = Alert.query.filter_by(organisation_id=org_id)

    for field, value in parsed['filters']:
        if field == 'severity':
            query = query.filter(Alert.severity.ilike(f'%{value}%'))
        elif field in ('type', 'alert_type'):
            query = query.filter(Alert.alert_type.ilike(f'%{value}%'))
        elif field == 'acknowledged':
            ack = value.lower() in ('true', '1', 'yes')
            query = query.filter(Alert.acknowledged == ack)

    if parsed['after']:
        query = query.filter(Alert.created_at >= parsed['after'])
    if parsed['before']:
        query = query.filter(Alert.created_at <= parsed['before'])

    for term in parsed['freetext']:
        like = f'%{term}%'
        query = query.filter(
            db.or_(
                Alert.message.ilike(like),
                Alert.alert_type.ilike(like),
                Alert.details.ilike(like),
            )
        )

    pag = query.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return pag


# ---------------------------------------------------------------------------
# Unified search across logs + alerts + attacks
# ---------------------------------------------------------------------------

def unified_search(org_id: int, q: str, limit: int = 20) -> list:
    """Quick cross-entity search — returns list of result dicts with a _type field."""
    results = []

    # Logs
    log_pag = search_logs(org_id, q, page=1, per_page=limit)
    for l in log_pag.items:
        d = l.to_dict()
        d['_type'] = 'log'
        results.append(d)

    # Alerts
    alert_pag = search_alerts(org_id, q, page=1, per_page=limit)
    for a in alert_pag.items:
        d = a.to_dict()
        d['_type'] = 'alert'
        results.append(d)

    # Sort by timestamp desc
    def _ts(r):
        ts = r.get('timestamp') or r.get('created_at') or ''
        return ts

    results.sort(key=_ts, reverse=True)
    return results[:limit]
