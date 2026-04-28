# app/correlation_engine.py — Courra-Sec multi-event correlation engine
"""
Correlation rules detect patterns that span multiple log events within a
configurable time window, grouped by a field (e.g. ip_address).

Example: brute-force (5 failed login events) followed by a successful login
from the same IP within 5 minutes → account_takeover correlation fires.

Rule conditions (stored as JSON list):
  [
    {"field": "endpoint", "op": "contains", "value": "/login"},
    {"field": "severity", "op": "in",       "value": ["high","critical"]}
  ]

All conditions must match for an event to count toward the rule.

Supported ops: eq, neq, contains, not_contains, in, not_in, regex, gt, lt
"""
import json
import re
import threading
from collections import defaultdict
from datetime import datetime, timedelta

from app.database import db
from app.models import CorrelationRule, Alert


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------

def _eval_condition(event: dict, cond: dict) -> bool:
    field = cond.get('field', '')
    op    = cond.get('op', 'contains')
    value = cond.get('value', '')

    actual = str(event.get(field, '') or '').lower()
    if isinstance(value, list):
        value_list = [str(v).lower() for v in value]
        value_s    = value_list[0] if value_list else ''
    else:
        value_s    = str(value).lower()
        value_list = [value_s]

    if op == 'eq':
        return actual in value_list
    elif op == 'neq':
        return actual not in value_list
    elif op == 'contains':
        return value_s in actual
    elif op == 'not_contains':
        return value_s not in actual
    elif op == 'starts_with':
        return actual.startswith(value_s)
    elif op == 'ends_with':
        return actual.endswith(value_s)
    elif op == 'in':
        return actual in value_list
    elif op == 'not_in':
        return actual not in value_list
    elif op == 'regex':
        try:
            return bool(re.search(value_s, actual))
        except re.error:
            return False
    elif op == 'gt':
        try:
            return float(actual) > float(value_s)
        except (ValueError, TypeError):
            return False
    elif op == 'lt':
        try:
            return float(actual) < float(value_s)
        except (ValueError, TypeError):
            return False
    return False


def matches_conditions(event: dict, conditions: list) -> bool:
    """Return True if event matches ALL conditions in the list."""
    if not conditions:
        return True
    return all(_eval_condition(event, c) for c in conditions)


# ---------------------------------------------------------------------------
# In-memory sliding window per (org_id, rule_id, group_key)
# ---------------------------------------------------------------------------

class _WindowBuffer:
    """Thread-safe sliding window of recent matching events."""

    def __init__(self):
        self._lock    = threading.Lock()
        # key → list of (timestamp, event_dict)
        self._windows: dict = defaultdict(list)

    def add(self, key: tuple, event: dict, window_secs: int) -> list:
        """Add event, prune old entries, return current window events."""
        now = datetime.utcnow()
        with self._lock:
            buf = self._windows[key]
            buf.append((now, event))
            cutoff = now - timedelta(seconds=window_secs)
            self._windows[key] = [(ts, ev) for ts, ev in buf if ts >= cutoff]
            return list(self._windows[key])

    def clear(self, key: tuple):
        with self._lock:
            self._windows.pop(key, None)


_buffer = _WindowBuffer()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:

    def evaluate(self, log_entry, org_id: int) -> list:
        """
        Check a log entry against all enabled correlation rules for this org.
        Returns list of fired rule dicts.
        """
        fired = []
        try:
            rules = CorrelationRule.query.filter_by(
                organisation_id=org_id, enabled=True
            ).all()
        except Exception:
            return fired

        event = {
            'ip_address':  log_entry.ip_address,
            'attack_type': log_entry.attack_type,
            'endpoint':    log_entry.endpoint,
            'severity':    log_entry.severity,
            'user_agent':  log_entry.user_agent,
            'payload':     log_entry.payload,
            'timestamp':   log_entry.timestamp.isoformat() if log_entry.timestamp else None,
        }

        for rule in rules:
            try:
                conditions = json.loads(rule.conditions or '[]')
            except (json.JSONDecodeError, TypeError):
                conditions = []

            if not matches_conditions(event, conditions):
                continue

            group_val = str(event.get(rule.group_by or 'ip_address', 'unknown'))
            key = (org_id, rule.id, group_val)
            window_events = _buffer.add(key, event, rule.time_window or 300)

            if len(window_events) >= (rule.min_events or 2):
                # Fire
                _buffer.clear(key)
                fired.append({
                    'rule_id':      rule.id,
                    'rule_name':    rule.name,
                    'severity':     rule.severity,
                    'mitre_tactic': rule.mitre_tactic,
                    'action':       rule.action,
                    'group_key':    group_val,
                    'event_count':  len(window_events),
                    'time_window':  rule.time_window,
                })

                # Update stats
                try:
                    rule.trigger_count  = (rule.trigger_count or 0) + 1
                    rule.last_triggered = datetime.utcnow()
                    db.session.add(rule)
                except Exception:
                    pass

        return fired

    def create_alert_for_correlation(self, fired: dict, org_id: int) -> Alert | None:
        """Persist an alert for a fired correlation rule."""
        from app.alert_system import AlertSystem
        as_ = AlertSystem()
        return as_.create_alert(
            message=(
                f"[Correlation] {fired['rule_name']} fired — "
                f"{fired['event_count']} events from {fired['group_key']} "
                f"within {fired['time_window']}s"
            ),
            alert_type=f"correlation:{fired['rule_name']}",
            severity=fired['severity'],
            details=fired,
            organisation_id=org_id,
        )


# Singleton
correlation_engine = CorrelationEngine()
