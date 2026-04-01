"""
app/rule_builder.py
Three-level rule evaluation engine for Quorra SIEM.

Level 1 & 2: YAML/JSON rule definitions evaluated by RuleEvaluator
Level 3:     Python DSL executed in a RestrictedPython sandbox
"""
from __future__ import annotations

import re
import json
import math
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Optional

# PyYAML is optional — fall back to JSON-only if not installed
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not installed — Level 2 rules must use JSON format.")

# RestrictedPython is optional — fall back with a warning if absent
try:
    from RestrictedPython import compile_restricted, safe_globals, safe_builtins
    RESTRICTED_PYTHON = True
except ImportError:
    RESTRICTED_PYTHON = False
    print("Warning: RestrictedPython not installed — Level 3 rules run without sandboxing.")


# ---------------------------------------------------------------------------
# Field schema exposed to the UI and condition evaluator
# ---------------------------------------------------------------------------

AVAILABLE_FIELDS = [
    {"id": "ip_address",  "label": "Source IP",        "type": "string"},
    {"id": "attack_type", "label": "Attack / Event Type", "type": "string"},
    {"id": "endpoint",    "label": "URL / Endpoint",   "type": "string"},
    {"id": "payload",     "label": "Request Payload",  "type": "string"},
    {"id": "severity",    "label": "Severity",         "type": "enum",
     "values": ["info", "low", "medium", "high", "critical"]},
    {"id": "user_agent",  "label": "User Agent",       "type": "string"},
]

SIMPLE_OPERATORS = [
    {"id": "equals",        "label": "equals",             "needs_value": True},
    {"id": "not_equals",    "label": "does not equal",     "needs_value": True},
    {"id": "contains",      "label": "contains",           "needs_value": True},
    {"id": "not_contains",  "label": "does not contain",   "needs_value": True},
    {"id": "starts_with",   "label": "starts with",        "needs_value": True},
    {"id": "ends_with",     "label": "ends with",          "needs_value": True},
    {"id": "regex_match",   "label": "matches regex",      "needs_value": True},
    {"id": "in_list",       "label": "is in list",         "needs_value": True},
    {"id": "not_in_list",   "label": "is not in list",     "needs_value": True},
    {"id": "greater_than",  "label": "greater than",       "needs_value": True},
    {"id": "less_than",     "label": "less than",          "needs_value": True},
    {"id": "is_null",       "label": "is empty",           "needs_value": False},
    {"id": "is_not_null",   "label": "is not empty",       "needs_value": False},
]

TEMPORAL_OPERATORS = [
    {"id": "count_within",        "label": "count >= threshold within window",      "needs_value": False},
    {"id": "unique_count_within", "label": "unique values >= threshold within window", "needs_value": False},
    {"id": "rate_within",         "label": "rate (events/sec) >= threshold within window", "needs_value": False},
]

MITRE_TACTICS = [
    "TA0001 - Initial Access",
    "TA0002 - Execution",
    "TA0003 - Persistence",
    "TA0004 - Privilege Escalation",
    "TA0005 - Defense Evasion",
    "TA0006 - Credential Access",
    "TA0007 - Discovery",
    "TA0009 - Collection",
    "TA0011 - Command and Control",
    "TA0040 - Impact",
]

# Field aliases so rules can use "source_ip", "event_type", etc.
_FIELD_ALIASES: dict[str, str] = {
    "source_ip":  "ip_address",
    "event_type": "attack_type",
    "type":       "attack_type",
    "path":       "endpoint",
    "url":        "endpoint",
    "ua":         "user_agent",
}


# ---------------------------------------------------------------------------
# Level 1 & 2 — Rule Evaluator
# ---------------------------------------------------------------------------

class RuleEvaluator:
    """
    Evaluates Level 1/2 YAML/JSON rule definitions against log events.

    Each instance maintains a rolling event history for temporal operators
    (count_within, unique_count_within, rate_within).
    """

    _MAX_HISTORY = 10_000

    def __init__(self) -> None:
        # deque of {"ts": datetime, "event": dict}
        self._history: deque = deque(maxlen=self._MAX_HISTORY)

    # ── public API ──────────────────────────────────────────────────────────

    def add_to_history(self, event_dict: dict) -> None:
        """Call this for every ingest event so temporal operators work."""
        self._history.append({"ts": datetime.utcnow(), "event": event_dict})

    def evaluate(self, rule_def: dict, event_dict: dict) -> bool:
        """
        Evaluate a rule definition dict against an event dict.
        Returns True if the rule triggers.
        """
        conditions = rule_def.get("conditions", [])
        logic      = str(rule_def.get("logic", "AND")).upper()
        if not conditions:
            return False

        results = [self._eval_condition(c, event_dict) for c in conditions]
        return all(results) if logic == "AND" else any(results)

    def parse_yaml(self, text: str) -> tuple[Optional[dict], Optional[str]]:
        """Parse YAML or JSON rule text. Returns (rule_def, error)."""
        try:
            if YAML_AVAILABLE:
                rule = yaml.safe_load(text)
            else:
                rule = json.loads(text)
            if not isinstance(rule, dict):
                return None, "Rule must be a YAML/JSON object"
            return rule, None
        except Exception as e:
            return None, str(e)

    def validate(self, rule_def: dict) -> tuple[bool, Optional[str]]:
        """Validate a parsed rule definition. Returns (valid, error)."""
        if not rule_def.get("rule_name") and not rule_def.get("name"):
            return False, "Missing rule_name"
        if not isinstance(rule_def.get("conditions"), list) or len(rule_def["conditions"]) == 0:
            return False, "Must have at least one condition"
        for i, cond in enumerate(rule_def["conditions"]):
            ok, err = self._validate_condition(cond, i)
            if not ok:
                return False, err
        valid_logics = {"AND", "OR"}
        logic = str(rule_def.get("logic", "AND")).upper()
        if logic not in valid_logics:
            return False, f"logic must be AND or OR, got: {logic}"
        return True, None

    # ── condition evaluation ─────────────────────────────────────────────────

    def _eval_condition(self, cond: dict, event_dict: dict) -> bool:
        operator = cond.get("operator", "equals")
        if operator in ("count_within", "unique_count_within", "rate_within"):
            return self._eval_temporal(cond, event_dict)
        field = _FIELD_ALIASES.get(cond.get("field", ""), cond.get("field", ""))
        field_val = self._get_field(event_dict, field)
        try:
            return self._apply_operator(operator, field_val, cond)
        except Exception:
            return False

    def _apply_operator(self, op: str, field_val: Any, cond: dict) -> bool:
        val = str(cond.get("value", ""))
        fv  = str(field_val) if field_val is not None else ""
        fvl, vl = fv.lower(), val.lower()

        if op == "equals":        return fvl == vl
        if op == "not_equals":    return fvl != vl
        if op == "contains":      return vl in fvl
        if op == "not_contains":  return vl not in fvl
        if op == "starts_with":   return fvl.startswith(vl)
        if op == "ends_with":     return fvl.endswith(vl)
        if op == "regex_match":   return bool(re.search(val, fv, re.IGNORECASE))
        if op == "in_list":
            items = [v.strip().lower() for v in val.split(",")]
            return fvl in items
        if op == "not_in_list":
            items = [v.strip().lower() for v in val.split(",")]
            return fvl not in items
        if op == "greater_than":
            return float(field_val or 0) > float(val or 0)
        if op == "less_than":
            return float(field_val or 0) < float(val or 0)
        if op == "is_null":     return field_val is None or fv == ""
        if op == "is_not_null": return field_val is not None and fv != ""
        return False

    def _eval_temporal(self, cond: dict, event_dict: dict) -> bool:
        field          = _FIELD_ALIASES.get(cond.get("field", "ip_address"), cond.get("field", "ip_address"))
        group_by_raw   = cond.get("group_by", "ip_address")
        group_by       = _FIELD_ALIASES.get(group_by_raw, group_by_raw)
        operator       = cond.get("operator", "count_within")
        threshold      = int(cond.get("threshold", 5))
        window_seconds = int(cond.get("window_seconds", 60))

        # Current event's group key
        current_group = self._get_field(event_dict, group_by)
        if not current_group:
            return False

        cutoff   = datetime.utcnow() - timedelta(seconds=window_seconds)
        relevant = [
            e["event"] for e in self._history
            if e["ts"] > cutoff
            and self._get_field(e["event"], group_by) == current_group
        ]

        if operator == "count_within":
            return (len(relevant) + 1) >= threshold   # +1 for current event

        if operator == "unique_count_within":
            vals = {self._get_field(e, field) for e in relevant}
            vals.add(self._get_field(event_dict, field))
            return len(vals) >= threshold

        if operator == "rate_within":
            rate = (len(relevant) + 1) / max(window_seconds, 1)
            return rate >= float(threshold)

        return False

    def _get_field(self, event_dict: dict, field: str) -> Any:
        """Get a field value, supporting dot-notation paths."""
        field = _FIELD_ALIASES.get(field, field)
        val: Any = event_dict
        for part in field.split("."):
            if isinstance(val, dict):
                val = val.get(part)
            else:
                return None
        return val

    def _validate_condition(self, cond: dict, idx: int) -> tuple[bool, Optional[str]]:
        if not cond.get("field"):
            return False, f"Condition {idx+1}: missing 'field'"
        if not cond.get("operator"):
            return False, f"Condition {idx+1}: missing 'operator'"
        op = cond["operator"]
        temporal = {"count_within", "unique_count_within", "rate_within"}
        if op in temporal:
            if not cond.get("threshold"):
                return False, f"Condition {idx+1}: temporal operators need 'threshold'"
            if not cond.get("window_seconds"):
                return False, f"Condition {idx+1}: temporal operators need 'window_seconds'"
        return True, None


# ---------------------------------------------------------------------------
# Level 3 — Python DSL sandbox
# ---------------------------------------------------------------------------

_DSL_SAFE_BUILTINS = {
    "None": None, "True": True, "False": False,
    "abs": abs, "all": all, "any": any, "bool": bool,
    "dict": dict, "divmod": divmod, "enumerate": enumerate,
    "filter": filter, "float": float, "frozenset": frozenset,
    "hasattr": hasattr, "hash": hash, "int": int,
    "isinstance": isinstance, "issubclass": issubclass,
    "iter": iter, "len": len, "list": list, "map": map,
    "max": max, "min": min, "next": next,
    "pow": pow, "range": range, "repr": repr, "reversed": reversed,
    "round": round, "set": set, "slice": slice, "sorted": sorted,
    "str": str, "sum": sum, "tuple": tuple, "type": type, "zip": zip,
    # safe stdlib subsets
    "re":   __import__("re"),
    "json": __import__("json"),
    "math": __import__("math"),
}

_DSL_TEMPLATE = '''\
def rule(event):
    """
    Evaluate a single log event.

    Available fields in `event`:
      ip_address   - source IP address
      attack_type  - event / attack type label
      endpoint     - URL path
      payload      - request payload (string)
      severity     - "info" | "low" | "medium" | "high" | "critical"
      user_agent   - User-Agent header

    Return True to trigger an alert, False to ignore.

    Examples:
      event.get("attack_type") == "SQL Injection Attempt"
      "union" in (event.get("payload") or "").lower()
      event.get("severity") in ("high", "critical")
    """
    attack = (event.get("attack_type") or "").lower()
    payload = (event.get("payload") or "").lower()

    # Example: flag SQL injection with UNION keyword
    if "sql" in attack and "union" in payload:
        return True

    return False
'''


class PythonDSLRunner:
    """
    Executes Level 3 Python DSL rules.

    When RestrictedPython is installed rules are sandboxed; otherwise they
    run in a restricted namespace (no __builtins__ access) with a logged warning.
    """

    template = _DSL_TEMPLATE

    def execute(self, code: str, event_dict: dict) -> tuple[bool, Optional[str]]:
        """
        Run the rule function against one event.
        Returns (triggered: bool, error: Optional[str]).
        """
        if RESTRICTED_PYTHON:
            return self._exec_restricted(code, event_dict)
        return self._exec_basic(code, event_dict)

    def validate(self, code: str) -> tuple[bool, Optional[str]]:
        """Validate code without executing. Returns (valid, error)."""
        if "def rule(" not in code and "def rule (" not in code:
            return False, "Must define a function named 'rule(event)'"
        if RESTRICTED_PYTHON:
            try:
                compiled = compile_restricted(code, "<rule>", "exec")
                if compiled is None:
                    return False, "Compilation failed — disallowed operations detected"
            except SyntaxError as e:
                return False, f"Syntax error: {e}"
            except Exception as e:
                return False, str(e)
        else:
            try:
                compile(code, "<rule>", "exec")
            except SyntaxError as e:
                return False, f"Syntax error: {e}"
        return True, None

    def _exec_restricted(self, code: str, event_dict: dict) -> tuple[bool, Optional[str]]:
        try:
            compiled = compile_restricted(code, "<rule>", "exec")
            if compiled is None:
                return False, "Compilation failed"
            g = dict(safe_globals)
            g["__builtins__"] = dict(safe_builtins)
            g["__builtins__"].update(_DSL_SAFE_BUILTINS)
            g["_getiter_"]  = iter
            g["_getattr_"]  = getattr
            g["_write_"]    = lambda x: x
            exec(compiled, g)  # noqa: S102
            return self._call_rule(g, event_dict)
        except SyntaxError as e:
            return False, f"Syntax error: {e}"
        except Exception as e:
            return False, f"Runtime error: {e}"

    def _exec_basic(self, code: str, event_dict: dict) -> tuple[bool, Optional[str]]:
        """Fallback when RestrictedPython is unavailable."""
        try:
            g: dict = {"__builtins__": _DSL_SAFE_BUILTINS}
            exec(compile(code, "<rule>", "exec"), g)  # noqa: S102
            return self._call_rule(g, event_dict)
        except SyntaxError as e:
            return False, f"Syntax error: {e}"
        except Exception as e:
            return False, f"Runtime error: {e}"

    @staticmethod
    def _call_rule(g: dict, event_dict: dict) -> tuple[bool, Optional[str]]:
        fn = g.get("rule")
        if not callable(fn):
            return False, "Must define a function named 'rule(event)'"
        result = fn(dict(event_dict))   # pass a copy so rules can't mutate state
        return bool(result), None


# Module-level singletons used by rules_engine.py
evaluator = RuleEvaluator()
dsl_runner = PythonDSLRunner()
