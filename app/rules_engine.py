from datetime import datetime, timedelta
import json
import logging
from app.database import db
from app.models import LogEntry, IPBlocklist, Attack
from app.config import Config
import geoip2.database
import geoip2.errors
from math import radians, sin, cos, sqrt, atan2

logger = logging.getLogger(__name__)


class RulesEngine:
    """Rules engine for detecting attacks."""

    _geoip_warning_printed = False

    def __init__(self):
        self.brute_force_cache = {}
        self.user_login_cache  = {}

        try:
            self.geoip_reader = geoip2.database.Reader(Config.GEOIP_DB_PATH)
        except Exception:
            self.geoip_reader = None
            if not RulesEngine._geoip_warning_printed:
                RulesEngine._geoip_warning_printed = True
                print("Warning: GeoIP database not found -- geo-velocity rule disabled.")

    # ------------------------------------------------------------------
    # Master check
    # ------------------------------------------------------------------

    def check_rules(self, log_entry):
        results = {
            "triggered": False,
            "rule":      None,
            "details":   {},
            "severity":  "low",
            "block_ip":  False,
        }

        # Already blocked? (scope to org if available)
        org_id = getattr(log_entry, 'organisation_id', None)
        bl_query = {'ip_address': log_entry.ip_address}
        if org_id is not None:
            bl_query['organisation_id'] = org_id
        is_blocked = IPBlocklist.query.filter_by(**bl_query).first()
        if is_blocked:
            return {
                "triggered": True,
                "rule":      "blocked_ip_detected",
                "details": {
                    "ip":         log_entry.ip_address,
                    "reason":     is_blocked.reason,
                    "blocked_at": is_blocked.blocked_at.isoformat(),
                },
                "severity":  "critical",
                "block_ip":  False,
            }

        # Rule 1 — brute force
        r = self.check_brute_force(log_entry)
        if r["triggered"]:
            results.update(r)
            results["block_ip"] = True

        # Rule 2 — geo-velocity
        r = self.check_geo_velocity(log_entry)
        if r["triggered"] and not results["triggered"]:
            results.update(r)

        # Rule 3 — admin privilege
        r = self.check_admin_privileges(log_entry)
        if r["triggered"] and not results["triggered"]:
            results.update(r)

        # Rule 4 — OS command injection
        r = self.check_os_command_injection(log_entry)
        if r["triggered"] and not results["triggered"]:
            results.update(r)
            results["block_ip"] = True

        # Rule 5 — multiple attack types
        r = self.check_multiple_attack_types(log_entry)
        if r["triggered"] and not results["triggered"]:
            results.update(r)
            results["block_ip"] = True

        # Custom rules are evaluated separately by evaluate_all_custom_rules()
        # called unconditionally from _process_ingest after this method returns.
        # This ensures all active custom rules run regardless of whether a
        # built-in rule already fired.

        return results

    # ------------------------------------------------------------------
    # Individual rules
    # ------------------------------------------------------------------

    def check_brute_force(self, log_entry):
        endpoint = (log_entry.endpoint or "").lower()
        if "login" in endpoint and log_entry.severity in ("low", "medium"):
            ip = log_entry.ip_address
            self.brute_force_cache.setdefault(ip, [])
            self.brute_force_cache[ip].append(datetime.utcnow())

            cutoff = datetime.utcnow() - timedelta(minutes=2)
            self.brute_force_cache[ip] = [
                t for t in self.brute_force_cache[ip] if t > cutoff
            ]

            if len(self.brute_force_cache[ip]) >= Config.BRUTEFORCE_THRESHOLD:
                return {
                    "triggered": True,
                    "rule":      "bruteforce",
                    "details": {
                        "ip":              ip,
                        "failed_attempts": len(self.brute_force_cache[ip]),
                        "time_window":     "2 minutes",
                        "endpoint":        log_entry.endpoint,
                    },
                    "severity": "high",
                }
        return {"triggered": False}

    def check_geo_velocity(self, log_entry):
        if not self.geoip_reader:
            return {"triggered": False}

        ip = log_entry.ip_address
        if not ip or ip == "unknown":
            return {"triggered": False}

        try:
            resp = self.geoip_reader.city(ip)
            current = {
                "country": resp.country.name,
                "city":    resp.city.name,
                "lat":     resp.location.latitude,
                "lon":     resp.location.longitude,
            }

            username = None
            try:
                payload  = json.loads(log_entry.payload) if log_entry.payload else {}
                username = payload.get("username") or payload.get("user")
            except Exception:
                pass

            if username and username in self.user_login_cache:
                prev      = self.user_login_cache[username]
                time_diff = (datetime.utcnow() - prev["timestamp"]).total_seconds() / 3600
                distance  = self.calculate_distance(
                    prev["location"]["lat"], prev["location"]["lon"],
                    current["lat"], current["lon"],
                )
                required_speed = distance / time_diff if time_diff > 0 else float("inf")

                if required_speed > 1000 and distance > 300:
                    return {
                        "triggered": True,
                        "rule":      "geo_velocity",
                        "details": {
                            "username":     username,
                            "ip":           ip,
                            "from_country": prev["location"]["country"],
                            "from_city":    prev["location"]["city"],
                            "to_country":   current["country"],
                            "to_city":      current["city"],
                            "distance_km":  round(distance, 2),
                            "time_hours":   round(time_diff, 2),
                            "speed_kmh":    round(required_speed, 2),
                        },
                        "severity": "medium",
                    }

            if username:
                self.user_login_cache[username] = {
                    "timestamp": datetime.utcnow(),
                    "location":  current,
                    "ip":        ip,
                }

        except (geoip2.errors.AddressNotFoundError, AttributeError):
            pass

        return {"triggered": False}

    def check_admin_privileges(self, log_entry):
        # /dashboard removed — too generic and produces false positives on legitimate dashboards
        admin_paths    = ["/admin", "/manage", "/control", "admin"]
        admin_keywords = ["admin", "sudo", "root", "privilege", "elevate", "superuser"]

        endpoint_lower = (log_entry.endpoint or "").lower()
        for path in admin_paths:
            if path in endpoint_lower:
                return {
                    "triggered": True,
                    "rule":      "admin_privilege_attempt",
                    "details": {
                        "ip":              log_entry.ip_address,
                        "endpoint":        log_entry.endpoint,
                        "matched_pattern": path,
                        "reason":          "Admin path accessed",
                    },
                    "severity": "high",
                }

        if log_entry.payload:
            pl = log_entry.payload.lower()
            for kw in admin_keywords:
                if kw in pl:
                    return {
                        "triggered": True,
                        "rule":      "admin_privilege_attempt",
                        "details": {
                            "ip":              log_entry.ip_address,
                            "endpoint":        log_entry.endpoint,
                            "matched_keyword": kw,
                            "reason":          "Admin keyword in payload",
                        },
                        "severity": "high",
                    }

        if "admin" in (log_entry.attack_type or "").lower():
            return {
                "triggered": True,
                "rule":      "admin_privilege_attempt",
                "details": {
                    "ip":          log_entry.ip_address,
                    "attack_type": log_entry.attack_type,
                    "reason":      "Admin-related attack type",
                },
                "severity": "high",
            }

        return {"triggered": False}

    def check_os_command_injection(self, log_entry):
        patterns = [
            ";", "|", "||", "&", "&&", "`", "$(",
            "rm ", "del ", "format ", "shutdown",
            "cat /etc/passwd", "/bin/bash",
            "wget", "curl", "nc ", "netcat",
            "python ", "perl ", "ruby ", "php ",
            "system(", "exec(", "popen(",
            "ls ", "dir ", "cd ", "pwd",
        ]

        if log_entry.payload:
            pl = log_entry.payload.lower()
            for pat in patterns:
                if pat in pl:
                    return {
                        "triggered": True,
                        "rule":      "os_command_injection",
                        "details": {
                            "ip":              log_entry.ip_address,
                            "pattern":         pat,
                            "payload_preview": log_entry.payload[:200],
                            "endpoint":        log_entry.endpoint,
                        },
                        "severity": "critical",
                    }

        at = (log_entry.attack_type or "").lower()
        if "command" in at or "injection" in at:
            return {
                "triggered": True,
                "rule":      "os_command_injection",
                "details": {
                    "ip":          log_entry.ip_address,
                    "attack_type": log_entry.attack_type,
                    "reason":      "Command injection attack type",
                },
                "severity": "critical",
            }

        return {"triggered": False}

    def check_multiple_attack_types(self, log_entry):
        ip     = log_entry.ip_address
        org_id = getattr(log_entry, 'organisation_id', None)
        threshold = datetime.utcnow() - timedelta(minutes=5)

        q = Attack.query.filter(
            Attack.ip_address == ip,
            Attack.detected_at >= threshold,
        )
        if org_id is not None:
            q = q.filter(Attack.organisation_id == org_id)
        recent = q.all()

        attack_types = {a.attack_type for a in recent}
        attack_types.add(log_entry.attack_type)

        if len(attack_types) >= 3:
            return {
                "triggered": True,
                "rule":      "multiple_attack_types",
                "details": {
                    "ip":           ip,
                    "attack_types": list(attack_types),
                    "time_window":  "5 minutes",
                    "total":        len(recent) + 1,
                },
                "severity": "high",
            }
        return {"triggered": False}

    def evaluate_custom_rules(self, log_entry):
        """Run all enabled custom rules (Levels 1, 2, 3) against the log entry."""
        try:
            from app.models import CustomRule
            from app.rule_builder import evaluator, dsl_runner
            import json as _json

            event_dict = {
                "ip_address":  log_entry.ip_address,
                "attack_type": log_entry.attack_type,
                "endpoint":    log_entry.endpoint,
                "payload":     log_entry.payload,
                "severity":    log_entry.severity,
                "user_agent":  log_entry.user_agent,
                "timestamp":   log_entry.timestamp.isoformat() if log_entry.timestamp else None,
            }

            # Add to temporal history for count_within etc.
            evaluator.add_to_history(event_dict)

            org_id = getattr(log_entry, 'organisation_id', None)
            if org_id is not None:
                rules = CustomRule.query.filter_by(enabled=True, organisation_id=org_id).all()
            else:
                rules = CustomRule.query.filter_by(enabled=True).all()
            for rule in rules:
                triggered = False
                error     = None

                if rule.level in (1, 2):
                    if rule.rule_definition:
                        try:
                            rule_def = _json.loads(rule.rule_definition)
                            triggered = evaluator.evaluate(rule_def, event_dict)
                        except Exception as e:
                            error = str(e)
                elif rule.level == 3:
                    if rule.rule_python:
                        triggered, error = dsl_runner.execute(rule.rule_python, event_dict)

                if error:
                    print(f"[RulesEngine] custom rule {rule.id} ({rule.name}) error: {error}")

                if triggered:
                    # Update stats
                    rule.trigger_count = (rule.trigger_count or 0) + 1
                    rule.last_triggered = datetime.utcnow()
                    from app.database import db
                    db.session.add(rule)
                    # Don't commit here — caller handles the transaction

                    return {
                        "triggered": True,
                        "rule":      f"custom:{rule.id}:{rule.name}",
                        "details": {
                            "ip":           log_entry.ip_address,
                            "rule_id":      rule.id,
                            "rule_name":    rule.name,
                            "rule_level":   rule.level,
                            "mitre_tactic": rule.mitre_tactic,
                            "action":       rule.action,
                        },
                        "severity": rule.severity,
                        "block_ip": rule.block_ip,
                    }
        except Exception as e:
            print(f"[RulesEngine] evaluate_custom_rules error: {e}")

        return {"triggered": False}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def calculate_distance(self, lat1, lon1, lat2, lon2):
        R = 6371
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        return R * 2 * atan2(sqrt(a), sqrt(1 - a))


# =============================================================================
# Standalone custom-rule evaluator — called from _process_ingest
# =============================================================================

def evaluate_all_custom_rules(log_entry, org_id):
    """
    Main entry point called from _process_ingest after log is saved.
    Evaluates ALL active custom rules for the organisation against the
    log entry.  Creates an Alert + Attack record for every rule that
    matches.  Catches all exceptions so a broken rule never crashes ingest.
    """
    try:
        _run_custom_rules(log_entry, org_id)
    except Exception as e:
        logger.error("Custom rules evaluation failed for log %s: %s", log_entry.id, e)


def _run_custom_rules(log_entry, org_id):
    """Core iteration — evaluate every enabled custom rule for the org."""
    from app.models import CustomRule, Alert, Attack as AttackModel, IPBlocklist
    from app.rule_builder import evaluator, dsl_runner
    import json as _json

    event_dict = {
        "ip_address":  log_entry.ip_address,
        "attack_type": log_entry.attack_type,
        "endpoint":    log_entry.endpoint,
        "payload":     log_entry.payload,
        "severity":    log_entry.severity,
        "user_agent":  log_entry.user_agent,
        "timestamp":   log_entry.timestamp.isoformat() if log_entry.timestamp else None,
    }

    # Feed temporal-operator history so count_within / rate_within work
    evaluator.add_to_history(event_dict)

    rules = CustomRule.query.filter_by(enabled=True, organisation_id=org_id).all()

    for rule in rules:
        try:
            triggered = False
            error     = None

            if rule.level in (1, 2):
                if rule.rule_definition:
                    rule_def, parse_err = evaluator.parse_yaml(rule.rule_definition)
                    if parse_err:
                        error = f"parse error: {parse_err}"
                    else:
                        triggered = evaluator.evaluate(rule_def, event_dict)

            elif rule.level == 3:
                if rule.rule_python:
                    if _is_sandbox_enabled(org_id):
                        triggered, error = dsl_runner.execute(rule.rule_python, event_dict)
                    else:
                        triggered, error = _execute_unrestricted(
                            rule.rule_python, event_dict, rule.name
                        )

            if error:
                logger.warning(
                    "Custom rule '%s' (id=%s) error: %s", rule.name, rule.id, error
                )

            if not triggered:
                continue

            # ── rule matched ─────────────────────────────────────────────
            rule.trigger_count  = (rule.trigger_count or 0) + 1
            rule.last_triggered = datetime.utcnow()
            db.session.add(rule)

            details_dict = {
                "rule_id":      rule.id,
                "rule_name":    rule.name,
                "rule_level":   rule.level,
                "ip_address":   log_entry.ip_address,
                "attack_type":  log_entry.attack_type,
                "endpoint":     log_entry.endpoint,
                "mitre_tactic": rule.mitre_tactic,
                "action":       rule.action,
            }

            db.session.add(Alert(
                organisation_id=org_id,
                message=(
                    f"Custom rule '{rule.name}' triggered "
                    f"from {log_entry.ip_address}"
                ),
                alert_type=f"custom:{rule.name}",
                severity=rule.severity or "medium",
                details=_json.dumps(details_dict),
            ))

            db.session.add(AttackModel(
                organisation_id=org_id,
                attack_type=f"custom:{rule.name}",
                ip_address=log_entry.ip_address,
                details=_json.dumps({"rule_id": rule.id, "rule_name": rule.name}),
                severity=rule.severity or "medium",
            ))

            if rule.block_ip and log_entry.ip_address:
                existing = IPBlocklist.query.filter_by(
                    organisation_id=org_id,
                    ip_address=log_entry.ip_address,
                ).first()
                if not existing:
                    db.session.add(IPBlocklist(
                        organisation_id=org_id,
                        ip_address=log_entry.ip_address,
                        reason=f"Auto-blocked by custom rule: {rule.name}",
                        blocked_by="system",
                    ))

            db.session.commit()

            logger.info(
                "ALERT [%s]: Custom rule '%s' (id=%s) matched log %s from %s",
                (rule.severity or "medium").upper(),
                rule.name, rule.id, log_entry.id, log_entry.ip_address,
            )

        except Exception as e:
            db.session.rollback()
            logger.error(
                "Error evaluating custom rule '%s' (id=%s): %s",
                rule.name, rule.id, e,
            )
            continue


# =============================================================================
# Sandbox helpers
# =============================================================================

def _is_sandbox_enabled(org_id) -> bool:
    """
    Returns True (sandbox ON) by default.
    Admins can disable in Settings → Security → Python DSL Sandbox.
    Fails safe: any DB error keeps the sandbox ON.
    """
    try:
        from app.models import OrganisationSettings
        settings = OrganisationSettings.query.filter_by(
            organisation_id=org_id
        ).first()
        if settings is None:
            return True
        return bool(settings.python_dsl_sandbox)
    except Exception:
        return True


def _execute_unrestricted(rule_code: str, event_dict: dict, rule_name: str):
    """
    Execute rule code without RestrictedPython sandbox.
    Only reached when an admin has explicitly disabled the sandbox.
    Returns (triggered: bool, error: str | None).
    """
    try:
        exec_globals = {
            "__builtins__": __builtins__,
            "re":           __import__("re"),
            "json":         __import__("json"),
            "math":         __import__("math"),
            "hashlib":      __import__("hashlib"),
            "ipaddress":    __import__("ipaddress"),
            "collections":  __import__("collections"),
            "itertools":    __import__("itertools"),
            "functools":    __import__("functools"),
            "string":       __import__("string"),
        }
        local_vars: dict = {}
        exec(compile(rule_code, "<rule>", "exec"), exec_globals, local_vars)  # noqa: S102
        rule_func = local_vars.get("rule")
        if not callable(rule_func):
            return False, "Must define a function named 'rule(event)'"
        result = rule_func(dict(event_dict))
        return bool(result), None
    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    except Exception as e:
        return False, f"Runtime error: {e}"
