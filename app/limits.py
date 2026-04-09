"""Free-tier limit enforcement for Courra-Sec SaaS."""

FREE_PLAN_LIMITS = {
    'max_users':        5,
    'max_logs_per_day': 10000,
    'max_rules':        10,
    'max_blocklist':    100,
    'ml_enabled':       True,
    'export_enabled':   True,
    'api_access':       True,
}

WARN_THRESHOLD = 0.80  # show warning at 80% of limit


def check_limit(org, limit_name: str) -> tuple:
    """Returns (allowed: bool, message: str)."""
    from app.models import CourraSecUser, CustomRule, IPBlocklist
    from app.database import db

    limit_val = FREE_PLAN_LIMITS.get(limit_name)
    if limit_val is None:
        return True, "ok"

    if limit_name == 'max_users':
        current = CourraSecUser.query.filter_by(
            organisation_id=org.id, is_active=True
        ).count()
        if current >= limit_val:
            return False, f"User limit reached ({limit_val} users on free plan)"

    elif limit_name == 'max_rules':
        current = CustomRule.query.filter_by(organisation_id=org.id).count()
        if current >= limit_val:
            return False, f"Rule limit reached ({limit_val} rules on free plan)"

    elif limit_name == 'max_blocklist':
        current = IPBlocklist.query.filter_by(organisation_id=org.id).count()
        if current >= limit_val:
            return False, f"Blocklist limit reached ({limit_val} entries on free plan)"

    return True, "ok"


def get_usage_warnings(org) -> list:
    """Return a list of warning strings for limits approaching 80%."""
    from app.models import CourraSecUser, CustomRule, ApiKeyUsage
    from datetime import datetime

    warnings = []

    # Users
    user_count = CourraSecUser.query.filter_by(
        organisation_id=org.id, is_active=True
    ).count()
    if user_count >= FREE_PLAN_LIMITS['max_users'] * WARN_THRESHOLD:
        warnings.append(
            f"Approaching user limit: {user_count}/{FREE_PLAN_LIMITS['max_users']} users"
        )

    # Rules
    rule_count = CustomRule.query.filter_by(organisation_id=org.id).count()
    if rule_count >= FREE_PLAN_LIMITS['max_rules'] * WARN_THRESHOLD:
        warnings.append(
            f"Approaching rule limit: {rule_count}/{FREE_PLAN_LIMITS['max_rules']} rules"
        )

    # Daily logs
    today = datetime.utcnow().date()
    usage = ApiKeyUsage.query.filter_by(
        organisation_id=org.id, date=today
    ).first()
    log_count = usage.log_count if usage else 0
    if log_count >= FREE_PLAN_LIMITS['max_logs_per_day'] * WARN_THRESHOLD:
        warnings.append(
            f"Approaching daily log limit: {log_count:,}/{FREE_PLAN_LIMITS['max_logs_per_day']:,} logs today"
        )

    return warnings
