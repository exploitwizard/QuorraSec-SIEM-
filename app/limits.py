"""Open-source Courra-Sec — no plan restrictions enforced."""


def check_limit(org, limit_name: str) -> tuple:
    """Always allowed — open-source build has no artificial limits."""
    return True, "ok"


def get_usage_warnings(org) -> list:
    """No usage warnings — limits are not enforced."""
    return []
