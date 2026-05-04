# app/security/access_control.py — OWASP A01: Broken Access Control
import logging
from flask import g, request

logger = logging.getLogger(__name__)


def check_object_ownership(obj, org_id=None):
    """Verify an object belongs to the current organisation (IDOR prevention)."""
    if org_id is None and hasattr(g, 'org'):
        org_id = g.org.id
    if not hasattr(obj, 'organisation_id'):
        return True
    if obj.organisation_id != org_id:
        logger.warning(
            "IDOR attempt: user=%s tried to access object org=%s from org=%s ip=%s",
            getattr(g, 'user', None) and g.user.id,
            obj.organisation_id, org_id,
            request.remote_addr,
        )
        return False
    return True
