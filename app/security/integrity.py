# app/security/integrity.py — OWASP A08: Software and Data Integrity
import hashlib
import hmac
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

_INTEGRITY_SECRET = os.environ.get('INTEGRITY_SECRET', '')
_ALLOWED_EXTENSIONS = {'csv', 'json', 'txt', 'log'}
_DANGEROUS_MARKERS = [b'#!/', b'<script', b'<%', b'<?php', b'MZ\x90']


def sign_data(data: dict) -> str:
    if not _INTEGRITY_SECRET:
        return ''
    payload = json.dumps(data, sort_keys=True, default=str)
    return hmac.new(_INTEGRITY_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def verify_data(data: dict, signature: str) -> bool:
    if not _INTEGRITY_SECRET:
        return True
    return hmac.compare_digest(sign_data(data), signature)


def validate_file_upload(file_stream, filename: str, max_size: int = 10 * 1024 * 1024) -> tuple:
    if '.' not in filename:
        return False, "File must have an extension"
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        return False, f"File type .{ext} not allowed"
    file_stream.seek(0, 2)
    size = file_stream.tell()
    file_stream.seek(0)
    if size > max_size:
        return False, f"File too large (max {max_size // 1024 // 1024}MB)"
    if size == 0:
        return False, "File is empty"
    header = file_stream.read(512)
    file_stream.seek(0)
    for marker in _DANGEROUS_MARKERS:
        if marker in header:
            return False, "File contains potentially dangerous content"
    return True, ""


def create_audit_entry(user_id: int, org_id: int, action: str,
                        resource_type: str, resource_id: int = None,
                        details: str = '') -> dict:
    entry = {
        'user_id': user_id, 'org_id': org_id, 'action': action,
        'resource_type': resource_type, 'resource_id': resource_id,
        'details': details, 'timestamp': datetime.utcnow().isoformat(),
    }
    entry['signature'] = sign_data(entry)
    return entry
