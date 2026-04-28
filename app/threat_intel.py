# app/threat_intel.py — Courra-Sec threat intelligence integration
"""
Integrates with:
  - OTX AlienVault (API key in env: OTX_API_KEY)
  - VirusTotal v3   (API key in env: VT_API_KEY)
  - MISP            (env: MISP_URL, MISP_API_KEY)
  - Manual IOC import (CSV / plain list)

Auto-enrichment: every ingested IP is checked against active ThreatIndicators
for the org. Hit count is incremented and an alert is created on match.
"""
import csv
import io
import json
import os
import re
import threading
from datetime import datetime, timedelta

import requests as _req

from app.database import db
from app.models import ThreatIndicator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OTX_BASE  = 'https://otx.alienvault.com/api/v1'
_VT_BASE   = 'https://www.virustotal.com/api/v3'


# ---------------------------------------------------------------------------
# Feed fetchers
# ---------------------------------------------------------------------------

def fetch_otx_indicators(api_key: str, org_id: int, limit: int = 500) -> int:
    """Pull recent malicious IPs/domains from OTX and store them."""
    if not api_key:
        return 0

    headers = {'X-OTX-API-KEY': api_key}
    imported = 0

    for itype, endpoint in [
        ('ip',     '/indicators/export?type=IPv4&limit=' + str(limit)),
        ('domain', '/indicators/export?type=domain&limit=' + str(limit)),
    ]:
        try:
            resp = _req.get(_OTX_BASE + endpoint, headers=headers, timeout=10)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                value = line.strip()
                if not value or value.startswith('#'):
                    continue
                imported += _upsert_indicator(
                    org_id=org_id,
                    indicator_type=itype,
                    value=value,
                    source='OTX',
                    confidence=70,
                )
        except Exception as e:
            print(f'[ThreatIntel] OTX fetch error ({itype}): {e}')

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    return imported


def lookup_virustotal_ip(ip: str, api_key: str) -> dict:
    """Look up an IP on VirusTotal and return a summary dict."""
    if not api_key:
        return {}
    try:
        resp = _req.get(
            f'{_VT_BASE}/ip_addresses/{ip}',
            headers={'x-apikey': api_key},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) or 1
            return {
                'ip':         ip,
                'malicious':  malicious,
                'total':      total,
                'score':      round(malicious / total * 100),
                'reputation': data.get('reputation', 0),
                'country':    data.get('country', ''),
                'owner':      data.get('as_owner', ''),
                'tags':       data.get('tags', []),
                'source':     'VirusTotal',
            }
    except Exception as e:
        print(f'[ThreatIntel] VirusTotal lookup error: {e}')
    return {}


def lookup_virustotal_hash(file_hash: str, api_key: str) -> dict:
    """Look up a file hash on VirusTotal."""
    if not api_key:
        return {}
    try:
        resp = _req.get(
            f'{_VT_BASE}/files/{file_hash}',
            headers={'x-apikey': api_key},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) or 1
            return {
                'hash':          file_hash,
                'malicious':     malicious,
                'total':         total,
                'score':         round(malicious / total * 100),
                'name':          data.get('meaningful_name', ''),
                'malware_names': list(data.get('popular_threat_name', {}).keys())[:5],
                'source':        'VirusTotal',
            }
    except Exception as e:
        print(f'[ThreatIntel] VirusTotal hash error: {e}')
    return {}


def fetch_misp_indicators(misp_url: str, misp_key: str, org_id: int, limit: int = 1000) -> int:
    """Pull recent attributes from a MISP instance."""
    if not misp_url or not misp_key:
        return 0

    headers = {
        'Authorization': misp_key,
        'Accept':        'application/json',
        'Content-Type':  'application/json',
    }
    imported = 0
    try:
        payload = {
            'limit':    limit,
            'type_attribute': ['ip-src', 'ip-dst', 'domain', 'md5', 'sha256', 'url', 'email-src'],
            'to_ids':   True,
        }
        resp = _req.post(
            f'{misp_url.rstrip("/")}/attributes/restSearch',
            headers=headers,
            json=payload,
            timeout=15,
            verify=False,
        )
        resp.raise_for_status()
        attrs = resp.json().get('response', {}).get('Attribute', [])

        type_map = {
            'ip-src': 'ip', 'ip-dst': 'ip',
            'domain': 'domain',
            'md5': 'hash', 'sha256': 'hash', 'sha1': 'hash',
            'url': 'url',
            'email-src': 'email',
        }

        for attr in attrs:
            itype = type_map.get(attr.get('type', ''))
            if not itype:
                continue
            value = attr.get('value', '').strip()
            if not value:
                continue
            imported += _upsert_indicator(
                org_id=org_id,
                indicator_type=itype,
                value=value,
                source='MISP',
                confidence=80,
                description=attr.get('comment', ''),
            )

        db.session.commit()
    except Exception as e:
        print(f'[ThreatIntel] MISP fetch error: {e}')
        db.session.rollback()

    return imported


# ---------------------------------------------------------------------------
# Manual import (CSV or plain list)
# ---------------------------------------------------------------------------

def import_indicators_csv(org_id: int, csv_content: str) -> tuple[int, list]:
    """
    Parse a CSV with columns: type, value, confidence, source, description, tags
    (header row is required). Returns (count_imported, list_of_errors).
    """
    imported = 0
    errors   = []
    reader   = csv.DictReader(io.StringIO(csv_content))

    for i, row in enumerate(reader, start=2):
        itype = (row.get('type') or '').strip().lower()
        value = (row.get('value') or '').strip()
        if not itype or not value:
            errors.append(f'Row {i}: missing type or value')
            continue
        if itype not in ('ip', 'domain', 'hash', 'url', 'email'):
            errors.append(f'Row {i}: unknown indicator_type "{itype}"')
            continue
        try:
            conf = int(row.get('confidence', 50) or 50)
        except ValueError:
            conf = 50

        imported += _upsert_indicator(
            org_id=org_id,
            indicator_type=itype,
            value=value,
            source=(row.get('source') or 'manual').strip(),
            confidence=min(100, max(0, conf)),
            description=(row.get('description') or '').strip(),
            tags=(row.get('tags') or '').strip(),
        )

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        errors.append(f'DB error: {e}')

    return imported, errors


def import_plain_list(org_id: int, text: str, indicator_type: str,
                       source: str = 'manual', confidence: int = 60) -> int:
    """Import a newline-separated list of indicator values."""
    imported = 0
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        imported += _upsert_indicator(
            org_id=org_id,
            indicator_type=indicator_type,
            value=value,
            source=source,
            confidence=confidence,
        )
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    return imported


# ---------------------------------------------------------------------------
# Enrichment — check a log entry against stored IOCs
# ---------------------------------------------------------------------------

def enrich_log_entry(log_entry, org_id: int) -> list:
    """
    Check log entry fields against active ThreatIndicators for this org.
    Returns list of matching indicator dicts. Increments hit_count in background.
    """
    matches = []
    candidates = {
        'ip':  [log_entry.ip_address],
        'url': [log_entry.endpoint],
    }

    # Extract domains from endpoint
    if log_entry.endpoint:
        m = re.search(r'https?://([^/]+)', log_entry.endpoint)
        if m:
            candidates.setdefault('domain', []).append(m.group(1))

    # Extract hashes from payload / raw_data
    if log_entry.payload or log_entry.raw_data:
        text = (log_entry.payload or '') + ' ' + (log_entry.raw_data or '')
        hashes = re.findall(r'\b([a-fA-F0-9]{32,64})\b', text)
        if hashes:
            candidates['hash'] = hashes[:5]

    for itype, values in candidates.items():
        for value in (v for v in values if v):
            ioc = ThreatIndicator.query.filter_by(
                organisation_id=org_id,
                indicator_type=itype,
                value=value,
                is_active=True,
            ).first()
            if ioc:
                matches.append(ioc.to_dict())
                # Update hit stats in background
                threading.Thread(
                    target=_record_hit, args=(ioc.id,), daemon=True
                ).start()

    return matches


def _record_hit(ioc_id: int):
    try:
        ioc = db.session.get(ThreatIndicator, ioc_id)
        if ioc:
            ioc.hit_count = (ioc.hit_count or 0) + 1
            ioc.last_hit  = datetime.utcnow()
            db.session.commit()
    except Exception:
        db.session.rollback()


# ---------------------------------------------------------------------------
# Internal upsert helper
# ---------------------------------------------------------------------------

def _upsert_indicator(org_id: int, indicator_type: str, value: str,
                       source: str = 'manual', confidence: int = 50,
                       description: str = '', tags: str = '') -> int:
    """Insert or update a ThreatIndicator. Returns 1 if new, 0 if updated."""
    existing = ThreatIndicator.query.filter_by(
        organisation_id=org_id,
        indicator_type=indicator_type,
        value=value,
    ).first()

    now = datetime.utcnow()

    if existing:
        existing.last_seen  = now
        existing.is_active  = True
        existing.confidence = max(existing.confidence, confidence)
        if description and not existing.description:
            existing.description = description
        db.session.add(existing)
        return 0
    else:
        ioc = ThreatIndicator(
            organisation_id=org_id,
            indicator_type=indicator_type,
            value=value,
            source=source,
            confidence=confidence,
            description=description,
            tags=json.dumps(tags.split(',')) if tags else None,
            first_seen=now,
            last_seen=now,
            is_active=True,
        )
        db.session.add(ioc)
        return 1


# ---------------------------------------------------------------------------
# Expiry cleanup
# ---------------------------------------------------------------------------

def expire_old_indicators(org_id: int) -> int:
    """Mark expired indicators as inactive. Returns count."""
    now = datetime.utcnow()
    expired = (
        ThreatIndicator.query
        .filter_by(organisation_id=org_id, is_active=True)
        .filter(ThreatIndicator.expires_at.isnot(None))
        .filter(ThreatIndicator.expires_at < now)
        .all()
    )
    for ioc in expired:
        ioc.is_active = False
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    return len(expired)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def get_stats(org_id: int) -> dict:
    base = ThreatIndicator.query.filter_by(organisation_id=org_id)
    by_type = {}
    for itype in ('ip', 'domain', 'hash', 'url', 'email'):
        by_type[itype] = base.filter_by(indicator_type=itype, is_active=True).count()

    by_source = {}
    rows = (
        db.session.query(ThreatIndicator.source, db.func.count(ThreatIndicator.id))
        .filter_by(organisation_id=org_id, is_active=True)
        .group_by(ThreatIndicator.source)
        .all()
    )
    for src, cnt in rows:
        by_source[src or 'unknown'] = cnt

    return {
        'total':     base.filter_by(is_active=True).count(),
        'by_type':   by_type,
        'by_source': by_source,
        'total_hits': db.session.query(db.func.sum(ThreatIndicator.hit_count))
                       .filter_by(organisation_id=org_id).scalar() or 0,
    }
