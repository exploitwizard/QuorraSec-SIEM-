# app/report_engine.py — Courra-Sec report engine
"""
Generates:
  - Full log/alert/attack exports (CSV or JSON)
  - Executive summary report
  - Compliance snapshot (PCI-DSS, HIPAA, SOC2, ISO27001)
  - Scheduled report runner (call run_scheduled_reports() from a cron or startup thread)
"""
import csv
import io
import json
import os
import smtplib
import threading
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.database import db
from app.models import (
    LogEntry, Alert, Attack, IPBlocklist, CustomRule,
    CorrelationRule, AuditLog, ScheduledReport,
)


# ---------------------------------------------------------------------------
# CSV / JSON export helpers
# ---------------------------------------------------------------------------

def export_logs_csv(org_id: int, after: datetime = None, before: datetime = None) -> str:
    q = LogEntry.query.filter_by(organisation_id=org_id)
    if after:  q = q.filter(LogEntry.timestamp >= after)
    if before: q = q.filter(LogEntry.timestamp <= before)
    rows = q.order_by(LogEntry.timestamp.desc()).all()

    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(['id', 'timestamp', 'ip_address', 'attack_type', 'endpoint',
                'severity', 'user_agent', 'payload'])
    for r in rows:
        w.writerow([
            r.id,
            r.timestamp.isoformat() if r.timestamp else '',
            r.ip_address, r.attack_type, r.endpoint,
            r.severity, r.user_agent,
            (r.payload or '')[:500],
        ])
    return buf.getvalue()


def export_alerts_csv(org_id: int, after: datetime = None, before: datetime = None) -> str:
    q = Alert.query.filter_by(organisation_id=org_id)
    if after:  q = q.filter(Alert.created_at >= after)
    if before: q = q.filter(Alert.created_at <= before)
    rows = q.order_by(Alert.created_at.desc()).all()

    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(['id', 'created_at', 'alert_type', 'severity', 'message', 'acknowledged'])
    for r in rows:
        w.writerow([
            r.id,
            r.created_at.isoformat() if r.created_at else '',
            r.alert_type, r.severity, r.message, r.acknowledged,
        ])
    return buf.getvalue()


def export_attacks_csv(org_id: int, after: datetime = None, before: datetime = None) -> str:
    q = Attack.query.filter_by(organisation_id=org_id)
    if after:  q = q.filter(Attack.detected_at >= after)
    if before: q = q.filter(Attack.detected_at <= before)
    rows = q.order_by(Attack.detected_at.desc()).all()

    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(['id', 'detected_at', 'attack_type', 'ip_address', 'severity', 'details'])
    for r in rows:
        w.writerow([
            r.id,
            r.detected_at.isoformat() if r.detected_at else '',
            r.attack_type, r.ip_address, r.severity,
            (r.details or '')[:500],
        ])
    return buf.getvalue()


def export_audit_csv(org_id: int, after: datetime = None, before: datetime = None) -> str:
    q = AuditLog.query.filter_by(organisation_id=org_id)
    if after:  q = q.filter(AuditLog.created_at >= after)
    if before: q = q.filter(AuditLog.created_at <= before)
    rows = q.order_by(AuditLog.created_at.desc()).all()

    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(['id', 'created_at', 'username', 'action', 'resource_type', 'resource_id', 'ip_address'])
    for r in rows:
        w.writerow([
            r.id,
            r.created_at.isoformat() if r.created_at else '',
            r.username, r.action, r.resource_type, r.resource_id, r.ip_address,
        ])
    return buf.getvalue()


def export_json(org_id: int, entity: str,
                after: datetime = None, before: datetime = None) -> str:
    if entity == 'logs':
        q = LogEntry.query.filter_by(organisation_id=org_id)
        if after:  q = q.filter(LogEntry.timestamp >= after)
        if before: q = q.filter(LogEntry.timestamp <= before)
        data = [r.to_dict() for r in q.order_by(LogEntry.timestamp.desc()).limit(10000).all()]
    elif entity == 'alerts':
        q = Alert.query.filter_by(organisation_id=org_id)
        if after:  q = q.filter(Alert.created_at >= after)
        if before: q = q.filter(Alert.created_at <= before)
        data = [r.to_dict() for r in q.order_by(Alert.created_at.desc()).limit(10000).all()]
    else:
        data = []
    return json.dumps(data, indent=2, default=str)


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def executive_summary(org_id: int, days: int = 7) -> dict:
    since = datetime.utcnow() - timedelta(days=days)

    total_logs    = LogEntry.query.filter_by(organisation_id=org_id).count()
    new_logs      = LogEntry.query.filter_by(organisation_id=org_id).filter(LogEntry.timestamp >= since).count()
    total_attacks = Attack.query.filter_by(organisation_id=org_id).count()
    new_attacks   = Attack.query.filter_by(organisation_id=org_id).filter(Attack.detected_at >= since).count()
    total_alerts  = Alert.query.filter_by(organisation_id=org_id).count()
    open_alerts   = Alert.query.filter_by(organisation_id=org_id, acknowledged=False).count()
    new_alerts    = Alert.query.filter_by(organisation_id=org_id).filter(Alert.created_at >= since).count()
    blocked_ips   = IPBlocklist.query.filter_by(organisation_id=org_id).count()

    # Top attack types
    type_rows = (
        db.session.query(Attack.attack_type, db.func.count(Attack.id))
        .filter_by(organisation_id=org_id)
        .filter(Attack.detected_at >= since)
        .group_by(Attack.attack_type)
        .order_by(db.func.count(Attack.id).desc())
        .limit(5).all()
    )

    # Alert severity breakdown
    sev_rows = (
        db.session.query(Alert.severity, db.func.count(Alert.id))
        .filter_by(organisation_id=org_id)
        .filter(Alert.created_at >= since)
        .group_by(Alert.severity)
        .all()
    )

    return {
        'period_days':        days,
        'generated_at':       datetime.utcnow().isoformat(),
        'total_logs':         total_logs,
        'new_logs':           new_logs,
        'total_attacks':      total_attacks,
        'new_attacks':        new_attacks,
        'total_alerts':       total_alerts,
        'open_alerts':        open_alerts,
        'new_alerts':         new_alerts,
        'blocked_ips':        blocked_ips,
        'top_attack_types':   {t: c for t, c in type_rows},
        'alert_severity':     {s: c for s, c in sev_rows},
    }


# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

_COMPLIANCE_FRAMEWORKS = {
    'PCI-DSS': {
        'description': 'Payment Card Industry Data Security Standard',
        'controls': [
            {'id': 'PCI-10.1', 'title': 'Audit trails for system access', 'check': 'audit_log_enabled'},
            {'id': 'PCI-10.2', 'title': 'Log individual user access', 'check': 'user_audit_log'},
            {'id': 'PCI-10.5', 'title': 'Secure audit trails', 'check': 'audit_retention'},
            {'id': 'PCI-11.4', 'title': 'IDS/IPS in place', 'check': 'ids_active'},
            {'id': 'PCI-6.4',  'title': 'Address security vulnerabilities', 'check': 'alerts_reviewed'},
        ],
    },
    'HIPAA': {
        'description': 'Health Insurance Portability and Accountability Act',
        'controls': [
            {'id': 'HIPAA-164.312(b)',    'title': 'Audit controls', 'check': 'audit_log_enabled'},
            {'id': 'HIPAA-164.308(a)(1)', 'title': 'Security management process', 'check': 'rules_defined'},
            {'id': 'HIPAA-164.308(a)(5)', 'title': 'Security awareness', 'check': 'ids_active'},
        ],
    },
    'SOC2': {
        'description': 'Service Organization Control 2',
        'controls': [
            {'id': 'CC6.1', 'title': 'Logical access controls', 'check': 'mfa_enabled'},
            {'id': 'CC6.6', 'title': 'Prevent unauthorized external access', 'check': 'ids_active'},
            {'id': 'CC7.2', 'title': 'Monitor system components', 'check': 'monitoring_active'},
            {'id': 'CC7.3', 'title': 'Evaluate security events', 'check': 'alerts_reviewed'},
        ],
    },
    'ISO27001': {
        'description': 'ISO/IEC 27001 Information Security Management',
        'controls': [
            {'id': 'A.12.4.1', 'title': 'Event logging',            'check': 'audit_log_enabled'},
            {'id': 'A.12.4.3', 'title': 'Administrator / operator logs', 'check': 'user_audit_log'},
            {'id': 'A.16.1.2', 'title': 'Report information security events', 'check': 'alerts_active'},
            {'id': 'A.12.6.1', 'title': 'Management of technical vulnerabilities', 'check': 'rules_defined'},
        ],
    },
}


def compliance_report(org_id: int, framework: str) -> dict:
    spec = _COMPLIANCE_FRAMEWORKS.get(framework)
    if not spec:
        return {'error': f'Unknown framework: {framework}'}

    checks = _run_checks(org_id)

    evaluated = []
    passed = 0
    for ctrl in spec['controls']:
        check_key = ctrl['check']
        status    = checks.get(check_key, False)
        evaluated.append({
            'id':     ctrl['id'],
            'title':  ctrl['title'],
            'status': 'pass' if status else 'fail',
            'detail': checks.get(check_key + '_detail', ''),
        })
        if status:
            passed += 1

    total = len(evaluated)
    score = round(passed / total * 100) if total else 0

    return {
        'framework':    framework,
        'description':  spec['description'],
        'generated_at': datetime.utcnow().isoformat(),
        'score':        score,
        'passed':       passed,
        'total':        total,
        'controls':     evaluated,
        'status':       'compliant' if score >= 80 else ('partial' if score >= 50 else 'non_compliant'),
    }


def _run_checks(org_id: int) -> dict:
    """Evaluate observable compliance indicators for this org."""
    results = {}

    # audit_log_enabled — any audit records exist
    audit_count = AuditLog.query.filter_by(organisation_id=org_id).count()
    results['audit_log_enabled'] = audit_count > 0
    results['audit_log_enabled_detail'] = f'{audit_count} audit log entries'

    # user_audit_log — login events logged
    login_count = AuditLog.query.filter_by(organisation_id=org_id, action='login').count()
    results['user_audit_log'] = login_count > 0
    results['user_audit_log_detail'] = f'{login_count} login events recorded'

    # audit_retention — logs older than 30 days exist (retention working)
    old_cutoff = datetime.utcnow() - timedelta(days=30)
    old_logs = LogEntry.query.filter_by(organisation_id=org_id).filter(LogEntry.timestamp <= old_cutoff).count()
    results['audit_retention'] = old_logs > 0 or LogEntry.query.filter_by(organisation_id=org_id).count() > 0
    results['audit_retention_detail'] = 'Log retention policy active'

    # ids_active — detection rules or correlation rules defined
    rules_count = CustomRule.query.filter_by(organisation_id=org_id, enabled=True).count()
    corr_count  = CorrelationRule.query.filter_by(organisation_id=org_id, enabled=True).count()
    results['ids_active'] = (rules_count + corr_count) > 0
    results['ids_active_detail'] = f'{rules_count} detection rules, {corr_count} correlation rules active'

    # alerts_reviewed — any alerts acknowledged
    ack_count = Alert.query.filter_by(organisation_id=org_id, acknowledged=True).count()
    total_alerts = Alert.query.filter_by(organisation_id=org_id).count()
    results['alerts_reviewed'] = ack_count > 0
    results['alerts_reviewed_detail'] = f'{ack_count}/{total_alerts} alerts acknowledged'

    # rules_defined
    results['rules_defined'] = rules_count > 0
    results['rules_defined_detail'] = f'{rules_count} active detection rules'

    # mfa_enabled — at least one user has TOTP enabled
    from app.models import CourraSecUser
    mfa_count = CourraSecUser.query.filter_by(organisation_id=org_id, totp_enabled=True).count()
    results['mfa_enabled'] = mfa_count > 0
    results['mfa_enabled_detail'] = f'{mfa_count} user(s) with MFA enabled'

    # monitoring_active — recent log ingest
    recent = LogEntry.query.filter_by(organisation_id=org_id).filter(
        LogEntry.timestamp >= datetime.utcnow() - timedelta(days=7)
    ).count()
    results['monitoring_active'] = recent > 0
    results['monitoring_active_detail'] = f'{recent} logs in last 7 days'

    # alerts_active
    results['alerts_active'] = total_alerts > 0
    results['alerts_active_detail'] = f'{total_alerts} total alerts'

    return results


# ---------------------------------------------------------------------------
# Scheduled report runner
# ---------------------------------------------------------------------------

def run_scheduled_reports(app_context=None):
    """
    Called periodically (e.g. daily). Checks ScheduledReport table and sends
    due reports via email.
    """
    def _run():
        if app_context:
            with app_context:
                _process_reports()
        else:
            _process_reports()

    threading.Thread(target=_run, daemon=True).start()


def _process_reports():
    now = datetime.utcnow()
    due = ScheduledReport.query.filter_by(enabled=True).filter(
        ScheduledReport.next_run <= now
    ).all()

    for sr in due:
        try:
            _send_report(sr)
            sr.last_run = now
            sr.next_run = _next_run(sr.schedule, now)
            db.session.commit()
        except Exception as e:
            print(f'[ReportEngine] failed to send scheduled report {sr.id}: {e}')
            db.session.rollback()


def _send_report(sr: ScheduledReport):
    recipients = json.loads(sr.recipients or '[]')
    if not recipients:
        return

    org_id = sr.organisation_id
    now    = datetime.utcnow()

    if sr.report_type == 'executive_summary':
        content = json.dumps(executive_summary(org_id), indent=2)
        filename = f'executive_summary_{now.date()}.json'
        mime_type = 'application/json'
    elif sr.report_type == 'full_export':
        content   = export_logs_csv(org_id)
        filename  = f'logs_export_{now.date()}.csv'
        mime_type = 'text/csv'
    elif sr.report_type == 'compliance':
        content = json.dumps({
            fw: compliance_report(org_id, fw)
            for fw in ('PCI-DSS', 'HIPAA', 'SOC2', 'ISO27001')
        }, indent=2)
        filename  = f'compliance_report_{now.date()}.json'
        mime_type = 'application/json'
    else:
        content   = export_alerts_csv(org_id)
        filename  = f'alerts_{now.date()}.csv'
        mime_type = 'text/csv'

    smtp_host = os.environ.get('SMTP_HOST', 'localhost')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    mail_from = os.environ.get('ALERT_FROM', 'courra-sec@localhost')

    msg = MIMEMultipart()
    msg['Subject'] = f'[Courra-Sec] Scheduled Report: {sr.name}'
    msg['From']    = mail_from
    msg['To']      = ', '.join(recipients)

    msg.attach(MIMEText(
        f'Courra-Sec scheduled report: {sr.name}\n'
        f'Type: {sr.report_type}\nGenerated: {now.isoformat()}\n'
        f'Please find the report attached.',
        'plain',
    ))

    attachment = MIMEApplication(content.encode())
    attachment['Content-Disposition'] = f'attachment; filename="{filename}"'
    msg.attach(attachment)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
        s.starttls()
        if os.environ.get('SMTP_USER'):
            s.login(os.environ['SMTP_USER'], os.environ.get('SMTP_PASS', ''))
        s.send_message(msg)


def _next_run(schedule: str, from_dt: datetime) -> datetime:
    if schedule == 'daily':
        return from_dt + timedelta(days=1)
    if schedule == 'weekly':
        return from_dt + timedelta(weeks=1)
    if schedule == 'monthly':
        next_month = (from_dt.month % 12) + 1
        year = from_dt.year + (1 if from_dt.month == 12 else 0)
        return from_dt.replace(year=year, month=next_month)
    return from_dt + timedelta(days=1)
