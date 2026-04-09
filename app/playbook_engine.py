# app/playbook_engine.py — Courra-Sec automated SOAR playbook engine
"""
Playbooks are triggered when an alert (or correlation event) matches
the playbook's trigger_on conditions. They then execute an ordered list
of actions.

Supported actions:
  block_ip         — add IP to org blocklist
  unblock_ip       — remove IP from blocklist
  send_slack       — post message to Slack webhook
  send_webhook     — POST JSON to a URL
  send_email       — send email via SMTP
  create_case      — open a new investigation case
  add_to_case      — attach an alert to an existing open case
  disable_user     — deactivate a Courra-Sec user account
  run_custom       — call a configured external URL
  create_jira      — create a Jira issue
  create_pagerduty — trigger a PagerDuty incident

Trigger conditions (trigger_on JSON):
  {
    "severity":    ["high", "critical"],    // match any
    "alert_type":  "bruteforce",            // substring match
    "rule_name":   "correlation:..."        // exact or substring
  }
  All specified keys must match (AND logic).
"""
import json
import threading
from datetime import datetime

from app.database import db
from app.models import (
    IPBlocklist, Alert, Case, CaseItem, CourraSecUser,
    Playbook, PlaybookRun, SoarAction,
)


# ---------------------------------------------------------------------------
# Trigger matching
# ---------------------------------------------------------------------------

def _matches_trigger(trigger_on: dict, alert: Alert) -> bool:
    """Return True if the alert satisfies all trigger conditions."""
    if not trigger_on:
        return True

    # severity: list or string
    if 'severity' in trigger_on:
        allowed = trigger_on['severity']
        if isinstance(allowed, str):
            allowed = [allowed]
        if alert.severity not in allowed:
            return False

    # alert_type: substring match
    if 'alert_type' in trigger_on:
        if trigger_on['alert_type'].lower() not in (alert.alert_type or '').lower():
            return False

    # rule_name: substring match on alert_type
    if 'rule_name' in trigger_on:
        if trigger_on['rule_name'].lower() not in (alert.alert_type or '').lower():
            return False

    return True


# ---------------------------------------------------------------------------
# Action executor
# ---------------------------------------------------------------------------

class PlaybookEngine:

    def run_for_alert(self, alert: Alert, org_id: int) -> list:
        """
        Check all enabled playbooks for this org; execute those that match.
        Returns list of PlaybookRun ids.
        """
        playbooks = Playbook.query.filter_by(organisation_id=org_id, enabled=True).all()
        run_ids   = []

        for pb in playbooks:
            try:
                trigger = json.loads(pb.trigger_on or '{}')
            except (json.JSONDecodeError, TypeError):
                trigger = {}

            if not _matches_trigger(trigger, alert):
                continue

            run = PlaybookRun(
                organisation_id=org_id,
                playbook_id=pb.id,
                triggered_by=f'alert:{alert.id}',
                status='running',
            )
            db.session.add(run)
            db.session.commit()
            run_ids.append(run.id)

            # Execute in background so it never blocks ingest
            threading.Thread(
                target=self._execute,
                args=(pb, run, alert, org_id),
                daemon=True,
            ).start()

        return run_ids

    # ------------------------------------------------------------------

    def _execute(self, pb: Playbook, run: PlaybookRun, alert: Alert, org_id: int):
        steps_log = []
        success   = True

        try:
            actions = json.loads(pb.actions or '[]')
        except (json.JSONDecodeError, TypeError):
            actions = []

        # Extract target IP from alert details
        target_ip = None
        try:
            details = json.loads(alert.details or '{}')
            target_ip = (
                details.get('source_ip') or
                details.get('ip') or
                details.get('ip_address')
            )
        except Exception:
            pass

        for action in actions:
            step_result = self._run_action(action, alert, target_ip, org_id)
            steps_log.append(step_result)
            if not step_result.get('ok') and action.get('stop_on_failure', False):
                success = False
                break

        # Persist run result
        try:
            run.status       = 'success' if success else 'failed'
            run.execution_log = json.dumps(steps_log)
            run.completed_at  = datetime.utcnow()

            pb.run_count  = (pb.run_count or 0) + 1
            pb.last_run   = datetime.utcnow()

            db.session.add(run)
            db.session.add(pb)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f'[Playbook] failed to persist run result: {e}')

    # ------------------------------------------------------------------

    def _run_action(self, action: dict, alert: Alert, target_ip, org_id: int) -> dict:
        atype = action.get('type', '')
        result = {'type': atype, 'ok': False, 'message': ''}

        try:
            if atype == 'block_ip':
                result = self._action_block_ip(action, alert, target_ip, org_id)

            elif atype == 'unblock_ip':
                result = self._action_unblock_ip(action, target_ip, org_id)

            elif atype == 'send_slack':
                result = self._action_send_slack(action, alert)

            elif atype == 'send_webhook':
                result = self._action_send_webhook(action, alert)

            elif atype == 'send_email':
                result = self._action_send_email(action, alert)

            elif atype == 'create_case':
                result = self._action_create_case(action, alert, org_id)

            elif atype == 'add_to_case':
                result = self._action_add_to_case(action, alert, org_id)

            elif atype == 'disable_user':
                result = self._action_disable_user(action, org_id)

            elif atype == 'create_jira':
                result = self._action_create_jira(action, alert)

            elif atype == 'create_pagerduty':
                result = self._action_pagerduty(action, alert)

            else:
                result['message'] = f'Unknown action type: {atype}'

        except Exception as e:
            result['ok']      = False
            result['message'] = str(e)

        # Record in SOAR actions log
        try:
            soar = SoarAction(
                organisation_id=org_id,
                action_type=atype,
                triggered_by=f'playbook/alert:{alert.id}',
                target=str(target_ip or ''),
                result='success' if result.get('ok') else 'failed',
                details=json.dumps(result),
            )
            db.session.add(soar)
            db.session.commit()
        except Exception:
            db.session.rollback()

        return result

    # ------------------------------------------------------------------
    # Individual action implementations
    # ------------------------------------------------------------------

    def _action_block_ip(self, action, alert, target_ip, org_id) -> dict:
        ip = action.get('ip') or target_ip
        if not ip:
            return {'type': 'block_ip', 'ok': False, 'message': 'No IP to block'}

        existing = IPBlocklist.query.filter_by(organisation_id=org_id, ip_address=ip).first()
        if not existing:
            bl = IPBlocklist(
                organisation_id=org_id,
                ip_address=ip,
                reason=f'Auto-blocked by playbook (alert: {alert.id})',
                blocked_by='playbook',
            )
            db.session.add(bl)
            db.session.commit()
        return {'type': 'block_ip', 'ok': True, 'message': f'Blocked {ip}'}

    def _action_unblock_ip(self, action, target_ip, org_id) -> dict:
        ip = action.get('ip') or target_ip
        if not ip:
            return {'type': 'unblock_ip', 'ok': False, 'message': 'No IP specified'}
        IPBlocklist.query.filter_by(organisation_id=org_id, ip_address=ip).delete()
        db.session.commit()
        return {'type': 'unblock_ip', 'ok': True, 'message': f'Unblocked {ip}'}

    def _action_send_slack(self, action, alert) -> dict:
        import requests as _r
        url = action.get('webhook_url', '')
        if not url:
            from app.config import Config
            url = Config.SLACK_WEBHOOK_URL
        if not url:
            return {'type': 'send_slack', 'ok': False, 'message': 'No Slack URL configured'}
        msg = action.get('message') or (
            f':rotating_light: *Playbook triggered* [{alert.severity.upper()}]\n'
            f'*Alert:* {alert.alert_type}\n*Message:* {alert.message}'
        )
        _r.post(url, json={'text': msg}, timeout=5)
        return {'type': 'send_slack', 'ok': True, 'message': 'Slack notification sent'}

    def _action_send_webhook(self, action, alert) -> dict:
        import requests as _r
        url = action.get('url', '')
        if not url:
            return {'type': 'send_webhook', 'ok': False, 'message': 'No URL configured'}
        payload = action.get('payload') or {
            'source':     'CourraSec',
            'alert_id':   alert.id,
            'alert_type': alert.alert_type,
            'severity':   alert.severity,
            'message':    alert.message,
        }
        _r.post(url, json=payload, timeout=5)
        return {'type': 'send_webhook', 'ok': True, 'message': f'Webhook posted to {url}'}

    def _action_send_email(self, action, alert) -> dict:
        import smtplib, os
        from email.mime.text import MIMEText
        to = action.get('to', os.environ.get('ALERT_TO', ''))
        if not to:
            return {'type': 'send_email', 'ok': False, 'message': 'No recipient configured'}
        subject = action.get('subject') or f'[Courra-Sec] {alert.alert_type} — {alert.severity.upper()}'
        body    = action.get('body')    or f'{alert.message}\n\nDetails: {alert.details}'
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From']    = os.environ.get('ALERT_FROM', 'courra-sec@localhost')
        msg['To']      = to
        smtp_host = os.environ.get('SMTP_HOST', 'localhost')
        smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.starttls()
            if os.environ.get('SMTP_USER'):
                s.login(os.environ['SMTP_USER'], os.environ.get('SMTP_PASS', ''))
            s.send_message(msg)
        return {'type': 'send_email', 'ok': True, 'message': f'Email sent to {to}'}

    def _action_create_case(self, action, alert, org_id) -> dict:
        title = action.get('title') or f'Auto-case: {alert.alert_type} [{alert.severity}]'
        case  = Case(
            organisation_id=org_id,
            title=title,
            description=action.get('description') or alert.message,
            priority=alert.severity if alert.severity in ('critical','high','medium','low') else 'medium',
            status='open',
        )
        db.session.add(case)
        db.session.flush()
        item = CaseItem(
            case_id=case.id,
            item_type='alert',
            item_id=alert.id,
            note=f'Auto-linked by playbook',
            added_by='playbook',
        )
        db.session.add(item)
        db.session.commit()
        return {'type': 'create_case', 'ok': True, 'case_id': case.id, 'message': f'Case #{case.id} created'}

    def _action_add_to_case(self, action, alert, org_id) -> dict:
        case_id = action.get('case_id')
        if not case_id:
            # Find the most recent open case
            case = Case.query.filter_by(organisation_id=org_id, status='open').order_by(Case.created_at.desc()).first()
        else:
            case = Case.query.filter_by(id=case_id, organisation_id=org_id).first()
        if not case:
            return {'type': 'add_to_case', 'ok': False, 'message': 'No open case found'}
        item = CaseItem(
            case_id=case.id,
            item_type='alert',
            item_id=alert.id,
            note='Auto-linked by playbook',
            added_by='playbook',
        )
        db.session.add(item)
        db.session.commit()
        return {'type': 'add_to_case', 'ok': True, 'case_id': case.id, 'message': f'Added to case #{case.id}'}

    def _action_disable_user(self, action, org_id) -> dict:
        username = action.get('username', '')
        if not username:
            return {'type': 'disable_user', 'ok': False, 'message': 'No username specified'}
        user = CourraSecUser.query.filter_by(organisation_id=org_id, username=username).first()
        if not user:
            return {'type': 'disable_user', 'ok': False, 'message': f'User {username} not found'}
        user.is_active = False
        db.session.commit()
        return {'type': 'disable_user', 'ok': True, 'message': f'User {username} disabled'}

    def _action_create_jira(self, action, alert) -> dict:
        import requests as _r
        url      = action.get('jira_url', '')
        token    = action.get('token', '')
        project  = action.get('project', 'SEC')
        if not url or not token:
            return {'type': 'create_jira', 'ok': False, 'message': 'Jira URL or token not configured'}
        payload = {
            'fields': {
                'project':     {'key': project},
                'summary':     f'[Courra-Sec] {alert.alert_type} — {alert.severity.upper()}',
                'description': alert.message,
                'issuetype':   {'name': 'Bug'},
            }
        }
        resp = _r.post(
            f'{url.rstrip("/")}/rest/api/2/issue',
            json=payload,
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
            timeout=10,
        )
        if resp.status_code in (200, 201):
            key = resp.json().get('key', '')
            return {'type': 'create_jira', 'ok': True, 'issue_key': key, 'message': f'Jira issue {key} created'}
        return {'type': 'create_jira', 'ok': False, 'message': f'Jira returned {resp.status_code}'}

    def _action_pagerduty(self, action, alert) -> dict:
        import requests as _r
        routing_key = action.get('routing_key', '')
        if not routing_key:
            return {'type': 'create_pagerduty', 'ok': False, 'message': 'No PagerDuty routing_key'}
        severity_map = {'critical': 'critical', 'high': 'error', 'medium': 'warning', 'low': 'info'}
        payload = {
            'routing_key':  routing_key,
            'event_action': 'trigger',
            'payload': {
                'summary':   f'[Courra-Sec] {alert.alert_type}: {alert.message}',
                'source':    'CourraSec',
                'severity':  severity_map.get(alert.severity, 'error'),
                'timestamp': alert.created_at.isoformat() if alert.created_at else None,
            },
        }
        resp = _r.post(
            'https://events.pagerduty.com/v2/enqueue',
            json=payload, timeout=10,
        )
        if resp.status_code == 202:
            return {'type': 'create_pagerduty', 'ok': True, 'message': 'PagerDuty incident triggered'}
        return {'type': 'create_pagerduty', 'ok': False, 'message': f'PagerDuty returned {resp.status_code}'}


# Singleton
playbook_engine = PlaybookEngine()
