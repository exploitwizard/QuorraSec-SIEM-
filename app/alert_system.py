import json
<<<<<<< HEAD
from datetime import datetime
=======
import os
import threading
from datetime import datetime, timedelta

>>>>>>> cea6978 (Reconnected project and updated files)
from app.database import db
from app.models import Alert
from app.config import Config

<<<<<<< HEAD
class AlertSystem:
    """Alert generation and notification system."""
    
    def __init__(self):
        self.email_enabled = Config.EMAIL_ENABLED
    
    def create_alert(self, message, alert_type, severity, details=None):
        """Create a new alert."""
=======

class AlertSystem:
    """Alert generation and multi-channel notification system."""

    def __init__(self):
        self.email_enabled  = Config.EMAIL_ENABLED
        self.slack_url      = Config.SLACK_WEBHOOK_URL
        self.webhook_url    = Config.ALERT_WEBHOOK_URL
        self.teams_url      = Config.TEAMS_WEBHOOK_URL

    # ------------------------------------------------------------------
    # Core creation
    # ------------------------------------------------------------------

    def create_alert(self, message: str, alert_type: str, severity: str, details=None) -> Alert | None:
        """Persist an alert and fire notifications asynchronously."""
>>>>>>> cea6978 (Reconnected project and updated files)
        try:
            alert = Alert(
                message=message,
                alert_type=alert_type,
                severity=severity,
<<<<<<< HEAD
                details=json.dumps(details) if details else None
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Print to console (for debugging)
            print(f"🚨 ALERT: {severity.upper()} - {message}")
            
            # Send notification if severity is high or critical
            if severity in ['high', 'critical']:
                self.send_notification(alert)
            
            return alert
            
        except Exception as e:
            print(f"Error creating alert: {e}")
            return None
    
    def send_notification(self, alert):
        """Send notification for alert."""
        # Email notification
        if self.email_enabled:
            self.send_email_alert(alert)
        
        # Could add other notification methods:
        # - Slack webhook
        # - SMS
        # - Push notification
    
    def send_email_alert(self, alert):
        """Send email alert."""
=======
                details=json.dumps(details) if details else None,
            )
            db.session.add(alert)
            db.session.commit()

            print(f"ALERT [{severity.upper()}]: {message}")

            if severity in ("high", "critical"):
                # Run notifications in a background thread so they never block ingest
                threading.Thread(
                    target=self._send_all_notifications,
                    args=(alert,),
                    daemon=True,
                ).start()

            return alert

        except Exception as e:
            print(f"Error creating alert: {e}")
            db.session.rollback()
            return None

    def create_ml_alert(self, ml_result: dict, log_entry=None) -> Alert | None:
        """Create an alert from an ML pipeline result dict."""
        severity   = ml_result.get("severity", "info").lower()
        risk_score = ml_result.get("risk_score", 0)
        threat     = ml_result.get("threat_label", "UNKNOWN")
        mitre      = ml_result.get("mitre_tactic") or "N/A"
        chains     = [c.get("pattern_name", "") for c in ml_result.get("attack_chain", [])]
        entity     = ml_result.get("risk", {}).get("entity_id", "unknown")

        flags = []
        if ml_result.get("is_anomaly"):      flags.append("anomaly")
        if ml_result.get("is_ueba_anomaly"): flags.append("UEBA")
        if ml_result.get("is_sequential"):   flags.append("sequential-pattern")
        if ml_result.get("is_novel_log"):    flags.append("novel-log")
        if chains:                           flags.append(f"chain:{','.join(chains)}")

        message = (
            f"[ML] {threat} detected — risk {risk_score}/100 from {entity}"
            + (f" | flags: {', '.join(flags)}" if flags else "")
        )

        details = {
            "risk_score":       risk_score,
            "threat_label":     threat,
            "mitre_tactic":     mitre,
            "flags":            flags,
            "chains":           chains,
            "signal_breakdown": ml_result.get("risk", {}).get("signal_breakdown", {}),
            "source_ip": (
                log_entry.ip_address if log_entry
                else ml_result.get("log", {}).get("source_ip", "unknown")
            ),
        }

        return self.create_alert(
            message=message,
            alert_type=f"ML:{threat}",
            severity=severity,
            details=details,
        )

    # ------------------------------------------------------------------
    # Notification dispatcher
    # ------------------------------------------------------------------

    def _send_all_notifications(self, alert: Alert) -> None:
        """Fire all configured notification channels. Runs in a daemon thread."""
        if self.email_enabled:
            self._send_email_alert(alert)
        if self.slack_url:
            self._send_slack_alert(alert)
        if self.webhook_url:
            self._send_generic_webhook(alert)
        if self.teams_url:
            self._send_teams_alert(alert)

    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------

    def _send_slack_alert(self, alert: Alert) -> None:
        """Post to a Slack incoming webhook URL."""
        try:
            import requests as _req
            severity_emoji = {
                "critical": ":rotating_light:",
                "high":     ":warning:",
                "medium":   ":large_yellow_circle:",
                "low":      ":large_blue_circle:",
                "info":     ":information_source:",
            }.get(alert.severity, ":bell:")

            payload = {
                "text": (
                    f"{severity_emoji} *Quorra SIEM Alert* "
                    f"[{alert.severity.upper()}]\n"
                    f"*Type:* {alert.alert_type}\n"
                    f"*Message:* {alert.message}\n"
                    f"*Time:* {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if alert.created_at else 'N/A'}"
                )
            }
            _req.post(self.slack_url, json=payload, timeout=5)
        except Exception as e:
            print(f"Slack notification failed: {e}")

    # ------------------------------------------------------------------
    # Generic webhook (JSON POST)
    # ------------------------------------------------------------------

    def _send_generic_webhook(self, alert: Alert) -> None:
        """POST alert data as JSON to a configurable webhook endpoint."""
        try:
            import requests as _req
            payload = {
                "source":      "QuorraSIEM",
                "alert_type":  alert.alert_type,
                "severity":    alert.severity,
                "message":     alert.message,
                "details":     json.loads(alert.details) if alert.details else {},
                "created_at":  alert.created_at.isoformat() if alert.created_at else None,
            }
            _req.post(self.webhook_url, json=payload, timeout=5)
        except Exception as e:
            print(f"Webhook notification failed: {e}")

    # ------------------------------------------------------------------
    # Microsoft Teams
    # ------------------------------------------------------------------

    def _send_teams_alert(self, alert: Alert) -> None:
        """Post an Adaptive Card to a Microsoft Teams incoming webhook."""
        try:
            import requests as _req
            color_map = {
                "critical": "attention",
                "high":     "warning",
                "medium":   "accent",
                "low":      "good",
                "info":     "default",
            }
            payload = {
                "@type":      "MessageCard",
                "@context":   "http://schema.org/extensions",
                "themeColor": {"critical": "FF0000", "high": "FF6600", "medium": "FFCC00",
                               "low": "00CC00", "info": "0078D4"}.get(alert.severity, "0078D4"),
                "summary":    f"Quorra SIEM Alert: {alert.alert_type}",
                "sections":   [{
                    "activityTitle":    f"**{alert.alert_type}** [{alert.severity.upper()}]",
                    "activitySubtitle": alert.message,
                    "facts": [
                        {"name": "Severity", "value": alert.severity.upper()},
                        {"name": "Time",     "value": alert.created_at.strftime(
                            "%Y-%m-%d %H:%M:%S UTC") if alert.created_at else "N/A"},
                    ],
                }],
            }
            _req.post(self.teams_url, json=payload, timeout=5)
        except Exception as e:
            print(f"Teams notification failed: {e}")

    # ------------------------------------------------------------------
    # Email (SMTP — disabled by default)
    # ------------------------------------------------------------------

    def _send_email_alert(self, alert: Alert) -> None:
>>>>>>> cea6978 (Reconnected project and updated files)
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
<<<<<<< HEAD
            
            # This is a placeholder - configure your email settings
            msg = MIMEMultipart()
            msg['From'] = 'quorra@localhost'
            msg['To'] = 'admin@localhost'
            msg['Subject'] = f"🚨 Quorra Alert: {alert.alert_type} - {alert.severity}"
            
=======

            smtp_host = os.environ.get("SMTP_HOST", "localhost")
            smtp_port = int(os.environ.get("SMTP_PORT", "587"))
            smtp_user = os.environ.get("SMTP_USER", "")
            smtp_pass = os.environ.get("SMTP_PASS", "")
            mail_from = os.environ.get("ALERT_FROM", "quorra@localhost")
            mail_to   = os.environ.get("ALERT_TO",   "admin@localhost")

            msg = MIMEMultipart()
            msg["From"]    = mail_from
            msg["To"]      = mail_to
            msg["Subject"] = f"[Quorra] {alert.alert_type} — {alert.severity.upper()}"

>>>>>>> cea6978 (Reconnected project and updated files)
            body = f"""
            <h2>Security Alert from Quorra SIEM</h2>
            <p><strong>Type:</strong> {alert.alert_type}</p>
            <p><strong>Severity:</strong> {alert.severity}</p>
            <p><strong>Message:</strong> {alert.message}</p>
            <p><strong>Time:</strong> {alert.created_at}</p>
<<<<<<< HEAD
            
            <h3>Details:</h3>
            <pre>{json.dumps(json.loads(alert.details), indent=2) if alert.details else 'No details'}</pre>
            
            <hr>
            <p><em>This is an automated alert from Quorra SIEM system.</em></p>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # This would need proper SMTP configuration
            # with smtplib.SMTP('localhost', 25) as server:
            #     server.send_message(msg)
            
            print(f"📧 Email alert prepared for: {alert.alert_type}")
            
        except Exception as e:
            print(f"Error preparing email alert: {e}")
    
    def acknowledge_alert(self, alert_id):
        """Acknowledge an alert."""
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                alert.acknowledged = True
                alert.read = True
=======
            <h3>Details:</h3>
            <pre>{json.dumps(json.loads(alert.details), indent=2) if alert.details else 'No details'}</pre>
            <hr><p><em>Automated alert from Quorra SIEM.</em></p>
            """
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                if smtp_user:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(mail_from, mail_to, msg.as_string())
        except Exception as e:
            print(f"Email alert failed: {e}")

    # ------------------------------------------------------------------
    # Acknowledge / read
    # ------------------------------------------------------------------

    def acknowledge_alert(self, alert_id: int) -> bool:
        try:
            alert = db.session.get(Alert, alert_id)
            if alert:
                alert.acknowledged = True
                alert.is_read = True
>>>>>>> cea6978 (Reconnected project and updated files)
                db.session.commit()
                return True
        except Exception as e:
            print(f"Error acknowledging alert: {e}")
<<<<<<< HEAD
        
        return False
    
    def mark_as_read(self, alert_id):
        """Mark an alert as read."""
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                alert.read = True
=======
            db.session.rollback()
        return False

    def mark_as_read(self, alert_id: int) -> bool:
        try:
            alert = db.session.get(Alert, alert_id)
            if alert:
                alert.is_read = True
>>>>>>> cea6978 (Reconnected project and updated files)
                db.session.commit()
                return True
        except Exception as e:
            print(f"Error marking alert as read: {e}")
<<<<<<< HEAD
        
        return False
    
    def get_unread_alerts(self):
        """Get all unread alerts."""
        return Alert.query.filter_by(read=False).order_by(Alert.created_at.desc()).all()
    
    def get_recent_alerts(self, count=10):
        """Get recent alerts."""
        return Alert.query.order_by(Alert.created_at.desc()).limit(count).all()
    
    def cleanup_old_alerts(self):
        """Clean up alerts older than retention period."""
        try:
            cutoff = datetime.utcnow() - timedelta(days=Config.ALERT_RETENTION_DAYS)
            old_alerts = Alert.query.filter(Alert.created_at < cutoff).all()
            
            for alert in old_alerts:
                db.session.delete(alert)
            
            db.session.commit()
            print(f"Cleaned up {len(old_alerts)} old alerts")
            
        except Exception as e:
            print(f"Error cleaning up old alerts: {e}")
=======
            db.session.rollback()
        return False

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_unread_alerts(self) -> list:
        return (Alert.query
                .filter_by(is_read=False)
                .order_by(Alert.created_at.desc())
                .all())

    def get_recent_alerts(self, count: int = 10) -> list:
        return Alert.query.order_by(Alert.created_at.desc()).limit(count).all()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_old_alerts(self) -> None:
        """Delete alerts older than ALERT_RETENTION_DAYS."""
        try:
            cutoff  = datetime.utcnow() - timedelta(days=Config.ALERT_RETENTION_DAYS)
            deleted = (Alert.query
                       .filter(Alert.created_at < cutoff)
                       .delete(synchronize_session=False))
            db.session.commit()
            print(f"Cleaned up {deleted} old alerts")
        except Exception as e:
            print(f"Error cleaning up old alerts: {e}")
            db.session.rollback()
>>>>>>> cea6978 (Reconnected project and updated files)
