#log_collector.py
import json
import requests
from datetime import datetime, timezone as _tz
import time
from app.config import Config
from app.database import db
from app.models import LogEntry, Organisation


class LogCollector:
    """Collect logs from Block Fortress application via authenticated API pull."""

    def __init__(self):
        self.block_fortress_url = Config.BLOCK_FORTRESS_URL
        self.ws_url = Config.BLOCK_FORTRESS_WS_URL
        self.last_fetch = None
        # Admin credentials for Block Fortress API (set via env)
        self._bf_username = getattr(Config, 'BLOCK_FORTRESS_ADMIN_USER', 'admin')
        self._bf_password = getattr(Config, 'BLOCK_FORTRESS_ADMIN_PASS', '')
        self._session = requests.Session()
        self._authenticated = False

    def _authenticate(self) -> bool:
        """Authenticate with Block Fortress and store the session cookie."""
        if not self._bf_password:
            return False
        try:
            resp = self._session.post(
                f"{self.block_fortress_url}/api/login",
                json={"username": self._bf_username, "password": self._bf_password},
                timeout=5,
            )
            data = resp.json()
            self._authenticated = bool(data.get("success"))
            return self._authenticated
        except Exception as e:
            print(f"Block Fortress auth failed: {e}")
            self._authenticated = False
            return False

    def fetch_logs_via_api(self, org_id: int):
        """Fetch security logs from Block Fortress admin API.

        Requires BLOCK_FORTRESS_ADMIN_PASS env var to be set.
        Returns a list of processed LogEntry objects.
        """
        # Need admin credentials to hit /api/admin/logs
        if not self._authenticated and not self._authenticate():
            print("Block Fortress: cannot fetch logs — no admin credentials configured")
            return []

        try:
            resp = self._session.get(
                f"{self.block_fortress_url}/api/admin/logs",
                timeout=5,
            )
            if resp.status_code == 401 or resp.status_code == 302:
                # Session expired — re-authenticate once
                self._authenticated = False
                if self._authenticate():
                    resp = self._session.get(
                        f"{self.block_fortress_url}/api/admin/logs",
                        timeout=5,
                    )
                else:
                    return []

            if resp.status_code == 200:
                logs = resp.json()
                if org_id and logs:
                    return self.process_logs(logs, org_id)
        except Exception as e:
            print(f"Error fetching logs via API: {e}")

        return []

    def process_logs(self, logs, org_id: int):
        """Process and store logs under a specific org."""
        processed_logs = []

        for log_data in logs:
            try:
                log_entry = LogEntry(
                    organisation_id=org_id,
                    ip_address=log_data.get('ipAddress', 'unknown'),
                    attack_type=log_data.get('attackType', 'unknown'),
                    endpoint=log_data.get('endpoint', 'unknown'),
                    payload=log_data.get('payload', '')[:1000],
                    user_agent=log_data.get('userAgent'),
                    severity=log_data.get('severity', 'medium'),
                    timestamp=(
                        datetime.fromisoformat(
                            log_data['timestamp'].replace('Z', '+00:00')
                        ).astimezone(_tz.utc).replace(tzinfo=None)
                        if log_data.get('timestamp') else datetime.utcnow()
                    ),
                    raw_data=json.dumps(log_data),
                )
                db.session.add(log_entry)
                processed_logs.append(log_entry)
            except Exception as e:
                print(f"Error processing log: {e}")

        if processed_logs:
            db.session.commit()

        return processed_logs

    def check_block_fortress_availability(self) -> bool:
        """Check if Block Fortress is reachable."""
        try:
            response = requests.get(
                f"{self.block_fortress_url}/api/products",
                timeout=3,
            )
            return response.status_code == 200
        except Exception:
            return False
