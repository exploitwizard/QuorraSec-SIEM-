<<<<<<< HEAD
import json
import requests
from datetime import datetime
=======
#log_collector.py
import json
import requests
from datetime import datetime, timezone as _tz
>>>>>>> cea6978 (Reconnected project and updated files)
import time
from app.config import Config
from app.database import db
from app.models import LogEntry

class LogCollector:
    """Collect logs from Block Fortress application."""
    
    def __init__(self):
        self.block_fortress_url = Config.BLOCK_FORTRESS_URL
        self.ws_url = Config.BLOCK_FORTRESS_WS_URL
        self.last_fetch = None
    
    def fetch_logs_via_api(self):
        """Fetch logs from Block Fortress API."""
        try:
            # Try to get logs from Block Fortress API
            response = requests.get(f"{self.block_fortress_url}/api/admin/logs", timeout=5)
            if response.status_code == 200:
                logs = response.json()
                return self.process_logs(logs)
        except Exception as e:
            print(f"Error fetching logs via API: {e}")
        
        return []
    
    def process_logs(self, logs):
        """Process and store logs."""
        processed_logs = []
        
        for log_data in logs:
            try:
                # Create log entry
                log_entry = LogEntry(
                    ip_address=log_data.get('ipAddress', 'unknown'),
                    attack_type=log_data.get('attackType', 'unknown'),
                    endpoint=log_data.get('endpoint', 'unknown'),
                    payload=log_data.get('payload', '')[:1000],
                    user_agent=log_data.get('userAgent'),
                    severity=log_data.get('severity', 'medium'),
<<<<<<< HEAD
                    timestamp=datetime.fromisoformat(log_data.get('timestamp').replace('Z', '+00:00')) 
=======
                    timestamp=datetime.fromisoformat(log_data.get('timestamp').replace('Z', '+00:00')).astimezone(_tz.utc).replace(tzinfo=None)
>>>>>>> cea6978 (Reconnected project and updated files)
                    if log_data.get('timestamp') else datetime.utcnow(),
                    raw_data=json.dumps(log_data)
                )
                
                db.session.add(log_entry)
                processed_logs.append(log_entry)
                
            except Exception as e:
                print(f"Error processing log: {e}")
        
        if processed_logs:
            db.session.commit()
        
        return processed_logs
    
    def simulate_test_logs(self):
        """Generate simulated logs for testing when Block Fortress is not available."""
<<<<<<< HEAD
        print("⚠️  Block Fortress not available. Generating test logs...")
=======
        print("Warning: Block Fortress not available. Generating test logs...")
>>>>>>> cea6978 (Reconnected project and updated files)
        
        test_logs = [
            {
                'ipAddress': '192.168.1.100',
                'attackType': 'SQL Injection Attempt',
                'endpoint': '/api/login',
                'payload': 'username=admin\' OR \'1\'=\'1&password=test',
                'userAgent': 'Mozilla/5.0 (Test)',
                'severity': 'high',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'ipAddress': '10.0.0.50',
                'attackType': 'Brute Force Attempt',
                'endpoint': '/api/login',
                'payload': 'username=admin&password=password123',
                'userAgent': 'Python/3.9',
                'severity': 'medium',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'ipAddress': '172.16.0.25',
                'attackType': 'XSS Attack',
                'endpoint': '/api/contact',
                'payload': 'name=<script>alert(1)</script>&email=test@test.com',
                'userAgent': 'Mozilla/5.0 (Attack)',
                'severity': 'high',
                'timestamp': datetime.utcnow().isoformat()
            }
        ]
        
        return self.process_logs(test_logs)
    
    def check_block_fortress_availability(self):
        """Check if Block Fortress is available."""
        try:
            response = requests.get(f"{self.block_fortress_url}/api/products", timeout=3)
            return response.status_code == 200
        except:
            return False