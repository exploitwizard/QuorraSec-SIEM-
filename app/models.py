from app.database import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


# =====================================================
<<<<<<< HEAD
# User Model (SINGLE SOURCE OF TRUTH)
=======
# User Model
>>>>>>> cea6978 (Reconnected project and updated files)
# =====================================================
class QuorraUser(db.Model):
    __tablename__ = "quorra_user"

<<<<<<< HEAD
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # 🔐 Password helpers
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
=======
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    is_admin  = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    last_login  = db.Column(db.DateTime)

    # -------------------------------------------------------
    # Force password change on first login (default account)
    # -------------------------------------------------------
    password_change_required = db.Column(db.Boolean, default=False)

    # -------------------------------------------------------
    # TOTP / 2FA  (opt-in per user)
    # -------------------------------------------------------
    totp_enabled = db.Column(db.Boolean, default=False)
    totp_secret  = db.Column(db.String(64), nullable=True)   # Base32 secret

    # Password helpers
    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # TOTP helpers
    def generate_totp_secret(self) -> str:
        """Generate and store a new TOTP secret. Returns the secret."""
        try:
            import pyotp
            self.totp_secret = pyotp.random_base32()
        except ImportError:
            import base64, secrets as _sec
            self.totp_secret = base64.b32encode(_sec.token_bytes(20)).decode()
        return self.totp_secret

    def get_totp_uri(self) -> str:
        """Return an otpauth:// URI for QR-code generation."""
        try:
            import pyotp
            from app.config import Config
            totp = pyotp.TOTP(self.totp_secret)
            return totp.provisioning_uri(name=self.username, issuer_name=Config.TOTP_ISSUER)
        except ImportError:
            return ""

    def verify_totp(self, code: str) -> bool:
        """Verify a TOTP code. Accepts current + adjacent windows for clock skew."""
        if not self.totp_secret or not code:
            return False
        try:
            import pyotp
            totp = pyotp.TOTP(self.totp_secret)
            return totp.verify(code, valid_window=1)
        except ImportError:
            return False

    def __repr__(self) -> str:
>>>>>>> cea6978 (Reconnected project and updated files)
        return f"<QuorraUser {self.username}>"


# =====================================================
# Log Entry Model
# =====================================================
class LogEntry(db.Model):
    __tablename__ = "log_entry"

<<<<<<< HEAD
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attack_type = db.Column(db.String(100))
    endpoint = db.Column(db.String(500))
    payload = db.Column(db.Text)
    user_agent = db.Column(db.Text)
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    raw_data = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "attack_type": self.attack_type,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat()
=======
    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attack_type = db.Column(db.String(100))
    endpoint   = db.Column(db.String(500))
    payload    = db.Column(db.Text)
    user_agent = db.Column(db.Text)
    severity   = db.Column(db.String(20))
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
    raw_data   = db.Column(db.Text)

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "ip_address":  self.ip_address,
            "attack_type": self.attack_type,
            "endpoint":    self.endpoint,
            "severity":    self.severity,
            "timestamp":   self.timestamp.isoformat() if self.timestamp else None,
>>>>>>> cea6978 (Reconnected project and updated files)
        }


# =====================================================
# Alert Model
# =====================================================
class Alert(db.Model):
    __tablename__ = "alert"

<<<<<<< HEAD
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    alert_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    details = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)  # ✅ renamed

    def to_dict(self):
        return {
            "id": self.id,
            "message": self.message,
            "severity": self.severity,
            "created_at": self.created_at.isoformat(),
            "acknowledged": self.acknowledged,
            "is_read": self.is_read
=======
    id         = db.Column(db.Integer, primary_key=True)
    message    = db.Column(db.Text, nullable=False)
    alert_type = db.Column(db.String(100))
    severity   = db.Column(db.String(20))
    details    = db.Column(db.Text)

    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    is_read      = db.Column(db.Boolean, default=False)

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "message":      self.message,
            "severity":     self.severity,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
            "acknowledged": self.acknowledged,
            "is_read":      self.is_read,
>>>>>>> cea6978 (Reconnected project and updated files)
        }


# =====================================================
# Attack Model
# =====================================================
class Attack(db.Model):
    __tablename__ = "attack"

<<<<<<< HEAD
    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))
    details = db.Column(db.Text)
    severity = db.Column(db.String(20))
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def get_statistics():
        from datetime import timedelta

        last_24h = datetime.utcnow() - timedelta(hours=24)

        by_type = dict(
            db.session.query(
                Attack.attack_type, db.func.count(Attack.id)
            ).group_by(Attack.attack_type).all()
        )

        return {
            "total": Attack.query.count(),
            "last_24h": Attack.query.filter(
                Attack.detected_at >= last_24h
            ).count(),
            "by_type": by_type
=======
    id          = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(100), nullable=False)
    ip_address  = db.Column(db.String(45))
    details     = db.Column(db.Text)
    severity    = db.Column(db.String(20))
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def get_statistics() -> dict:
        from datetime import timedelta
        last_24h = datetime.utcnow() - timedelta(hours=24)
        by_type  = dict(
            db.session.query(Attack.attack_type, db.func.count(Attack.id))
            .group_by(Attack.attack_type).all()
        )
        return {
            "total":    Attack.query.count(),
            "last_24h": Attack.query.filter(Attack.detected_at >= last_24h).count(),
            "by_type":  by_type,
>>>>>>> cea6978 (Reconnected project and updated files)
        }


# =====================================================
# IP Blocklist Model
# =====================================================
class IPBlocklist(db.Model):
    __tablename__ = "ip_blocklist"

<<<<<<< HEAD
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.Text)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.String(100))

    def to_dict(self):
        return {
            "ip_address": self.ip_address,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat()
=======
    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason     = db.Column(db.Text)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.String(100))

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "reason":     self.reason,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
        }


# =====================================================
# Custom Rule Model (three-level rule authoring)
# =====================================================
class CustomRule(db.Model):
    __tablename__ = "custom_rule"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

    # 1 = visual (builds into JSON), 2 = YAML/JSON, 3 = Python DSL
    level = db.Column(db.Integer, nullable=False, default=2)

    # Levels 1 & 2: rule stored as JSON
    rule_definition = db.Column(db.Text)

    # Level 3: raw Python source
    rule_python = db.Column(db.Text)

    # Settings
    enabled      = db.Column(db.Boolean, default=True)
    severity     = db.Column(db.String(20), default="medium")
    mitre_tactic = db.Column(db.String(100))
    action       = db.Column(db.String(20), default="alert")  # alert | block | alert_and_block
    block_ip     = db.Column(db.Boolean, default=False)

    # Authoring metadata
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Stats
    trigger_count  = db.Column(db.Integer, default=0)
    last_triggered = db.Column(db.DateTime)

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "name":            self.name,
            "description":     self.description,
            "level":           self.level,
            "rule_definition": self.rule_definition,
            "rule_python":     self.rule_python,
            "enabled":         self.enabled,
            "severity":        self.severity,
            "mitre_tactic":    self.mitre_tactic,
            "action":          self.action,
            "block_ip":        self.block_ip,
            "created_by":      self.created_by,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
            "updated_at":      self.updated_at.isoformat() if self.updated_at else None,
            "trigger_count":   self.trigger_count,
            "last_triggered":  self.last_triggered.isoformat() if self.last_triggered else None,
>>>>>>> cea6978 (Reconnected project and updated files)
        }
