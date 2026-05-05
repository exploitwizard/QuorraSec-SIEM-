# ═══════════════════════════════════════════════════════════════════════════════
# DEVELOPER RULE — ADDING NEW COLUMNS
# ═══════════════════════════════════════════════════════════════════════════════
# When you add a new db.Column() to ANY model in this file:
#
# 1. Add the column to the model class (you already did this)
#
# 2. ALSO add it to REQUIRED_COLUMNS in app/migrate.py
#    Format: ("table_name", "column_name", "SQLITE_TYPE", default)
#    Example: ("organisations", "my_new_col", "TEXT", None)
#
# 3. NEVER rely on db.create_all() to add columns to existing tables —
#    it only creates NEW tables, never alters existing ones.
#
# 4. The migration runs automatically at startup via init_db() so existing
#    deployments get the column on next restart.
# ═══════════════════════════════════════════════════════════════════════════════

from app.database import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


# =====================================================
# Organisation Model (Tenant)
# =====================================================
class Organisation(db.Model):
    __tablename__ = 'organisations'

    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(120), nullable=False)
    slug           = db.Column(db.String(60), unique=True, nullable=False)
    plan           = db.Column(db.String(20), default='open')   # open (no restrictions)
    status         = db.Column(db.String(20), default='active')  # active / suspended

    # SDK credentials
    api_key        = db.Column(db.String(64), unique=True, nullable=False)
    api_key_prefix = db.Column(db.String(10), nullable=False, default='qrr_live_')

    # Contact
    owner_email    = db.Column(db.String(120), nullable=False)

    # Connected application info
    app_name       = db.Column(db.String(120), nullable=True)
    app_url        = db.Column(db.String(255), nullable=True)
    app_type       = db.Column(db.String(50),  nullable=True)

    # Seat limits — 20 total, owner allocates by role
    max_users         = db.Column(db.Integer, default=20)
    max_admins        = db.Column(db.Integer, default=5)
    max_analysts      = db.Column(db.Integer, default=10)
    max_readonly      = db.Column(db.Integer, default=4)

    # No log or rule limits — open source
    max_logs_per_day  = db.Column(db.Integer, default=9999999)
    max_rules         = db.Column(db.Integer, default=9999)

    # Timestamps
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    last_active  = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    users    = db.relationship('CourraSecUser', backref='organisation', lazy=True)
    logs     = db.relationship('LogEntry',   backref='organisation', lazy=True)
    alerts   = db.relationship('Alert',      backref='organisation', lazy=True)
    attacks  = db.relationship('Attack',     backref='organisation', lazy=True)

    def __repr__(self):
        return f"<Organisation {self.slug}>"


# =====================================================
# User Model (updated for multi-tenancy)
# =====================================================
class CourraSecUser(db.Model):
    __tablename__ = 'users'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False)
    username        = db.Column(db.String(80), nullable=False)
    email           = db.Column(db.String(120), nullable=False)
    password_hash   = db.Column(db.String(256), nullable=False)

    # Role within organisation
    role = db.Column(db.String(20), default='analyst')  # owner / admin / analyst / readonly

    # Auth
    is_active            = db.Column(db.Boolean, default=True)
    totp_secret          = db.Column(db.String(64), nullable=True)
    totp_enabled         = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=True)

    # Legacy compat fields
    is_admin                 = db.Column(db.Boolean, default=False)
    password_change_required = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Full name
    full_name = db.Column(db.String(120), nullable=True)

    # Unique per organisation (not globally unique)
    __table_args__ = (
        db.UniqueConstraint('organisation_id', 'username', name='uq_org_username'),
        db.UniqueConstraint('organisation_id', 'email',    name='uq_org_email'),
    )

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------
    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # ------------------------------------------------------------------
    # TOTP helpers
    # ------------------------------------------------------------------
    def generate_totp_secret(self) -> str:
        try:
            import pyotp
            self.totp_secret = pyotp.random_base32()
        except ImportError:
            import base64, secrets as _sec
            self.totp_secret = base64.b32encode(_sec.token_bytes(20)).decode()
        return self.totp_secret

    def get_totp_uri(self) -> str:
        try:
            import pyotp
            from app.config import Config
            totp = pyotp.TOTP(self.totp_secret)
            return totp.provisioning_uri(name=self.username, issuer_name=Config.TOTP_ISSUER)
        except ImportError:
            return ""

    def verify_totp(self, code: str) -> bool:
        if not self.totp_secret or not code:
            return False
        try:
            import pyotp
            totp = pyotp.TOTP(self.totp_secret)
            return totp.verify(code, valid_window=1)
        except ImportError:
            return False

    def __repr__(self) -> str:
        return f"<CourraSecUser {self.username}>"


# =====================================================
# Log Entry Model (tenant-scoped)
# =====================================================
class LogEntry(db.Model):
    __tablename__ = "log_entry"

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    ip_address      = db.Column(db.String(45), nullable=False)
    attack_type     = db.Column(db.String(100))
    endpoint        = db.Column(db.String(500))
    payload         = db.Column(db.Text)
    user_agent      = db.Column(db.Text)
    severity        = db.Column(db.String(20))
    timestamp       = db.Column(db.DateTime, default=datetime.utcnow)
    raw_data        = db.Column(db.Text)
    suppressed      = db.Column(db.Boolean, default=False)

    # ML Analysis Results — populated by background ML pipeline after ingest
    ml_risk_score    = db.Column(db.Float,    nullable=True)
    ml_anomaly_score = db.Column(db.Float,    nullable=True)
    ml_is_anomaly    = db.Column(db.Boolean,  nullable=True)
    ml_ueba_flags    = db.Column(db.Text,     nullable=True)  # JSON list
    ml_attack_chains = db.Column(db.Text,     nullable=True)  # JSON list
    ml_analysis      = db.Column(db.Text,     nullable=True)  # full JSON
    ml_analyzed_at   = db.Column(db.DateTime, nullable=True)
    ml_model_version = db.Column(db.String(20), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "ip_address":      self.ip_address,
            "attack_type":     self.attack_type,
            "endpoint":        self.endpoint,
            "payload":         self.payload,
            "user_agent":      self.user_agent,
            "severity":        self.severity,
            "timestamp":       self.timestamp.isoformat() if self.timestamp else None,
            "raw_data":        self.raw_data,
            "suppressed":      self.suppressed,
            "ml_risk_score":   self.ml_risk_score,
            "ml_anomaly_score":self.ml_anomaly_score,
            "ml_is_anomaly":   self.ml_is_anomaly,
            "ml_analyzed_at":  self.ml_analyzed_at.isoformat() if self.ml_analyzed_at else None,
        }


# =====================================================
# Alert Model (tenant-scoped)
# =====================================================
class Alert(db.Model):
    __tablename__ = "alert"

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    message         = db.Column(db.Text, nullable=False)
    alert_type      = db.Column(db.String(100))
    severity        = db.Column(db.String(20))
    details         = db.Column(db.Text)

    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    is_read      = db.Column(db.Boolean, default=False)

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "message":      self.message,
            "alert_type":   self.alert_type,
            "severity":     self.severity,
            "details":      self.details,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
            "acknowledged": self.acknowledged,
            "is_read":      self.is_read,
        }


# =====================================================
# Attack Model (tenant-scoped)
# =====================================================
class Attack(db.Model):
    __tablename__ = "attack"

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    attack_type     = db.Column(db.String(100), nullable=False)
    ip_address      = db.Column(db.String(45))
    details         = db.Column(db.Text)
    severity        = db.Column(db.String(20))
    detected_at     = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def get_statistics(org_id: int) -> dict:
        from datetime import timedelta
        last_24h = datetime.utcnow() - timedelta(hours=24)
        by_type = dict(
            db.session.query(Attack.attack_type, db.func.count(Attack.id))
            .filter_by(organisation_id=org_id)
            .group_by(Attack.attack_type).all()
        )
        return {
            "total":    Attack.query.filter_by(organisation_id=org_id).count(),
            "last_24h": Attack.query.filter_by(organisation_id=org_id)
                              .filter(Attack.detected_at >= last_24h).count(),
            "by_type":  by_type,
        }


# =====================================================
# IP Blocklist Model (tenant-scoped)
# =====================================================
class IPBlocklist(db.Model):
    __tablename__ = "ip_blocklist"

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    ip_address      = db.Column(db.String(45), nullable=False)
    reason          = db.Column(db.Text)
    blocked_at      = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by      = db.Column(db.String(100))

    # Unique per org, not globally
    __table_args__ = (
        db.UniqueConstraint('organisation_id', 'ip_address', name='uq_org_ip'),
    )

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "reason":     self.reason,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
        }


# =====================================================
# Custom Rule Model (tenant-scoped)
# =====================================================
class CustomRule(db.Model):
    __tablename__ = "custom_rule"

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    name            = db.Column(db.String(200), nullable=False)
    description     = db.Column(db.Text)

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
        }


# =====================================================
# SOAR Action Model
# =====================================================
class SoarAction(db.Model):
    __tablename__ = 'soar_actions'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    action_type     = db.Column(db.String(50))   # block_ip, send_slack, create_ticket
    triggered_by    = db.Column(db.String(50))   # rule name or playbook name
    target          = db.Column(db.String(120))  # IP or user affected
    result          = db.Column(db.String(20))   # success / failed
    details         = db.Column(db.Text)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)


# =====================================================
# API Key Usage Model (daily rate limiting per org)
# =====================================================
class ApiKeyUsage(db.Model):
    __tablename__ = 'api_key_usage'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False)
    date            = db.Column(db.Date, nullable=False)
    log_count       = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('organisation_id', 'date', name='uq_org_date'),
    )


# =====================================================
# Correlation Rule Model
# =====================================================
class CorrelationRule(db.Model):
    __tablename__ = 'correlation_rule'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    name            = db.Column(db.String(200), nullable=False)
    description     = db.Column(db.Text)

    # JSON list of condition dicts: [{field, op, value}]
    conditions      = db.Column(db.Text)
    # Grouping field — events are correlated per value of this field (e.g. "ip_address")
    group_by        = db.Column(db.String(50), default='ip_address')
    time_window     = db.Column(db.Integer, default=300)   # seconds
    min_events      = db.Column(db.Integer, default=2)

    severity        = db.Column(db.String(20), default='high')
    mitre_tactic    = db.Column(db.String(100))
    action          = db.Column(db.String(20), default='alert')  # alert | block | alert_and_block
    enabled         = db.Column(db.Boolean, default=True)

    created_by      = db.Column(db.String(100))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    trigger_count   = db.Column(db.Integer, default=0)
    last_triggered  = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id':           self.id,
            'name':         self.name,
            'description':  self.description,
            'conditions':   self.conditions,
            'group_by':     self.group_by,
            'time_window':  self.time_window,
            'min_events':   self.min_events,
            'severity':     self.severity,
            'mitre_tactic': self.mitre_tactic,
            'action':       self.action,
            'enabled':      self.enabled,
            'trigger_count':self.trigger_count,
            'last_triggered': self.last_triggered.isoformat() if self.last_triggered else None,
            'created_at':   self.created_at.isoformat() if self.created_at else None,
        }


# =====================================================
# Case Management Models
# =====================================================
class Case(db.Model):
    __tablename__ = 'case'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    title           = db.Column(db.String(300), nullable=False)
    description     = db.Column(db.Text)

    status          = db.Column(db.String(20), default='open')      # open / in_progress / resolved / closed
    priority        = db.Column(db.String(20), default='medium')    # critical / high / medium / low

    assigned_to_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_by_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    tags            = db.Column(db.Text)                            # JSON list
    mitre_tactic    = db.Column(db.String(100))

    sla_deadline    = db.Column(db.DateTime)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at       = db.Column(db.DateTime)

    items           = db.relationship('CaseItem', backref='case', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id':           self.id,
            'title':        self.title,
            'description':  self.description,
            'status':       self.status,
            'priority':     self.priority,
            'tags':         self.tags,
            'mitre_tactic': self.mitre_tactic,
            'sla_deadline': self.sla_deadline.isoformat() if self.sla_deadline else None,
            'created_at':   self.created_at.isoformat() if self.created_at else None,
            'updated_at':   self.updated_at.isoformat() if self.updated_at else None,
            'closed_at':    self.closed_at.isoformat() if self.closed_at else None,
        }


class CaseItem(db.Model):
    __tablename__ = 'case_item'

    id          = db.Column(db.Integer, primary_key=True)
    case_id     = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    item_type   = db.Column(db.String(20), nullable=False)  # alert / log / note / ioc
    item_id     = db.Column(db.Integer)                     # references alert/log id
    note        = db.Column(db.Text)
    added_by    = db.Column(db.String(100))
    added_at    = db.Column(db.DateTime, default=datetime.utcnow)


# =====================================================
# Threat Intelligence Indicator (IOC)
# =====================================================
class ThreatIndicator(db.Model):
    __tablename__ = 'threat_indicator'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)

    indicator_type  = db.Column(db.String(20), nullable=False)  # ip / domain / hash / url / email
    value           = db.Column(db.String(500), nullable=False)
    source          = db.Column(db.String(100))                 # OTX / VirusTotal / MISP / manual
    confidence      = db.Column(db.Integer, default=50)         # 0-100
    tags            = db.Column(db.Text)                        # JSON list
    description     = db.Column(db.Text)

    malware_family  = db.Column(db.String(200))
    threat_type     = db.Column(db.String(100))

    first_seen      = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen       = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at      = db.Column(db.DateTime)
    is_active       = db.Column(db.Boolean, default=True)

    hit_count       = db.Column(db.Integer, default=0)
    last_hit        = db.Column(db.DateTime)

    __table_args__ = (
        db.UniqueConstraint('organisation_id', 'indicator_type', 'value', name='uq_org_ioc'),
    )

    def to_dict(self):
        return {
            'id':             self.id,
            'indicator_type': self.indicator_type,
            'value':          self.value,
            'source':         self.source,
            'confidence':     self.confidence,
            'tags':           self.tags,
            'description':    self.description,
            'malware_family': self.malware_family,
            'threat_type':    self.threat_type,
            'first_seen':     self.first_seen.isoformat() if self.first_seen else None,
            'expires_at':     self.expires_at.isoformat() if self.expires_at else None,
            'is_active':      self.is_active,
            'hit_count':      self.hit_count,
        }


# =====================================================
# Suppression Rule
# =====================================================
class SuppressionRule(db.Model):
    __tablename__ = 'suppression_rule'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    name            = db.Column(db.String(200), nullable=False)
    description     = db.Column(db.Text)
    # JSON list of {field, op, value} conditions — all must match to suppress
    conditions      = db.Column(db.Text)
    enabled         = db.Column(db.Boolean, default=True)
    expires_at      = db.Column(db.DateTime)
    created_by      = db.Column(db.String(100))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    hit_count       = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id':          self.id,
            'name':        self.name,
            'description': self.description,
            'conditions':  self.conditions,
            'enabled':     self.enabled,
            'expires_at':  self.expires_at.isoformat() if self.expires_at else None,
            'created_by':  self.created_by,
            'created_at':  self.created_at.isoformat() if self.created_at else None,
            'hit_count':   self.hit_count,
        }


# =====================================================
# Organisation Settings (per-tenant security config)
# =====================================================
class OrganisationSettings(db.Model):
    __tablename__ = 'organisation_settings'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(
        db.Integer,
        db.ForeignKey('organisations.id'),
        unique=True,
        nullable=False,
    )

    # Python DSL sandbox toggle.
    # True  = sandbox ON  (default, RestrictedPython — secure)
    # False = sandbox OFF (plain exec — full Python, admin only)
    python_dsl_sandbox    = db.Column(db.Boolean, default=True)

    # Audit trail for sandbox changes
    sandbox_changed_by    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    sandbox_changed_at    = db.Column(db.DateTime, nullable=True)

    max_rule_execution_ms = db.Column(db.Integer, default=500)

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# =====================================================
# Audit Log
# =====================================================
class AuditLog(db.Model):
    __tablename__ = 'audit_log'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=True, index=True)
    user_id         = db.Column(db.Integer, nullable=True)
    username        = db.Column(db.String(80))
    action          = db.Column(db.String(100), nullable=False)
    resource_type   = db.Column(db.String(50))
    resource_id     = db.Column(db.String(100))
    details         = db.Column(db.Text)   # JSON
    ip_address      = db.Column(db.String(45))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':            self.id,
            'username':      self.username,
            'action':        self.action,
            'resource_type': self.resource_type,
            'resource_id':   self.resource_id,
            'details':       self.details,
            'ip_address':    self.ip_address,
            'created_at':    self.created_at.isoformat() if self.created_at else None,
        }


# =====================================================
# Playbook (automated SOAR)
# =====================================================
class Playbook(db.Model):
    __tablename__ = 'playbook'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    name            = db.Column(db.String(200), nullable=False)
    description     = db.Column(db.Text)
    # JSON: {severity: ['high','critical'], alert_type: 'bruteforce', rule_name: '...'}
    trigger_on      = db.Column(db.Text)
    # JSON ordered list of action dicts: [{type: 'block_ip'}, {type: 'send_slack', message: '...'}]
    actions         = db.Column(db.Text)
    enabled         = db.Column(db.Boolean, default=True)
    created_by      = db.Column(db.String(100))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    run_count       = db.Column(db.Integer, default=0)
    last_run        = db.Column(db.DateTime)

    runs            = db.relationship('PlaybookRun', backref='playbook', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id':          self.id,
            'name':        self.name,
            'description': self.description,
            'trigger_on':  self.trigger_on,
            'actions':     self.actions,
            'enabled':     self.enabled,
            'run_count':   self.run_count,
            'last_run':    self.last_run.isoformat() if self.last_run else None,
            'created_at':  self.created_at.isoformat() if self.created_at else None,
        }


class PlaybookRun(db.Model):
    __tablename__ = 'playbook_run'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    playbook_id     = db.Column(db.Integer, db.ForeignKey('playbook.id'), nullable=False)
    triggered_by    = db.Column(db.String(200))    # alert_id or rule name
    status          = db.Column(db.String(20), default='running')   # running / success / failed
    execution_log   = db.Column(db.Text)           # JSON list of step results
    started_at      = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at    = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id':           self.id,
            'playbook_id':  self.playbook_id,
            'triggered_by': self.triggered_by,
            'status':       self.status,
            'execution_log':self.execution_log,
            'started_at':   self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


# =====================================================
# Asset Inventory
# =====================================================
class Asset(db.Model):
    __tablename__ = 'asset'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    hostname        = db.Column(db.String(253))
    ip_address      = db.Column(db.String(45))
    mac_address     = db.Column(db.String(17))
    asset_type      = db.Column(db.String(50), default='server')  # server / workstation / network / cloud / mobile
    os              = db.Column(db.String(100))
    os_version      = db.Column(db.String(100))
    owner           = db.Column(db.String(120))
    department      = db.Column(db.String(120))
    criticality     = db.Column(db.String(20), default='medium')  # critical / high / medium / low
    tags            = db.Column(db.Text)   # JSON list
    notes           = db.Column(db.Text)
    first_seen      = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen       = db.Column(db.DateTime, default=datetime.utcnow)
    is_active       = db.Column(db.Boolean, default=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':          self.id,
            'hostname':    self.hostname,
            'ip_address':  self.ip_address,
            'mac_address': self.mac_address,
            'asset_type':  self.asset_type,
            'os':          self.os,
            'owner':       self.owner,
            'department':  self.department,
            'criticality': self.criticality,
            'tags':        self.tags,
            'first_seen':  self.first_seen.isoformat() if self.first_seen else None,
            'last_seen':   self.last_seen.isoformat() if self.last_seen else None,
            'is_active':   self.is_active,
        }


# =====================================================
# Scheduled Report
# =====================================================
class ScheduledReport(db.Model):
    __tablename__ = 'scheduled_report'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    name            = db.Column(db.String(200), nullable=False)
    report_type     = db.Column(db.String(50))   # executive_summary / compliance / attack_summary / full_export
    schedule        = db.Column(db.String(20))   # daily / weekly / monthly
    format          = db.Column(db.String(10), default='csv')  # csv / json
    recipients      = db.Column(db.Text)         # JSON list of emails
    enabled         = db.Column(db.Boolean, default=True)
    last_run        = db.Column(db.DateTime)
    next_run        = db.Column(db.DateTime)
    created_by      = db.Column(db.String(100))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':          self.id,
            'name':        self.name,
            'report_type': self.report_type,
            'schedule':    self.schedule,
            'format':      self.format,
            'recipients':  self.recipients,
            'enabled':     self.enabled,
            'last_run':    self.last_run.isoformat() if self.last_run else None,
            'next_run':    self.next_run.isoformat() if self.next_run else None,
        }


# =====================================================
# Org IP Allowlist
# =====================================================
class OrgIPAllowlist(db.Model):
    __tablename__ = 'org_ip_allowlist'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False, index=True)
    ip_cidr         = db.Column(db.String(50), nullable=False)   # single IP or CIDR
    description     = db.Column(db.Text)
    created_by      = db.Column(db.String(100))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('organisation_id', 'ip_cidr', name='uq_org_allowlist_ip'),
    )

    def to_dict(self):
        return {
            'id':          self.id,
            'ip_cidr':     self.ip_cidr,
            'description': self.description,
            'created_by':  self.created_by,
            'created_at':  self.created_at.isoformat() if self.created_at else None,
        }


# =====================================================
# Default Rule Override (admin enable/disable/annotate
# the 5 built-in detection rules per organisation)
# =====================================================
class DefaultRuleOverride(db.Model):
    __tablename__ = 'default_rule_overrides'

    id              = db.Column(db.Integer, primary_key=True)
    organisation_id = db.Column(db.Integer,
                        db.ForeignKey('organisations.id'),
                        nullable=False)
    rule_id         = db.Column(db.String(80), nullable=False)
    is_active       = db.Column(db.Boolean, default=True)
    notes           = db.Column(db.Text, nullable=True)
    edited_at       = db.Column(db.DateTime,
                        default=datetime.utcnow)
    edited_by       = db.Column(db.Integer,
                        db.ForeignKey('users.id'),
                        nullable=True)
    edited_by_name  = db.Column(db.String(80), nullable=True)

    __table_args__ = (
        db.UniqueConstraint('organisation_id', 'rule_id',
                            name='uq_default_rule_override_org_rule'),
        db.Index('idx_default_rule_overrides_org', 'organisation_id'),
    )
