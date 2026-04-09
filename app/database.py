from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event, text
from sqlalchemy.engine import Engine


def _add_column_if_missing(db, table: str, column: str, col_def: str):
    """Safely add a column to an existing SQLite table if it doesn't already exist."""
    try:
        rows = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
        existing = [r[1] for r in rows]
        if column not in existing:
            db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
            db.session.commit()
    except Exception:
        db.session.rollback()


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


# ---------------------------------------------------------------------------
# SQLite WAL mode
# ---------------------------------------------------------------------------
@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA cache_size=-65536")
        cursor.close()
    except Exception:
        pass


def init_db(app):
    """Initialize the database with the Flask app context."""
    db.init_app(app)

    with app.app_context():
        from app.models import (
            Organisation, CourraSecUser, LogEntry, Alert, Attack,
            IPBlocklist, CustomRule, SoarAction, ApiKeyUsage,
            # v3.0 new models
            CorrelationRule, Case, CaseItem, ThreatIndicator,
            SuppressionRule, AuditLog, Playbook, PlaybookRun,
            Asset, ScheduledReport, OrgIPAllowlist,
        )

        # Create all tables
        db.create_all()

        # ---------------------------------------------------------------------------
        # Incremental column migrations (ALTER TABLE for existing databases)
        # SQLite does not support IF NOT EXISTS on ADD COLUMN, so we check first.
        # ---------------------------------------------------------------------------
        _add_column_if_missing(db, 'log_entry', 'suppressed', 'BOOLEAN DEFAULT 0')

        # Create default organisation and owner if none exists
        import secrets as _sec
        default_org = Organisation.query.filter_by(slug='default').first()
        if not default_org:
            from app.config import Config
            api_key = 'qrr_live_' + _sec.token_urlsafe(32)
            default_org = Organisation(
                name='Default Organisation',
                slug='default',
                api_key=api_key,
                api_key_prefix='qrr_live_',
                owner_email=Config.COURRA_SEC_USERNAME + '@localhost',
                plan='free',
                status='active',
            )
            db.session.add(default_org)
            db.session.flush()  # get the id

            # Create default admin user
            default_user = CourraSecUser.query.filter_by(
                organisation_id=default_org.id,
                username=Config.COURRA_SEC_USERNAME
            ).first()
            if not default_user:
                default_user = CourraSecUser(
                    organisation_id=default_org.id,
                    username=Config.COURRA_SEC_USERNAME,
                    email=Config.COURRA_SEC_USERNAME + '@localhost',
                    role='owner',
                    is_admin=True,
                    must_change_password=Config.FORCE_PASSWORD_CHANGE,
                    password_change_required=Config.FORCE_PASSWORD_CHANGE,
                )
                default_user.set_password(Config.COURRA_SEC_PASSWORD)
                db.session.add(default_user)

            db.session.commit()
            print(f"Default org created. API key: {api_key}")
        else:
            # Ensure existing users that lack organisation_id are assigned
            from app.config import Config
            orphan_users = CourraSecUser.query.filter_by(organisation_id=None).all()
            for u in orphan_users:
                u.organisation_id = default_org.id
                u.role = 'owner'
                if not u.email:
                    u.email = u.username + '@localhost'
            if orphan_users:
                db.session.commit()
