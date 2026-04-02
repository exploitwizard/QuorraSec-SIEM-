from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event
from sqlalchemy.engine import Engine


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


# ---------------------------------------------------------------------------
# SQLite WAL mode
# Enabled on every new connection for better concurrent read/write performance
# on all platforms (Windows file locking issues are significantly reduced).
# ---------------------------------------------------------------------------
@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Apply SQLite performance and safety pragmas on every new connection."""
    try:
        cursor = dbapi_connection.cursor()
        # Write-Ahead Logging — improves concurrency; readers don't block writers
        cursor.execute("PRAGMA journal_mode=WAL")
        # Fsync only at checkpoints — safe and faster on all platforms
        cursor.execute("PRAGMA synchronous=NORMAL")
        # Keep temp tables in memory
        cursor.execute("PRAGMA temp_store=MEMORY")
        # 64 MB page cache
        cursor.execute("PRAGMA cache_size=-65536")
        cursor.close()
    except Exception:
        # Not a SQLite connection (e.g. PostgreSQL) — skip silently
        pass


def init_db(app):
    """Initialize the database with the Flask app context."""
    db.init_app(app)

    with app.app_context():
        from app.models import QuorraUser, LogEntry, Alert, Attack, IPBlocklist, CustomRule

        # Create all tables (safe to call even if they already exist)
        db.create_all()

        # Create default admin user if it does not exist
        from app.config import Config
        default_user = QuorraUser.query.filter_by(username=Config.QUORRA_USERNAME).first()
        if not default_user:
            default_user = QuorraUser(
                username=Config.QUORRA_USERNAME,
                is_admin=True,
                # Require password change on first login for the default account
                password_change_required=Config.FORCE_PASSWORD_CHANGE,
            )
            default_user.set_password(Config.QUORRA_PASSWORD)
            db.session.add(default_user)
            db.session.commit()
            print("Default Quorra user created")
