"""
Auto-migration for Courra-Sec SIEM.
Compares SQLAlchemy models against the live SQLite DB schema
and adds any missing columns using ALTER TABLE.
Runs at startup before any DB query. Safe to run repeatedly.
"""

import sqlite3
import logging
import os

logger = logging.getLogger(__name__)


# ── Master column registry ────────────────────────────────────────────────────
# Every column that has EVER been added to each model goes here.
# Format: (table_name, column_name, sqlite_type, default_sql)
# default_sql = None means NULL default (no DEFAULT clause)
#
# RULE: Only ADD entries here. Never remove old ones.
# This ensures every deployment gets every column it needs.

REQUIRED_COLUMNS = [

    # ── organisations ─────────────────────────────────────────────────────────
    ("organisations", "app_name",          "TEXT",    None),
    ("organisations", "app_url",           "TEXT",    None),
    ("organisations", "app_type",          "TEXT",    None),
    ("organisations", "max_users",         "INTEGER", "20"),
    ("organisations", "max_admins",        "INTEGER", "5"),
    ("organisations", "max_analysts",      "INTEGER", "10"),
    ("organisations", "max_readonly",      "INTEGER", "4"),
    ("organisations", "max_logs_per_day",  "INTEGER", "9999999"),
    ("organisations", "max_rules",         "INTEGER", "9999"),
    ("organisations", "max_playbooks",     "INTEGER", "9999"),
    ("organisations", "max_blocklist",     "INTEGER", "9999"),

    # ── log_entry ─────────────────────────────────────────────────────────────
    ("log_entry",     "ml_risk_score",     "REAL",    None),
    ("log_entry",     "ml_anomaly_score",  "REAL",    None),
    ("log_entry",     "ml_is_anomaly",     "INTEGER", None),
    ("log_entry",     "ml_ueba_flags",     "TEXT",    None),
    ("log_entry",     "ml_attack_chains",  "TEXT",    None),
    ("log_entry",     "ml_analysis",       "TEXT",    None),
    ("log_entry",     "ml_analyzed_at",    "DATETIME",None),
    ("log_entry",     "ml_model_version",  "TEXT",    None),

    # ── alert ─────────────────────────────────────────────────────────────────
    ("alert",         "ml_risk_score",     "REAL",    None),
    ("alert",         "ml_anomaly_score",  "REAL",    None),
    ("alert",         "ml_is_anomaly",     "INTEGER", None),
    ("alert",         "ml_ueba_flags",     "TEXT",    None),
    ("alert",         "ml_analysis",       "TEXT",    None),
    ("alert",         "is_read",           "INTEGER", "0"),
    ("alert",         "acknowledged",      "INTEGER", "0"),
    ("alert",         "acknowledged_by",   "INTEGER", None),
    ("alert",         "acknowledged_at",   "DATETIME",None),

    # ── attack ────────────────────────────────────────────────────────────────
    ("attack",        "ml_risk_score",     "REAL",    None),
    ("attack",        "ml_attack_chains",  "TEXT",    None),
    ("attack",        "log_id",            "INTEGER", None),

    # ── custom_rule ───────────────────────────────────────────────────────────
    ("custom_rule",   "rule_type",         "TEXT",    "'python'"),
    ("custom_rule",   "conditions",        "TEXT",    None),
    ("custom_rule",   "rule_definition",   "TEXT",    None),
    ("custom_rule",   "rule_code",         "TEXT",    None),
    ("custom_rule",   "action",            "TEXT",    "'alert'"),
    ("custom_rule",   "mitre_tactic",      "TEXT",    None),
    ("custom_rule",   "mitre_technique",   "TEXT",    None),
    ("custom_rule",   "is_tested",         "INTEGER", "0"),
    ("custom_rule",   "trigger_count",     "INTEGER", "0"),
    ("custom_rule",   "last_triggered",    "DATETIME",None),

    # ── organisation_settings ─────────────────────────────────────────────────
    # (table created by db.create_all if it doesn't exist)
    # columns added here if table already exists without them:
    ("organisation_settings", "python_dsl_sandbox",   "INTEGER", "1"),
    ("organisation_settings", "sandbox_changed_by",   "INTEGER", None),
    ("organisation_settings", "sandbox_changed_at",   "DATETIME",None),
    ("organisation_settings", "max_rule_execution_ms","INTEGER", "500"),

    # ── default_rule_overrides ────────────────────────────────────────────────
    ("default_rule_overrides", "is_active",      "INTEGER", "1"),
    ("default_rule_overrides", "notes",          "TEXT",    None),
    ("default_rule_overrides", "edited_at",      "DATETIME",None),
    ("default_rule_overrides", "edited_by",      "INTEGER", None),
    ("default_rule_overrides", "edited_by_name", "TEXT",    None),

    # ── users ─────────────────────────────────────────────────────────────────
    ("users",         "is_active",          "INTEGER", "1"),
    ("users",         "must_change_password","INTEGER", "0"),
    ("users",         "totp_secret",        "TEXT",    None),
    ("users",         "totp_enabled",       "INTEGER", "0"),
    ("users",         "last_login_at",      "DATETIME",None),
    ("users",         "last_login_ip",      "TEXT",    None),
    ("users",         "invite_token",       "TEXT",    None),
    ("users",         "invite_expires_at",  "DATETIME",None),
]


def get_db_path(app=None):
    """Locate the SQLite database file."""
    # Try Flask app config first
    if app:
        uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if uri.startswith('sqlite:///'):
            path = uri.replace('sqlite:///', '')
            if os.path.exists(path):
                return path

    # Try environment variables (both naming conventions used in this project)
    for env_var in ('DB_PATH', 'DATABASE_PATH'):
        env_path = os.environ.get(env_var, '')
        if env_path and os.path.exists(env_path):
            return env_path

    # Try common locations
    candidates = [
        'data/courra-sec.db',
        'data/courra.db',
        'data/quorra.db',
        'courra.db',
        'quorra.db',
        'data/database.db',
        'instance/courra.db',
    ]
    for c in candidates:
        if os.path.exists(c):
            return c

    return None


def get_existing_columns(cursor, table_name):
    """Return set of column names that exist in the table."""
    try:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return {row[1] for row in cursor.fetchall()}
    except Exception:
        return set()


def get_existing_tables(cursor):
    """Return set of table names that exist in the DB."""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )
    return {row[0] for row in cursor.fetchall()}


def run_migrations(app=None):
    """
    Compare REQUIRED_COLUMNS against the live DB and add
    any missing columns using ALTER TABLE.

    Called at app startup before any SQLAlchemy query runs.
    Safe to call repeatedly — skips existing columns.
    """
    db_path = get_db_path(app)
    if not db_path:
        logger.warning(
            "migrate.run_migrations: DB file not found yet — "
            "skipping column migration (db.create_all will run next)"
        )
        return

    try:
        conn   = sqlite3.connect(db_path)
        cursor = conn.cursor()

        existing_tables = get_existing_tables(cursor)
        added_count     = 0
        skipped_count   = 0

        for table, col, col_type, default_val in REQUIRED_COLUMNS:

            # Skip if the table doesn't exist yet
            # (db.create_all() will create it with all columns)
            if table not in existing_tables:
                continue

            existing_cols = get_existing_columns(cursor, table)
            if col in existing_cols:
                skipped_count += 1
                continue

            # Build ALTER TABLE statement
            try:
                if default_val is not None:
                    sql = (
                        f"ALTER TABLE {table} "
                        f"ADD COLUMN {col} {col_type} "
                        f"DEFAULT {default_val}"
                    )
                    cursor.execute(sql)
                    # Also backfill existing NULL rows
                    cursor.execute(
                        f"UPDATE {table} "
                        f"SET {col} = {default_val} "
                        f"WHERE {col} IS NULL"
                    )
                else:
                    sql = (
                        f"ALTER TABLE {table} "
                        f"ADD COLUMN {col} {col_type}"
                    )
                    cursor.execute(sql)

                added_count += 1
                logger.info(
                    "Migration: added %s.%s (%s DEFAULT %s)",
                    table, col, col_type, default_val,
                )

            except sqlite3.OperationalError as e:
                # Column may have been added by another process
                if 'duplicate column' in str(e).lower():
                    skipped_count += 1
                else:
                    logger.error("Migration error — %s.%s: %s", table, col, e)

        conn.commit()
        conn.close()

        if added_count > 0:
            logger.info(
                "Migration complete: %d column(s) added, %d already existed.",
                added_count, skipped_count,
            )
        else:
            logger.debug(
                "Migration: all columns present (%d checked).", skipped_count
            )

    except Exception as e:
        logger.error("Migration failed: %s", e)
        # NEVER crash the app — log and continue
        # db.create_all() will still run after this


def run_data_migrations(app=None):
    """
    One-time data fixes after column migration.
    - Set plan = 'open' for any legacy free/trial orgs
    - Ensure seat limits are not 0 or NULL
    """
    db_path = get_db_path(app)
    if not db_path:
        return

    try:
        conn   = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Update plan to 'open' for legacy orgs
        try:
            cursor.execute(
                "UPDATE organisations "
                "SET plan = 'open' "
                "WHERE plan IN ('free', 'trial') OR plan IS NULL"
            )
            if cursor.rowcount > 0:
                logger.info(
                    "Data migration: set plan='open' for %d org(s)",
                    cursor.rowcount,
                )
        except Exception as e:
            logger.debug("Plan update skipped: %s", e)

        # Ensure no org has 0 or negative seat limits
        try:
            cursor.execute(
                "UPDATE organisations SET max_users = 20 "
                "WHERE max_users IS NULL OR max_users < 1"
            )
            cursor.execute(
                "UPDATE organisations SET max_logs_per_day = 9999999 "
                "WHERE max_logs_per_day IS NULL OR max_logs_per_day < 1"
            )
        except Exception as e:
            logger.debug("Seat limit update skipped: %s", e)

        conn.commit()
        conn.close()

    except Exception as e:
        logger.error("Data migration failed: %s", e)
