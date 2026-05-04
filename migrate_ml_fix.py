"""
Add ML result columns to log_entry table.
Safe to run multiple times — skips existing columns.
"""
import sqlite3
import os

DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'data', 'courra-sec.db'))

NEW_COLUMNS = [
    ("ml_risk_score",    "REAL"),
    ("ml_anomaly_score", "REAL"),
    ("ml_is_anomaly",    "INTEGER"),
    ("ml_ueba_flags",    "TEXT"),
    ("ml_attack_chains", "TEXT"),
    ("ml_analysis",      "TEXT"),
    ("ml_analyzed_at",   "DATETIME"),
    ("ml_model_version", "TEXT"),
]


def migrate():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(log_entry)")
    existing = {row[1] for row in cursor.fetchall()}

    added = []
    for col_name, col_type in NEW_COLUMNS:
        if col_name not in existing:
            cursor.execute(f"ALTER TABLE log_entry ADD COLUMN {col_name} {col_type}")
            added.append(col_name)
            print(f"  Added column: {col_name}")
        else:
            print(f"  Already exists: {col_name}")

    conn.commit()
    conn.close()

    print(f"\nMigration complete. Added {len(added)} column(s) to log_entry.")


if __name__ == '__main__':
    migrate()
