"""
Add indexes for fast log and alert queries.
Run once: python3 migrate_speed.py
Safe to re-run — uses CREATE INDEX IF NOT EXISTS.
"""
import sqlite3
import os

DB_PATH = os.environ.get('DB_PATH',
          os.path.join(os.path.dirname(__file__), 'data', 'courra-sec.db'))

INDEXES = [
    # Fast lookup of logs by org + timestamp (used on every page load)
    ("idx_log_entry_org_ts",
     "CREATE INDEX IF NOT EXISTS idx_log_entry_org_ts "
     "ON log_entry(organisation_id, timestamp DESC)"),

    # Fast ML backfill scan
    ("idx_log_entry_ml_analyzed",
     "CREATE INDEX IF NOT EXISTS idx_log_entry_ml_analyzed "
     "ON log_entry(ml_analyzed_at)"),

    # Fast org + ID lookup (log detail route)
    ("idx_log_entry_org_id",
     "CREATE INDEX IF NOT EXISTS idx_log_entry_org_id "
     "ON log_entry(organisation_id, id)"),

    # Fast API key lookup on every ingest
    ("idx_organisations_api_key",
     "CREATE INDEX IF NOT EXISTS idx_organisations_api_key "
     "ON organisations(api_key)"),

    # Fast alert queries by org
    ("idx_alert_org_created",
     "CREATE INDEX IF NOT EXISTS idx_alert_org_created "
     "ON alert(organisation_id, created_at DESC)"),

    # Fast attack queries by org
    ("idx_attack_org_detected",
     "CREATE INDEX IF NOT EXISTS idx_attack_org_detected "
     "ON attack(organisation_id, detected_at DESC)"),

    # Fast daily usage limit checks
    ("idx_api_key_usage_org_date",
     "CREATE INDEX IF NOT EXISTS idx_api_key_usage_org_date "
     "ON api_key_usage(organisation_id, date)"),
]


def migrate():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for name, sql in INDEXES:
        try:
            cursor.execute(sql)
            print(f"  Created index: {name}")
        except Exception as e:
            print(f"  Error on {name}: {e}")

    conn.commit()
    conn.close()
    print(f"\nIndex migration complete. {len(INDEXES)} indexes processed.")


if __name__ == '__main__':
    migrate()
