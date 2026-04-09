"""
migrate.py — Run ONCE to migrate existing single-tenant data to multi-tenant schema.
Creates a "default" organisation and assigns all orphaned rows to it.

Usage:
    python3 migrate.py
"""
import os
import secrets
import sys

# Ensure app package is on path
sys.path.insert(0, os.path.dirname(__file__))


def migrate():
    from app.main import app
    from app.database import db
    from app.models import (
        Organisation, CourraSecUser, LogEntry, Alert,
        Attack, IPBlocklist, CustomRule, SoarAction, ApiKeyUsage,
    )

    with app.app_context():
        # Create any new tables (idempotent)
        db.create_all()
        print("Schema up to date.")

        # ── SQL-level: add organisation_id to legacy tables if missing ─────
        from sqlalchemy import text
        legacy_tables = ['log_entry', 'alert', 'attack', 'ip_blocklist', 'custom_rule']
        for table in legacy_tables:
            try:
                db.session.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN organisation_id INTEGER REFERENCES organisations(id)")
                )
                db.session.commit()
                print(f"Added organisation_id to {table}")
            except Exception:
                db.session.rollback()  # column already exists or other error — safe to ignore

        # ── Ensure default organisation exists ────────────────────────────
        default_org = Organisation.query.filter_by(slug='default').first()
        if not default_org:
            api_key = 'qrr_live_' + secrets.token_urlsafe(32)
            default_org = Organisation(
                name='Default Organisation',
                slug='default',
                api_key=api_key,
                api_key_prefix='qrr_live_',
                owner_email='admin@localhost',
                plan='free',
                status='active',
            )
            db.session.add(default_org)
            db.session.flush()
            print(f"Created default organisation  (API key: {api_key})")
        else:
            print(f"Default organisation already exists (id={default_org.id})")

        org_id = default_org.id

        # ── Assign orphaned rows to default org ───────────────────────────
        migrated = {}
        for Model in [LogEntry, Alert, Attack, IPBlocklist, CustomRule,
                      SoarAction]:
            count = (db.session.query(Model)
                     .filter(Model.organisation_id == None)  # noqa: E711
                     .update({'organisation_id': org_id},
                             synchronize_session='fetch'))
            if count:
                migrated[Model.__tablename__] = count

        # ── Assign orphaned users ─────────────────────────────────────────
        orphan_users = CourraSecUser.query.filter_by(organisation_id=None).all()
        for u in orphan_users:
            u.organisation_id = org_id
            u.role = 'owner'
            if not u.email:
                u.email = u.username + '@localhost'
        if orphan_users:
            migrated['users'] = len(orphan_users)

        db.session.commit()

        if migrated:
            print("Migrated orphaned rows:")
            for table, n in migrated.items():
                print(f"  {table}: {n} row(s)")
        else:
            print("No orphaned rows found — nothing to migrate.")

        # ── Summary ───────────────────────────────────────────────────────
        print("\nMigration complete.")
        print(f"  Organisations : {Organisation.query.count()}")
        print(f"  Users         : {CourraSecUser.query.count()}")
        print(f"  Log entries   : {LogEntry.query.count()}")
        print(f"  Alerts        : {Alert.query.count()}")
        print(f"  Attacks       : {Attack.query.count()}")


if __name__ == '__main__':
    migrate()
