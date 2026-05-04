"""
migrate_rules_fix.py
One-time migration: creates the organisation_settings table and backfills
default settings rows for any organisations that were created before this
migration was added.

Run once:
    cd CourraSec
    python3 migrate_rules_fix.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from app.main import app
from app.database import db
from app.models import Organisation, OrganisationSettings


def migrate():
    with app.app_context():
        # Create any tables that don't exist yet (safe — won't drop existing tables)
        db.create_all()
        print("db.create_all() complete")

        # Backfill OrganisationSettings for existing orgs
        orgs = Organisation.query.all()
        created = 0
        for org in orgs:
            existing = OrganisationSettings.query.filter_by(
                organisation_id=org.id
            ).first()
            if not existing:
                db.session.add(OrganisationSettings(
                    organisation_id=org.id,
                    python_dsl_sandbox=True,
                ))
                created += 1

        if created:
            db.session.commit()

        print(f"Migration complete.")
        print(f"  New table:  organisation_settings")
        print(f"  Backfilled: {created} organisation(s) with default sandbox=ON settings")
        print(f"  Skipped:    {len(orgs) - created} organisation(s) already had settings")


if __name__ == "__main__":
    migrate()
