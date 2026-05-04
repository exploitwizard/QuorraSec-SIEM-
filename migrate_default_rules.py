"""
Migration: create the default_rule_overrides table.
Run once: python3 migrate_default_rules.py
"""
from app.main import app
from app.models import db

with app.app_context():
    db.create_all()
    print("DefaultRuleOverride table created (or already exists)")
