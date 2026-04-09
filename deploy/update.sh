#!/bin/bash
# Courra-Sec — one-command deployment update
set -e

APP_DIR="/home/ubuntu/courra-sec"
echo "Updating Courra-Sec..."

cd "$APP_DIR"
git pull origin main

source venv/bin/activate
pip install -r requirements.txt --quiet

# Run any DB migrations (safe to call multiple times — create_all is idempotent)
python3 -c "
from app.database import db
from app.main import app
with app.app_context():
    db.create_all()
    print('DB schema up to date.')
" 2>/dev/null || true

sudo supervisorctl restart courra-sec
echo ""
echo "Update complete."
sudo supervisorctl status courra-sec
