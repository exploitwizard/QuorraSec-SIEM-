#!/bin/bash
# Courra-Sec — Oracle Cloud ARM (Always Free) full setup
# Run as: bash deploy/setup.sh
set -e

echo "======================================"
echo "  Courra-Sec SaaS — Server Setup"
echo "======================================"

# ── System update ──────────────────────────────────────────────────────────
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv git nginx supervisor ufw \
                    python3-dev libffi-dev build-essential \
                    netfilter-persistent iptables-persistent curl

# ── App directory ──────────────────────────────────────────────────────────
APP_DIR="/home/ubuntu/courra-sec"
if [ ! -d "$APP_DIR" ]; then
  echo "Cloning repository..."
  cd /home/ubuntu
  git clone https://github.com/YOUR_USERNAME/courra-sec.git
fi
cd "$APP_DIR"

# ── Python environment ─────────────────────────────────────────────────────
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# ── Data directories ───────────────────────────────────────────────────────
mkdir -p data/models data/geolite logs

# ── Environment file ───────────────────────────────────────────────────────
if [ ! -f .env ]; then
  cat > .env << 'ENVEOF'
FLASK_ENV=production
SECRET_KEY=CHANGE_THIS_TO_A_LONG_RANDOM_STRING_AT_LEAST_32_CHARS
SUPERADMIN_USERNAME=superadmin
PORT=5000
DB_PATH=/home/ubuntu/courra-sec/data/courra-sec.db

# Optional threat intelligence keys
ABUSEIPDB_KEY=
VIRUSTOTAL_KEY=
OTX_KEY=
MAXMIND_LICENSE_KEY=

# Alert channels (optional)
SLACK_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=
ALERT_WEBHOOK_URL=

# Syslog listener (set to true to enable)
SYSLOG_LISTENER_ENABLED=false
ENVEOF
  echo ""
  echo ">>> IMPORTANT: Edit .env before continuing:"
  echo "    nano $APP_DIR/.env"
  echo "    At minimum, change SECRET_KEY to a random 32+ char string."
  echo ""
fi

# ── Oracle Cloud iptables rules ────────────────────────────────────────────
# Oracle Cloud VMs have a kernel-level firewall that UFW does not control.
# These rules must be added manually.
echo "Configuring Oracle Cloud iptables firewall rules..."
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80   -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443  -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 5141 -j ACCEPT 2>/dev/null || true
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 5140 -j ACCEPT 2>/dev/null || true
sudo netfilter-persistent save || true

# ── UFW (secondary firewall) ───────────────────────────────────────────────
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable || true

# ── Supervisor ────────────────────────────────────────────────────────────
sudo cp "$APP_DIR/deploy/supervisor.conf" /etc/supervisor/conf.d/courra-sec.conf
sudo supervisorctl reread
sudo supervisorctl update

# ── Nginx ─────────────────────────────────────────────────────────────────
sudo cp "$APP_DIR/deploy/nginx.conf" /etc/nginx/sites-available/courra-sec
sudo ln -sf /etc/nginx/sites-available/courra-sec /etc/nginx/sites-enabled/courra-sec
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx

# ── Initialise database ────────────────────────────────────────────────────
source venv/bin/activate
export $(grep -v '^#' .env | xargs)
python3 -c "
from app import create_app
from app.database import init_db
app = create_app()
init_db(app)
print('Database initialised.')
" 2>/dev/null || python3 -c "
from app.database import db, init_db
from app.main import app
with app.app_context():
    db.create_all()
    print('Database tables created.')
"

echo ""
echo "======================================"
echo "  Setup complete!"
echo "======================================"
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_VPS_IP")
echo "  Visit: http://$PUBLIC_IP"
echo ""
echo "  Next steps:"
echo "  1. Edit .env:        nano $APP_DIR/.env"
echo "  2. Restart app:      sudo supervisorctl restart courra-sec"
echo "  3. Check logs:       tail -f $APP_DIR/logs/courra-sec-err.log"
echo ""
