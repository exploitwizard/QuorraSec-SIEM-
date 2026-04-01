#!/usr/bin/env python3
"""
Quorra SIEM Installation Script
<<<<<<< HEAD
=======
Cross-platform: Windows, Linux, macOS
>>>>>>> cea6978 (Reconnected project and updated files)
"""

import os
import sys
import subprocess
<<<<<<< HEAD
import shutil

def run_command(cmd, check=True):
    """Run a shell command."""
    print(f"➜ {cmd}")
=======
import argparse
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def run_command(cmd: str, check: bool = True) -> bool:
    """Run a shell command and print it."""
    print(f"  > {cmd}")
>>>>>>> cea6978 (Reconnected project and updated files)
    try:
        subprocess.run(cmd, shell=True, check=check)
        return True
    except subprocess.CalledProcessError as e:
<<<<<<< HEAD
        print(f"Command failed: {e}")
        return False

def main():
    print(" Installing Quorra SIEM Tool...")
    print("=" * 50)
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        print(f"Error: Python 3.8+ required. Found Python {python_version.major}.{python_version.minor}")
        sys.exit(1)
    
    print(f"Python {python_version.major}.{python_version.minor}.{python_version.micro} detected")
    
    # Create necessary directories
    print("\n📁 Creating directories...")
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    
    # Create virtual environment
    if not os.path.exists("venv"):
        print("\n Creating virtual environment...")
        run_command("python -m venv venv")
    else:
        print("\n Virtual environment already exists")
    
    # Determine activation command
    if os.name == 'nt':  # Windows
        python_cmd = "venv\\Scripts\\python"
        pip_cmd = "venv\\Scripts\\pip"
    else:  # Linux/Mac
        python_cmd = "venv/bin/python"
        pip_cmd = "venv/bin/pip"
    
    # Install dependencies
    print("\n📦 Installing dependencies...")
    run_command(f"{pip_cmd} install --upgrade pip")
    run_command(f"{pip_cmd} install -r requirements.txt")
    
    # Make main script executable
    if os.name != 'nt':  # Not Windows
        print("\n⚙️  Setting up permissions...")
        run_command("chmod +x quorra.py")
    
    # Install globally
    print("\n🔗 Installing globally...")
    run_command(f"{pip_cmd} install -e .")
    
    # Create initial database
    print("\n🗃️  Initializing database...")
    run_command(f"{python_cmd} -c \"from app.database import db; from app import app; with app.app_context(): db.create_all()\"")
    
    print("\n" + "=" * 50)
    print("Installation complete!")
    print("\n To start Quorra SIEM:")
    print("   1. First start Block Fortress on port 5000")
    print("   2. Run: quorra")
    print("\n Login Credentials:")
    print("   Username: user-quorra")
    print("   Password: quorra@1000")
    print("\n Login page will be available at: http://localhost:5001/login")
    print("\n  Troubleshooting:")
    print("   - Make sure port 5001 is available")
    print("   - Check if Block Fortress is running on port 5000")
    print("   - If login fails, check the database in data/quorra.db")
=======
        print(f"  Command failed: {e}")
        return False


def get_venv_paths() -> tuple[str, str]:
    """Return (python_cmd, pip_cmd) for the venv on the current platform."""
    if sys.platform == "win32":
        return (str(BASE_DIR / "venv" / "Scripts" / "python.exe"),
                str(BASE_DIR / "venv" / "Scripts" / "pip.exe"))
    else:
        return (str(BASE_DIR / "venv" / "bin" / "python"),
                str(BASE_DIR / "venv" / "bin" / "pip"))


def create_directories() -> None:
    """Create all required data and log directories."""
    dirs = [
        BASE_DIR / "data",
        BASE_DIR / "data" / "geolite",
        BASE_DIR / "data" / "models",
        BASE_DIR / "data" / "tls",
        BASE_DIR / "logs",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    print("  Directories created")


def download_geoip_db(license_key: str) -> None:
    """
    Download the free GeoLite2-City database from MaxMind.
    Requires a free MaxMind account and license key.
    Set MAXMIND_LICENSE_KEY environment variable or pass --geoip-key.
    """
    if not license_key:
        print("\n  GeoIP auto-download skipped (no MAXMIND_LICENSE_KEY).")
        print("  To enable geo-location features:")
        print("    1. Sign up free at https://www.maxmind.com/")
        print("    2. Download GeoLite2-City.mmdb")
        print(f"    3. Place it in: {BASE_DIR / 'data' / 'geolite' / 'GeoLite2-City.mmdb'}")
        return

    import urllib.request
    import tarfile
    import tempfile

    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
    )
    dest = BASE_DIR / "data" / "geolite" / "GeoLite2-City.mmdb"

    if dest.exists():
        print(f"  GeoLite2 database already present: {dest}")
        return

    print("  Downloading GeoLite2-City database...")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "geolite2.tar.gz"
            urllib.request.urlretrieve(url, archive)
            with tarfile.open(archive, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.name.endswith(".mmdb"):
                        member.name = Path(member.name).name
                        tf.extract(member, path=str(dest.parent))
                        extracted = dest.parent / member.name
                        if extracted != dest:
                            extracted.rename(dest)
                        break
        print(f"  GeoLite2 database saved to: {dest}")
    except Exception as e:
        print(f"  GeoIP download failed: {e}")
        print("  You can download it manually from MaxMind.")


def create_windows_launcher() -> None:
    """Create quorra.bat for Windows users who prefer double-click launch."""
    bat = BASE_DIR / "quorra.bat"
    content = (
        "@echo off\r\n"
        "cd /d \"%~dp0\"\r\n"
        "if exist venv\\Scripts\\python.exe (\r\n"
        "    venv\\Scripts\\python.exe quorra.py %*\r\n"
        ") else (\r\n"
        "    python quorra.py %*\r\n"
        ")\r\n"
    )
    bat.write_text(content)
    print(f"  Windows launcher created: {bat}")


def create_unix_launcher() -> None:
    """Create quorra.sh for Unix/macOS convenience."""
    sh = BASE_DIR / "quorra.sh"
    content = (
        "#!/bin/sh\n"
        "cd \"$(dirname \"$0\")\"\n"
        "if [ -f venv/bin/python ]; then\n"
        "    exec venv/bin/python quorra.py \"$@\"\n"
        "else\n"
        "    exec python3 quorra.py \"$@\"\n"
        "fi\n"
    )
    sh.write_text(content)
    sh.chmod(0o755)
    print(f"  Unix launcher created: {sh}")


def create_env_template() -> None:
    """Write a .env.example file documenting all environment variables."""
    env_example = BASE_DIR / ".env.example"
    if env_example.exists():
        return
    content = """\
# Quorra SIEM — Environment Variables
# Copy this file to .env and fill in the values.

# ---- Security (REQUIRED for production) ----
SECRET_KEY=change-me-to-a-random-64-char-hex-string
INGEST_API_KEY=change-me-to-a-random-api-key
QUORRA_USERNAME=user-quorra
QUORRA_PASSWORD=change-me-strong-password

# ---- Block Fortress ----
BLOCK_FORTRESS_URL=http://localhost:5000
BLOCK_FORTRESS_WS_URL=ws://localhost:5000/api/ws/logs

# ---- Database ----
# DB_PATH=C:\\ProgramData\\QuorraSIEM\\quorra.db   # Windows example
# DB_PATH=/var/lib/quorra/quorra.db               # Linux example

# ---- Alerts / Notifications ----
SLACK_WEBHOOK_URL=
ALERT_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=
EMAIL_ENABLED=false
SMTP_HOST=localhost
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
ALERT_FROM=quorra@localhost
ALERT_TO=admin@localhost

# ---- GeoIP ----
MAXMIND_LICENSE_KEY=

# ---- Syslog listener (disabled by default) ----
SYSLOG_LISTENER_ENABLED=false
SYSLOG_UDP_PORT=5140
SYSLOG_TCP_PORT=5141

# ---- Prometheus metrics ----
METRICS_ENABLED=true
METRICS_TOKEN=

# ---- TLS (optional HTTPS) ----
TLS_ENABLED=false
TLS_CERT_FILE=data/tls/cert.pem
TLS_KEY_FILE=data/tls/key.pem
"""
    env_example.write_text(content)
    print(f"  Environment template created: {env_example}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install Quorra SIEM Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--geoip-key", default=os.environ.get("MAXMIND_LICENSE_KEY", ""),
                        help="MaxMind license key for GeoLite2 auto-download")
    parser.add_argument("--no-venv",   action="store_true",
                        help="Skip virtual environment creation")
    parser.add_argument("--install-service", action="store_true",
                        help="Install Quorra as a system service after installation")
    args = parser.parse_args()

    print("\nInstalling Quorra SIEM Tool...")
    print("=" * 60)

    # --- Python version check ---
    vi = sys.version_info
    if vi < (3, 8):
        print(f"Error: Python 3.8+ required. Found {vi.major}.{vi.minor}")
        sys.exit(1)
    print(f"  Python {vi.major}.{vi.minor}.{vi.micro} ({sys.platform})")

    # --- Directories ---
    print("\nCreating directories...")
    create_directories()

    # --- Virtual environment ---
    if not args.no_venv:
        if not (BASE_DIR / "venv").exists():
            print("\nCreating virtual environment...")
            run_command(f'"{sys.executable}" -m venv venv')
        else:
            print("\n  Virtual environment already exists")

        python_cmd, pip_cmd = get_venv_paths()

        print("\nInstalling dependencies...")
        run_command(f'"{pip_cmd}" install --upgrade pip --quiet')
        run_command(f'"{pip_cmd}" install -r requirements.txt')

        print("\nInstalling Quorra package...")
        run_command(f'"{pip_cmd}" install -e . --quiet')

    # --- Platform-specific setup ---
    if sys.platform != "win32":
        print("\nSetting file permissions...")
        for f in ("quorra.py", "quorra.sh"):
            fp = BASE_DIR / f
            if fp.exists():
                fp.chmod(0o755)
    else:
        print("\nCreating Windows launcher...")
        create_windows_launcher()

    # Unix launcher (always useful on Linux/macOS)
    if sys.platform != "win32":
        create_unix_launcher()

    # --- GeoIP ---
    print("\nChecking GeoIP database...")
    download_geoip_db(args.geoip_key)

    # --- .env template ---
    print("\nCreating configuration template...")
    create_env_template()

    # --- Service installation ---
    if args.install_service:
        print("\nInstalling system service...")
        run_command(f'"{sys.executable}" quorra.py --install-service')

    print("\n" + "=" * 60)
    print("Installation complete!")
    print()
    print("To start Quorra SIEM:")
    if sys.platform == "win32":
        print("  quorra.bat")
        print("  -- or --")
        print("  venv\\Scripts\\python.exe quorra.py")
    else:
        print("  ./quorra.sh")
        print("  -- or --")
        print("  venv/bin/python quorra.py")
    print()
    print("Available CLI flags:")
    print("  --no-browser        Don't auto-open the browser")
    print("  --port <N>          Use a specific port")
    print("  --log-level DEBUG   Verbose logging")
    print("  --tls               Enable HTTPS")
    print("  --install-service   Install as OS service")
    print()
    print("Default credentials (CHANGE BEFORE PRODUCTION USE):")
    print("  Username : user-quorra")
    print("  Password : quorra@1000")
    print()
    print("  Set QUORRA_USERNAME, QUORRA_PASSWORD, and INGEST_API_KEY")
    print("  environment variables (or copy .env.example to .env).")
    print()
    print("Endpoints:")
    print("  Dashboard  : http://localhost:5001/")
    print("  Health     : http://localhost:5001/health")
    print("  Metrics    : http://localhost:5001/metrics")
    print("=" * 60)

>>>>>>> cea6978 (Reconnected project and updated files)

if __name__ == "__main__":
    main()
