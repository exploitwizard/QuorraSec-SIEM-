#!/usr/bin/env python3
"""
Quorra SIEM Installation Script
Cross-platform: Windows, Linux, macOS

Usage:
    python3 install.py              # standard install
    python3 install.py --no-venv    # skip virtual environment
    python3 install.py --geoip-key <key>   # auto-download GeoLite2 DB
    python3 install.py --install-service   # also register as OS service
"""

import os
import sys
import subprocess
import argparse
import sysconfig
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def run_command(cmd, check=True):
    """Run a shell command and print it."""
    print(f"  > {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=check)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Command failed: {e}")
        return False


def get_venv_paths():
    """Return (python_cmd, pip_cmd) for the venv on the current platform."""
    if sys.platform == "win32":
        return (str(BASE_DIR / "venv" / "Scripts" / "python.exe"),
                str(BASE_DIR / "venv" / "Scripts" / "pip.exe"))
    else:
        return (str(BASE_DIR / "venv" / "bin" / "python"),
                str(BASE_DIR / "venv" / "bin" / "pip"))


def create_directories():
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


def download_geoip_db(license_key):
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


def create_windows_launcher():
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


def create_unix_launcher():
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


def create_global_launcher(venv_python):
    """
    Create a global 'quorra' command so it can be run from any terminal.

    On Linux/macOS: writes a wrapper shell script to ~/.local/bin/quorra
                    (falls back to /usr/local/bin if writable).
    On Windows:     writes quorra.bat to the user Python Scripts directory,
                    which pip already adds to PATH during Python installation.
    """
    quorra_script = BASE_DIR / "quorra.py"

    if sys.platform == "win32":
        # User Scripts directory (no admin required)
        scripts_dir = Path(sysconfig.get_path("scripts", "nt_user"))
        scripts_dir.mkdir(parents=True, exist_ok=True)
        bat = scripts_dir / "quorra.bat"
        bat.write_text(
            "@echo off\r\n"
            f"cd /d \"{BASE_DIR}\"\r\n"
            f"\"{venv_python}\" \"{quorra_script}\" %*\r\n"
        )
        print(f"  Global command created : {bat}")
        print(f"  Ensure this directory is in your PATH: {scripts_dir}")
        return

    # Unix / macOS — try candidates in order of preference
    candidates = [
        Path.home() / ".local" / "bin",   # user-writable, standard on Linux/macOS
        Path("/usr/local/bin"),            # system-wide (may need sudo)
    ]

    for bin_dir in candidates:
        wrapper = bin_dir / "quorra"
        try:
            bin_dir.mkdir(parents=True, exist_ok=True)
            wrapper.write_text(
                "#!/bin/sh\n"
                f"exec \"{venv_python}\" \"{quorra_script}\" \"$@\"\n"
            )
            wrapper.chmod(0o755)
            print(f"  Global command created : {wrapper}")

            # Warn if the directory is not on PATH
            path_dirs = os.environ.get("PATH", "").split(":")
            if str(bin_dir) not in path_dirs:
                shell_rc = _detect_shell_rc()
                print(f"\n  NOTE: {bin_dir} is not in your PATH.")
                print(f"  Add it by running:")
                print(f'    echo \'export PATH="{bin_dir}:$PATH"\' >> {shell_rc}')
                print(f"    source {shell_rc}")
            return
        except PermissionError:
            continue

    print("  Warning: Could not create global launcher (permission denied).")
    print(f"  Run install.py with sudo, or add this to PATH manually:")
    print(f"    {BASE_DIR / 'venv' / 'bin'}")


def _detect_shell_rc():
    """Return the most likely shell rc file path for the current user."""
    shell = os.environ.get("SHELL", "")
    home = Path.home()
    if "zsh" in shell:
        return home / ".zshrc"
    if "fish" in shell:
        return home / ".config" / "fish" / "config.fish"
    return home / ".bashrc"


def create_env_template():
    """Write a .env.example file documenting all environment variables."""
    env_example = BASE_DIR / ".env.example"
    if env_example.exists():
        return
    content = """\
# Quorra SIEM - Environment Variables
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


def main():
    parser = argparse.ArgumentParser(
        description="Install Quorra SIEM Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--geoip-key", default=os.environ.get("MAXMIND_LICENSE_KEY", ""),
                        help="MaxMind license key for GeoLite2 auto-download")
    parser.add_argument("--no-venv",   action="store_true",
                        help="Skip virtual environment creation (use system Python)")
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

    # --- Virtual environment + dependencies ---
    if args.no_venv:
        python_cmd = sys.executable
        pip_cmd    = f'"{sys.executable}" -m pip'
        print("\nSkipping virtual environment (--no-venv).")
    else:
        venv_dir = BASE_DIR / "venv"
        if not venv_dir.exists():
            print("\nCreating virtual environment...")
            run_command(f'"{sys.executable}" -m venv "{venv_dir}"')
        else:
            print("\n  Virtual environment already exists")

        python_cmd, pip_cmd = get_venv_paths()
        python_cmd = f'"{python_cmd}"'
        pip_cmd    = f'"{pip_cmd}"'

    print("\nInstalling dependencies...")
    run_command(f'{pip_cmd} install --upgrade pip --quiet')
    run_command(f'{pip_cmd} install -r "{BASE_DIR / "requirements.txt"}"')

    print("\nInstalling Quorra package (editable)...")
    run_command(f'{pip_cmd} install -e "{BASE_DIR}" --quiet')

    # --- Platform-specific setup ---
    if sys.platform != "win32":
        print("\nSetting file permissions...")
        for fname in ("quorra.py", "quorra.sh"):
            fp = BASE_DIR / fname
            if fp.exists():
                fp.chmod(0o755)
        create_unix_launcher()
    else:
        print("\nCreating Windows launcher...")
        create_windows_launcher()

    # --- Global 'quorra' command ---
    print("\nCreating global 'quorra' command...")
    if args.no_venv:
        venv_python = sys.executable
    else:
        venv_python, _ = get_venv_paths()
    create_global_launcher(venv_python)

    # --- GeoIP ---
    print("\nChecking GeoIP database...")
    download_geoip_db(args.geoip_key)

    # --- .env template ---
    print("\nCreating configuration template...")
    create_env_template()

    # --- Service installation ---
    if args.install_service:
        print("\nInstalling system service...")
        run_command(f'"{sys.executable}" "{BASE_DIR / "quorra.py"}" --install-service')

    print("\n" + "=" * 60)
    print("Installation complete!")
    print()
    print("To start Quorra SIEM, open a NEW terminal and run:")
    print("  quorra")
    print()
    if sys.platform == "win32":
        print("  Or double-click: quorra.bat")
    else:
        print("  Or run directly: ./quorra.sh")
    print()
    print("Available CLI flags:")
    print("  --no-browser        Don't auto-open the browser")
    print("  --port <N>          Use a specific port")
    print("  --log-level DEBUG   Verbose logging")
    print("  --tls               Enable HTTPS")
    print("  --install-service   Register as OS service")
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
    print("  Login      : http://localhost:5001/login")
    print("  Health     : http://localhost:5001/health")
    print("  Metrics    : http://localhost:5001/metrics")
    print("=" * 60)


if __name__ == "__main__":
    main()
