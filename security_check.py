#!/usr/bin/env python3
"""
OWASP A06 — Vulnerable and Outdated Components
Run: python3 security_check.py
"""
import subprocess
import sys
import json


def check_dependencies():
    print("Checking for vulnerable dependencies...")
    print("=" * 50)
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pip-audit', '-q'], check=True)
        result = subprocess.run(
            [sys.executable, '-m', 'pip_audit', '--format', 'json'],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            try:
                audits = json.loads(result.stdout or '[]')
                if not audits:
                    print("✓ No known vulnerabilities found")
                else:
                    print(f"⚠ {len(audits)} vulnerable packages:")
                    for a in audits:
                        print(f"  - {a.get('name')} {a.get('version')}")
            except json.JSONDecodeError:
                if 'No known vulnerabilities found' in result.stdout:
                    print("✓ No known vulnerabilities found")
                else:
                    print(result.stdout)
    except Exception as e:
        print(f"Could not run pip-audit: {e}")
        print("Run manually: pip install pip-audit && pip-audit")

    print("\nChecking for outdated packages...")
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--outdated', '--format', 'json'],
            capture_output=True, text=True,
        )
        outdated = json.loads(result.stdout or '[]')
        if not outdated:
            print("✓ All packages up to date")
        else:
            critical = {'flask', 'werkzeug', 'sqlalchemy', 'cryptography',
                        'requests', 'urllib3', 'certifi', 'pyotp'}
            print(f"ℹ {len(outdated)} packages have updates available:")
            for pkg in outdated:
                flag = "⚠ CRITICAL" if pkg['name'].lower() in critical else "  "
                print(f"  {flag} {pkg['name']}: {pkg['version']} → {pkg['latest_version']}")
    except Exception as e:
        print(f"Could not check outdated packages: {e}")


def check_pinned_requirements():
    print("\nChecking requirements.txt...")
    unpinned = []
    try:
        with open('requirements.txt') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '==' not in line and '>=' not in line:
                    unpinned.append(line)
    except FileNotFoundError:
        print("⚠ requirements.txt not found")
        return
    if unpinned:
        print(f"⚠ Unpinned dependencies: {', '.join(unpinned)}")
    else:
        print("✓ All dependencies are pinned")


if __name__ == '__main__':
    check_dependencies()
    check_pinned_requirements()
    print("\nDone. Run weekly: python3 security_check.py")
