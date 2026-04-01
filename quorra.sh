#!/bin/sh
# Quorra SIEM — Unix / macOS launcher
#
# Usage:
#   ./quorra.sh                  Start with auto-selected port
#   ./quorra.sh --no-browser     Start without opening a browser
#   ./quorra.sh --port 8080      Start on a specific port
#   ./quorra.sh --help           Show all options

set -e
cd "$(dirname "$0")"

# Load .env if present
if [ -f ".env" ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' .env | grep -v '^\s*$' | xargs)
fi

# Prefer the virtual-environment Python
if [ -f "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    PYTHON="python"
fi

echo "Starting Quorra SIEM..."
exec "$PYTHON" quorra.py "$@"
