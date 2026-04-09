#!/bin/sh
# Courra-Sec — Unix / macOS launcher
#
# Usage:
#   ./courra-sec.sh                  Start with auto-selected port
#   ./courra-sec.sh --no-browser     Start without opening a browser
#   ./courra-sec.sh --port 8080      Start on a specific port
#   ./courra-sec.sh --help           Show all options

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

echo "Starting Courra-Sec..."
exec "$PYTHON" courra-sec.py "$@"
