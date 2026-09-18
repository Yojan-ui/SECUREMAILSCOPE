#!/usr/bin/env bash
# Start SecureMailScope. macOS and Linux.
#
#   ./run.sh
#
# Creates a local virtual environment on first run, installs dependencies into
# it, starts the server and opens a browser. Nothing is installed system-wide
# and nothing outside this folder is touched.

set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8000}"
VENV=".venv"

say() { printf "\n  %s\n" "$*"; }

# --- find a usable Python --------------------------------------------------
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
      PY="$candidate"; break
    fi
  fi
done

if [ -z "$PY" ]; then
  say "Python 3.10 or newer is needed and was not found."
  say "Install it from https://www.python.org/downloads/ and run this again."
  exit 1
fi
say "Using $($PY --version)"

# --- set up the environment once -------------------------------------------
if [ ! -d "$VENV" ]; then
  say "First run: creating a local environment (about a minute)..."
  "$PY" -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

if ! python -c "import fastapi, dns, reportlab" >/dev/null 2>&1; then
  say "Installing dependencies. This needs internet and takes a minute..."
  python -m pip install --upgrade pip --quiet --retries 5 --timeout 60 || true
  if ! python -m pip install -r requirements.txt --quiet --retries 5 --timeout 60; then
    say "The install did not finish, usually a slow or blocked connection."
    say "Check your internet and run this again: it resumes, it does not start over."
    exit 1
  fi
  if ! python -c "import fastapi, dns, reportlab" >/dev/null 2>&1; then
    say "Dependencies are still missing after the install. Try again on a"
    say "different network, or install by hand:  pip install -r requirements.txt"
    exit 1
  fi
fi

# --- pick a free port ------------------------------------------------------
while python - "$PORT" <<'EOF' 2>/dev/null
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)      # in use
finally:
    s.close()
sys.exit(1)          # free
EOF
do
  PORT=$((PORT + 1))
done

URL="http://127.0.0.1:${PORT}"
say "Starting SecureMailScope on ${URL}"
say "Press Ctrl+C here to stop it."
echo

# open the browser once the server answers
(
  for _ in $(seq 1 40); do
    if curl -fsS "$URL/healthz" >/dev/null 2>&1; then
      if command -v open >/dev/null 2>&1; then open "$URL"
      elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
      fi
      break
    fi
    sleep 0.5
  done
) &

exec python -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT"
