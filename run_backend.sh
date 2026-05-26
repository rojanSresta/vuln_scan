#!/usr/bin/env bash
# run_backend.sh — Start the FastAPI server
# Run this from the project root: bash run_backend.sh

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT/backend"

if [ ! -d "venv" ]; then
  echo "Creating virtual environment…"
  python3 -m venv venv
fi

echo "Activating venv and installing dependencies…"
source venv/bin/activate

# Python 3.14 is newer than pydantic-core's Rust bindings officially support.
# This env var tells PyO3 to use the stable ABI and build anyway.
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1

pip install -r requirements.txt -q

DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://wavs:wavs@localhost:5432/wavs}"
export DATABASE_URL

python - <<'PY'
import os
import socket
import sys
from urllib.parse import urlparse

database_url = os.environ["DATABASE_URL"]
parsed = urlparse(database_url)

if parsed.scheme.startswith("postgresql"):
    host = parsed.hostname or "localhost"
    port = parsed.port or 5432
    try:
        with socket.create_connection((host, port), timeout=2):
            pass
    except OSError as exc:
        print("")
        print(f"Postgres is not reachable at {host}:{port}.")
        print(f"Error: {exc}")
        print("")
        print("Start the local database first, then run this script again:")
        print("  docker compose up -d postgres")
        print("  bash run_backend.sh")
        print("")
        print("Or set DATABASE_URL to a running Postgres database.")
        sys.exit(1)
PY

echo ""
echo "✅  Starting FastAPI on http://localhost:8000"
echo "   Swagger docs: http://localhost:8000/docs"
echo ""

uvicorn main:app --reload --host 0.0.0.0 --port 8000
