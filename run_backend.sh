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

python - <<'PY'
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

backend_dir = Path.cwd()
project_root = backend_dir.parent

def load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value

load_env_file(backend_dir / ".env")
load_env_file(project_root / ".env")

database_url = os.getenv("DATABASE_URL", "postgresql+psycopg://wavs:wavs@localhost:5432/wavs")
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
