#!/usr/bin/env bash
# run_backend.sh — Start the FastAPI server
# Run this from the project root: bash run_backend.sh

set -e

cd "$(dirname "$0")/backend"

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

echo ""
echo "✅  Starting FastAPI on http://localhost:8000"
echo "   Swagger docs: http://localhost:8000/docs"
echo ""

uvicorn main:app --reload --host 0.0.0.0 --port 8000