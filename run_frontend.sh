#!/usr/bin/env bash
# run_frontend.sh — Start the React dev server
# Run from project root: bash run_frontend.sh

set -e

cd "$(dirname "$0")/frontend"

if [ ! -d "node_modules" ] || [ "package-lock.json" -nt "node_modules" ]; then
  echo "Installing npm packages (first run may take a minute)…"
  npm ci
else
  echo "Dependencies up to date, skipping install."
fi

echo ""
echo "✅  Starting React on http://localhost:3000"
echo ""

npm start
