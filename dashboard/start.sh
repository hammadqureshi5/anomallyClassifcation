#!/usr/bin/env bash
# Start the ACDS console. First run: creates the backend venv, installs packages and builds the UI.
#   ./start.sh          → http://127.0.0.1:8000   (built UI served by FastAPI)
#   ./start.sh dev      → API on :8000 + Vite dev server with hot reload on :5173
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/uvicorn ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r backend/requirements.txt
fi
[ -d frontend/node_modules ] || (cd frontend && npm install)

if [ "${1:-}" = "dev" ]; then
  (cd backend && ../.venv/bin/uvicorn app.main:app --reload --port 8000) &
  trap 'kill %1' EXIT
  cd frontend && npm run dev
else
  (cd frontend && npm run build)
  cd backend && exec ../.venv/bin/uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
fi
