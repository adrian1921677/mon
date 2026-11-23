#!/usr/bin/env bash
# Smoke-Check (Linux/macOS/CI): Backend-Health, Projects, Tools, OpenAPI.
# Usage:
#   ./scripts/smoke-check.sh              # erwartet laufendes Backend
#   ./scripts/smoke-check.sh --start      # startet Backend aus venv kurzzeitig
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_URL="${HCK_BASE_URL:-http://127.0.0.1:8765}"
START=0
BACKEND_PID=""
FAILED=0

for arg in "$@"; do
  case "$arg" in
    --start) START=1 ;;
    --base-url=*) BASE_URL="${arg#*=}" ;;
  esac
done

ok() { echo "[OK] $1"; }
fail() { echo "[FAIL] $1 — $2"; FAILED=$((FAILED + 1)); }

cleanup() {
  if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
    kill "${BACKEND_PID}" 2>/dev/null || true
    wait "${BACKEND_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ "${START}" -eq 1 ]]; then
  PY="${ROOT}/backend/.venv/bin/python"
  if [[ ! -x "${PY}" ]]; then
    echo "Kein venv — bitte: cd backend && python3 -m venv .venv && pip install -e '.[dev]'"
    exit 1
  fi
  export HCK_HOST=127.0.0.1 HCK_PORT=8765
  export HCK_DATA_DIR="${HCK_DATA_DIR:-${TMPDIR:-/tmp}/hck-smoke}"
  mkdir -p "${HCK_DATA_DIR}"
  (cd "${ROOT}/backend" && "${PY}" -m app.main) &
  BACKEND_PID=$!
  sleep 2
fi

if curl -fsS --max-time 5 "${BASE_URL}/health" | grep -q '"status"'; then
  ok "GET /health"
else
  fail "GET /health" "unreachable"
fi

if curl -fsS --max-time 5 "${BASE_URL}/openapi.json" >/dev/null; then
  ok "GET /openapi.json"
else
  fail "GET /openapi.json" "unreachable"
fi

if curl -fsS --max-time 5 "${BASE_URL}/api/v1/projects" >/dev/null; then
  ok "GET /api/v1/projects"
else
  fail "GET /api/v1/projects" "unreachable"
fi

TOOLS_JSON="$(curl -fsS --max-time 10 "${BASE_URL}/api/v1/tools" || true)"
if [[ -n "${TOOLS_JSON}" ]]; then
  ok "GET /api/v1/tools"
else
  fail "GET /api/v1/tools" "empty/unreachable"
fi

NAME="smoke-$(date +%s)"
CREATED="$(curl -fsS --max-time 5 -X POST "${BASE_URL}/api/v1/projects" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"${NAME}\",\"description\":\"phase9\"}" || true)"
if echo "${CREATED}" | grep -q '"id"'; then
  ID="$(echo "${CREATED}" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  curl -fsS --max-time 5 -X DELETE "${BASE_URL}/api/v1/projects/${ID}" >/dev/null || true
  ok "POST/DELETE project"
else
  fail "POST/DELETE project" "create failed"
fi

if [[ "${FAILED}" -gt 0 ]]; then
  echo "${FAILED} Smoke-Check(s) fehlgeschlagen."
  exit 1
fi
echo "Alle Smoke-Checks bestanden."
