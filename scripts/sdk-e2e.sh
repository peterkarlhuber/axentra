#!/usr/bin/env bash
# Contract tests of both SDKs against a real, PostgreSQL-backed `axentra serve`.
#
#   AXENTRA_TEST_DATABASE_URL=postgresql://postgres:pg@127.0.0.1:5432/postgres scripts/sdk-e2e.sh
#
# What it does:
#   1. creates a temporary database owned by a temporary NON-superuser role (RLS is enforced),
#   2. migrates it and creates a first-run setup token (`axentra admin setup-token`),
#   3. starts `axentra serve` on a free loopback port,
#   4. bootstraps a platform admin through the API (POST /v1/auth/setup), then creates a
#      product, a tenant and a product-wide API key,
#   5. runs the TypeScript SDK e2e suite (sdk/typescript, `npm run test:e2e`) and the Python SDK
#      e2e suite (sdk/python/tests/e2e) with AXENTRA_SDK_E2E_* set,
#   6. stops the server and drops the database and the role (also on failure).
#
# Env:
#   AXENTRA_TEST_DATABASE_URL  superuser URL (required)
#   AXENTRA_PYTHON             Python with `axentra[server]` and sdk/python[test] installed
#                              (default: .venv/bin/python if present, else python3)
#   NPM                        npm binary (default: npm on PATH)
#   SDK_E2E_ONLY               "ts" or "python" to run only one suite
#   SDK_E2E_KEEP               "1" keeps the server running and prints the env (debugging; Ctrl-C ends it)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${AXENTRA_TEST_DATABASE_URL:?set AXENTRA_TEST_DATABASE_URL to a PostgreSQL superuser URL}"
if [[ -z "${AXENTRA_PYTHON:-}" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then AXENTRA_PYTHON="$ROOT/.venv/bin/python"; else AXENTRA_PYTHON=python3; fi
fi
NPM="${NPM:-npm}"
ONLY="${SDK_E2E_ONLY:-}"
PY="$AXENTRA_PYTHON"

log() { printf '[sdk-e2e] %s\n' "$*" >&2; }
json_get() { "$PY" -c 'import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(d)' "$1"; }

SUFFIX="$(date +%s)_$$"
DB="axentra_sdk_e2e_${SUFFIX}"
ROLE="axentra_sdk_e2e_${SUFFIX}"
ROLE_PW="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(18))')"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  local code=$?
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  psql "$AXENTRA_TEST_DATABASE_URL" -q -v ON_ERROR_STOP=0 \
    -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" -c "DROP ROLE IF EXISTS \"$ROLE\"" >/dev/null 2>&1 || true
  if [[ $code -ne 0 && -f "$WORK/server.log" ]]; then
    log "server log (last 60 lines):"
    tail -n 60 "$WORK/server.log" >&2 || true
  fi
  rm -rf "$WORK"
  exit "$code"
}
trap cleanup EXIT INT TERM

# 1. database + non-superuser role
log "creating database $DB and role $ROLE"
psql "$AXENTRA_TEST_DATABASE_URL" -q -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE \"$ROLE\" LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '$ROLE_PW'" \
  -c "CREATE DATABASE \"$DB\" OWNER \"$ROLE\"" >/dev/null
APP_URL="$("$PY" - "$AXENTRA_TEST_DATABASE_URL" "$DB" "$ROLE" "$ROLE_PW" <<'PY'
import sys
from psycopg.conninfo import conninfo_to_dict, make_conninfo
params = conninfo_to_dict(sys.argv[1])
params.update(dbname=sys.argv[2], user=sys.argv[3], password=sys.argv[4])
print(make_conninfo(**params))
PY
)"

PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
BASE="http://127.0.0.1:$PORT"

AXENTRA=("$PY" -c 'import sys; from axentra.cli import main; sys.exit(main())')

# Server configuration (environment variables only; see docs/operations/CONFIGURATION.md).
export AXENTRA__ENVIRONMENT=test
export AXENTRA__MODE=multi
export AXENTRA__DATABASE__URL="$APP_URL"
export AXENTRA__DATABASE__POOL_MAX=8
export AXENTRA__SECURITY__PUBLIC_URL="$BASE"
export AXENTRA__SECURITY__MASTER_KEYS="$("${AXENTRA[@]}" keys generate --kid e2e)"
export AXENTRA__SECURITY__LOGIN_RATE_PER_MINUTE=100
export AXENTRA__STORAGE__LOCAL_PATH="$WORK/storage"
unset AXENTRA_CONFIG

# 2. migrate + setup token
log "migrating"
"${AXENTRA[@]}" migrate >/dev/null
SETUP_TOKEN="$("${AXENTRA[@]}" admin setup-token)"

# 3. serve
log "starting axentra serve on $BASE"
"${AXENTRA[@]}" serve --host 127.0.0.1 --port "$PORT" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
  if curl -fsS "$BASE/v1/health/ready" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then log "server exited early"; exit 1; fi
  sleep 0.2
done
curl -fsS "$BASE/v1/health/ready" >/dev/null

# 4. bootstrap through the API (cookie session + CSRF, like a browser would)
ADMIN_EMAIL="sdk-e2e-admin@example.com"
ADMIN_PASSWORD="$("$PY" -c 'import secrets; print("pw-" + secrets.token_urlsafe(16))')"
JAR="$WORK/cookies.txt"
post() { # post <path> <json> -> body (fails on HTTP >= 400)
  curl -fsS -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -H "X-Axentra-CSRF: ${CSRF:-}" \
    -X POST "$BASE$1" --data "$2"
}
log "bootstrapping admin, product, tenant and API key"
SETUP_BODY="$("$PY" -c 'import json,sys; print(json.dumps({"setup_token": sys.argv[1], "email": sys.argv[2], "name": "SDK e2e admin", "password": sys.argv[3]}))' "$SETUP_TOKEN" "$ADMIN_EMAIL" "$ADMIN_PASSWORD")"
CSRF="$(CSRF='' post /v1/auth/setup "$SETUP_BODY" | json_get csrf_token)"
PRODUCT_ID="$(post /v1/products '{"name": "SDK e2e", "slug": "sdk-e2e"}' | json_get id)"
TENANT_ID="$(post "/v1/products/$PRODUCT_ID/tenants" '{"name": "Main", "slug": "main"}' | json_get id)"
PERMS='["product:read","tenants:read","tenants:create","tenants:update","tenants:delete","roles:read","api_keys:read","audit:read","collections:read","usage:manage","billing:manage","notify:manage","tenant:read","members:read","records:read","records:write","files:read","files:write","usage:read","usage:record","billing:read","notify:send"]'
API_KEY="$(post "/v1/products/$PRODUCT_ID/api-keys" "{\"name\": \"sdk-e2e\", \"permissions\": $PERMS}" | json_get secret)"

export AXENTRA_SDK_E2E_URL="$BASE"
export AXENTRA_SDK_E2E_API_KEY="$API_KEY"
export AXENTRA_SDK_E2E_PRODUCT_ID="$PRODUCT_ID"
export AXENTRA_SDK_E2E_TENANT_ID="$TENANT_ID"
export AXENTRA_SDK_E2E_ADMIN_EMAIL="$ADMIN_EMAIL"
export AXENTRA_SDK_E2E_ADMIN_PASSWORD="$ADMIN_PASSWORD"
# The suites must not see the server's own settings.
unset AXENTRA__DATABASE__URL AXENTRA__SECURITY__MASTER_KEYS

if [[ "${SDK_E2E_KEEP:-}" == "1" ]]; then
  env | grep '^AXENTRA_SDK_E2E_' | sed 's/^/export /'
  log "server running at $BASE (Ctrl-C to stop)"
  wait "$SERVER_PID"
fi

status=0
# 5. suites
if [[ -z "$ONLY" || "$ONLY" == "ts" ]]; then
  log "TypeScript SDK e2e"
  (
    cd "$ROOT/sdk/typescript"
    [[ -d node_modules ]] || "$NPM" ci --no-audit --no-fund
    "$NPM" run --silent test:e2e
  ) || status=1
fi
if [[ -z "$ONLY" || "$ONLY" == "python" ]]; then
  log "Python SDK e2e"
  (cd "$ROOT/sdk/python" && "$PY" -m pytest -q -p no:cacheprovider tests/e2e) || status=1
fi
[[ $status -eq 0 ]] && log "all SDK e2e suites passed" || log "SDK e2e FAILED"
exit $status
