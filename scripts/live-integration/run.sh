#!/usr/bin/env bash
# Opt-in live integration run (NOT part of CI). Starts the pinned services from compose.yml, runs the
# checks against a real `axentra serve`, writes evidence, stops the services (LC_KEEP=1 keeps them).
#
#   scripts/live-integration/run.sh [smtp] [s3] [oidc] [webhooks] [stripe-mock]   (default: all)
#
# Needs: Docker + Compose v2, openssl, a local PostgreSQL superuser URL in LC_PG_ADMIN_URL
# (default postgresql://postgres:pg@127.0.0.1:5432/postgres; the run creates role lc_ax and databases lc_*),
# and a Python with Axentra's dependencies + boto3 in LC_PYTHON (default: python3).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
export LC_RUN="${LC_RUN:-$here/.run}"
export LC_CERTS="$LC_RUN/certs"
export LC_EVIDENCE="${LC_EVIDENCE:-$here/evidence}"
export LC_PYTHON="${LC_PYTHON:-python3}"
export LC_PG_ADMIN_URL="${LC_PG_ADMIN_URL:-postgresql://postgres:pg@127.0.0.1:5432/postgres}"
checks=("$@"); [ ${#checks[@]} -eq 0 ] && checks=(smtp s3 oidc webhooks stripe-mock)
mkdir -p "$LC_EVIDENCE"

# Reuse a CA younger than two days: running Mailpit containers keep the certificate they started with.
if [ -z "$(find "$LC_CERTS/ca.pem" -mmin -2880 2>/dev/null)" ]; then
    "$here/make_certs.sh" "$LC_CERTS"
    compose_recreate=1
fi
"$LC_PYTHON" -I - "$LC_PG_ADMIN_URL" <<'PY'
import sys, psycopg
with psycopg.connect(sys.argv[1], autocommit=True) as c:
    if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = 'lc_ax'").fetchone():
        c.execute("CREATE ROLE lc_ax LOGIN PASSWORD 'lc_ax_pw'")  # synthetic, NOSUPERUSER NOBYPASSRLS
PY

compose() { docker compose -f "$here/compose.yml" "$@"; }
cleanup() { [ "${LC_KEEP:-0}" = 1 ] || compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
compose up -d ${compose_recreate:+--force-recreate}
wait_url() { for _ in $(seq 1 120); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 2; done; echo "timeout: $1" >&2; return 1; }
wait_url http://127.0.0.1:19126/api/v1/info
wait_url http://127.0.0.1:19127/api/v1/info
wait_url http://127.0.0.1:19180/realms/master/.well-known/openid-configuration
for _ in $(seq 1 60); do curl -s -o /dev/null 2>/dev/null http://127.0.0.1:19333/ && break; sleep 2; done
compose ps > "$LC_EVIDENCE/compose-ps.txt"

status=0
for c in "${checks[@]}"; do
    echo "=== $c ==="
    if PYTHONPATH="$here/../../src" "$LC_PYTHON" "$here/check_${c//-/_}.py" 2>&1 | tee "$LC_EVIDENCE/$c-console.txt"; then :; else status=1; fi
done
for svc in mailpit-starttls mailpit-tls seaweedfs keycloak stripe-mock; do compose logs --no-color "$svc" > "$LC_EVIDENCE/container-$svc.log" 2>&1 || true; done
exit $status
