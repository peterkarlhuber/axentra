#!/usr/bin/env bash
# Start a compose stack of deploy/compose and smoke-test it end to end:
#   scripts/compose_smoke.sh single|multi [host port]
# Needs the image `axentra:local` (`docker build -t axentra:local .`), Docker Compose v2, curl and python3.
# Generates throwaway passwords and a keyring, starts db + migrate + api, waits for readiness, checks the mode,
# creates the first platform admin through a setup token and writes data as the restricted application role
# (row-level security applies). The stack and its volumes are removed afterwards, also on failure.
set -euo pipefail

mode="${1:?usage: compose_smoke.sh single|multi [port]}"
port="${2:-18080}"
case "$mode" in single | multi) ;; *) echo "unknown mode: $mode" >&2; exit 2 ;; esac

root="$(cd "$(dirname "$0")/.." && pwd)"
file="$root/deploy/compose/docker-compose.$mode.yml"
project="axentra-smoke-$mode"
work="$(mktemp -d)"
base="http://127.0.0.1:$port"

compose() { docker compose -p "$project" --env-file "$work/.env" -f "$file" "$@"; }

cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ -f "$work/.env" ]; then
        compose logs --no-color --tail 200 || true
    fi
    [ -f "$work/.env" ] && compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT

secret() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }
keys="$(docker run --rm axentra:local keys generate --kid k1)"
cat >"$work/.env" <<EOF
POSTGRES_PASSWORD=$(secret)
AXENTRA_DB_OWNER_PASSWORD=$(secret)
AXENTRA_DB_APP_PASSWORD=$(secret)
AXENTRA_MASTER_KEYS=$keys
AXENTRA_ENVIRONMENT=development
AXENTRA_PUBLIC_URL=http://localhost:$port
AXENTRA_ALLOWED_ORIGINS=[]
AXENTRA_HTTP_PORT=$port
EOF

compose up -d --no-build
for _ in $(seq 1 90); do
    if curl -fsS "$base/v1/health/ready" >/dev/null 2>&1; then break; fi
    sleep 2
done
curl -fsS "$base/v1/health/ready" >/dev/null

token="$(compose run --rm --no-deps -T api admin setup-token | tail -n 1 | tr -d '\r')"
python3 -I - "$base" "$mode" "$token" <<'PY'
import json
import sys
import urllib.request

base, mode, token = sys.argv[1:4]


def call(method, path, body=None, token=None):
    req = urllib.request.Request(base + path, method=method)
    req.add_header("Accept", "application/json")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if token:
        # The session token as a bearer credential (no cookie, so no CSRF header is needed).
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, data, timeout=30) as resp:  # noqa: S310 - loopback test URL
        return resp.status, json.loads(resp.read() or b"null"), resp.headers.get_all("Set-Cookie") or []


status, meta, _ = call("GET", "/v1/meta")
assert status == 200 and meta["mode"] == mode and meta["api_version"]["major"] == 1, meta
status, _, cookies = call(
    "POST",
    "/v1/auth/setup",
    {"setup_token": token, "email": "admin@example.com", "password": "smoke test password 12345"},
)
assert status == 200 and cookies, status
session = next(
    c.split(";", 1)[0].split("=", 1)[1] for c in cookies if c.split("=", 1)[0].endswith("axentra-session")
)
status, me, _ = call("GET", "/v1/me", token=session)
assert status == 200 and me["platform_role"] == "platform_admin", me
if mode == "multi":
    status, product, _ = call("POST", "/v1/products", {"slug": "smoke", "name": "Smoke"}, token=session)
    assert status == 201, product
    pid = product["id"]
else:
    status, products, _ = call("GET", "/v1/products", token=session)
    assert status == 200 and len(products) == 1, products
    pid = products[0]["id"]
status, tenant, _ = call("POST", f"/v1/products/{pid}/tenants", {"slug": "acme", "name": "Acme"}, token=session)
assert status == 201, tenant
tid = tenant["id"]
status, record, _ = call(
    "POST", f"/v1/products/{pid}/tenants/{tid}/records/notes", {"data": {"text": "hello"}}, token=session
)
assert status == 201, record
status, page, _ = call("GET", f"/v1/products/{pid}/tenants/{tid}/records/notes", token=session)
assert status == 200 and [r["id"] for r in page["items"]] == [record["id"]], page
print(f"compose smoke ({mode}): ok")
PY
