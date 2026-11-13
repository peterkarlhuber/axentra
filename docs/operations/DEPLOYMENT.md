# Deployment

Axentra runs as a stateless HTTP process (`axentra serve`) in front of PostgreSQL. This page
covers the container image, the compose stacks and the production checklist. Settings:
[CONFIGURATION](CONFIGURATION.md). Mode choice: [DEPLOYMENT_MODELS](../architecture/DEPLOYMENT_MODELS.md).

## Components

| Component | Notes |
|---|---|
| PostgreSQL 15+ (16 recommended) | Two roles: an **owner** for migrations and a restricted **application** role for the API |
| Migration job | `axentra migrate` once per release, before new API processes start; safe to run concurrently (advisory lock) |
| API processes | `axentra serve --host 0.0.0.0 --port 8080`; scale horizontally, no sticky sessions needed |
| Reverse proxy | TLS termination, request size and rate limits, HTTP/2; forward to port 8080 |
| Secrets | Database URLs and the keyring via `env:` or `file:` references |
| Persistent volume | `/var/lib/axentra/var` (local file storage, `storage.local_path`) |

## Container image

```bash
docker build -t axentra:local .                                 # extras: server
docker build --build-arg EXTRAS=server,oidc,s3,otel -t axentra:full .
```

- Multi-stage build on `python:3.13-slim`; the runtime stage contains only a virtual environment
  in `/opt/axentra` and no build tools.
- Every installed distribution is pinned by version and hash (`pip install --require-hashes`):
  `deploy/locks/server.txt` for `EXTRAS=server`, `deploy/locks/full.txt` for any other `EXTRAS`
  (it holds the dependencies of all extras), and the build backend (hatchling) from
  `deploy/locks/build.txt`, which builds Axentra's own wheel offline in a separate venv that does
  not reach the image. Tabrion is not on a package index: `deploy/locks/tabrion.txt` pins the
  source archive of the commit that `requirements/tabrion.txt` names by hash, and the build stage
  builds its wheel offline with the same backend. `pip check` in the build fails when a lock lacks a dependency of the
  requested extras. The versions follow `deploy/constraints.txt` (used for installs without the
  image); after a change to it or to the dependencies, regenerate the locks with
  `scripts/update_locks.sh` (needs `uv`); CI's `scripts/check_locks.py` refuses locks that drift
  from the constraints or lack hashes.
- SBOM: the build writes a CycloneDX 1.5 SBOM of the image's Python environment to
  `/opt/axentra/sbom.cdx.json` (`deploy/sbom.py`, deterministic; a timestamp only with
  `SOURCE_DATE_EPOCH`). Read it with
  `docker run --rm --entrypoint cat axentra:local /opt/axentra/sbom.cdx.json`; CI keeps it as the
  artifact `sbom-axentra`. It covers Python distributions, not the Debian packages of the base
  image (scan the image for those).
- Runs as `axentra` (uid/gid 10001), working directory `/var/lib/axentra`.
- `ENTRYPOINT ["axentra"]`, default `CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]`, so
  `docker run axentra:local migrate` or `... admin setup-token` run other commands.
- `HEALTHCHECK` calls `GET /v1/health/live`. Use `/v1/health/ready` (checks the database, `503`
  when unavailable) for load balancer readiness.
- The image contains no configuration; mount a TOML file and set `AXENTRA_CONFIG`.

## Compose stacks

`deploy/compose/docker-compose.single.yml` and `docker-compose.multi.yml` are identical except for
the configuration file (`deploy/config/single.toml` or `multi.toml`):

- `db`: `postgres:16`, pinned by digest (CI checks the pin; Dependabot proposes updates), with a named
  volume. On first initialization,
  `deploy/compose/initdb/01-roles.sql` creates `axentra_owner` (owns the database and schema,
  runs migrations) and `axentra_app` (no superuser, no BYPASSRLS, no DDL, `SELECT/INSERT/UPDATE/
  DELETE` on the owner's tables through default privileges). The port is not published.
- `migrate`: one-shot `axentra migrate --grant-runtime-role axentra_app` as `axentra_owner`, after
  the database is healthy (the grant also makes `axentra_schema_migrations` read-only for the
  application role; idempotent, `axentra db grant-runtime-role`).
- `api`: `axentra serve` as `axentra_app`, after `migrate` completed successfully. Read-only root
  filesystem, all capabilities dropped, `no-new-privileges`, `/tmp` as tmpfs.

`deploy/compose/docker-compose.taskboard.yml` follows the same pattern for the demo product
[examples/taskboard](../../examples/taskboard/), which embeds Axentra as a library. Its `migrate`
job runs `taskboard migrate` (Axentra's and the `taskboard` namespace), and its `app` serves
Taskboard with the Axentra API mounted under `/axentra`, on port 8090, using its own database.

Values come from `deploy/compose/.env` (template: `.env.example`): database passwords
(URL-safe, e.g. `openssl rand -hex 24`), the keyring (`AXENTRA_MASTER_KEYS`, from
`axentra keys generate`), and `AXENTRA_ENVIRONMENT`, `AXENTRA_PUBLIC_URL`,
`AXENTRA_ALLOWED_ORIGINS`, `AXENTRA_HTTP_PORT`, which override the TOML file.

```bash
cd deploy/compose
cp .env.example .env && $EDITOR .env
docker compose -f docker-compose.single.yml up -d --build
docker compose -f docker-compose.single.yml logs migrate                 # {"applied": [...]}
docker compose -f docker-compose.single.yml run --rm api admin setup-token
curl -fsS http://localhost:8080/v1/health/ready
```

Then create the first platform admin with `POST /v1/auth/setup` (or through Studio).

`scripts/compose_smoke.sh single|multi [port]` does all of this unattended against the image
`axentra:local`: throwaway passwords and keyring, `up`, readiness, the mode in `/v1/meta`, a setup
token, the first admin, a product (multi), a tenant and a record written as the restricted role;
the stack and its volumes are removed afterwards. CI runs it for both stacks with the image it
built (the Taskboard stack is built, not started).

Upgrades: pull/build the new image, then `docker compose ... up -d`: the `migrate` job runs
again (idempotent) before the API restarts. Take a backup first
([BACKUP_RESTORE](BACKUP_RESTORE.md)); migrations are forward-only.

The compose files are a starting point for a single host. They do not include a reverse proxy or
TLS; `.env.example` uses `development` so that plain HTTP on localhost works.

## Production checklist

- `environment = "production"`; `security.public_url` is the external `https://` URL.
- TLS terminated by a reverse proxy; the proxy's address in `security.trusted_proxies` (and
  nothing broader), so client IPs for throttling and audit are correct.
- `security.allowed_origins`: exactly the product frontends and Studio origins (https).
- Invitation links: when the page that accepts invitations (Studio or a product frontend) is not
  served on `security.public_url`, set `notify.invitation_accept_url` (for Studio
  `https://studio.example.com/invitations/accept`) or the product's `settings.invitation_accept_url`;
  the default `<public_url>/accept-invitation` points to the API origin.
- Keyring via `security.master_keys_ref` (`file:/run/secrets/...` preferred), backed up separately
  from database backups.
- Database URL via `database.url_ref`; the API role is not a superuser and has no `BYPASSRLS`
  (startup fails otherwise). Do not set `database.allow_superuser`.
- Separate roles: migrations run as the **owner** role (`axentra migrate --grant-runtime-role
  axentra_app`, or `database.migration_url_ref`), and the API, the worker and the notification
  dispatcher connect as the **runtime** role, which owns no table. Production refuses to start when
  the runtime role owns the tables protected by row-level security (it could switch RLS off);
  `database.allow_table_owner = true` (`AXENTRA__DATABASE__ALLOW_TABLE_OWNER=true`) overrides this
  with a warning at every start and should stay a temporary measure.
- `database.pool_max` x number of API processes stays below PostgreSQL `max_connections` (leave
  room for migrations, backups and administration).
- Limits: Axentra refuses bodies above `security.max_body_bytes` (10 MiB; uploads use
  `storage.max_file_bytes`) and can rate-limit per credential and per IP
  (`security.rate_limit_per_minute`, `rate_limit_ip_per_minute`; off by default, per process).
  Keep timeouts, slow-client protection and any global rate limit in the reverse proxy.
- `/v1/docs` and `/v1/openapi.json` are disabled in production unless `security.api_docs` is
  `public` or `authenticated`.
- Logs are JSON on stdout (`observability.log_format = "json"`), with request ids; ship them to
  your log system. Secrets are redacted, but treat logs as personal data (IP addresses, emails).
- Backups scheduled and restore tested ([BACKUP_RESTORE](BACKUP_RESTORE.md)).
- Retention: the job worker's leader runs `axentra maintenance purge` tasks hourly (audit
  retention, expired sessions, notification retention, storage purge); without a worker, schedule
  `axentra maintenance purge` yourself.
- Key rotation: `axentra secrets reencrypt` after a new key is in front of the keyring
  ([SECURITY_MODEL](../architecture/SECURITY_MODEL.md#secrets-and-the-keyring)).

## Without containers

```bash
pip install --constraint deploy/constraints.txt -r requirements/tabrion.txt "axentra[server]"  # pip >= 25.0
AXENTRA_CONFIG=/etc/axentra/axentra.toml axentra migrate          # as the owner role
AXENTRA_CONFIG=/etc/axentra/axentra.toml axentra serve --host 0.0.0.0 --port 8080
```

Run `axentra serve` under a process manager (systemd) as an unprivileged user. For roles on an
existing PostgreSQL server, run the statements of `deploy/compose/initdb/01-roles.sql` with your
own passwords (the `\getenv` lines are psql-specific), or create the two roles yourself and let
`axentra db grant-runtime-role axentra_app` (as the owner) grant the runtime role; `axentra db
inspect-role` shows whether row-level security fully applies to the application role (no
superuser, no `BYPASSRLS`, owns no table).

## Administration over HTTP (`axentra remote`)

The other CLI commands connect to PostgreSQL and need the configuration (database URL, keyring).
`axentra remote` needs only the API's URL and a credential, uses the API's permission checks and
audit trail, and works with the core install (standard library HTTP only):

```bash
export AXENTRA_URL=https://api.example.com
export AXENTRA_SESSION_TOKEN="$(axentra remote login admin@example.com)"   # password prompted
axentra remote whoami
axentra remote products create crm "CRM"                 # platform admins; also list|get|archive|restore
axentra remote tenants create prd_... acme "Acme"        # also list|get|suspend|activate
axentra remote keys create prd_... ci --permission tenant:read --tenant-id ten_...   # secret printed once
axentra remote keys rotate prd_... key_... --grace-seconds 3600                      # also list|revoke
axentra remote users list --q alice                      # also disable|enable|revoke-sessions
```

The credential comes from `AXENTRA_API_KEY` or `AXENTRA_SESSION_TOKEN` (or `--api-key-file` /
`--session-token-file`), never from a command-line argument, so it does not appear in `ps` or the
shell history; `login` reads the password from a prompt (or `AXENTRA_PASSWORD` for scripts).
Answers are printed as JSON; an error answer prints `axentra: <code>: <detail>` and exits with 2.
Revoke a session token you no longer need with `axentra remote users revoke-sessions <your id>`
or by signing out in Studio.
