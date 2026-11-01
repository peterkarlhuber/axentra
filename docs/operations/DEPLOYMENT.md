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
| Persistent volume | `/var/lib/axentra/var` (local file storage of the planned storage module) |

## Container image

```bash
docker build -t axentra:local .                                 # extras: server
docker build --build-arg EXTRAS=server,oidc,s3,otel -t axentra:full .
```

- Multi-stage build on `python:3.13-slim`; the runtime stage contains only a virtual environment
  in `/opt/axentra` and no build tools.
- Dependencies are pinned with `deploy/constraints.txt` (`pip install --constraint`); regenerate
  it as described in its header after dependency changes.
- Runs as `axentra` (uid/gid 10001), working directory `/var/lib/axentra`.
- `ENTRYPOINT ["axentra"]`, default `CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]`, so
  `docker run axentra:local migrate` or `... admin setup-token` run other commands.
- `HEALTHCHECK` calls `GET /v1/health/live`. Use `/v1/health/ready` (checks the database, `503`
  when unavailable) for load balancer readiness.
- The image contains no configuration; mount a TOML file and set `AXENTRA_CONFIG`.

## Compose stacks

`deploy/compose/docker-compose.single.yml` and `docker-compose.multi.yml` are identical except for
the configuration file (`deploy/config/single.toml` or `multi.toml`):

- `db`: `postgres:16` with a named volume. On first initialization,
  `deploy/compose/initdb/01-roles.sql` creates `axentra_owner` (owns the database and schema,
  runs migrations) and `axentra_app` (no superuser, no BYPASSRLS, no DDL, `SELECT/INSERT/UPDATE/
  DELETE` on the owner's tables through default privileges). The port is not published.
- `migrate`: one-shot `axentra migrate` as `axentra_owner`, after the database is healthy.
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
- Keyring via `security.master_keys_ref` (`file:/run/secrets/...` preferred), backed up separately
  from database backups.
- Database URL via `database.url_ref`; the API role is not a superuser and has no `BYPASSRLS`
  (startup fails otherwise). Do not set `database.allow_superuser`.
- `database.pool_max` x number of API processes stays below PostgreSQL `max_connections` (leave
  room for migrations, backups and administration).
- Reverse proxy limits: request body size (Axentra has no global limit; records are capped at
  256 KiB), request rate, timeouts.
- Decide whether `/v1/docs` and `/v1/openapi.json` should be reachable publicly; block them at the
  proxy if not.
- Logs are JSON on stdout (`observability.log_format = "json"`), with request ids; ship them to
  your log system. Secrets are redacted, but treat logs as personal data (IP addresses, emails).
- Backups scheduled and restore tested ([BACKUP_RESTORE](BACKUP_RESTORE.md)).
- Retention: expired sessions and old audit events are not purged automatically yet
  ([TODO](../TODO.md)).

## Without containers

```bash
pip install --constraint deploy/constraints.txt "axentra[server]"
AXENTRA_CONFIG=/etc/axentra/axentra.toml axentra migrate          # as the owner role
AXENTRA_CONFIG=/etc/axentra/axentra.toml axentra serve --host 0.0.0.0 --port 8080
```

Run `axentra serve` under a process manager (systemd) as an unprivileged user. For roles on an
existing PostgreSQL server, run the statements of `deploy/compose/initdb/01-roles.sql` with your
own passwords (the `\getenv` lines are psql-specific).
