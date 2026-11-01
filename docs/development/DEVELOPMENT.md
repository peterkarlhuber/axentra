# Development

## Requirements

- Python 3.11, 3.12 or 3.13 ([ADR 0002](../adr/0002-python-versions.md)).
- PostgreSQL 15 or newer (16 recommended; CI uses 15, 16 and 17), plus the client tools
  `pg_dump`/`pg_restore` for the backup/restore test.
- Optional: Docker with Compose v2 for the container image and compose stacks.

## Virtual environment

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
# or, with uv:
uv venv .venv -p 3.12 && VIRTUAL_ENV=$PWD/.venv uv pip install -e ".[dev]"
```

`dev` installs the `server` and `oidc` extras plus pytest, mypy, ruff, import-linter, moto and
boto3.

## PostgreSQL for development and tests

Any reachable server works. Examples:

```bash
# Debian/Ubuntu package
sudo pg_ctlcluster 16 main start
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'pg'"

# or a container
docker run -d --name axentra-pg -e POSTGRES_PASSWORD=pg -p 5432:5432 postgres:16
```

Run the API against a local database:

```bash
createdb -h 127.0.0.1 -U postgres axentra
export AXENTRA__DATABASE__URL=postgresql://postgres:pg@127.0.0.1:5432/axentra
.venv/bin/axentra migrate
.venv/bin/axentra admin setup-token          # one-time token for POST /v1/auth/setup
.venv/bin/axentra serve                      # http://127.0.0.1:8080/v1/docs
```

The default environment is `development`: superuser database roles are tolerated, plain HTTP
cookies are used for `http://` public URLs, and a keyring is generated in `./var/dev-keyring`.
For Studio on `http://localhost:5173`, add
`AXENTRA__SECURITY__ALLOWED_ORIGINS='["http://localhost:5173"]'`.

## Tests

```bash
export AXENTRA_TEST_DATABASE_URL=postgresql://postgres:pg@127.0.0.1:5432/postgres
.venv/bin/pytest -q
```

- `AXENTRA_TEST_DATABASE_URL` must be a **superuser** URL. Each test session creates its own
  database (`axentra_test_<random>`), so parallel runs do not collide, and drops it at the end.
- The fixtures create the role **`axentra_test_app`** (`LOGIN NOSUPERUSER NOBYPASSRLS`), make it
  the owner of the test database and run migrations and the application as that role. Because
  the policies are `FORCE`d, row-level security is enforced in every integration test, exactly as
  in production. `tests/integration/test_rls.py` checks that the role really is not privileged.
- Without the variable, PostgreSQL tests are **skipped and reported** (`-ra`). CI fails if any
  test was skipped.
- `tests/integration/test_backup_restore.py` needs `pg_dump`/`pg_restore` with a major version at
  least the server's; set `AXENTRA_TEST_PG_BINDIR=/usr/lib/postgresql/17/bin` to choose them.
- Fixtures: `world` (multi-product app with a bootstrapped platform admin `Browser` that sends the
  Studio origin and CSRF header), `single_world` (single-product mode), `ax_factory(**overrides)`
  for custom settings. Every test starts with truncated `axentra_*` tables.
- Markers: `postgres` (needs the database), `slow`.

## Checks

The same checks run in CI (`.github/workflows/ci.yml`); run them before every commit:

```bash
.venv/bin/ruff check src tests
.venv/bin/ruff format src tests            # CI runs `ruff format --check`
.venv/bin/mypy                             # strict, Python 3.11 target
.venv/bin/lint-imports                     # layering and independence contracts
.venv/bin/axentra openapi export           # regenerate openapi/axentra-v1.json; commit it
AXENTRA_TEST_DATABASE_URL=... .venv/bin/pytest -q
```

- **Architecture**: `lint-imports` enforces the contracts in `pyproject.toml`;
  `tests/unit/test_architecture.py` checks the same rules plus "the library imports without
  FastAPI" and "no Nodestro/orkexa/Studio in the dependencies". A new domain package must be added
  to the first import-linter contract and to `DOMAIN` in the test.
- **OpenAPI**: `axentra openapi export` writes the contract generated in multi-product mode with
  all modules; `--check` fails on drift (CI and `tests/unit/test_openapi.py`). Any change to
  routes or response models changes this file; commit it in the same change.
- **Security scans** (CI): `bandit -r src`, `pip-audit`.
- **Container** (CI): `docker build`, `docker compose config` for both compose files.

## Conventions

- Services take a `Principal` first, call `authz.require`, use the narrowest `DbScope`, and write
  `audit.record` in the same transaction ([OVERVIEW](../architecture/OVERVIEW.md)).
- Raise `axentra.core.errors` classes; never return error dicts.
- SQL with bound parameters only. New tables follow the RLS template
  ([DATA](../architecture/DATA.md)); never edit an applied migration.
- Every `/v1` route depends on `CurrentPrincipal` or is listed in `PUBLIC_ROUTES`.
- Add a line to `CHANGELOG.md` under "Unreleased".
