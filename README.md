<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/branding/axentra-logo-on-dark.png">
    <img src="assets/branding/axentra-logo.png" alt="Axentra" width="480">
  </picture>
</p>

# Axentra

Axentra is a reusable, modular backend foundation for SaaS products. It provides the parts
almost every SaaS backend needs (users and sessions, products and tenants, roles and API keys,
tenant-isolated data, an audit trail) as one Python package on PostgreSQL, so a product team can
build on it instead of rewriting them.

- **Python >= 3.11**, FastAPI (HTTP layer only), psycopg 3, PostgreSQL 15+ (16 recommended).
- **Security by default**: deny-by-default authorization, no existence oracle, forced row-level
  security on every product and tenant table, hashed session tokens and API keys, CSRF and origin
  checks, redacted logs and audit details.
- **Independent**: Axentra does not depend on Nodestro, orkexa or Axentra Studio. These
  dependencies are forbidden by import-linter contracts, by an architecture test and by a CI check
  of the installed packages.

Status: **alpha** (`0.1.0.dev0`, HTTP API `v1`, API version `1.0`), not production-ready: no
production deployment, no load tests, provider adapters tested against local fakes only. What is
implemented and tested, with evidence and the acceptance criteria status:
[docs/AXENTRA_IMPLEMENTATION_REPORT.md](docs/AXENTRA_IMPLEMENTATION_REPORT.md). See also
[docs/ROADMAP.md](docs/ROADMAP.md) and [docs/TODO.md](docs/TODO.md).

## Two ways to use it

Axentra is not published on PyPI yet; install it from the
repository at a commit, or from a checkout (`pip install -e ".[server]"`).

| | Library | HTTP API |
|---|---|---|
| Install | `pip install "axentra @ git+https://github.com/peterkarlhuber/axentra.git@<commit>"` | `pip install "axentra[server] @ git+https://github.com/peterkarlhuber/axentra.git@<commit>"` or the container image |
| Entry point | `axentra.platform.Axentra` | `axentra serve`, `/v1/...` |
| Security context | You pass a `Principal` to every service call | Built from the session cookie, bearer session token or API key |
| Typical user | A Python product backend that runs Axentra in-process | Frontends, other languages, Axentra Studio |

```python
from axentra.config import load_settings
from axentra.platform import Axentra

ax = Axentra.from_settings(load_settings("axentra.toml"))
ax.migrate()   # once per deployment (or `axentra migrate`)
ax.start()
principal = ax.api_keys.authenticate("axk_...")          # or ax.identity.resolve_session(token)
record = ax.records.create(principal, product_id, tenant_id, "invoices", {"total": 42})
```

The HTTP API is a thin layer over exactly these services. See
[docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md).

## Two deployment models

- **Single-product** (`mode = "single"`): one installation serves one SaaS product. The product
  is created on first start from `[product]`; product creation and archiving are refused.
- **Multi-product** (`mode = "multi"`): one installation serves several products. Platform admins
  create, archive and restore products; each product has its own operators, roles, API keys,
  tenants and data.

See [docs/architecture/DEPLOYMENT_MODELS.md](docs/architecture/DEPLOYMENT_MODELS.md).

## Modules

Status legend: **implemented** means the code is merged and covered by unit tests and by
PostgreSQL integration tests. **planned** means it does not exist in this codebase yet.

| Module | What it does | Status |
|---|---|---|
| `core` | Errors, prefixed ids, cursor pagination, `Principal`, redaction | implemented |
| `config` | TOML + `AXENTRA__*` environment settings, secret references, AES-256-GCM keyring | implemented |
| `data` | Connection pool, scoped transactions, RLS, checksummed migrations, JSON records | implemented |
| `identity` | Users, Argon2id passwords, server-side sessions, first-run setup, login throttling | implemented |
| `identity` (OIDC) | Login with OpenID Connect providers (code + PKCE, state, nonce) | implemented |
| `tenancy` | Products, product operators, tenants, memberships, invitations | implemented |
| `access` | Permission catalog, built-in and custom roles, authorizer, API keys | implemented |
| `audit` | Append-only, redacted audit trail written in the same transaction | implemented |
| `api` | FastAPI `/v1`, RFC 9457 errors, security headers, CORS, committed OpenAPI | implemented |
| `cli` | `axentra serve / migrate / worker / admin / openapi / storage / notify-dispatch / maintenance / keys / secrets`, and `axentra remote` (administration over the HTTP API, no database access) | implemented |
| `storage` | File storage (local, S3-compatible), quotas, signed downloads | implemented (S3 tested against moto only) |
| `events` | Events, background jobs (at least once), schedules, webhooks | implemented |
| `usage` | Meters, idempotent usage recording, quotas, reservations | implemented |
| `observability` | Prometheus metrics, OpenTelemetry tracing, health checks | implemented |
| `realtime` | Server-sent events for events and jobs (database polling) | implemented; no WebSockets |
| `billing` | Plans, subscriptions, entitlements, payment provider adapters (manual, fake, Stripe) | implemented (Stripe adapter not tested against Stripe) |
| `notify` | Email templates, outbox, delivery (local, SMTP), preferences | implemented (email only) |
| `search` | Tenant-scoped PostgreSQL full-text search (ranking, highlights), pluggable search adapters | implemented (no vector search, no external adapters shipped) |

Endpoint catalog: [docs/architecture/API_V1_ENDPOINTS.md](docs/architecture/API_V1_ENDPOINTS.md);
the authoritative contract is [openapi/axentra-v1.json](openapi/axentra-v1.json).

## Quick start

### Docker Compose

Needs Docker with Compose v2.

```bash
cd deploy/compose
cp .env.example .env
docker build -t axentra:local ../..                                  # or let compose build it
docker run --rm axentra:local keys generate --kid k1                 # put the output into AXENTRA_MASTER_KEYS
# fill in the three database passwords in .env (openssl rand -hex 24)
docker compose -f docker-compose.single.yml up -d                    # or docker-compose.multi.yml
docker compose -f docker-compose.single.yml run --rm api admin setup-token
curl -s http://localhost:8080/v1/meta
```

Then create the first platform admin with the printed token:

```bash
curl -s -X POST http://localhost:8080/v1/auth/setup -H 'Content-Type: application/json' \
  -d '{"setup_token": "axsetup_...", "email": "you@example.com", "name": "You", "password": "a long passphrase"}'
```

`.env.example` starts in `development` so that plain HTTP on localhost works. For production,
read [docs/operations/DEPLOYMENT.md](docs/operations/DEPLOYMENT.md).

### Local virtual environment

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"     # or: uv venv && uv pip install -e ".[dev]"
createdb axentra                                                   # a local PostgreSQL
export AXENTRA__DATABASE__URL=postgresql://$USER@127.0.0.1:5432/axentra
.venv/bin/axentra migrate
.venv/bin/axentra admin setup-token
.venv/bin/axentra serve                                            # http://127.0.0.1:8080/v1/docs
```

In `development` (the default environment) Axentra creates a local keyring in `./var/dev-keyring`
and tolerates a superuser database role. Development setup, tests and checks:
[docs/development/DEVELOPMENT.md](docs/development/DEVELOPMENT.md).

## Configuration

One validated settings object from defaults, an optional TOML file (`AXENTRA_CONFIG` or
`--config`) and `AXENTRA__SECTION__KEY` environment variables. Secrets are referenced
(`env:NAME`, `file:/path`), never inlined in production. Every setting:
[docs/operations/CONFIGURATION.md](docs/operations/CONFIGURATION.md). Examples:
[deploy/config/single.toml](deploy/config/single.toml), [deploy/config/multi.toml](deploy/config/multi.toml).

## Axentra Studio

[Axentra Studio](https://github.com/peterkarlhuber/axentra-studio) is the optional admin UI for
Axentra, in a separate repository. It talks to Axentra only through the public HTTP API and its
committed OpenAPI contract, and it checks `GET /v1/meta` for a compatible API version at startup.
Axentra runs without Studio; Studio is just another client. Tested combinations are listed in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Documentation

- Architecture: [overview](docs/architecture/OVERVIEW.md), [security model](docs/architecture/SECURITY_MODEL.md),
  [data](docs/architecture/DATA.md), [embedding](docs/architecture/EMBEDDING.md), [deployment models](docs/architecture/DEPLOYMENT_MODELS.md),
  [versioning](docs/architecture/VERSIONING.md), [API conventions](docs/architecture/API_CONVENTIONS.md),
  [decisions (ADRs)](docs/adr/)
- Guides: [building a product](docs/guides/BUILDING_A_PRODUCT.md), [product tables](docs/guides/PRODUCT_TABLES.md);
  tested examples: [examples/](examples/README.md) (Taskboard demo SaaS, single- and multi-product deployments)
- Client SDKs: [TypeScript](docs/sdk/TYPESCRIPT.md) (`sdk/typescript`), [Python](docs/sdk/PYTHON.md) (`sdk/python`)
- Modules: [identity](docs/modules/IDENTITY.md), [events and jobs](docs/modules/EVENTS_AND_JOBS.md),
  [storage](docs/modules/STORAGE.md), [usage](docs/modules/USAGE.md), [billing](docs/modules/BILLING.md),
  [notify](docs/modules/NOTIFY.md), [search](docs/modules/SEARCH.md)
- Operations: [deployment](docs/operations/DEPLOYMENT.md), [configuration](docs/operations/CONFIGURATION.md),
  [backup and restore](docs/operations/BACKUP_RESTORE.md), [observability](docs/operations/OBSERVABILITY.md)
  (metrics, tracing, health, logs)
- Project: [implementation report](docs/AXENTRA_IMPLEMENTATION_REPORT.md), [roadmap](docs/ROADMAP.md),
  [open work](docs/TODO.md), [compatibility matrix](docs/COMPATIBILITY.md), [changelog](CHANGELOG.md),
  [Nodestro reuse analysis](docs/architecture/NODESTRO_REUSE.md),
  [Nodestro migration plan](docs/integrations/NODESTRO_MIGRATION_PLAN.md) (analysis only)

## License

MIT, see [LICENSE](LICENSE). Provenance of adapted code: [NOTICE.md](NOTICE.md).
