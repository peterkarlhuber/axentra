<p align="center">
  <img src="assets/branding/axentra-logo.png" alt="Axentra" width="560">
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

Status: **alpha** (`0.1.0.dev0`, HTTP API `v1`, API version `1.0`). See
[docs/ROADMAP.md](docs/ROADMAP.md) and [docs/TODO.md](docs/TODO.md).

## Two ways to use it

| | Library | HTTP API |
|---|---|---|
| Install | `pip install axentra` | `pip install "axentra[server]"` or the container image |
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
| `identity` (OIDC) | Login with OpenID Connect providers (settings and tables exist, endpoints do not yet) | in progress (Phase 1) |
| `tenancy` | Products, product operators, tenants, memberships, invitations | implemented |
| `access` | Permission catalog, built-in and custom roles, authorizer, API keys | implemented |
| `audit` | Append-only, redacted audit trail written in the same transaction | implemented |
| `api` | FastAPI `/v1`, RFC 9457 errors, security headers, CORS, committed OpenAPI | implemented |
| `cli` | `axentra serve / migrate / admin setup-token / openapi export / keys generate` | implemented |
| `storage` | File storage (local, S3-compatible) | planned (Phase 2) |
| `events` | Events, background jobs, webhooks | planned (Phase 2) |
| `usage` | Meters, usage recording, quotas | planned (Phase 2) |
| `observability` | Metrics, OpenTelemetry tracing | planned (Phase 2) |
| `realtime` | Server-sent events | planned (Phase 2) |
| `billing` | Plans, subscriptions, entitlements, payment provider adapters | planned (Phase 3) |
| `notify` | Notification templates, email delivery, preferences | planned (Phase 3) |

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
  [data](docs/architecture/DATA.md), [deployment models](docs/architecture/DEPLOYMENT_MODELS.md),
  [versioning](docs/architecture/VERSIONING.md), [API conventions](docs/architecture/API_CONVENTIONS.md),
  [decisions (ADRs)](docs/adr/)
- Guides: [product tables](docs/guides/PRODUCT_TABLES.md)
- Client SDKs: [TypeScript](docs/sdk/TYPESCRIPT.md) (`sdk/typescript`), [Python](docs/sdk/PYTHON.md) (`sdk/python`)
- Operations: [deployment](docs/operations/DEPLOYMENT.md), [configuration](docs/operations/CONFIGURATION.md),
  [backup and restore](docs/operations/BACKUP_RESTORE.md)
- Project: [roadmap](docs/ROADMAP.md), [open work](docs/TODO.md), [changelog](CHANGELOG.md),
  [Nodestro reuse analysis](docs/architecture/NODESTRO_REUSE.md),
  [Nodestro migration plan](docs/integrations/NODESTRO_MIGRATION_PLAN.md) (analysis only)

## License

MIT, see [LICENSE](LICENSE). Provenance of adapted code: [NOTICE.md](NOTICE.md).
