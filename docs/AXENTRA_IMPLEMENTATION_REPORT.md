# Axentra implementation report

Status: **alpha**, package `0.1.0.dev0`, HTTP API `v1` (API version `1.0`). Report date:
2026-11-02. Basis: `master` at
[`7511a37`](https://github.com/peterkarlhuber/axentra/commit/7511a37ce0876c13e5a9c861e3b9e31b6401d99c)
(merge of PR #9). All local numbers below were measured on 2026-11-02 on that commit plus the
one-line test fix in this report's pull request (section 7.3), on Linux (Ubuntu, Python 3.12.3,
PostgreSQL 16). Later additions are marked: the search module (PR #11, `f80429f`), a second
flaky-test fix (section 7.3) and the Studio single-product results (PR #4 in Studio, criterion 24).

This report covers the backend (`peterkarlhuber/axentra`). The admin UI has its own report:
[`docs/AXENTRA_STUDIO_IMPLEMENTATION_REPORT.md` in peterkarlhuber/axentra-studio](https://github.com/peterkarlhuber/axentra-studio/blob/master/docs/AXENTRA_STUDIO_IMPLEMENTATION_REPORT.md)
(Studio functions, screenshots, design system and branding, browser tests). Where this report says
"Studio report", it means that file.

Nothing here is production-ready in the sense of the order: Axentra has not been deployed to a
production environment, has not been load-tested, and its provider adapters (Stripe, S3, SMTP)
have only been tested against local fakes. Section 12 lists every open limitation.

## Contents

1. [Architecture overview](#1-architecture-overview)
2. [Implemented modules and actual scope](#2-implemented-modules-and-actual-scope)
3. [Components reused or adapted from Nodestro](#3-components-reused-or-adapted-from-nodestro)
4. [API and SDK overview](#4-api-and-sdk-overview)
5. [Installation and start commands](#5-installation-and-start-commands)
6. [Deployment models: evidence](#6-deployment-models-evidence)
7. [Test evidence and CI results](#7-test-evidence-and-ci-results)
8. [Security checks](#8-security-checks)
9. [Independent builds and headless operation](#9-independent-builds-and-headless-operation)
10. [Version and API compatibility](#10-version-and-api-compatibility)
11. [Joint integration tests with Axentra Studio](#11-joint-integration-tests-with-axentra-studio)
12. [Open limitations and residual risks](#12-open-limitations-and-residual-risks)
13. [Pull requests and merge SHAs](#13-pull-requests-and-merge-shas)
14. [Notes for the later Nodestro integration](#14-notes-for-the-later-nodestro-integration)
15. [Acceptance criteria status](#15-acceptance-criteria-status)

## 1. Architecture overview

- **Modular monolith** in one Python package `axentra` (Python >= 3.11; CI runs 3.11, 3.12 and 3.13)
  on one PostgreSQL database (15, 16 and 17 in CI). Decision records: [docs/adr/](adr/)
  (12 ADRs, e.g. [0001](adr/0001-modular-monolith-single-package.md),
  [0005 row-level security](adr/0005-row-level-security.md),
  [0010 single/multi product](adr/0010-single-and-multi-product.md),
  [0012 Studio separation](adr/0012-studio-separation.md)).
- **Two ways to use it, same services.** As a library (`axentra.platform.Axentra`, every service
  call takes a `Principal`) or as an HTTP service (`axentra serve`, FastAPI, `/v1`). The HTTP
  layer is a thin adapter over the library services; FastAPI is only in the optional `server`
  extra.
- **Layering** (enforced by import-linter, 4 contracts, and `tests/unit/test_architecture.py`):
  `core` is the bottom layer; domain packages (`identity`, `tenancy`, `access`, `data`, `audit`,
  `config`, `storage`, `events`, `usage`, `billing`, `notify`, `observability`) never import
  FastAPI/Starlette/uvicorn, `axentra.api` or `axentra.cli`; `usage` never depends on `billing`;
  nothing depends on Nodestro, orkexa or Axentra Studio.
- **Data isolation in the database.** Every product and tenant table carries `product_id`
  (+ `tenant_id`) and has `ENABLE` + `FORCE ROW LEVEL SECURITY` with the policy
  `axentra_scope_allows(product_id, tenant_id)`. Services open the narrowest `DbScope`
  (platform, product or tenant) per transaction, and the app connects as a non-superuser role.
  Tests run under such a role so that RLS is really enforced.
- **Security model**: deny-by-default authorizer ("unrelated is 404, related without permission is
  403"), hashed session tokens and API keys, CSRF + origin checks for cookie sessions, AES-256-GCM
  keyring with key ids and rotation, redaction of secrets in logs and audit details. Details:
  [architecture/SECURITY_MODEL.md](architecture/SECURITY_MODEL.md).
- Further reading: [architecture/OVERVIEW.md](architecture/OVERVIEW.md),
  [architecture/DATA.md](architecture/DATA.md),
  [architecture/API_CONVENTIONS.md](architecture/API_CONVENTIONS.md),
  [architecture/DEPLOYMENT_MODELS.md](architecture/DEPLOYMENT_MODELS.md).

Migrations (forward-only, checksummed, advisory-locked): `0001_foundation`, `0002_events`,
`0003_storage`, `0004_usage_billing`, `0005_notify`, `0006_search`, plus product namespaces through the
`axentra.migrations` entry point group (used by the Taskboard example).

## 2. Implemented modules and actual scope

Legend: **implemented + tested** = merged on `master` and covered by unit tests and by PostgreSQL
integration tests that ran in this report's run. **partial** = some of the functions the order
lists are missing (named). **not implemented** = no code exists.

| Area (order section 4) | Status | What exists | Missing (see section 12 / [TODO.md](TODO.md)) | Main tests |
|---|---|---|---|---|
| A Identity | implemented + tested (partial) | Users, Argon2id passwords, server-side sessions (hashed tokens, idle/absolute expiry, list + revoke own and other users' sessions), first-run setup token, DB-backed login throttling, OIDC login (code + PKCE S256, state bound to a login cookie, nonce, exact issuer, asymmetric algorithms only, verified-email linking), memberships, invitations | MFA, password reset, email verification, OIDC providers are managed by configuration only (no API), RP-initiated logout, users without email, data export/erasure | `test_auth.py` (14), `test_oidc.py` (51), `test_oidc_helpers.py` (34) |
| B Access | implemented + tested (partial) | Permission catalog, built-in and custom roles, authorizer, product/tenant API keys (`axk_`, hash-only, rotation with grace, revocation, expiry inheritance, cascade revocation of derived keys), role ceiling | Product-defined permissions (closed catalog, G-1) | `test_access.py` (8), `test_security_review.py` (15), `test_permissions.py`, `test_route_protection.py` |
| C Tenancy | implemented + tested | Products (single/multi mode), product operators, tenants, memberships, invitations, last-owner guards under concurrency | Claim of ownerless tenants (G-5), operator invitations at product level | `test_tenancy.py` (7), `test_deployment_models.py` (8), `test_security_review.py` |
| D Data | implemented + tested | Pool, scoped transactions, forced RLS, migrations (namespaces, checksums), tenant JSON records (filter, sort, cursor pages, `If-Match`), product tables guide, backup/restore of the database | Records: top-level JSON containment filters only; migration runner features G-2; no down-migrations | `test_rls.py` (5), `test_migrations.py` (2), `test_backup_restore.py` (1), `test_product_tables_guide.py` (1) |
| E Storage | implemented + tested | Local (atomic, fsync) and S3 backends, streamed uploads with size limit, SHA-256, type sniffing + blocklist, attachment-only downloads, exact quotas under concurrency, HMAC-signed download URLs, expiry and purge | Per-product type policy (G-7), resumable/presigned uploads, malware scanning; S3 tested against moto only | `test_storage.py` (14), `test_storage_s3.py` (3), `test_storage_unit.py` (29) |
| F Events and jobs | implemented + tested | PostgreSQL job queue (`SKIP LOCKED`, leases, heartbeats, reaper), priorities, delays, retries with backoff and jitter, dead letters, manual retry, cancel, idempotency keys, schedules (cron, UTC) with leader lock and one firing per slot, events with transactional outbox and subscribers, outgoing webhooks (HMAC signatures, SSRF guard, redelivery), job stats. Guarantee: **at least once**, no exactly-once | Automatic disabling of failing webhook endpoints, non-UTC cron | `test_events_jobs.py` (21), `test_events_webhooks_api.py` (7), `test_events_unit.py` (24) |
| G Config and secrets | implemented + tested | Typed settings (TOML + `AXENTRA__*`), secret references (`env:`, `file:`), AES-256-GCM keyring with key ids, `axentra secrets reencrypt` rotation, production start refused on unsafe settings, feature flags (`features.<name>`) | Secret references support `env:` and `file:` only; no secret manager/KMS provider is bundled (the `SecretProvider` interface allows adding one) | `test_hardening.py` (11), `test_hardening_unit.py` (6), `test_core.py` |
| H Usage | implemented + tested | Meters (sum/max/last), idempotent recording, hard/soft quotas that never overshoot under concurrency, reservations, periods, time series | Separate quota windows; export to metered billing; sweeps must be scheduled by the operator | `test_usage.py` (11) |
| I Billing | implemented + tested (partial) | Plans, subscriptions with a state machine, trials, entitlements feeding usage quotas, providers `manual`, `fake` (test double with signed webhooks) and `stripe` (REST adapter) | Stripe adapter only tested over `httpx.MockTransport`, never against Stripe; no proration, invoices, taxes, portal | `test_billing.py` (9), `test_usage_billing_units.py` (7) |
| J Notify | implemented + tested (partial) | Versioned email templates (de/en), safe renderer, encrypted outbox, idempotent send, preferences, local mailbox and SMTP (STARTTLS) providers, dispatcher with leases and backoff, delivery stats | Email only (no SMS/push); SMTP tested only against an in-process `aiosmtpd` server; per-tenant send rate limits | `test_notify.py` (21), `test_notify_smtp.py` (5), `test_notify_render.py` (6) |
| K Audit and observability | implemented + tested | Append-only redacted audit trail in the same transaction, JSON logs with request ids, `/v1/health/live` and `/v1/health/ready`, Prometheus `/metrics` (token-protected), optional OpenTelemetry tracing, retention purge | OTLP export tested only with an in-memory span processor, never against a collector | `test_observability.py` (5 + 6 unit), audit assertions throughout |
| L Search and realtime | implemented + tested (partial) | Search ([modules/SEARCH.md](modules/SEARCH.md)): tenant-scoped PostgreSQL full-text index (migration `0006_search`, table `axentra_search_documents` with forced RLS, generated `tsvector`, GIN index), index upsert/delete by kind + ref id through `ax.search` and `PUT`/`DELETE .../search/documents/{kind}/{ref_id}` (`search:index`, audited), ranked query with `ts_rank`, HTML-escaped `ts_headline` highlights, kind filter and cursor paging (`GET .../search`, `search:query`), configurable text search configuration (`search.language`, default `simple`), pluggable `SearchAdapter` protocol with the PostgreSQL adapter as default. Realtime: SSE streams `GET .../events/stream` and `.../jobs/stream` (database polling every `events.sse_poll_seconds`) | Search: no vector/semantic search, no external adapters shipped, no prefix/fuzzy matching or accent folding, one language per installation, tenant scope only (no cross-tenant product search, no per-document visibility), offset paging bounded by `search.max_offset`, no bulk/reindex API, no typed Python SDK methods. No WebSockets | `test_search.py` (11), `test_search_unit.py` (6), `test_events_jobs.py::test_job_changes_stream_positions_follow_commit_order` |
| API | implemented + tested | FastAPI `/v1`, RFC 9457 problems, security headers, CORS, body limit, optional rate limit, route protection registry, committed OpenAPI | Problem responses not described in the OpenAPI | `test_openapi.py`, `test_route_protection.py` |
| CLI | implemented + tested | `serve`, `migrate`, `worker`, `admin setup-token`, `openapi export [--check]`, `storage purge`, `notify-dispatch`, `maintenance`, `keys generate`, `secrets reencrypt` | Administration over HTTP | used in tests and section 5 |

Example product (library model): `examples/taskboard` (own tables with forced RLS, authorization via
`ax.authz`, attachments, plan limits), 11 tests in the main pytest run.

## 3. Components reused or adapted from Nodestro

The analysis of all Nodestro repositories (components, decisions Adopt/Adapt/Concept only/Do not
adopt) is [architecture/NODESTRO_REUSE.md](architecture/NODESTRO_REUSE.md); provenance notice in
[NOTICE.md](../NOTICE.md). Source commits (Nodestro `master`, read-only):
nodestro-api `e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea`, nodestro-runtime
`a42b6724702821849af478ee9dd0bfa13617e28b`. All MIT, Copyright (c) 2026 Peter Karlhuber.

Files that carry an "Adapted from" header (grep of `src` and `tests` at `7511a37`):

| Axentra file | Source | What was taken |
|---|---|---|
| `src/axentra/identity/oidc.py` | nodestro-api `src/nodestro_api/identity.py` @ `e7fb1db` | OIDC flow: PKCE, state/nonce, login cookie binding, discovery checks, ID token validation; extended with JWKS TTL, several providers, `client_secret_post` |
| `src/axentra/audit/logging.py` | nodestro-api `src/nodestro_api/identity.py` @ `e7fb1db` | Redaction of auth query values in access logs |
| `src/axentra/events/jobs.py` | nodestro-runtime `src/nodestro_runtime/jobs.py` @ `a42b672` | Claim with `SKIP LOCKED`, leases, heartbeats, conditional finish, reaping, cancellation; Axentra added products/tenants, priorities, delays, retries, dead letters, idempotency, results |
| `src/axentra/events/schedules.py` | nodestro-runtime `src/nodestro_runtime/jobs.py` @ `a42b672` | `LeaderLock` (advisory lock), `ScheduleFirings` (one firing per slot) |
| `tests/integration/test_oidc.py` | nodestro-api `tests/stub_oidc.py` @ `e7fb1db` | In-process stub OIDC provider (`httpx.MockTransport`) |
| `src/axentra/access/api_keys.py` | nodestro-api `api_keys.py`/`serving.py` (concept, no code) | Hash-only storage, constant-time comparison, throttled `last_used_at` |

Everything else (database layer, tenancy, storage, usage, billing, notify, webhooks, SDKs) was
written for Axentra, using Nodestro at most as a design reference ("Concept only" in the analysis).
Deviation from the analysis' attribution policy: it proposed a separate `THIRD_PARTY_NOTICES` list
of ported files; the repository has `NOTICE.md` plus the per-file headers above instead.

## 4. API and SDK overview

- **HTTP API**: `openapi/axentra-v1.json` (OpenAPI 3.1.0, `info.version` 1.0): **109 paths, 150
  operations**. Operations per tag: access 10, audit 3, auth 8, billing 17, events 26 (events,
  jobs, webhooks, schedules, SSE), files 11, meta 3, notify 15, observability 1 (`/metrics`),
  products 11, records 6, tenants 13, usage 18, users 8. Catalog:
  [architecture/API_V1_ENDPOINTS.md](architecture/API_V1_ENDPOINTS.md). The committed file is
  checked against the code by `axentra openapi export --check` (CI and this run: up to date).
- **TypeScript SDK** `@axentra/sdk` 0.1.0 (`sdk/typescript`): types generated from the committed
  OpenAPI (openapi-typescript), `openapi-fetch` client, API key / bearer / cookie mode with CSRF,
  `AxentraApiError`, `checkCompatibility()`, `paginate()`. Docs: [sdk/TYPESCRIPT.md](sdk/TYPESCRIPT.md).
- **Python SDK** `axentra-client` (`sdk/python`): httpx, sync + async (sync generated by
  `scripts/unasync.py`), pydantic models for the main resources; jobs, events and webhooks only
  through `request_json()` (no typed methods yet). Installs without the server package. Docs:
  [sdk/PYTHON.md](sdk/PYTHON.md).
- Neither SDK is published to npm or PyPI.

## 5. Installation and start commands

Verified in this run, from a wheel built from this commit, in a fresh virtual environment that
contains no frontend, no Studio, no Nodestro and no orkexa package (30 packages in `pip freeze`, 0
matches for `nodestro|orkexa|studio`):

```bash
uv build --wheel --sdist -o dist .                       # axentra-0.1.0.dev0-py3-none-any.whl + sdist
python3.12 -m venv /tmp/srv && /tmp/srv/bin/pip install "dist/axentra-0.1.0.dev0-py3-none-any.whl[server]"
/tmp/srv/bin/axentra --version                           # axentra 0.1.0.dev0
export AXENTRA__DATABASE__URL=postgresql://postgres:pg@127.0.0.1:5432/axentra_report_smoke
/tmp/srv/bin/axentra migrate                             # applied axentra:0001_foundation ... 0005_notify
/tmp/srv/bin/axentra admin setup-token                   # prints a one-time axsetup_... token
/tmp/srv/bin/axentra serve --port 18089
curl -s http://127.0.0.1:18089/v1/health/live            # 200 {"status":"ok","checks":{"process":true}}
curl -s http://127.0.0.1:18089/v1/health/ready           # 200 {"status":"ok","checks":{"database":true,"notify_provider":true}}
curl -s http://127.0.0.1:18089/v1/meta                   # mode "single", api_version {"major":1,"minor":0}
```

This used the `development` environment (local dev keyring, superuser role tolerated). Production
settings (keyring from secrets, non-superuser role, HTTPS origins) are described in
[operations/DEPLOYMENT.md](operations/DEPLOYMENT.md) and
[operations/CONFIGURATION.md](operations/CONFIGURATION.md) and are enforced at start-up, but no
production deployment was carried out. The Docker Compose path in the [README](../README.md) was not
run locally (no Docker daemon in this environment); the image and compose files are built and
validated only in CI (section 7.2).

## 6. Deployment models: evidence

| Model | Automated test | Demo against a real `axentra serve` (this run) |
|---|---|---|
| Single-product (`mode = "single"`) | `tests/integration/test_deployment_models.py`: `test_single_product_deployment`, `..._rejects_a_multi_product_server`, `..._rejects_another_product`, `..._detects_a_leak` | `examples/single-product/provision.py --create-users`: exit 0, "19 checks passed, 0 leaks, 0 other failures"; second (idempotent) run exit 0, same result |
| Multi-product (`mode = "multi"`, two products) | `test_multi_product_deployment_isolates_products`, `..._script_detects_a_leak`, `..._refuses_a_single_product_server`, `..._main_exit_codes` | `examples/multi-product/provision.py --create-users` (products `taskboard` and `invoicing`): exit 0, "84 checks passed, 0 leaks, 0 other failures"; second run exit 0 |

The 8 tests in `test_deployment_models.py` passed. The demos ran with the example configs
(`examples/*/axentra.toml`) against fresh databases. A single-product installation needs no central
Axentra infrastructure: it is one process plus its own PostgreSQL database. Not done: starting the
compose stacks (`deploy/compose/docker-compose.single.yml`, `.multi.yml`) and smoke-testing them.

## 7. Test evidence and CI results

### 7.1 Local run (2026-11-02, `7511a37` + test fix, Python 3.12.3, PostgreSQL 16)

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check src tests` / `ruff check examples` | All checks passed |
| Format | `ruff format --check src tests` / `examples` | 135 + 13 files already formatted |
| Types | `mypy` (strict, 98 source files); examples with `mypy --strict` | no issues |
| Architecture | `lint-imports` | 4 contracts kept, 0 broken |
| Contract drift | `axentra openapi export --check` | up to date |
| Backend tests | `pytest -q -rs` (real PostgreSQL, non-superuser role) | **360 passed, 0 failed, 0 skipped** (135 unit, 214 integration, 11 Taskboard example) in 262 s |
| Python SDK | `ruff`, `mypy`, `unasync --check`, `pytest tests/unit tests/integration` | 40 passed; client-only venv without `axentra`: 27 unit tests passed |
| TypeScript SDK | `npm ci`, `generate:check`, `typecheck`, `npm test`, `build` | generated sources up to date; 20 passed; build ok |
| SDK e2e | `scripts/sdk-e2e.sh` (PostgreSQL-backed `axentra serve`, non-superuser role) | TypeScript 8 passed, Python 6 passed |
| Security | `bandit -q -r src -c pyproject.toml`; `pip-audit --skip-editable` | 0 issues; no known vulnerabilities |
| Headless wheel | section 5 and 9 | passed |

### 7.2 CI on GitHub for `master` `7511a37`

Workflow run [41369224331](https://github.com/peterkarlhuber/axentra/actions/runs/41369224331)
(`gh api repos/peterkarlhuber/axentra/commits/7511a37.../check-runs`): **10 of 11 jobs succeeded,
1 failed.**

| Job | Result |
|---|---|
| Lint, types, architecture, contract | success |
| Tests (Python 3.11, PostgreSQL 15) | success |
| Tests (Python 3.12, PostgreSQL 16) | success |
| Tests (Python 3.13, PostgreSQL 17) | **failure**: 1 failed, 359 passed (`test_access.py::test_api_key_lifecycle_and_scope`) |
| TypeScript SDK (generated types, unit tests, build) | success |
| Python SDK (Python 3.11) / (Python 3.13) | success / success |
| SDK contract tests against axentra serve | success |
| Package builds and installs headless | success |
| Container image and compose files (image build, non-root, no forbidden deps) | success |
| Security scans (bandit, pip-audit) | success |

The same pull request's head commit `091ea5f` passed all 11 jobs. The failure is a **flaky test**,
not a product defect (section 7.3). The same flake also failed one job on master `d5e2ba7` (PR #2).
All other merge commits (`37f2919`, `28e2c98`, `55f5be7`, `33dce58`, `b548d11`, `3b110fe`,
`537484f`) and every PR head commit (PR #1 to #9) passed all their jobs.

### 7.3 Flaky test and fix

The test checked that an API key listing does not contain the secret with
`secret.split("_")[-1] not in listing`. The secret part of a key (`axk_<26-char id>_<43 chars>`)
is URL-safe base64 and may itself contain `_`, so the "last segment" was sometimes a single
character (`'g'`, `'k'`) that appears anywhere in the JSON. The fix in this pull request cuts the
secret part by position and asserts it has at least 32 characters.

CI on `master` after that merge (`ddc1f53`, PR #10) then failed one job (Python 3.12) in
`test_security_review.py::test_I4_login_throttling_is_atomic`: 97 password checks passed instead of
the budget of 50. Cause: the test fires 100 concurrent attempts and can straddle a minute
boundary; login throttling uses fixed one-minute windows, which by design allow up to twice the
budget across a boundary (documented in `docs/architecture/SECURITY_MODEL.md`). The counting
itself is atomic. Reproduced locally by making the window alternate between two minutes (100
checks passed); the fix pins the window in the test. `master` `f80429f` (PR #11) passed all 11
jobs on its push run [41381388692](https://github.com/peterkarlhuber/axentra/actions/runs/41381388692).

### 7.4 Coverage of skips

CI fails a test job when PostgreSQL tests were skipped and the Python SDK job fails on any skip.
In this run nothing was skipped.

## 8. Security checks

- **Static analysis and dependencies** (CI job "Security scans", green on `7511a37`; repeated
  locally): `bandit` over `src` with `B101` (assert) and `B608` (SQL string building) skipped in
  `pyproject.toml`, no `nosec` markers; `pip-audit` over the installed `server,oidc,s3` extras
  reports no known vulnerabilities. B608 is skipped project-wide: values are always passed as
  query parameters, but about 20 statements build SQL text with f-strings from column lists and
  identifiers defined in code (and validated identifiers for product-registered columns). This is
  checked by review and tests, not by a scanner rule.
- **Independent review** [security/REVIEW-2026-11-01.md](security/REVIEW-2026-11-01.md) of commit
  `537484f`: no Critical or High finding, no cross-tenant read or write through RLS gaps. Findings:
  3 Medium (F1 role self-promotion of product support, F2 user/email existence oracle across
  products, F6 phishing relay through `notify:send`), 5 Low (F3-F5, F7, F8), 5 Info (I1-I5).
- **Resolution** (PR #9, merge `7511a37`): F1-F8 and I1-I4 fixed, each with a regression test in
  `tests/integration/test_security_review.py` (15 tests, passed); I5 kept as a documented design
  decision. Residuals recorded in [TODO.md](TODO.md): first password for OIDC-only users within the
  fresh-login window (F3), per-tenant send rate limits (F6), revocation of user-created keys when the
  user leaves (F5), optional stricter OIDC auto-linking (I5).
- **Built-in tests of security properties**: forced RLS under a non-superuser role (`test_rls.py`),
  cross-tenant and cross-product tests in every module, 403/404 permission tests, CSRF and origin
  checks, session revocation, login throttling, OIDC adversarial cases (tampered claims, `alg=none`,
  login CSRF), storage path traversal and dangerous types, SSRF guard for webhooks, secret redaction,
  route protection registry (every non-public route needs a principal).
- Not done: penetration test of a deployed instance, fuzzing, a second review after PR #9.

## 9. Independent builds and headless operation

- The core wheel installs **without any extra** and imports `axentra.platform`, `identity`,
  `tenancy`, `storage`, `events`, `usage`, `billing`, `notify`; `fastapi` is absent in that venv
  (checked in this run and in CI job "Package builds and installs headless").
- With the `server` extra, `axentra migrate`, `axentra serve` and both health checks work without
  any frontend (section 5).
- `grep -rE '^\s*(import|from) (nodestro|orkexa|axentra_studio)' src tests examples sdk`: 0 hits.
  `pyproject.toml` mentions these names only in the import-linter contract that forbids them.
  `tests/unit/test_architecture.py` checks imports and package metadata; CI checks `pip freeze` of
  the installed wheel and of the container image.
- Local Nodestro and orkexa checkouts (11 repositories) are at their examined commits with no local
  changes; per the lead's evidence the working branch `claude/project-thread-wj7vfx` does not exist
  in any of them and no PR was opened there.
- Axentra and Studio have separate repositories, CI workflows, versions and changelogs. Axentra's
  build and tests never fetch Studio.

## 10. Version and API compatibility

- Rules: [architecture/VERSIONING.md](architecture/VERSIONING.md). Package SemVer (`0.1.0.dev0`,
  pre-1.0: minor releases may break), HTTP API major in the path (`/v1`), API minor in
  `GET /v1/meta` `api_version` and the `Axentra-API-Version` header (`1.0`; single source
  `axentra.API_VERSION`).
- Both SDKs and Studio refuse a server with a different major or a lower minor than they need
  (`checkCompatibility()`, `check_compatibility()`, Studio `src/api/compat.ts`,
  `REQUIRED_API = {major: 1, minor: 0}`).
- **Studio pin**: Studio `master` `ee7d9f2` pins `api/BACKEND_REF =
  7511a37ce0876c13e5a9c861e3b9e31b6401d99c`; its vendored `api/openapi.json` must be byte-identical
  to that commit's `openapi/axentra-v1.json` (Studio CI job "API contract matches the pinned
  backend").
- Tested combinations: [COMPATIBILITY.md](COMPATIBILITY.md).

## 11. Joint integration tests with Axentra Studio

Responsibility: the **Studio repository** owns the joint integration test. Its CI
(`.github/workflows/ci.yml`) does, for every Studio pull request:

1. reads `api/BACKEND_REF` (a full Axentra SHA) and checks out `peterkarlhuber/axentra` at it;
2. job `contract`: Studio's vendored contract and generated types equal that commit's OpenAPI;
3. job `e2e`: installs `axentra[server]` from that checkout, runs the backend's own drift check,
   starts PostgreSQL 16, the backend and a worker (`scripts/e2e-backend.sh`) and runs every
   Playwright spec (Chromium, desktop and 360 px) against it; uploads report, traces and backend logs.

Results:

| Axentra | Studio | Contract | E2E (GitHub CI) |
|---|---|---|---|
| `a2ca72a` (PR #8 head; same tree as `master` `537484f`) | PR #2, merge `0aed4fc` | success (job 125053499893) | **180 passed, 0 failed** (job 125053499801) |
| `7511a37` (`master`) | PR #3, merge `ee7d9f2` (Studio `master`) | success (job 125058075510) | **186 passed, 0 failed** (job 125058075685) |

Limitations: the jobs ran on the pull requests (GitHub tests the merge of the PR head into the
then-current `master`, which is what the merge commit contains); Studio's workflow triggers on
pushes to `main` while its default branch is `master`, so merge commits on Studio `master` have no
CI run of their own. Nothing on the Axentra side triggers the Studio suites for a new Axentra
commit; a new combination is tested only when Studio moves its pin. The e2e suite runs the backend
in **multi-product mode**; a single-product e2e matrix is being added in a separate Studio pull
request (criterion 24). Only Chromium is tested.

## 12. Open limitations and residual risks

The full prioritized list is [TODO.md](TODO.md). The most important points:

**Not implemented or partial (functional scope)**
- Search module: PostgreSQL full-text search over a tenant-scoped index is implemented (see
  [modules/SEARCH.md](modules/SEARCH.md)); still missing are vector/semantic search, external
  search adapters, prefix/fuzzy matching and accent folding, and product-wide search across
  tenants. No WebSockets.
- No MFA (TOTP/WebAuthn), no password reset or email verification flows, no data subject export or
  erasure, no users without an email address.
- Product-defined permissions: the permission catalog is closed, so product resources reuse
  `records:*` and custom roles/API keys cannot carry product permissions.
- OIDC providers are managed only through configuration (no API or UI); no RP-initiated logout.
- Notifications: email only (no SMS/push). Billing: no proration, invoices, taxes, customer portal.
- Library embedders get no mapping of `AxentraError` to HTTP outside `axentra.api`.
- Python SDK has no typed methods for jobs, events, webhooks and several other operations; SDKs not
  published; problem+json error responses are not described in the OpenAPI.

**Untested or unproven**
- Stripe, S3 and SMTP adapters were never exercised against live providers (only
  `httpx.MockTransport`, moto and an in-process `aiosmtpd` server). The OIDC flow was tested only
  against an in-process stub provider, not against a real IdP.
- No load or performance testing; no capacity numbers exist.
- No production deployment has been carried out. Docker images and compose files are built and
  validated only in CI (no local Docker daemon); the compose stacks were never started and
  smoke-tested in CI.
- Only Linux was used (CI `ubuntu-latest`, local Ubuntu); macOS and Windows are untested.
- Backup/restore is tested for the database only, not for file storage together with it.
- No concurrency tests for `If-Match` races or parallel migration runners.
- No second security review after the fixes in PR #9.

**Operational properties to know**
- The general rate limit is off by default and in memory **per process** (N processes allow N
  times the rate); only login throttling is shared through PostgreSQL. The body size limit does not
  protect against slow clients (use a reverse proxy).
- SSE streams poll the database every `events.sse_poll_seconds` (default 1 s); no push.
- Jobs and webhooks are at least once; handlers must be idempotent. Usage sweeps and billing period
  advancement must be scheduled by the operator.
- `axentra_users`, sessions and external identities are global tables without RLS (protected in
  the service layer); unique constraints on natural keys can reveal existence through conflicts.
- `pg_dump` needs a superuser or a `BYPASSRLS` backup role; migrations are forward-only.
- Pre-1.0: the library API and configuration may change between minor releases.

**Residual risks**: authorization semantics were the weak spot found by the review (fixed, but
only one review round); provider adapters may behave differently against live APIs; per-process
rate limiting is weak against distributed abuse; performance under load is unknown.

## 13. Pull requests and merge SHAs

Axentra (`peterkarlhuber/axentra`, all merged into `master` from `claude/project-thread-wj7vfx`):

| PR | Title | Merged (UTC) | Merge SHA |
|---|---|---|---|
| [#1](https://github.com/peterkarlhuber/axentra/pull/1) | Phase 1: Axentra backend foundation | 2026-11-01 22:30 | `37f291961a1cf43e863fbba1b69a83cdbb682d90` |
| [#2](https://github.com/peterkarlhuber/axentra/pull/2) | Phase 1: OpenID Connect login and route-protection fix | 2026-11-01 22:45 | `d5e2ba7d294f3794e5262ab1f7fdd7fed7277eb5` |
| [#3](https://github.com/peterkarlhuber/axentra/pull/3) | Phase 2: Storage module (local + S3, quotas, signed downloads) | 2026-11-01 22:53 | `28e2c983498c8c4548c99febd540b741c04a7e7c` |
| [#4](https://github.com/peterkarlhuber/axentra/pull/4) | Phase 2/3: Usage, billing, notifications and observability | 2026-11-01 22:58 | `55f5be7933e204a510303ba190117ada15b227bc` |
| [#5](https://github.com/peterkarlhuber/axentra/pull/5) | Phase 2: Events, jobs, webhooks, SSE + docs, ADRs and deployment | 2026-11-01 23:05 | `33dce584fc576740d8b02394f74d2f4218267350` |
| [#6](https://github.com/peterkarlhuber/axentra/pull/6) | Phase 6: Nodestro migration plan (analysis only) | 2026-11-01 23:12 | `b548d11c83779f74ba3a8977ddd54988e09ec9b5` |
| [#7](https://github.com/peterkarlhuber/axentra/pull/7) | Phase 4: Python and TypeScript SDKs, Taskboard demo, deployment demos | 2026-11-01 23:30 | `3b110feade7511f079abd8f119380ead6db69ed4` |
| [#8](https://github.com/peterkarlhuber/axentra/pull/8) | Phase 5: Backend hardening (secret re-encryption, limits, docs protection, migration discovery) | 2026-11-01 23:39 | `537484f5f30872400ade683306b4becbd61ac6ac` |
| [#9](https://github.com/peterkarlhuber/axentra/pull/9) | Security: fix independent review findings F1-F8 and I1-I4 | 2026-11-02 00:49 | `7511a37ce0876c13e5a9c861e3b9e31b6401d99c` |
| [#10](https://github.com/peterkarlhuber/axentra/pull/10) | Final implementation report, compatibility matrix, TODO refresh, flaky test fix | 2026-11-02 02:50 | `ddc1f533f9bc3c1fcf88cc63fcd71cbf2728fa7e` |
| [#11](https://github.com/peterkarlhuber/axentra/pull/11) | Search module: tenant-scoped PostgreSQL full-text search | 2026-11-02 03:08 | `f80429f129f76bc019118bd825bef637feaf8ecf` |

Axentra Studio (`peterkarlhuber/axentra-studio`), details in the Studio report:

| PR | Title | Merged (UTC) | Merge SHA |
|---|---|---|---|
| [#1](https://github.com/peterkarlhuber/axentra-studio/pull/1) | Phase 1: Studio foundation, design system and Phase 1 admin areas | 2026-11-01 23:39 | `f1351991614f3f60cac1e9405a00207ce111f34a` |
| [#2](https://github.com/peterkarlhuber/axentra-studio/pull/2) | Phase 2/3: all admin areas, e2e against a real backend in CI, compatibility matrix | 2026-11-02 02:03 | `0aed4fce5dc2e4dc3c662d5fdcd066611077c4da` |
| [#3](https://github.com/peterkarlhuber/axentra-studio/pull/3) | Adapt Studio to the Axentra security fixes (backend 7511a37) | 2026-11-02 02:21 | `ee7d9f2a9007a1f570d800b2d77e584ddfe6a5cb` |
| [#4](https://github.com/peterkarlhuber/axentra-studio/pull/4) | Single- and multi-product e2e (CI matrix), template preview fix, CI push trigger `master` | 2026-11-02 03:32 | `4d2df1aed0756abc9b6fcf884f28f3c1e8b9a3f6` |
| [#5](https://github.com/peterkarlhuber/axentra-studio/pull/5) | Studio implementation report with screenshots | see Studio repository | - |

Important dependency versions are pinned in `deploy/constraints.txt` (container image) and
`sdk/typescript/package-lock.json`.

## 14. Notes for the later Nodestro integration

Source: [integrations/NODESTRO_MIGRATION_PLAN.md](integrations/NODESTRO_MIGRATION_PLAN.md)
(analysis only; nothing implemented, no Nodestro repository changed).

- The migration is a separate, optional project; the dependency direction is only
  Nodestro -> Axentra. Nodestro must first move to Python >= 3.11 ([ADR 0002](adr/0002-python-versions.md)).
- Recommended model: Axentra as a library inside Nodestro's processes, same database, one Axentra
  product `nodestro`, Nodestro tenants as Axentra tenants, mapping tables for ids, Nodestro product
  tables untouched; Nodestro's external contracts (cookies, `/api/auth/*`, error format, `ndk_` keys)
  kept behind adapters with per-function flags (strangler pattern).
- Order (steps M1-M12): pin Axentra and run both migration runners; dual-write audit and usage;
  secrets to the `axs1` keyring (gives Nodestro key rotation); identity and tenancy (largest step);
  API keys; notifications and metrics; files; migration runner and pool unification with RLS on
  Nodestro tables; jobs last, with a drained queue; finally remove legacy paths.
- Generic Axentra prerequisites (tracked in [TODO.md](TODO.md)): G-1 product-defined permissions,
  G-2 migration runner features, G-3 users without email, G-4 login without membership, G-5 tenant
  claim token, G-7 per-product content-type policy, G-8 Nodestro job semantics ("never retry,
  interrupt on lease loss", unique active job per reference). G-6 (re-encryption registry) is done.
  The jobs, schedules and SSE modules the plan called missing were merged afterwards (PR #5); their
  fit for Nodestro (G-8) is still to be verified.
- Each step: backup, rehearsal on a production copy, shadow comparison, switch, rollback window,
  security re-review. 14 open questions for the product owner are listed in section 12 of the plan.

## 15. Acceptance criteria status

Status values: **met**, **met with limitation**, **not met**, or a pointer to the Studio report.
"Studio report" criteria are assessed there; the backend evidence that they rely on is named here.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Independence from Nodestro, orkexa, Studio | met | Section 9; import-linter contract; `tests/unit/test_architecture.py`; CI "Package builds and installs headless" and container freeze check; headless install in this run |
| 2 | Secure login and session revocation | met with limitation | `test_auth.py` (login, logout, CSRF, origin, revoke session, password change), `test_oidc.py` (51), throttling; no MFA, OIDC tested only against a stub IdP |
| 3 | Several products and tenants independently managed | met | `test_tenancy.py`, `test_deployment_models.py`, multi-product demo (2 products, 4 tenants) |
| 4 | Roles and API permissions enforced server-side | met with limitation | Authorizer, `test_access.py`, `test_route_protection.py`, `test_security_review.py` (role ceiling, key expiry/cascade); permissions catalog closed, no product-defined permissions |
| 5 | Product data stored durably and securely in PostgreSQL | met | Records API with `If-Match`, product tables guide (`test_product_tables_guide.py`), forced RLS, migrations tests, `test_backup_restore.py` |
| 6 | No unauthorized cross-tenant access | met | `test_rls.py`, cross-tenant/cross-product tests in every module, deployment demos (0 leaks), independent review: no RLS gap |
| 7 | Files uploaded, managed, downloaded with authorization | met with limitation | `test_storage.py` (14), `test_storage_s3.py`; S3 only against moto, no live object store |
| 8 | Jobs processed reliably, monitored, retried under control | met | `test_events_jobs.py` (leases, worker killed mid-job, two workers, dead letter + manual retry, schedules once per slot), `GET .../jobs/stats`, SSE stream; guarantee is at least once (documented) |
| 9 | Usage recorded correctly, idempotently and limited | met | `test_usage.py` (idempotent recording, concurrent check-and-record never overshoots, reservations) |
| 10 | Plans and entitlements with a testable provider adapter | met with limitation | `test_billing.py` (fake provider with signed webhooks, entitlements feed quotas); Stripe adapter never run against Stripe |
| 11 | Notifications through exchangeable adapters | met with limitation | `test_notify.py`, `test_notify_smtp.py` (local and SMTP providers); email only, SMTP only against an in-process server |
| 12 | Public API usable from Python and TypeScript | met with limitation | SDKs, `scripts/sdk-e2e.sh` (TS 8, Python 6 passed), CI `sdk-e2e`; Python SDK lacks typed jobs/events/webhooks methods; SDKs not published |
| 13 | Deployment, migrations, configuration, monitoring, recovery documented and checked | met with limitation | `docs/operations/*`; migrations, health, metrics and database backup/restore tested; image built in CI; compose stacks never started, no production deployment, file-storage backup not tested |
| 14 | Relevant automated tests and security checks pass | met with limitation | Local: 360 passed/0 skipped, SDK suites, bandit, pip-audit green; CI on `master`: `7511a37` and `ddc1f53` each had one flaky test failure (section 7.3, both test-only, both fixed); `f80429f` green on all 11 jobs |
| 15 | Nodestro and orkexa repositories unchanged | met | Evidence of the lead (no branch, no PR in 11 repositories); local checkouts clean at the examined commits |
| 16 | Single-product installation serves one product without central infrastructure | met | `test_deployment_models.py` single tests; demo against `axentra serve` (19 checks, 0 leaks) |
| 17 | Shared installation serves at least two products without cross-product access | met | `test_multi_product_deployment_isolates_products`; demo (84 checks, 0 leaks); independent review (F2 cross-product user oracle fixed) |
| 18 | Studio: complete integrated admin UI in its own repository | see Studio report | Studio PRs #1-#5; backend side: all admin areas use `/v1` endpoints from `openapi/axentra-v1.json` |
| 19 | Branding with the Axentra logo | see Studio report | - |
| 20 | UI areas work with real backend endpoints, no dead placeholders | see Studio report | Studio CI e2e runs against a real backend at `7511a37` (186 passed) |
| 21 | Light mode, dark mode, responsive, tested | see Studio report | Studio e2e desktop and 360 px projects |
| 22 | UI security: permission limits, sessions, admin actions protected | see Studio report | Enforcement is server-side in Axentra (criteria 2, 4, 6); Studio `e2e/security.spec.ts` |
| 23 | Central user flows pass automated e2e tests | see Studio report | Studio CI job 125058075685: 186 passed, 0 failed |
| 24 | Studio works in single- and multi-product configuration | met with limitation | Studio CI runs the full e2e suite against a `mode = "multi"` and a `mode = "single"` backend (PR #4 run 41383014581: multi 188 passed, single 196 passed, 0 failed); backend refuses product create/archive in single mode with 409 (asserted at API level only; Studio offers no such action there). Backend demos: single 19 checks, multi 84 checks |
| 25 | Repositories technically and organizationally separate | met | Separate repositories, CI, versions, changelogs, TODO lists; [ADR 0012](adr/0012-studio-separation.md) |
| 26 | Studio uses Axentra through public interfaces; Axentra never needs Studio | met | Axentra: forbidden imports/dependencies (section 9). Studio: vendored OpenAPI + HTTP only (Studio report) |
| 27 | Both repositories build and test independently | met with limitation | Axentra CI (11 jobs) and Studio CI (3 jobs) are separate; Studio CI runs on pushes to Studio `master` since `4d2df1a` (earlier merge commits had no own run) |
| 28 | Studio runs with a defined compatible Axentra version | met | `api/BACKEND_REF` pin, `REQUIRED_API`, runtime check of `GET /v1/meta`, [COMPATIBILITY.md](COMPATIBILITY.md) |
| 29 | Axentra works fully without frontend dependencies | met | Headless wheel install, migrate, serve, health (section 5, 9); CI headless job |
| 30 | Joint e2e pipeline confirms both components | met with limitation | Studio CI contract + e2e jobs against the pinned backend (180/180 at `a2ca72a`, 186/186 at `7511a37`); runs only on Studio pull requests, multi-product mode only so far, Chromium only, no Axentra-side trigger |

No acceptance criterion is marked "not met" for the backend. The functional scope item "Search"
(order section 4 L) is implemented as PostgreSQL full-text search with a pluggable adapter
interface; optional vector search is not implemented (no adapter), see section 12.
