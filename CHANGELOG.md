# Changelog

All notable changes to Axentra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).
The HTTP API has its own version (`api_version` in `GET /v1/meta`), see docs/architecture/VERSIONING.md.

## [Unreleased]

### Added
- SDKs (Phase 4): TypeScript SDK `@axentra/sdk` in `sdk/typescript` (types generated from the
  committed OpenAPI with openapi-typescript, openapi-fetch client with API key/session bearer or
  cookie mode with automatic CSRF header, `AxentraApiError` from problem details,
  `checkCompatibility()`, cursor `paginate()`, `idempotencyKey()`; `generate:check` staleness
  check in CI) and Python SDK `axentra-client` in `sdk/python` (pure httpx client, sync + async,
  pydantic models for the main resources, streamed file transfer; contract tests against an
  in-process server). `scripts/sdk-e2e.sh` runs both SDKs' e2e suites against a PostgreSQL-backed
  `axentra serve`; CI jobs `sdk-typescript`, `sdk-python`, `sdk-e2e`. See docs/sdk/.
- Examples: `examples/taskboard`, a demo multi-tenant SaaS backend (FastAPI) that uses Axentra as
  a library and mounts the Axentra API under `/axentra` in the same process. It has its own tables
  (`taskboard` migration namespace, forced RLS), authorization via `ax.authz`, attachments via
  `ax.storage`, a `tasks_created` meter with plan limits (free 50/month, pro unlimited, 429 when
  exceeded) and audited deletions, plus a scripted walkthrough and PostgreSQL tests in the main
  pytest run. `examples/single-product` and `examples/multi-product` are configs and httpx scripts
  that provision products, tenants, operators and API keys and assert isolation (exit 1 on any
  leak), tested in `tests/integration/test_deployment_models.py`. Compose stack
  `deploy/compose/docker-compose.taskboard.yml`, guide `docs/guides/BUILDING_A_PRODUCT.md`.
- Foundation (Phase 1): core (errors, ids, pagination, redaction), typed configuration with secret
  references and a rotatable AES-256-GCM keyring, PostgreSQL pool with scoped transactions and
  forced row-level security, versioned SQL migrations with checksums and advisory lock.
- Identity: users, Argon2id passwords, server-side sessions (hashed tokens, CSRF tokens, idle and
  absolute expiry, revocation), first-run setup token, DB-backed login throttling.
- Tenancy: products (single- and multi-product mode), tenants, product operators, tenant
  memberships, invitations.
- Access: permission catalog, built-in and custom roles, authorizer (default deny, no existence
  oracle), product/tenant-scoped API keys with rotation (grace period) and revocation.
- Data: tenant-owned JSON records with filtering, sorting, cursor pagination and optimistic concurrency.
- Audit: append-only, redacted audit trail written in the same transaction as each change.
- Storage: generic tenant files with local (atomic, fsync) and S3 backends (optional extra `s3`),
  streaming uploads with size limit enforced while reading, SHA-256, content type sniffing and a
  blocklist for executable/HTML/SVG types, attachment-only downloads, exact per-tenant quotas under
  concurrency (bytes and files, defaults from product settings), HMAC-signed short-lived download
  URLs (optional presigned S3 URLs), expiry, purge of expired/abandoned/orphaned objects
  (`axentra storage purge`), migration `0003_storage`. See docs/modules/STORAGE.md.
- HTTP API `/v1` (FastAPI) with RFC 9457 problem details, request ids, security headers, CORS for
  configured origins, route-protection registry; committed OpenAPI contract `openapi/axentra-v1.json`.
- CLI: `axentra serve | migrate | admin setup-token | openapi export | keys generate`.
- Identity: OpenID Connect login (`GET /v1/auth/oidc/{provider}/start` and `/callback`):
  authorization code + PKCE S256, hashed single-use state bound to a browser login cookie,
  nonce, discovery with exact issuer match, cached JWKS with refresh on unknown `kid`, strict ID
  token checks (asymmetric algorithms only, `aud`/`azp`, `iss`, `exp`/`iat`), verified-email
  linking, signup/invitation/allowed-domain rules, safe `return_to` (relative paths or allowed
  origins), `?login_error=<code>` redirects; redaction of auth query values in `uvicorn.access`.
  New settings: `security.login_page`, `oidc[].token_endpoint_auth_method`.
- Notify (migration `0005_notify.sql`): versioned email templates with de/en locale variants and a safe
  `{{ var }}` renderer, built-in invitation template, encrypted outbox with idempotent send, preferences
  (opt-out per category), local mailbox and SMTP (STARTTLS) providers, `NotifyDispatcher` with
  SKIP LOCKED leases and exponential backoff, delivery stats, invitation emails via `ax.on_invitation`,
  `axentra notify-dispatch --once|--loop`.
- Observability: Prometheus metrics registry (`ax.metrics`) at `GET /metrics` (bearer token via
  `observability.metrics_token_ref`; disabled in production without one), optional OpenTelemetry request
  tracing, notify readiness check, `axentra maintenance purge` (audit, sessions, notify retention).
- Usage (migration 0004): generic meters (sum/max/last; reset none/day/month/billing period),
  idempotent usage events with atomically updated counters, per-tenant quotas (hard/soft;
  defaults from plan entitlements or the meter), concurrency-safe `check_and_record`,
  reservations (reserve/commit/release/sweep), summaries and daily time series; docs/modules/USAGE.md.
- Billing (migration 0004): plans with prices and entitlements, tenant subscriptions with a strict
  state machine, entitlement overrides feeding usage quotas, manual/fake/Stripe provider adapters
  (Stripe guarded by explicit keys and `live_payments`), signed and replay-safe webhooks with
  out-of-order protection; no payment processing or card data in Axentra; docs/modules/BILLING.md.
- Documentation: README, architecture overview, security model (RLS limits, threat model, GDPR
  responsibilities), data, deployment models, versioning/compatibility (`docs/COMPATIBILITY.md`),
  ADRs 0001-0012, product-table guide with a tested example, roadmap, central TODO list,
  development, deployment, configuration and backup/restore guides.
- Deployment: multi-stage `Dockerfile` (python:3.13-slim, non-root uid 10001, healthcheck,
  constraints-pinned dependencies in `deploy/constraints.txt`), compose stacks for single- and
  multi-product mode with separate owner/application database roles
  (`deploy/compose/initdb/01-roles.sql`), example configurations in `deploy/config/`.
- Tests: automated backup/restore test (`pg_dump`/`pg_restore`, data, RLS and a working app on the
  restored database) and a test for the product-table template; CI installs matching PostgreSQL
  client tools and builds the container image.
- Events module (migration 0002): PostgreSQL job queue (SKIP LOCKED claims, leases + heartbeats,
  reaper, retries with capped exponential backoff and jitter, dead letters, idempotency keys,
  cancellation, manual retry, LISTEN/NOTIFY wake-up), `JobWorker` and `axentra worker`, recurring
  schedules (interval or 5-field cron, leader lock, each slot fires at most once), events with a
  transactional outbox (`publish_in_tx`) and in-process subscribers, signed outgoing webhooks
  (HMAC-SHA256, SSRF protection, retries, redelivery, test ping, secret rotation with grace), SSE
  streams for events and job changes with `Last-Event-ID` resume, retention purge. See
  docs/modules/EVENTS_AND_JOBS.md.
- Docs: Nodestro migration plan (Phase 6, analysis only, nothing implemented):
  `docs/integrations/NODESTRO_MIGRATION_PLAN.md` - functions Nodestro could take from Axentra,
  modules that become adapters, table-by-table data mapping (one product `nodestro`, legacy
  `ndk_` keys, `nodestro:enc:v1` secrets, session hashes), compatibility, version pins, tests,
  phased order, rollback, risks and open questions. The migration is a separate future project and
  not a prerequisite for Axentra; Axentra keeps no dependency on Nodestro.
- Hardening (Phase 5):
  - `axentra secrets reencrypt [--dry-run] [--batch-size N] [--load MODULE]` and
    `ax.reencrypt_secrets()`: re-encrypts every stored SecretBox value not under the active key
    (OIDC login states, webhook secrets, notification content and mailbox) in batches with a
    per-row compare-and-swap; dry run reports counts per column and key id. Products register
    their own columns with `ax.register_encrypted_column(EncryptedColumn(...))`.
  - Records: audit events `data.record.create` and `data.record.replace` (collection and version,
    never the data), written in the same transaction as the change; `data.record.delete` now
    also commits atomically with the delete.
  - Request body limit `security.max_body_bytes` (default 10 MiB, 413 problem+json; file uploads
    keep `storage.max_file_bytes`) and an optional in-memory token-bucket rate limit per
    credential and per client IP (`security.rate_limit_per_minute`, `rate_limit_ip_per_minute`,
    `rate_limit_burst`; off by default; 429 with `Retry-After`).
  - `security.api_docs` (`public` / `authenticated` / `disabled`) for `/v1/docs` and
    `/v1/openapi.json`; `GET /v1/settings` reports the effective limits in a new `limits` object.
  - `axentra migrate` applies product namespaces discovered from `database.extra_migrations`
    (`"package.module:attribute"`) and the `axentra.migrations` entry point group
    (`database.migration_entry_points`); `package_migrations(namespace, package)` helper;
    `axentra migrate --status` includes them. New `database.migration_url_ref`.
  - `storage.store_blocked_as_inert`: optionally keep executable/HTML/SVG/script uploads as inert
    `application/octet-stream` attachments instead of refusing them.
  - `from axentra import load_settings, Settings` works (lazy re-export), matching the documented
    library example.

### Changed
- `/v1/docs` and `/v1/openapi.json` are disabled by default in production (set
  `security.api_docs = "public"` to keep the previous behavior).
- Registering the identical migration twice is now a no-op; two different migrations with the same
  `namespace:version` are refused.

### Security
Fixes for the independent security review of 2026-11-01 (`docs/security/REVIEW-2026-11-01.md`,
regression tests in `tests/integration/test_security_review.py`). Behavior changes for API clients
are marked **(API)**.
- F1 **(API)** Role ceiling: assigning, inviting with, changing or removing a role needs every
  permission of the role (and of the member's current role) in the caller's own grant; the owner
  roles (`tenant_owner`, `product_owner`) need the owner rank (an owner of the scope, a product
  operator for tenants, or a platform admin). Violations are `403`. `product_support` therefore
  manages viewers only and can no longer make itself a tenant owner; tenant admins can no longer
  demote, remove or create tenant owners.
- F2 **(API)** Adding existing users directly (tenant members by email or id, `owner_user_id` on
  tenant creation, product operators) resolves only users visible to the caller (platform admin:
  all; `product_users:read`: the product's users; otherwise members of the tenant). Everyone else
  gets the same `404` as an unknown user (no installation-wide email oracle, no enrollment without
  consent); use invitations.
- F6 **(API)** The built-in `invitation` template is system-only (`Template.system_only`), `POST
  .../notify/send` refuses it with `403`. Sending to an email address that is not a member of the
  tenant needs the new product permission `notify:send_external` (held by `product_owner` and
  `product_admin`).
- F4 **(API)** Callers without `jobs:manage` may enqueue only job kinds declared with
  `enqueue_permission` (`ax.jobs.register(..., enqueue_permission=..., permissions=...)` or
  `ax.jobs.declare(...)`); other kinds answer `403`. Handler principals hold the kind's declared
  permissions, intersected with the enqueuer's current permissions for API-enqueued jobs
  (`ax.jobs.principal_for(job)`).
- F8 **(API)** Idempotency-Key replays of jobs and events return the stored row only for the same
  request and to its creator or a `jobs:read` holder; otherwise `409`.
- F5 **(API)** API keys created by an API key never outlive it (inherited expiry, later
  `expires_at` is `422`) and are revoked together with it (recursive cascade on revoke).
- F3 **(API)** Users without a password (OIDC-only) can set a first password only within
  `security.fresh_login_minutes` (default 5) of their login (`403 reauthentication_required`
  otherwise); `security.first_password = "disabled"` switches it off.
- F7 The last-owner guards lock the tenant/product row, so concurrent demotions cannot remove the
  last owner.
- I1 Production refuses `events.webhook_allow_private_targets` unless
  `events.webhook_allow_private_targets_in_production = true`.
- I2 The webhook SSRF guard also blocks IPv6 site-local addresses (`fec0::/10`).
- I3 **(API)** `GET /v1/audit/{id}` answers `404` (not `403`) for installation-wide events the
  caller may not read.
- I4 Login and setup throttling count atomically before verifying (`IdentityService.hit()` /
  `refund()`); a successful login gives its attempt back.
- I5 OIDC auto-linking of existing accounts by verified email is documented as a design decision
  in `docs/architecture/SECURITY_MODEL.md`.
