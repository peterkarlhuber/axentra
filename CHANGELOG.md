# Changelog

All notable changes to Axentra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).
The HTTP API has its own version (`api_version` in `GET /v1/meta`), see docs/architecture/VERSIONING.md.

## [Unreleased]

### Added
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
