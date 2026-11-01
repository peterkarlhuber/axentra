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
- HTTP API `/v1` (FastAPI) with RFC 9457 problem details, request ids, security headers, CORS for
  configured origins, route-protection registry; committed OpenAPI contract `openapi/axentra-v1.json`.
- CLI: `axentra serve | migrate | admin setup-token | openapi export | keys generate`.
- Events module (migration 0002): PostgreSQL job queue (SKIP LOCKED claims, leases + heartbeats,
  reaper, retries with capped exponential backoff and jitter, dead letters, idempotency keys,
  cancellation, manual retry, LISTEN/NOTIFY wake-up), `JobWorker` and `axentra worker`, recurring
  schedules (interval or 5-field cron, leader lock, each slot fires at most once), events with a
  transactional outbox (`publish_in_tx`) and in-process subscribers, signed outgoing webhooks
  (HMAC-SHA256, SSRF protection, retries, redelivery, test ping, secret rotation with grace), SSE
  streams for events and job changes with `Last-Event-ID` resume, retention purge. See
  docs/modules/EVENTS_AND_JOBS.md.
