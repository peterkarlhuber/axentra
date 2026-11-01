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
- Usage (migration 0004): generic meters (sum/max/last; reset none/day/month/billing period),
  idempotent usage events with atomically updated counters, per-tenant quotas (hard/soft;
  defaults from plan entitlements or the meter), concurrency-safe `check_and_record`,
  reservations (reserve/commit/release/sweep), summaries and daily time series; docs/modules/USAGE.md.
- Billing (migration 0004): plans with prices and entitlements, tenant subscriptions with a strict
  state machine, entitlement overrides feeding usage quotas, manual/fake/Stripe provider adapters
  (Stripe guarded by explicit keys and `live_payments`), signed and replay-safe webhooks with
  out-of-order protection; no payment processing or card data in Axentra; docs/modules/BILLING.md.
