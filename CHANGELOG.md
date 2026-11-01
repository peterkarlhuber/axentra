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
