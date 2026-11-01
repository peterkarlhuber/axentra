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
