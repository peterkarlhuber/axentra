# Open work

The central, versioned list of open work for Axentra. Priorities: **P0** blocks the next release,
**P1** needed for a production-ready 1.0, **P2** important improvement, **P3** nice to have.
Studio has its own list in its repository; items here mention Studio only where the backend is
involved. Remove an item in the change that completes it.

Last reviewed: 2026-11-01 (`0.1.0.dev0`).

## Work in progress (parallel branches)

| Pri | Area | Item |
|---|---|---|
| P0 | identity | OIDC login endpoints (`/v1/auth/oidc/{provider}/start`, `/callback`); settings, tables and `link_external_identity` exist |
| P0 | storage | File storage module (local, S3-compatible), `/v1/files/download/{token}` |
| P0 | events | Events, background jobs and webhooks (including SSRF protection for webhook targets) |
| P0 | usage | Meters, usage recording, quotas |
| P0 | billing | Plans, subscriptions, entitlements, provider adapters (manual/fake/Stripe), billing webhooks |
| P0 | notify | Templates, email delivery (local/SMTP), preferences |
| P0 | observability | `/metrics`, OpenTelemetry tracing, audit/job retention |
| P0 | release | Fill in `docs/COMPATIBILITY.md` with the merged Axentra and Studio commits |

## Backend

| Pri | Area | Item |
|---|---|---|
| P1 | security | `axentra secrets reencrypt`: bulk re-encryption with the active key (needed before old keys can be removed once modules store ciphertexts) |
| P1 | operations | Scheduled retention: call `IdentityService.purge_expired` and `AuditLog.purge(observability.audit_retention_days)` (methods exist, nothing runs them) |
| P1 | data | Records: write audit events for create and replace (only delete is audited today) |
| P1 | migrations | `axentra migrate` cannot apply product namespaces; add discovery (entry points or config) so one command migrates everything |
| P1 | config | `database.migration_url` has no `_ref` variant; add `migration_url_ref` |
| P1 | security | General request rate limiting and a request body size limit (today: login/setup throttling only; rely on the reverse proxy) |
| P1 | access | Product-defined permissions (the catalog is fixed in code; product tables reuse `records:*`) |
| P1 | identity | Data subject tooling: user data export and erasure/anonymization across users, memberships, audit |
| P2 | security | Option to disable or protect `/v1/docs` and `/v1/openapi.json` in production (public today) |
| P2 | realtime | Server-sent events with an async path that does not hold pooled connections (Phase 2) |
| P2 | identity | Password reset and email verification flows (need the notify module) |
| P2 | identity | MFA (TOTP/WebAuthn) |

## Developer experience (Phase 4)

| Pri | Area | Item |
|---|---|---|
| P1 | sdk | After the events/jobs/webhooks merge: `npm run generate` in `sdk/typescript`; typed Python methods for jobs, events and webhooks |
| P1 | api | Document `application/problem+json` error responses in the OpenAPI (today only FastAPI's default 422 `HTTPValidationError` is listed, which does not match the real body) |
| P2 | sdk | Publish `@axentra/sdk` (npm) and `axentra-client` (PyPI); release process and provenance |
| P2 | sdk | Python SDK: remaining operations (templates, preferences, reservations, checkout, users admin) |
| P2 | cli | CLI for administration over HTTP (products, tenants, keys) and `axentra admin` tasks without database access |
| P2 | studio | Backend support for Studio Phase 2/3 views (files, jobs/events, usage charts, audit/monitoring, plans, subscriptions, notifications) as those modules land |

## Hardening (Phase 5)

| Pri | Area | Item |
|---|---|---|
| P1 | operations | Backup/restore of file storage together with the database (test exists for the database only) |
| P1 | build | Reproducible container builds: pin the base image by digest, build hatchling from pinned versions, compare digests of two builds |
| P2 | build | Hash-pinned constraints (`--require-hashes`) and SBOM generation for the image |
| P2 | tests | Deployment tests that start the compose stacks in CI and run smoke tests (the single-/multi-product scenarios run in-process today: `tests/integration/test_deployment_models.py`) |
| P2 | tests | Concurrency tests for `If-Match` races and migration runners started in parallel |
| P2 | tests | Cross-repository compatibility test: Studio contract tests against each Axentra commit |

## Nodestro (Phase 6)

| Pri | Area | Item |
|---|---|---|
| P2 | integration | `docs/integrations/NODESTRO_MIGRATION_PLAN.md` (analysis only; Nodestro must first drop Python 3.10, see ADR 0002) |

## Known limitations

These are current, deliberate or accepted properties; some have an item above.

- `axentra_users` (and sessions, platform roles, external identities) are global tables without
  row-level security; protection is in the service layer.
- In tenant scope, RLS also shows product-level rows (`tenant_id IS NULL`) of the same product.
- Unique constraints on natural keys (emails, product slugs, tenant slugs, role keys) can reveal
  existence through conflict errors.
- Login throttling uses fixed one-minute windows (bursts up to twice the budget at a window
  boundary); no lockout, no CAPTCHA.
- No total counts in list responses (by design).
- Records support only top-level JSON containment filters and sorting by id/created/updated.
- Services are synchronous; long-lived streaming (SSE) is not available yet.
- Migrations are forward-only; rollback means restore from backup.
