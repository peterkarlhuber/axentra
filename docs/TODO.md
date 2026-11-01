# Open work

The central, versioned list of open work for Axentra. Priorities: **P0** blocks the next release,
**P1** needed for a production-ready 1.0, **P2** important improvement, **P3** nice to have.
Studio has its own list in its repository; items here mention Studio only where the backend is
involved. Remove an item in the change that completes it.

Last reviewed: 2026-11-01 (`0.1.0.dev0`, after the Phase 5 hardening change).

## Release

| Pri | Area | Item |
|---|---|---|
| P0 | release | Fill in `docs/COMPATIBILITY.md` with the merged Axentra and Studio commits (still "to be filled at merge") |

## Backend

| Pri | Area | Item |
|---|---|---|
| P1 | access | Product-defined permissions: the permission catalog is closed (`CATALOG` in code; `validate_permissions` refuses other names), so product tables reuse `records:*` and custom roles/API keys cannot carry product permissions (Nodestro plan G-1) |
| P1 | identity | Data subject tooling: user data export and erasure/anonymization across users, memberships, audit |
| P1 | identity | Users without an email address: `axentra_users.email` is `NOT NULL` (unique on `lower(email)`), so external-identity-only users (no verified email claim) cannot exist (Nodestro plan G-3) |
| P1 | library | `AxentraError` is mapped to problem+json only by the HTTP app; library embedders with their own web layer get no handler or mapping helper (an escaping `AxentraError` becomes a 500 there). Provide a documented mapping (status, code, extras) usable outside `axentra.api` |
| P2 | identity | OIDC providers without `email_verified` (Entra ID v2 usually omits it): an explicit, per-provider opt-in (e.g. single-tenant directories only, or mapping a verified-email claim) instead of refusing with `email_not_verified`; must not reopen the "nOAuth" takeover. Documented in `modules/IDENTITY.md`, no setting yet |
| P2 | identity | Password reset and email verification flows (the notify module is available now) |
| P2 | identity | MFA (TOTP/WebAuthn) |
| P2 | storage | Content-type policy per product: `.html`, `.js`, `.sh`, `.php`, `.ps1`, `.bat` and other blocked types are refused installation-wide, or stored inert with the global `storage.store_blocked_as_inert`; the blocklist itself is fixed in code (Nodestro plan G-7) |
| P2 | migrations | Runner features from Nodestro (plan G-2): pre-migration backup hook, refusal when the schema is newer than the code, a serving gate for a compatible schema range, optional non-transactional steps |
| P2 | security | Shared rate limiting across API processes (the general limit is an in-memory token bucket per process; only login throttling is shared through PostgreSQL) |
| P2 | release | Version checks against the package metadata: Axentra uses `dynamic = ["version"]` (hatch reads `src/axentra/_version.py`), so tools that read `project.version` from `pyproject.toml` (e.g. Nodestro's `check_versions.py`) see none; document/offer a supported way (`axentra --version`, `importlib.metadata.version("axentra")`, or a static version) |

## Developer experience (Phase 4)

| Pri | Area | Item |
|---|---|---|
| P1 | sdk | Python SDK generated from `openapi/axentra-v1.json` |
| P1 | sdk | TypeScript SDK generated from the same document (Studio currently generates types only) |
| P2 | cli | CLI for administration over HTTP (products, tenants, keys) and `axentra admin` tasks without database access |
| P2 | demo | Demo SaaS application using Axentra as a library with its own product tables |
| P2 | studio | Backend support for Studio Phase 2/3 views (files, jobs/events, usage charts, audit/monitoring, plans, subscriptions, notifications): the modules are merged; add endpoints or fields as the views need them |

## Hardening (Phase 5)

| Pri | Area | Item |
|---|---|---|
| P1 | operations | Backup/restore of file storage together with the database (test exists for the database only) |
| P1 | build | Reproducible container builds: pin the base image by digest, build hatchling from pinned versions, compare digests of two builds |
| P2 | build | Hash-pinned constraints (`--require-hashes`) and SBOM generation for the image |
| P2 | tests | Deployment tests that start both compose stacks in CI and run smoke tests |
| P2 | tests | Concurrency tests for `If-Match` races and migration runners started in parallel |
| P2 | tests | Cross-repository compatibility test: Studio contract tests against each Axentra commit |

## Nodestro (Phase 6)

| Pri | Area | Item |
|---|---|---|
| P2 | integration | `docs/integrations/NODESTRO_MIGRATION_PLAN.md` (analysis only; Nodestro must first drop Python 3.10, see ADR 0002). Generic gaps from its section 9 are listed above (G-1, G-2, G-3, G-7); G-6 (re-encryption registry) is done |

## Known limitations

These are current, deliberate or accepted properties; some have an item above.

- `axentra_users` (and sessions, platform roles, external identities) are global tables without
  row-level security; protection is in the service layer.
- In tenant scope, RLS also shows product-level rows (`tenant_id IS NULL`) of the same product.
- Unique constraints on natural keys (emails, product slugs, tenant slugs, role keys) can reveal
  existence through conflict errors.
- Login throttling uses fixed one-minute windows (bursts up to twice the budget at a window
  boundary); no lockout, no CAPTCHA.
- The general rate limit is off by default and per process (N processes allow N times the rate);
  the request body limit does not protect against slow clients (use the reverse proxy).
- `pg_dump` needs a superuser or a `BYPASSRLS` backup role (forced RLS); see
  `operations/BACKUP_RESTORE.md`.
- No total counts in list responses (by design).
- Records support only top-level JSON containment filters and sorting by id/created/updated.
- Services are synchronous; SSE streams poll the database every `events.sse_poll_seconds` through
  the thread pool (no push, no connection held between polls).
- `axentra migrate` applies migrations of every installed package that declares the
  `axentra.migrations` entry point group (disable with `database.migration_entry_points = false`).
- Migrations are forward-only; rollback means restore from backup.
