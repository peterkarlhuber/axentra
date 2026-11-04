# Open work

The central, versioned list of open work for Axentra. Priorities: **P0** blocks the next release,
**P1** needed for a production-ready 1.0, **P2** important improvement, **P3** nice to have.
Studio has its own list in its repository; items here mention Studio only where the backend is
involved. Remove an item in the change that completes it.

Last reviewed: 2026-11-04 (`0.1.0.dev0`, internal backend audit round 3 against `e7c06d0`: no regressions; AX3-01
key bounding, AX3-02, AX2-07 and the Dependabot config fixed in the PR that updates this line; new items marked AX3-NN;
login and setup audit events record ip, request id and actor since the round-3 follow-up, UX round 3 handover).
Before that: 2026-11-03 (internal backend audit round 2: CI on `master` is green again and
the security review rounds are closed, so both items were removed; new items from the audit and the DX review
are marked AX2-NN / DX-NN; AX2-05 and AX2-08 were decided and fixed, so their items were removed; Studio-facing backend items from the UX
round 2 are marked AXS-BN).

## Release and verification

| Pri | Area | Item |
|---|---|---|
| P1 | operations | No production deployment has been carried out; no production-like environment exists |
| P1 | tests | No load or performance tests; no capacity figures for the API, workers, SSE or the job queue |
| P1 | tests | Provider adapters never exercised against live services: Stripe (only `httpx.MockTransport`), S3 (only moto; no MinIO/AWS), SMTP (only an in-process `aiosmtpd`), OIDC (only an in-process stub IdP). Needs a sandbox run without paid calls |
| P2 | build | Docker images and compose files are built/validated only in CI (no local Docker in the development environment); the compose stacks are never started (see the deployment-test item below) |
| P2 | build | The CI image job builds only `EXTRAS=server`; also build the documented full image (`server,oidc,s3,otel`) so a constraint bump that breaks an extra fails in CI (Dependabot python-dateutil 3.0.0 conflicted with botocore, AX3-05) |
| P2 | platform | Only Linux is tested (CI `ubuntu-latest`); macOS and Windows are untested for the library, CLI and SDKs |
| P3 | tests | The full suite logs a few "Logging error" tracebacks from background threads that still log after pytest closed the capture; stop/join those threads in the fixtures (AX2-10) |

## Backend

| Pri | Area | Item |
|---|---|---|
| P1 | identity | Data subject tooling: user data export and erasure/anonymization across users, memberships, audit |
| P2 | identity | OIDC providers without `email_verified` (Entra ID v2 usually omits it): an explicit, per-provider opt-in (e.g. single-tenant directories only, or mapping a verified-email claim) instead of refusing with `email_not_verified`; must not reopen the "nOAuth" takeover. Documented in `modules/IDENTITY.md`, no setting yet |
| P2 | identity | Password reset and email verification flows (the notify module is available now) |
| P2 | identity | MFA (TOTP/WebAuthn) |
| P3 | identity | A refused password (policy) answers `422` with only `detail`; add `errors[{loc: ["body", "password"], msg}]` like other validation errors, and expose the minimum length in `/v1/meta` so clients can check before sending (AXS-B6, UX round 3) |
| P3 | identity | Drop the deprecated `invitation` query parameter from the `GET /v1/auth/oidc/{provider}/start` contract (OpenAPI) at the next `/v1` cleanup; it is refused since security review round 4 (R4-1, `login_error=invitation_requires_post`) and only stays declared to document that |
| P3 | identity | A failed OIDC login redirects to `<login page>?login_error=...` without the original `return_to`, so a deep link (for example an invitation accept page) is lost; Studio keeps an opened invitation per tab as a workaround. Pass a validated `return_to` along |
| P3 | realtime | WebSockets (only SSE exists, polling-based) |
| P2 | search | Optional vector/semantic search through an adapter (e.g. pgvector with an embedding step; order section 4 L) |
| P2 | search | External search adapters (OpenSearch, Meilisearch, ...) implementing `SearchAdapter`; only `PostgresSearchAdapter` exists, and an external engine's audit event cannot be atomic with its write |
| P2 | search | Prefix (search-as-you-type) and fuzzy matching, accent folding (`unaccent`), per-tenant or per-document language |
| P3 | search | Bulk index/delete API (e.g. delete all documents of a kind), a reindex job, product-wide search across tenants, filters on `metadata` |
| P2 | identity | Identity providers are managed only through configuration (`[[oidc]]`); no API (and therefore no Studio view) to list, add or disable providers |
| P2 | tenancy | Product-level invitations for operators: `POST /v1/products/{id}/members` resolves only users the caller can see, so a product owner who is not a platform admin cannot add an operator without a visible account (Studio TODO, marked backend) |
| P2 | events | List the job kinds a tenant caller may enqueue (declared `enqueue_permission`), so clients can offer them (Studio TODO, marked backend) |
| P3 | migrations | Runner follow-ups (plan G-2; the backup hook, newer-schema refusal, serving gate and `-- axentra:no-transaction` steps exist): a declared forward-compatible range per namespace (today any unknown applied version fails the gate), Python (data backfill) migrations, a per-migration lock/statement timeout, dry-run SQL output |
| P3 | notify | SMS and push adapters (email is the only channel) |
| P2 | usage | `UsageService.record_in` costs about 15 statements per meter (authorization, meter, idempotency, counters, quota; about 4 ms per meter measured by an embedding host that records 4 meters per entry). A batch variant (several meters or events under one authorization) |
| P2 | notify | Per-tenant send rate limits for `POST .../notify/send` (review 2026-11-01, F6 follow-up; the relay itself is closed by `notify:send_external` and system-only templates) |
| P2 | identity | Optional stricter OIDC auto-linking: require `allowed_email_domains` for linking existing accounts, or skip it for platform admins (review 2026-11-01, I5; documented as a design decision in SECURITY_MODEL.md). Linking can now be turned off per provider (`link_by_verified_email = false`) |
| P2 | identity | Users without an email address: no HTTP API or Studio view to create them or to link/unlink external identities (library only: `create_external_user`, `link_identity`); OIDC login states and login throttling windows still use the host clock |
| P2 | identity | First password for OIDC-only users through a fresh IdP re-authentication (`prompt=login`/`max_age`) or an emailed link instead of the session-age window (review 2026-11-01, F3 follow-up) |
| P3 | access | API keys are bounded by their creator's current access since audit round 3 (AX3-01, `api_key_creator_lost_access`), but the key list still shows such a key as `active`; expose an effective state for Studio, and consider disabling the creator's schedules when the creator loses access (AX2-01 follow-up) |
| P2 | security | Shared rate limiting across API processes (the general limit is an in-memory token bucket per process; only login throttling is shared through PostgreSQL) |
| P2 | search | Expensive requests reachable with read permissions: search ranks every match before the limit (common terms take seconds on large tenants) and records sorted by time have no composite index per product/tenant/collection. Bounded candidate set or rank cutoff, a shorter statement timeout for search, time-sort indexes, a default per-credential limit for heavy endpoints (AX2-06) |
| P2 | events | Webhook deliveries share the job queue and worker slots with all other kinds; attempts are now time-bounded, but a separate concurrency pool or a per-product cap for deliveries is still missing (AX2-02 follow-up) |
| P3 | events | Webhook URLs accept any port; decide whether to restrict them (for example 443 and >= 1024). Legacy IPv4 notations are refused at creation since audit round 3 (AX2-07) |
| P3 | events | Schedules whose creator lost access keep firing (their jobs now run without permissions); optionally disable a user's schedules when the user loses product access, together with the API key revocation item above (AX2-01 follow-up) |
| P2 | tenancy | Refused invitation accepts all answer `403 forbidden`, so Studio has to match the English `detail`. Give the three reasons (e-mail mismatch, inactive scope, inviter lost access) their own problem codes or a `reason` member (AXS-B1, UX round 2) |
| P3 | search | List a tenant's indexed search kinds (for example `GET .../search/kinds` with counts), so clients can offer a picker instead of a free-text kind filter (AXS-B2, UX round 2) |
| P3 | tenancy | `sort=name` on `GET .../tenants`, so pickers can list the first N tenants by name instead of the oldest N (AXS-B3, UX round 2) |
| P3 | access | After a key rotation the old key stays `active` with a future `revoked_at`; expose the grace period explicitly (for example `grace_until`) or document it in the OpenAPI (AXS-B4, UX round 2) |
| P3 | access | Built-in role descriptions are English-only; add a stable description key to the role catalog so clients can translate them (AXS-B5, UX round 2) |
| P2 | identity | `GET /v1/me` lists every readable tenant (no cap since AX2-03), so for product operators and platform roles the response grows with the number of tenants (measured in audit round 3, AX3-03: about 1 KB per tenant, 10,000 tenants = 10 MB, p50 0.4 s). Consider an opt-in parameter (for example memberships only, or paging) at the next `/v1` cleanup, coordinated with Studio, which needs only memberships and product-level permissions |

## Developer experience (Phase 4)

| Pri | Area | Item |
|---|---|---|
| P1 | sdk | Python SDK: typed methods for jobs, events and webhooks (reachable today through `request_json()`) |
| P2 | sdk | Python SDK: typed methods for the search endpoints (reachable today through `request_json()`) |
| P1 | api | Document `application/problem+json` error responses in the OpenAPI (today only FastAPI's default 422 `HTTPValidationError` is listed, which does not match the real body), and declare `securitySchemes` (session cookie, bearer API key); confirmed open by the DX review (DX-43) |
| P2 | sdk | Publish `@axentra/sdk` (npm) and `axentra-client` (PyPI); release process and provenance |
| P2 | sdk | Python SDK: remaining operations (templates, preferences, reservations, checkout, users admin) |
| P2 | cli | CLI for administration over HTTP (products, tenants, keys) and `axentra admin` tasks without database access |
| P3 | cli | A command that fails after creating its `Axentra` instance (for example a database error in `axentra worker --once`) exits without closing the connection pool, so the pool threads delay the exit by about 20 seconds (`admin setup-token` also waited on success; fixed in audit round 3, AX3-02) |
| P3 | branding | The product name collides with an unrelated company that owns `axentra.dev` (problem type URIs no longer use that domain, DX-41); decide on naming/branding before a public release |
| P3 | sdk | `npm audit` reports moderate advisories for the TypeScript SDK's development dependency `minimatch` (none in the production tree); update when a fixed release is in range (AX2-09) |

## Hardening (Phase 5)

| Pri | Area | Item |
|---|---|---|
| P1 | operations | Backup/restore of file storage together with the database (test exists for the database only) |
| P1 | build | Reproducible container builds: build hatchling from pinned versions and compare digests of two builds (the `python:3.13-slim` base is digest-pinned with a CI check since audit round 2, OPS2-12) |
| P3 | build | The compose stacks still use `postgres:16` (and other service images) by tag; pin by digest like the application image (OPS2-12 rest) |
| P2 | build | Hash-pinned constraints (`--require-hashes`) and SBOM generation for the image |
| P2 | tests | Deployment tests that start the compose stacks in CI and run smoke tests (the single-/multi-product scenarios run in-process today: `tests/integration/test_deployment_models.py`) |
| P2 | tests | Concurrency tests for `If-Match` races and migration runners started in parallel |
| P2 | tests | Cross-repository compatibility: Studio's contract and e2e jobs run only for the commit pinned in Studio's `api/BACKEND_REF`, only on Studio pull requests and only in multi-product mode; nothing on the Axentra side triggers them for a new Axentra commit (a single-product e2e matrix is being added on the Studio side) |

## Nodestro (Phase 6)

| Pri | Area | Item |
|---|---|---|
| P2 | integration | `docs/integrations/NODESTRO_MIGRATION_PLAN.md`: generic gaps G-1 (product-defined permissions), G-3, G-4, G-6 (re-encryption registry) and G-7 (per-product content-type policy) are done; G-2 follow-ups are listed above. Phase 6 is done on the Axentra side (see ROADMAP.md). Nodestro uses Axentra as a library in its server profile (Python 3.11+ only via an extra marker; see nodestro-runtime docs/AXENTRA.md) |
| Rejected | integration | G-5 (claim token for ownerless tenants): rejected for now. Nodestro's setup links must keep working in every identity mode and across a rollback, so they stay in Nodestro's table and travel through Axentra's OIDC login as host context (`start(context=...)`); a generic claim token is worth adding only for a product without its own store |
| Rejected | jobs | G-8 "jobs module with Nodestro's semantics" (configurable at-most-once delivery, unique active key per `(tenant, kind, ref)`, interrupt-on-lease-loss callbacks, product capacity gates): rejected by architecture decision 2026-11-02. Nodestro's no-duplicate guarantee lives in its run fence, interrupted state, tool journal and approval checkpoints, not in the queue, so these options would be Nodestro semantics in a generic module that no other product needs; Nodestro keeps its run queue permanently (M11 closed; nodestro-runtime `docs/AXENTRA.md`). Axentra jobs stay at least once (`max_attempts=1` for no retry); evidence: `tests/integration/test_job_delivery_semantics.py` |
| Rejected | identity | Endpoint that revokes all of the caller's sessions except the current one (Studio's "Sign out all other sessions"): not needed for now. A user has a handful of sessions; Studio sends `DELETE /v1/auth/sessions/{id}` per session (bounded concurrency, never the session marked `current`, `404` counted as done, partial failures reported), which also keeps one `identity.session.revoke` audit event per session. Worth adding only for atomicity or users with very many sessions |
| P3 | notify | Inbox channel: HTTP routes and an Axentra Studio page (today a host serves it through its own API, as Nodestro does) |
| P3 | events | `GET /v1/settings` reports no `[events]` values, so clients (Studio) cannot show the effective job and webhook retry schedule (`webhook_max_attempts`, `webhook_backoff_base_seconds`, `webhook_backoff_max_seconds`); Studio's help documents the defaults |

## Known limitations

These are current, deliberate or accepted properties; some have an item above.

- `axentra_users` (and sessions, platform roles, external identities) are global tables without
  row-level security; protection is in the service layer.
- In tenant scope, RLS also shows product-level rows (`tenant_id IS NULL`) of the same product
  (read-only there since migration `0011`).
- Unique constraints on natural keys (emails, product slugs, tenant slugs, role keys) can reveal
  existence through conflict errors.
- Login throttling uses fixed one-minute windows (bursts up to twice the budget at a window
  boundary); no CAPTCHA. The per-account budget lets anyone who knows an email block password
  logins of that account for up to a minute (accepted trade-off, see SECURITY_MODEL.md).
- Job kinds and their handler permissions are declared in process (`ax.jobs.register`/`declare`);
  an API process that does not declare a kind refuses it to tenant callers (fail closed).
- Product permissions registered in process without versioned access definitions are mirrored at
  start, and with several processes of one product the last start wins (a rolling deployment may
  briefly flip a definition). A product that applies `ax.access_definitions` (migration `0009`) is
  deterministic instead: an older revision is skipped (an old process never downgrades) and the
  same revision with other content is refused (409). Retired
  permissions stay listed in custom roles and API keys (without effect) until removed there.
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
