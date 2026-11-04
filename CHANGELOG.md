# Changelog

All notable changes to Axentra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).
The HTTP API has its own version (`api_version` in `GET /v1/meta`), see docs/architecture/VERSIONING.md.

## [Unreleased]

- Docs: the Nodestro migration plan states that it was carried out and notes where the implemented switches and
  rollback differ from the plan (sections 4.6 and 8).

### Security
- API keys no longer outlive their creator's authority (audit round 3, AX3-01). Every request made with a key is
  bounded by what the key's creator (`created_by`) holds now in the same product and tenant; for a key created by a
  key, by that key's bounded permissions. A removed, demoted or disabled creator takes those rights from the key,
  which answers `403` with the new problem code `api_key_creator_lost_access` (member `permission`) and records an
  `access.api_key.use` audit event with outcome `denied` (throttled to one per key and scope per minute and
  process). Keys are not revoked or deleted: restoring the creator restores the key; administrators can still
  revoke or rotate it. Keys created in process by system callers are unchanged. **Behaviour change** for keys
  whose creator already lost access. New `Authorizer.refuse()` for services that inspect a `Grant` themselves;
  `Grant` has new fields `withheld` and `key_creator`.

### Fixed
- The audit events of logins and first-run setup (`identity.login` with outcome `success` or `denied`, for
  passwords and OpenID Connect, `identity.setup.complete` and `identity.external.link`) record the client
  `ip` and the `request_id` like every other event; before, both were empty. A successful login records the
  user's email (else name) as `actor_display` instead of an empty string (audit round 3). `AuditLog.record`
  takes explicit `ip` and `request_id` keyword arguments for flows without a principal;
  `IdentityService.login_password`, `complete_setup`, `start_session`, `link_external_identity` and
  `OidcService.finish` take an optional `request_id`.
- `axentra admin setup-token` closes its database pool: it printed the token and then waited about 20 seconds
  for the pool threads ("couldn't stop thread ... within 5.0 seconds") before exiting (audit round 3).
- Webhook URLs with legacy IPv4 notations (`2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`, `0`) or with
  whitespace or percent signs in the host are refused when the endpoint is created or changed (audit round 2,
  AX2-07). Before, they were accepted and only the delivery-time address check refused them.
- `GET /v1/me` listed only tenants among the product's first 200 (by id), so members of later tenants got
  an empty `tenants` list and lost their tenant permissions in Axentra Studio (audit round 2, AX2-03). It now
  lists every readable tenant, with the same entries, order and response shape as before; the per-tenant
  authorization (one round of queries per tenant) is replaced by `Authorizer.tenant_grants`, a fixed number of
  queries per product, and `TenancyService.tenants_by_id`.

### Changed
- Problem details `type` URIs are now `urn:axentra:problem:<code>` instead of `https://axentra.dev/problems/<code>`
  (DX-41: that domain belongs to an unrelated company). **Breaking** only for clients that compared `type`
  instead of `code`; Axentra Studio and the SDKs use `code`. See ADR 0009 (amendment).
- CLI: operator errors (configuration, unreachable database, database errors, unknown `--load` module) print
  `axentra: <code>: <message>` and exit with status 2 instead of a 20-line traceback (DX-42); new global
  `--debug` (or `AXENTRA_DEBUG=1`) shows the traceback.
- New official Axentra logo. `assets/branding/` now holds the two logo masters
  (`axentra-logo-transparent.png`, `axentra-logo-white.png`), the vendored derivation script
  `derive_branding.py` and the derived `axentra-logo.png` (light surfaces),
  `axentra-logo-on-dark.png` (dark surfaces) and `axentra-mark.png` (symbol). The README logo
  switches between light and dark with the GitHub color scheme. The old `axentra-logo.png` was
  replaced; provenance and the regenerate command are in `assets/branding/README.md`.
- GitHub social preview `assets/branding/social-preview.png` (1280 × 640), rendered by the shared
  template `social_preview.py` (also used by Nodestro and Orkexa) from the logo master. It is
  uploaded by hand in the repository settings.
- Docs: Roadmap Phase 6 (Nodestro integration) marked done on the Axentra side; the "last start wins" limitation
  now names versioned access definitions as the deterministic way.
- `IdentityService.resolve_session` reads the user in the session's transaction (one transaction per
  resolution instead of two: one snapshot, four round trips fewer on every request of an embedding host).

### Security
- Product overview without cross-tenant numbers (audit round 2, AX2-05). `GET /v1/products/{id}/overview`
  returns product-wide counts only to callers that hold `tenants:read` on the product (product operators,
  platform roles, product-wide API keys with that permission). Every other caller with `product:read` (plain
  tenant members, product-wide keys without `tenants:read`) now gets the counts of its own tenants:
  `tenants`, `users` and `records` cover only the tenants in which it holds `tenant:read`, `members:read`
  and `records:read`, and `api_keys`, `audit_events_24h` and `denied_events_24h` are `null`; the whole
  product is no longer counted for them. New required response field `scope` (`"product"` or `"tenant"`).
  **Contract change**: the three product-level counters are now nullable (Axentra Studio already ignores
  non-numeric counters).
- Usage backdating is limited (audit round 2, AX2-08). The built-in `member` role keeps `usage:record`, but
  an `occurred_at` before the start of the tenant's current billing period (the subscription cycle, or the
  calendar month without one) now needs `usage:manage` held at product level; other callers (members, tenant
  admins, tenant-bound API keys) get `403` with the new problem code `backdating_not_permitted`
  (`urn:axentra:problem:backdating_not_permitted`) and `period_start`, the earliest allowed `occurred_at`.
  The 400-day bound still applies to everyone. Replays of an accepted idempotency key are unaffected.
  **Behavior change** for integrations that backfill older usage with a `usage:record`-only key: give that
  key `usage:manage` (product-wide).
- Background work follows current access (audit round 2, AX2-01). Jobs fired by a schedule are reduced to
  what the schedule's creator holds *when the job runs*, like jobs enqueued through `POST /jobs` (before,
  they kept all handler permissions after the creator was removed or disabled; a job whose schedule was
  deleted now holds none). Workers no longer run jobs of an archived product or a suspended tenant: they end
  as `failed` with `last_error` `skipped: ...` and stay retryable (webhook deliveries as `dead`, can be
  redelivered). The scheduler skips schedules of archived products and suspended tenants (schedule kept,
  `events.schedule.skip` audit event once per inactive period). Behaviour change for handlers that relied
  on full permissions in schedule jobs created by users or API keys.
- Webhook delivery attempts have a total deadline (audit round 2, AX2-02): `events.webhook_timeout_seconds`
  now bounds connect, TLS handshake, request, response headers and body together (before it applied to
  each socket operation, so a receiver that trickled bytes could hold a worker slot for hours). New
  `max_runtime_seconds` for `ax.jobs.register`: the worker stops renewing the lease of an attempt that runs
  longer; webhook deliveries declare timeout + 30 s.
- Invitation acceptance re-checks the inviter and the scope (audit round 2, AX2-04): `POST /v1/invitations/accept`
  answers `403` when the tenant is suspended or the product archived, or when the inviter can no longer
  invite with that role (removed, disabled, downgraded, revoked key; `members:manage` and the role ceiling
  with the inviter's current access). The `denied` audit event of a refused acceptance is now kept (it was
  rolled back together with the refusal) and carries `details.reason`. `Authorizer.actor_principal` resolves a
  recorded actor id to its current principal (also used for job enqueuers).
- The `GET` OIDC start no longer acts on an invitation (security review round 4, R4-1, login-CSRF-like). It is
  a plain link without an `Origin` check, so a cross-site link to
  `GET /v1/auth/oidc/{provider}/start?invitation=<token>` (or with the token inside `return_to`) made a browser
  with an identity provider session join the inviter's tenant without a prompt, when the invitation was
  addressed to that browser's user. Now, failing closed:
  - `GET .../start` with a non-blank `invitation` query starts no login (no login state, no login cookie, no
    provider redirect) and redirects to the login page with the new code `login_error=invitation_requires_post`
    (on the origin of `return_to`, as other login errors); an empty `invitation=` is ignored. The parameter
    stays declared (deprecated) in the OpenAPI contract to document this. **Breaking** for clients that still
    sent the token there: use `POST /v1/auth/oidc/{provider}/start`, the only start that takes an invitation
    (Origin checked). Axentra Studio uses the `POST` start since its last release.
  - An Axentra invitation token in `return_to` (as `token`/`invitation`) is removed and no longer adopted as
    the login's invitation. `OidcService.stored_return_to` returns the stored `return_to` only (it returned a
    `(return_to, adopted invitation)` pair).
- Invitation tokens never end up in a stored or logged URL (security review round 3, NF-2/NF-3, the rest of
  AX-R2):
  - New `POST /v1/auth/oidc/{provider}/start` with the JSON body `{return_to?, invitation?}` (Origin checked):
    same login state and login cookie as the `GET` start, answered with `{redirect_url}` (the provider URL, or
    the login page with `?login_error=`). The invitation token travels only in the body, never in a URL that
    a proxy log, the browser history or a `Referer` records. The `GET` start without an invitation is
    unchanged; with one it is refused (entry below).
  - `return_to` loses every query parameter that carries a secret before it is stored in
    `axentra_login_states.return_to` and sent back as the redirect, whatever the path and its spelling
    (`/invitations/accept/`, other casing, percent-encoding): parameters named like a secret (`token`,
    `*_token`, `invitation`, `setup`, `password`, ...) after percent-decoding, and parameters whose value holds
    a token or a nested URL with one in any encoding. A fragment with a secret is dropped. New helpers `strip_secret_params`, `carries_secret` and
    `fully_unquote` in `axentra.core.redaction`, `OidcService.stored_return_to`.
  - Redaction matches the percent-encoded form too: the `uvicorn.access` filter (`redact_auth_query`, now in
    `axentra.core.redaction` and re-exported from `axentra.audit.logging`) redacts `code`, `state`, `*token`,
    `setup` and `invitation` values inside an encoded `return_to` (`%3Ftoken%3D...`, any depth, either hex
    case) and also applies `redact_text`; `redact_text` (logs, problems, audit details) masks
    `axinv_`/`axk_` tokens with an encoded `_` and the values of `*token`, `invitation` and `setup` query
    parameters, literal or encoded.
- OIDC callback: when the `invitation` given on `POST /v1/auth/oidc/{provider}/start` was accepted during
  the login, the redirect to `return_to` carries `invitation_accepted=<tenant id>` (re-review AX-R2), so a
  frontend can show the accepted invitation instead of asking for a confirmation that would fail with
  `404`. `LoginResult.invitation_tenant_id` gives embedding hosts the same information. A failed
  acceptance redirects without it, as before.
- Malformed pagination cursors are a `400 invalid_cursor` (detail `invalid cursor`) on every list endpoint
  instead of a `500` (re-review AX-R1): before, a cursor with the wrong number or types of values, a NUL
  character, a lone surrogate or a timestamp PostgreSQL rejects (ISO week dates, comma fractions, offsets
  with microseconds, out-of-range values) reached the SQL, for example on `/notify/messages`,
  `/notify/mailbox`, `/v1/audit` and `/tenants`. `decode_cursor(cursor, shape)` now takes the expected
  value types (`"str"`, `"timestamp"`, `"int"`), accepts only the timestamp form Axentra issues and
  returns it as an aware UTC datetime; without a shape it still rejects NUL characters, lone surrogates,
  non-finite numbers and cursors over 4096 characters. The new error `InvalidCursor` is a subclass of
  `ValidationFailed`. **Breaking (HTTP):** a tampered cursor that was a `422 validation_failed` before
  (for example one that is not base64 JSON) is now a `400 invalid_cursor`. Embedding hosts that page
  their own tables should pass a shape (docs/guides/PRODUCT_TABLES.md).
- Row-level security: tenant scope can no longer write product-level rows (security review SR-02).
  Migration `0011_tenant_scope_writes` adds `axentra_scope_allows_write` (tenant scope requires
  `tenant_id` = the current tenant) and uses it in every `scope` policy's `WITH CHECK` plus new
  restrictive `scope_update` / `scope_delete` policies. Reading product-level rows from tenant scope is
  unchanged. Product tables with nullable `tenant_id` should follow (docs/guides/PRODUCT_TABLES.md).
- `secrets reencrypt` also re-encrypts the OIDC login state's `host_context` (security review SR-05):
  before, a value there stayed under the old key after `pending: 0`. The report adds `by_kid` (values per
  key id over every column) for hosts that check their keyring against stored values. A test scans
  every text column of every Axentra table after a rotation and finds no value under the old key.

### Changed
- Webhook deliveries retry on their own schedule instead of the job backoff (2 s doubling), which
  made a delivery `dead` about 2-4 minutes after the first attempt, so a short receiver outage
  lost events. New `[events]` settings `webhook_backoff_base_seconds` (default 120) and
  `webhook_backoff_max_seconds` (default 21600, must not be below the base); same jitter as jobs.
  With the default 8 attempts the retries now span about 2.1 to 4.2 hours
  (docs/modules/EVENTS_AND_JOBS.md). Ordinary jobs keep `backoff_*`.
- Setup and user-creation conflicts carry distinct codes (still HTTP 409 and subclasses of
  `Conflict`, so existing handling keeps working): `setup_already_completed` when a platform
  admin already exists, `email_taken` when another user has the email address
  (`axentra.core.errors.SetupAlreadyCompleted`, `EmailTaken`). Clients no longer need to parse the
  message. docs/architecture/API_CONVENTIONS.md lists every error code a client can receive.

### Fixed
- Product operators can read a suspended tenant's record again, so they can reactivate it:
  `GET /v1/products/{p}/tenants/{t}` now accepts `tenants:read` held for the whole product (product
  roles, product-wide API keys, platform roles), whatever the tenant's status, exactly as the tenant
  list already showed it. Everyone else still needs `tenant:read` in the tenant, which a suspended
  tenant refuses. The tenant's data (members, invitations, records, files, usage, billing, ...) stays
  closed to everyone but platform roles; unrelated principals still get `404`; archived products
  stay closed. The `tenancy.tenant.update` audit event of a status change now carries
  `previous_status`.
- Invitation links in split-origin deployments: the new installation setting
  `notify.invitation_accept_url` (absolute http(s) URL, https in production, `{token}` placeholder
  like the product setting) is used when a product has no own `settings.invitation_accept_url`.
  Before, such links always pointed to `<security.public_url>/accept-invitation`, the API origin,
  where no accept page exists when Studio or the product frontend lives on another origin. The
  default is unchanged; `GET /v1/settings` reports the effective base as
  `notify.invitation_accept_url`.
- An Axentra transaction inside `Database.joined()` restores the scope it found on the connection.
  Before, it restored the scope of the moment `joined()` began, so a service call (for example an
  authorization read) inside a `join(conn, scope)` block emptied that block's scope: under
  row-level security the next statements of the block saw no rows (`UsageService.record_in` found
  no meter). Superuser test roles hid it.

### Added
- `tests/integration/test_job_delivery_semantics.py`: a worker that lost its lease keeps running its
  handler while the retry runs it again (at least once); `max_attempts=1` makes the job `dead`;
  idempotency keys deduplicate for good. Backs the G-8 decision: Nodestro keeps its own run queue
  (docs/TODO.md, docs/modules/EVENTS_AND_JOBS.md "Limitations").
- Notify: in-app **inbox** channel (migration `0010_notify_inbox`: channel `inbox`, `read_at`).
  Inbox messages go to a user id, are stored encrypted and final at enqueue (`sent`, provider
  `inbox`); the dispatcher never claims them, so they never reach a delivery provider.
  `NotifyService.list_inbox`, `unread_count`, `mark_read` (the caller's own messages only).
- Observability for embedding hosts: `register_pool_metrics` (several named pools, label `pool`,
  with `in_use`), `MetricsRegistry.counter_callback` / `CallbackCounter` (host-kept totals as
  counters), `CachedCallback` (expensive scrape-time values at most once per TTL), `pool_stats`.
- Versioned access definitions (migration `0009_access_definitions`, table
  `axentra_access_definitions`, forced RLS): `ax.access_definitions.apply(product,
  AccessDefinitions(revision, permissions, roles))` applies an embedding product's permissions and
  custom roles once per revision (content hash per product, advisory lock, audit event
  `access.definitions.apply`); an equal revision is a no-op, an older one is never applied
  (`stale`), the same revision with other content is `409`. Managed roles cannot be changed or
  deleted over the API; the unversioned `ax.permissions.register` is ignored for such products.
  `drift()` compares for reconciliation. Replaces "last start wins".
- `OidcService` for host routes: `redirect_uri=` (callback URL), `start(context=...)` (host
  context stored encrypted with the login state, returned as `LoginResult.context`),
  `finish(start_session=False)` and `LoginResult.identity` (issuer, subject, verified address,
  name). Column `axentra_login_states.host_context` (migration `0009`).
- Database roles (docs/architecture/EMBEDDING.md#database-roles): `axentra.data.roles`
  (`grant_runtime_role`, `inspect_role`), `axentra db grant-runtime-role ROLE`,
  `axentra db inspect-role [ROLE]` and `axentra migrate --grant-runtime-role ROLE` give a runtime
  role data privileges only (refusing superuser, `BYPASSRLS` and owning roles; the migration
  bookkeeping stays read-only for it). `Database.role_info()` reports `table_owner`;
  `check_role(allow_table_owner=...)` and `database.allow_table_owner` (default `true`) refuse an
  owning role in production. The compose stacks grant `axentra_app` after `migrate`.
  `AXENTRA_TEST_SPLIT_ROLES=1` runs the test suite with separate owner and runtime roles.
- `Database.on_pool(pool)`: Axentra borrows the host application's connection pool (one pool per
  process; autocommit connections and any row factory work; the pool is never opened or closed by
  Axentra).
- Embedding Axentra as a library (docs/architecture/EMBEDDING.md):
  - `axentra.core.errors.problem_details(exc)` maps any exception to a framework-independent
    `ProblemInfo` (status, code, title, redacted detail, extra members, headers such as
    `Retry-After`, `internal` flag, `body()`); the HTTP API's handlers use it.
    `AxentraError(..., retry_after=)` sets `Retry-After`.
  - `ax.db.joined(conn)`: every Axentra transaction on the calling thread runs on the host's
    psycopg connection inside a savepoint, so services commit or roll back with the host
    transaction. `axentra.data.join(conn, scope)` yields a `Tx` on the host connection;
    `UsageService.record_in(tx, ...)` records usage in it. `Tx` returns dict rows regardless of
    the connection's row factory.
  - `Axentra(settings, keyring=...)` accepts a keyring loaded by the host; production then does
    not require `security.master_keys_ref`.
- Migrations: `MigrationRunner.check()` (applied, pending and unknown versions per namespace),
  `require_current()` / `ax.require_current_schema()` raising `SchemaNotCurrent`,
  `migrate(before_apply=..., allow_newer=...)`, `-- axentra:no-transaction` migrations,
  `database.require_current_schema` (start gate and a `schema` readiness check), and
  `axentra migrate --check [--namespace] [--allow-newer] [--load]`.
- Users without an email address (migration `0007_users_without_email`): `create_user(email=None)`,
  per-provider `oidc[].allow_signup_without_email` (default false) and
  `oidc[].link_by_verified_email` (default true; false never links an unknown identity to an
  existing user by email), `IdentityService.create_external_user`, `link_identity` and
  `list_identities` for imports. Notifications to such users are recorded as `suppressed`.
- Product-defined permissions (Nodestro plan G-1): products declare their own namespaced
  permissions (`<namespace>.<resource>:<action>`, e.g. `crm.deals:approve`) with scope
  (`product`/`tenant`), description, `read_like` and optional `default_roles` for built-in roles.
  Embedding products register them in process (`ax.permissions.register(product, [ProductPermission(...)])`,
  mirrored at `ax.start()`); other products declare them over HTTP
  (`PUT`/`DELETE /v1/products/{pid}/permissions/{name}`, new product permission
  `permissions:manage`, held by `product_owner` only). New table `axentra_product_permissions`
  (migration `0008_product_permissions`, forced RLS). `GET /v1/products/{pid}/permissions` lists
  the built-in and product permissions grantable in a product (`roles:read`, `api_keys:read` or
  `permissions:manage`); `PermissionInfo` gained `source`, `read_like`, `default_roles`,
  `declared_by`, `retired_at`. Custom roles and API keys are validated per product (another
  product's names are `422`); owners/admins hold product permissions automatically, viewer and
  support roles the read-like ones; tenant roles confer tenant-scoped product permissions.
  Permissions that are no longer declared are retired, never deleted, and grant nothing while
  retired (key rotation drops them). Job kinds accept product permission names. Python SDK:
  `roles.permissions(product_id)`. See SECURITY_MODEL.md, "Product-defined permissions".
- Per-product storage content-type policy (Nodestro plan G-7): `settings.storage.blocked_types`
  (`refuse`/`store_inert`, default from `storage.store_blocked_as_inert`), extra
  `blocked_extensions`/`blocked_content_types` (tighten only) and `inert_extensions` (accepted as
  inert even when refusing); one rule for declared type, extension and sniffed content, including
  shebang scripts. `GET`/`PUT /v1/products/{pid}/storage/policy`; product settings updates
  validate these keys. Files stored inert keep their declared type in the new
  `FileInfo.original_content_type` and are flagged `stored_inert` (migration `0008` adds both
  columns); they are still only served as `application/octet-stream` attachments with `nosniff`.
  Renaming a file to a blocked extension follows the same policy. See docs/modules/STORAGE.md.
- Search module (`axentra.search`, order section 4 L): tenant-scoped PostgreSQL full-text index
  (migration `0006_search`, table `axentra_search_documents` with forced RLS, generated weighted
  `tsvector` over title and body, GIN index). Products index documents by kind + ref id through
  `ax.search.upsert/delete` or `PUT`/`DELETE /v1/products/{pid}/tenants/{tid}/search/documents/{kind}/{ref_id}`
  (new permission `search:index`, audited without content); users query with
  `GET /v1/products/{pid}/tenants/{tid}/search?q&kind&limit&cursor` (new permission `search:query`):
  web search syntax, `ts_rank` ranking, HTML-escaped `ts_headline` highlights, kind filter, cursor
  paging. Pluggable `SearchAdapter` protocol with `PostgresSearchAdapter` as default. New settings
  section `[search]` (`language`, default `simple`; `max_body_chars`, `max_offset`,
  `audit_index_writes`). Role defaults: all built-in roles may query; owners/admins (tenant and
  product) and platform admins may index. No vector search. See docs/modules/SEARCH.md.
- Implementation report `docs/AXENTRA_IMPLEMENTATION_REPORT.md`: architecture, actual module
  scope (implemented + tested vs. planned; the search module is not implemented), Nodestro
  provenance, API/SDK overview, verified install and start commands, test and CI evidence,
  security checks, deployment-model and headless proofs, compatibility, open limitations, PRs and
  merge SHAs, and the status of all 30 acceptance criteria. `docs/COMPATIBILITY.md` now lists the
  two combinations tested in Studio CI (Axentra `a2ca72a` with Studio `0aed4fc`, e2e 180/180;
  Axentra `7511a37` with Studio `ee7d9f2`, e2e 186/186, contract identical) and how rows are added.
  README, ROADMAP, OVERVIEW and TODO brought in line with the merged modules.
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
- `migrate()` now refuses to run when a registered namespace has applied versions the code does
  not know (pass `allow_newer=True`), and checks all checksums before applying anything.
- HTTP: `email` in `User`, `Membership` and `ProductMember` responses is `string | null`. It is
  `null` only for users without an email address, which exist only after opting in (provider
  options above or library calls); the API version stays `1.0`.
- Session expiry (absolute and idle), setup tokens and invitation expiry are computed and compared
  on the database clock instead of the API host's clock.
- New built-in product permission `permissions:manage` (declare and retire product permissions
  over the API). `product_owner` and platform admins hold it; `product_admin` does not (like
  `product_members:manage`), because a declaration changes what built-in roles hold.
- Product settings updates validate the storage content-type policy keys of `settings.storage`
  (`422` for invalid values); other settings are unchanged.
- Tests: `test_I4_login_throttling_is_atomic` pins the one-minute throttling window. When its 100
  concurrent attempts straddled a minute boundary, the new window granted a fresh budget (fixed
  windows allow up to twice the budget across a boundary, as documented), so the test failed.
- Tests: `test_api_key_lifecycle_and_scope` no longer fails at random. It cut the key secret with
  `split("_")[-1]`, but the secret part may contain `_`, so the remainder could be a single
  character found anywhere in the listing (failed CI on `d5e2ba7` and `7511a37`).
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
