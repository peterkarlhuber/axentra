# Nodestro on Axentra: migration plan

Status: **analysis and plan only (Roadmap Phase 6)**, 2026-11-01. Author: Claude, for the Axentra project.
Nothing described here is implemented. No Nodestro repository was changed; they were read at the commits below.

> **This migration is a separate, future project.** It is *not* a prerequisite for Axentra, for any Axentra
> release or for Axentra Studio. Axentra stays independent: it never imports, installs, pins or calls Nodestro or
> orkexa (see [NODESTRO_REUSE.md](../architecture/NODESTRO_REUSE.md), rule 1, and `tests/unit/test_architecture.py`).
> The dependency direction of everything below is one-way: **Nodestro -> Axentra**, never the reverse. Whether and
> when Nodestro adopts Axentra is a product decision for Nodestro (open question Q-1).

Companion documents: [NODESTRO_REUSE.md](../architecture/NODESTRO_REUSE.md) (what Axentra took from Nodestro and
why), [SECURITY_MODEL.md](../architecture/SECURITY_MODEL.md), [DATA.md](../architecture/DATA.md),
[VERSIONING.md](../architecture/VERSIONING.md), [ADR 0002](../adr/0002-python-versions.md) (Python versions),
[ADR 0010](../adr/0010-single-and-multi-product.md) (single/multi product), [ADR 0011](../adr/0011-keyring-rotation.md)
(keyring).

## 0. Basis of this plan

### 0.1 Examined commits

| Repository | Commit (HEAD, read-only) | Used for |
| --- | --- | --- |
| axentra (worktree `wip/migplan`) | `03e73c368f7c76cefc58f6bda1f6cdf18d2aed75` | `src/axentra/**`, `docs/architecture/*`, `docs/modules/*` |
| nodestro-api | `e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea` | `identity.py`, `permissions.py`, `api_keys.py`, `serving.py`, `server_app.py`, `server.py`, `api.py`, `worker.py` |
| nodestro-runtime | `a42b6724702821849af478ee9dd0bfa13617e28b` | `identity_store.py`, `storage_postgres.py`, `postgres_tables.py`, `migrations/postgres/0001-0006`, `jobs.py`, `server_settings.py`, `workspace.py`, `usage_log.py`, `cost_tracking.py`, `input_files.py`, `file_formats.py` |
| nodestro-server | `42e95af25ad20466c4b78211272eeefd45b2c57b` | `compose/compose.yaml`, `image/Dockerfile`, `studio.json`, `docs/RUNBOOK.md`, `tests/e2e/test_acceptance.py` |
| nodestro-studio | `8e18caecea17b2fab5a837359a324896b565c313` | `platform/versions.json`, `scripts/check_versions.py`, `pyproject.toml`, `frontend/src/api/{client,access}.ts` |
| nodestro-sdk | `05080f69ee8337c3043167e2ef9b694b61370b27` | `python/tests/test_contract.py`, `test_http.py`, `published.py` |
| orkexa | `34679404e42dd0ae8eecfe53be21180450be5923` | dependency of nodestro-runtime only; not touched by this plan |

Note: the platform pins (`nodestro-studio/platform/versions.json`) name older commits for nodestro-runtime
(`ac96c6f7...`) and nodestro-api (`4e2c8cdc...`) than the HEADs above. A real migration starts from the then-pinned
commits and re-checks every finding here.

### 0.2 What Axentra offers at this commit

| Area | Axentra module (library API) | Ready for Nodestro? |
| --- | --- | --- |
| Identity: users, OIDC (PKCE, state, nonce, login cookie binding), sessions, setup token, login throttling | `axentra.identity.service.IdentityService`, `axentra.identity.oidc.OidcService` | Yes, with gaps G-3, G-4 |
| Products, tenants, memberships, invitations, product operators | `axentra.tenancy.service.TenancyService` | Yes, with gap G-5 |
| Permission catalog, built-in and custom roles, authorizer, API keys (`axk_`) | `axentra.access.*` | Gap G-1 (no product permissions) |
| PostgreSQL pool, `DbScope`, forced RLS, migrations with namespaces and checksums | `axentra.data.database`, `axentra.data.migrations` | Gap G-2 (runner features) |
| Settings, secret references, AES-256-GCM keyring `axs1` with rotation | `axentra.config.settings`, `axentra.config.secrets` | Gap G-6 (re-encrypt hook) |
| Audit (append-only, same transaction) | `axentra.audit.log.AuditLog` | Yes |
| File storage (local/S3, quotas, signed URLs) | `axentra.storage.service.StorageService` | Gap G-7 (content-type policy) |
| Usage metering, quotas, reservations | `axentra.usage.service.UsageService` | Yes |
| Billing | `axentra.billing` | Not needed by Nodestro today |
| Notifications (e-mail, in-app mailbox, preferences) | `axentra.notify.service.NotifyService` | Yes (new function for Nodestro) |
| Metrics, tracing | `axentra.observability` | Yes |
| Events, jobs, webhooks, leader lock, schedules | merged after this analysis (axentra PR #5, `33dce58`); Nodestro-specific semantics still to verify | **Partly blocked** (gap G-8) |
| Realtime (SSE) | not present (`docs/TODO.md` P2) | Blocked |

## 1. Nodestro functions that could use Axentra

The decision column says how Nodestro would use the Axentra function. "Library" means in-process use of the Axentra
services inside Nodestro's processes, against the same PostgreSQL database (decision D-1 below).

| # | Nodestro function today | Nodestro code | Axentra counterpart | Use |
| --- | --- | --- | --- | --- |
| F-1 | OIDC login (PKCE, state, nonce, login cookie) | `nodestro_api.identity.OidcClient`, `auth_router` (`/api/auth/login`, `/callback`) | `OidcService.start/finish`, `OidcClient` (adapted from Nodestro, plus JWKS TTL, multiple providers, `client_secret_post`/`none`) | Library; Nodestro keeps its routes |
| F-2 | Sessions (12 h absolute, 2 h idle, hash-only) | `IdentityStore.create_session/session/end_session/end_sessions`, `SessionResolver` | `IdentityService.start_session/resolve_session/logout/revoke_all_sessions` (same defaults: `session_ttl_hours=12`, `session_idle_minutes=120`) | Library |
| F-3 | Tenants | `IdentityStore.create_tenant/tenant/tenants`, `nodestro_tenants` | `TenancyService` tenants in one product (status, settings, version) | Library |
| F-4 | Memberships and five fixed roles, last-owner guard | `IdentityStore.set_role/remove_member/_keep_an_owner`, `ROLE_PERMISSIONS` | `TenancyService.set_member/remove_member` (`_guard_last_tenant_owner`), built-in + custom roles | Library + role map (section 3.4) |
| F-5 | Tenant bootstrap (first owner by one-time link) | `IdentityStore.create_bootstrap_token/use_bootstrap` | Partly: `invite()` (e-mail bound), platform setup token. No "claim an ownerless tenant" token | Stays Nodestro (gap G-5) |
| F-6 | Permission dependencies, route registry, stream re-check | `nodestro_api.permissions` (`Access`, `StreamAccess`, `check_routes`) | `Authorizer.require/has`, Axentra's `PUBLIC_ROUTES` registry (HTTP layer only) | Stays Nodestro; principal built from Axentra |
| F-7 | API keys for published workflows | `nodestro_api.api_keys.ApiKeys`, `serving.new_key/parse_token/hash_secret`, `ServingCore.authenticate` | `ApiKeyService` (`axk_`, product/tenant bound, expiry, rotation with grace) | Library + legacy `ndk_` verifier |
| F-8 | PostgreSQL pool and transactions | `storage_postgres.PostgresDatabase` (pool, serialized transactions, session locks) | `axentra.data.database.Database` (`DbScope`, `SET LOCAL` scope settings) | Later: Nodestro's store on Axentra's pool |
| F-9 | Migration runner | `PostgresDatabase.migrate` (`nodestro_schema_migrations`, backup hook, schema gate) | `MigrationRunner` (namespaces, checksums, advisory lock) | Library, after gap G-2 |
| F-10 | Configuration and secret files | `server_settings.ServerSettings` (`*_FILE` variables) | `axentra.config.settings` (`*_ref` = `env:`/`file:`) | Nodestro builds Axentra settings from its own |
| F-11 | Encrypted tenant secrets (provider API keys) | `server_settings.SecretBox`, `workspace._seal` | `SecretBox` (`axs1.<kid>...`, keyring, rotation) | Library + legacy decryptor; gives Nodestro key rotation |
| F-12 | Job queue, leases, reaper, cancel | `jobs.JobQueue`, `nodestro_jobs` | Axentra jobs module (merged in PR #5; semantics per G-8 open) | Blocked (G-8) |
| F-13 | Scheduler leader lock and schedule slots | `jobs.LeaderLock`, `jobs.ScheduleFirings` | Axentra jobs/scheduler (merged in PR #5; semantics per G-8 open) | Blocked (G-8) |
| F-14 | Run event log for multi-replica streaming | `jobs.PostgresEventLog`, `nodestro_run_events` | Axentra event streams (not present) | Blocked; stays Nodestro until then |
| F-15 | Input files (uploads per tenant on the data volume) | `input_files.InputFiles`, `_Blobs` (orkexa `LocalFileStore`), `server_app.TenantFiles` | `StorageService` (local/S3, quotas, SHA-256, signed URLs) | Library behind `_Blobs`-shaped adapter |
| F-16 | Audit (tool approvals, capped at 5000 per tenant) | `tool_approvals.record_audit/audit_events` | `AuditLog.record` (append-only, redacted, same transaction) | Dual-write, later read |
| F-17 | Usage ledger outside runs, cost tracking | `usage_log.UsageLog` (`usage_log` collection), `cost_tracking.PricedTracker` | `UsageService.record/check_and_record/reserve/commit_reservation`, quotas | Dual-write; budgets later via quotas |
| F-18 | Notifications | none (no e-mail, no webhooks in Nodestro) | `NotifyService` (templates, e-mail, mailbox, preferences) | New function (e.g. "run failed", "approval needed") |
| F-19 | Metrics, health | `server_app.DatabaseHealth`, `/api/health`; no metrics, no tracing | `axentra.observability` (`/metrics`, OpenTelemetry), DB pool metrics | New function |
| F-20 | Login/invalid-key rate limits | `serving._Window` (per process), proxy `limit_req` | DB-backed throttle (`IdentityService.throttle`, `axentra_rate_limits`) for logins | Library for logins; published API limits stay Nodestro |
| F-21 | Housekeeping (expired sessions, login states) | `IdentityStore.cleanup`, `worker.clean_up` | `IdentityService.purge_expired`, `axentra maintenance purge` | Library |

Functions that Axentra could take over but that are **not worth moving**: the document store (`PostgresStore`,
JSONB per `(tenant, collection, id)`) - Nodestro's workflows, runs and settings live there and Axentra's
`axentra_records` is not a better home for them (see NODESTRO_REUSE 3.7); the secret sanitizer
(`sanitize.py`, Axentra has its own `core/redaction.py`); the per-process rate window for published APIs.

## 2. Nodestro modules: disappear, become adapters, or stay

### 2.1 Disappear (replaced by Axentra) once the respective phase is complete

| Nodestro file / class | Replaced by | Phase |
| --- | --- | --- |
| `nodestro_api/identity.py`: `OidcClient`, `OidcSettings`, `secure_url`, `ALGORITHMS`, PKCE helpers | `axentra.identity.oidc.OidcClient/OidcService` | M5 |
| `nodestro_api/identity.py`: `safe_return_path` | `OidcService.safe_return_to` | M5 |
| `nodestro_runtime/identity_store.py`: session, login-state, user, tenant and membership SQL; `cleanup` | `IdentityService`, `TenancyService`, `purge_expired` | M5 (adapter first, removed in M12) |
| `nodestro_runtime/migrations/postgres/0003_identity.sql` tables (`nodestro_tenants`, `nodestro_users`, `nodestro_memberships`, `nodestro_sessions`, `nodestro_login_states`) | `axentra_tenants`, `axentra_users` + `axentra_user_identities`, `axentra_memberships`, `axentra_sessions`, `axentra_login_states` | frozen in M5, dropped in M12 |
| `nodestro_api/serving.py`: `new_key`, `hash_secret`, `secret_matches`, key part of `ServingCore.authenticate` | `ApiKeyService.create_key/authenticate` | M6 |
| `nodestro_api/api_keys.py`: `ApiKeys` storage in the `api_keys` document collection | `axentra_api_keys` + Nodestro grant table | M6 |
| `nodestro_runtime/server_settings.py`: `SecretBox` as the writer | `axentra.config.secrets.SecretBox` | M4 (legacy decrypt kept until M12) |
| `nodestro_runtime/storage_postgres.py`: `PostgresDatabase` pool and `migrate` | `axentra.data.database.Database`, `MigrationRunner` | M9 (runner), M10 (pool) |
| `nodestro_runtime/jobs.py`: `JobQueue`, `LeaderLock`, `ScheduleFirings`; tables `nodestro_jobs`, `nodestro_schedule_firings` | Axentra jobs module | M11 (only after G-8) |
| `nodestro_api/server_app.py`: `DatabaseHealth` | Axentra readiness check | M7 (optional) |

### 2.2 Become adapters (Nodestro interface kept, Axentra underneath)

Adapters keep Nodestro's call sites unchanged, which is what makes every phase reversible (section 8).

| Adapter (new Nodestro code) | Keeps this Nodestro interface | Calls |
| --- | --- | --- |
| `AxentraIdentityStore` | `IdentityStore` (`login`, `memberships`, `members`, `role`, `set_role`, `remove_member`, `create_session`, `session`, `end_session(s)`, `create/take_login_state`) | `IdentityService`, `TenancyService`, mapping tables |
| `AxentraSessionResolver` | `SessionResolver` -> Nodestro `Principal(id, tenant_id, role, permissions)` | `IdentityService.resolve_session` + `nodestro_session_tenants` + Nodestro `ROLE_PERMISSIONS` |
| `auth_router` (kept, thinned) | `/api/auth/login`, `/callback`, `/me`, `/switch`, `/logout`; cookies `__Host-nodestro-session`, `__Host-nodestro-login`; error codes `identity.*` | `OidcService.start/finish`, `AxentraIdentityStore` |
| `AxentraApiKeys` | `ApiKeys` (`create`, `list`, `revoke`, `rotate`, `delete`, `verify`) and `KeyIdentity` | `ApiKeyService` + `LegacyNdkVerifier` + `nodestro_api_key_grants` |
| `CompatSecretBox` | `SecretBox.encrypt/decrypt(tenant_id, name, ...)`, `is_encrypted` | `axentra SecretBox` for `axs1`, legacy decryptor for `nodestro:enc:v1:` |
| `AxentraBlobs` | `_Blobs.put/open/delete/__contains__` (input files) | `StorageService` (system principal, tenant scope) |
| `AuditBridge` | `tool_approvals.record_audit` | `AuditLog.record` (dual-write) |
| `UsageBridge` | `UsageLog.record` | `UsageService.record` (idempotency key = entry id) |
| `ErrorBridge` | Nodestro error JSON (`{"detail","code","params"}`), `NodestroError` | translates `AxentraError` subclasses (section 4.5) |
| `AxentraQueue` (M11 only) | `JobQueue`, `LeaderLock`, `ScheduleFirings` | Axentra jobs module |

### 2.3 Stay Nodestro-specific (never move to Axentra)

Workflows and workflow versions; runs, run manager, engine, flow driver, orchestrator and teams; agents, assistants,
architect; tools, tool library, tool approvals, pre-grants, tool policy and journal; sandbox (Docker-in-Docker,
gateway, policy); MCP client, server, OAuth and vault; knowledge (`nodestro_files`, `nodestro_chunks` with
`tsvector`, `PostgresIndex`, `nodestro_memory_files`); publications and the published-API business logic
(`ServingCore` minus key verification: limits, idempotency, SSE events); schedules and batches as product objects;
pricing (`pricing.py`, `pricing_sync.py`, `cost_tracking.py`); examples and library; file format detection
(`file_formats.py`) and file delivery to agents; the run event log until Axentra has event streams; the
document store (`nodestro_documents`); and the **desktop and local profiles** (SQLite, `launch.py`,
`local_access.py`, desktop vault key), which have no PostgreSQL and therefore never use Axentra.

## 3. Data migrations

### 3.1 Decisions

- **D-1 Same database, library mode.** Axentra's tables (`axentra_*`, namespace `axentra`) are created in
  Nodestro's PostgreSQL database next to `nodestro_*`. Nodestro uses Axentra as a library in its own `api` and
  `worker` processes. Not a separate Axentra service: that would add a network hop to every request (session
  resolution), a second deployment and distributed failure modes for no gain. Axentra's own `/v1` HTTP API is
  *not* mounted on Nodestro's public origin (it may be served on an internal admin origin for Axentra Studio, Q-7).
- **D-2 One product.** One Axentra product `nodestro` (slug `nodestro`); every Nodestro tenant becomes one Axentra
  tenant of that product. nodestro-server runs Axentra in `mode = "single"` (product created from configuration by
  `ax.start()`, ADR 0010). An installation that hosts Nodestro next to other Axentra products uses `mode = "multi"`;
  the adapter then takes the product id from `NODESTRO_AXENTRA_PRODUCT`. Not chosen: one Axentra product per
  Nodestro tenant (products are operator-level objects; it would multiply roles, plans and settings per tenant).
- **D-3 New Axentra ids plus mapping tables.** Axentra ids keep their format (`ten_`, `usr_`, `key_` + 26
  Crockford base32 characters, `core/ids.py`). Nodestro ids are kept unchanged in all `nodestro_*` product tables;
  a Nodestro-namespace table maps them. Not chosen: reusing Nodestro ids as Axentra primary keys (they do not match
  `is_id`, Axentra code derives display prefixes from id bodies, e.g. `access/api_keys._model`, and Nodestro tenant
  ids are operator-chosen names) and not chosen: rewriting `tenant_id` in `nodestro_documents`, `nodestro_files`,
  `nodestro_chunks`, `nodestro_jobs` (large rewrites of primary keys, and the ids appear in file paths under
  `<data_root>/tenants/<id>`).

  ```sql
  -- Nodestro namespace migration (illustrative)
  CREATE TABLE nodestro_axentra_ids (
      kind text NOT NULL CHECK (kind IN ('tenant', 'user', 'api_key')),
      nodestro_id text COLLATE "C" NOT NULL,
      axentra_id text NOT NULL,
      PRIMARY KEY (kind, nodestro_id),
      UNIQUE (kind, axentra_id)
  );
  ```
- **D-4 Roles.** Map to Axentra built-in roles where one fits, so Axentra's guards (last-owner guard keyed to
  `tenant_owner`, `tenancy/service._guard_last_tenant_owner`) apply; custom roles for the rest (section 3.4).
- **D-5 Hashes move, secrets do not.** Session-token and API-key hashes are copied (both systems use SHA-256 of
  the same kind of 256-bit token), so nobody is logged out and no published key changes. Encrypted values are
  re-encrypted, never decrypted into plain storage.

### 3.2 Table-by-table mapping

All copy statements run in the migration role with `SET LOCAL axentra.scope = 'platform'` (Axentra tables have
FORCE RLS; `axentra_scope_allows` refuses everything without a scope). They are idempotent (`ON CONFLICT DO
NOTHING` / upsert) so a backfill can be re-run.

| Nodestro table / collection | Axentra table | Mapping | Phase |
| --- | --- | --- | --- |
| (none) | `axentra_products` | one row, slug `nodestro`, created by `ax.start()` in single mode | M2 |
| `nodestro_tenants (id, name, created_at)` | `axentra_tenants (id, product_id, slug, name, status, settings, version)` | `id` = new `ten_...`; `slug` = Nodestro id normalized (below); `name`; `status='active'`; `settings` = `{"nodestro_id": <id>}`; mapping row `('tenant', id)` | M5 |
| `nodestro_users (id, issuer, subject, email, name, last_login_at)` | `axentra_users` + `axentra_user_identities` | user: new `usr_...`, `email` (see 3.3), `name` (or `''`), `password_hash NULL`, `last_login_at`; identity: `provider` = configured Axentra OIDC provider id whose `issuer` equals the row's `issuer`, `subject`; mapping row `('user', id)` | M5 |
| `nodestro_memberships (tenant_id, user_id, role)` | `axentra_memberships (id, product_id, tenant_id, user_id, role)` | new `mem_...`; ids through the mapping; role per 3.4 | M5 |
| `nodestro_sessions (token_hash bytea, user_id, tenant_id, created_at, last_seen_at, expires_at)` | `axentra_sessions (id, user_id, token_hash text, csrf_token, auth_method, ...)` + Nodestro `nodestro_session_tenants (session_id, tenant_id)` | `token_hash = encode(token_hash, 'hex')` (Nodestro: `sha256(token).digest()`, Axentra: `sha256(token).hexdigest()`, `identity/tokens.hash_token`); new `ses_...`; `csrf_token` random; `auth_method='oidc'`; times copied; active tenant in the Nodestro table | M5 |
| `nodestro_login_states` | `axentra_login_states` | **not migrated** (10-minute lifetime; drain: logins started during the switch get `identity.login_expired` once) | M5 |
| `nodestro_bootstrap_tokens` | none | stays Nodestro (gap G-5); unused tokens keep working through the Nodestro code path | - |
| documents `api_keys` (`ApiKey`: `id`, `name`, `secret_hash`, `scopes`, `publications`, `created_at`, `last_used_at`, `revoked_at`, `replaces`) | `axentra_api_keys` + Nodestro `nodestro_api_key_grants (key_id, publication_id)` | new `key_...`; `secret_hash` copied unchanged (both `sha256(secret).hexdigest()`); `tenant_id` = the tenant whose store held the key; `permissions` = mapped scopes (3.5); `replaces` through the mapping; mapping row `('api_key', <12-hex id>)`; publications into the grant table | M6 |
| documents `settings/app` fields `providers.<p>.api_key` (`nodestro:enc:v1:`) | stay in the document, value re-encrypted to `axs1.<kid>....` | section 3.6 | M4 |
| documents `usage_log` (`UsageEntry`) | `axentra_usage_events` (meters `ai.tokens.input`, `ai.tokens.output`, `ai.cost`) | `idempotency_key` = `nodestro:usage:<entry id>`; amounts as `Decimal`; history backfill optional (Q-9) | M3 |
| tool approval audit (documents, max 5000 per tenant) | `axentra_audit_events` | `action = 'nodestro.tool_approval.<kind>'`, `actor_kind` user/system, `details` = existing hashes only (`arguments_hash`, never arguments) | M3 |
| input files on disk `<data_root>/tenants/<id>/...` (`_Blobs`, content-addressed) | `axentra_files` + storage backend (local or S3) | copy per tenant, keep Nodestro's input metadata (documents) and store the Axentra file id beside the old blob id | M8 |
| `nodestro_jobs`, `nodestro_schedule_firings` | Axentra jobs tables (merged in PR #5) | **drain, do not copy** active jobs (section 7, M11); copy the latest firing slot per schedule so no slot fires twice | M11 |
| `nodestro_schema_migrations (version, name, applied_at)` | `axentra_schema_migrations (namespace='nodestro', version, name, checksum)` | one-off adoption: insert rows 1-6 with the checksums of the unchanged files | M9 |
| `nodestro_documents`, `nodestro_files`, `nodestro_chunks`, `nodestro_memory_files`, `nodestro_run_events` | none | stay; get RLS in M10 | - |

Tenant slug normalization: Nodestro ids match `[a-z0-9][a-z0-9_-]{0,62}` (`TENANT_ID`, `storage_postgres.py`);
Axentra slugs must match `^[a-z0-9][a-z0-9-]{1,62}$` (`0001_foundation.sql`). Ids with `_` or of length 1 do not
fit: replace `_` by `-`, pad single characters (`a` -> `a-0`), add `-2`, `-3` on collision. The slug is only a
label; `nodestro_axentra_ids` is authoritative. The migration report lists every changed slug.

### 3.3 Users and e-mail addresses

`nodestro_users.email` is nullable and filled only from `email_verified: true` claims; Axentra requires
`axentra_users.email NOT NULL` with a unique index on `lower(email)`, and `link_external_identity` refuses unknown
identities without a verified e-mail.

- Users with a verified e-mail: copied as is.
- Two Nodestro users (different issuers) with the same e-mail: **one** Axentra user with two
  `axentra_user_identities`. This matches Axentra's own rule (link by verified e-mail), but it merges memberships of
  two accounts; the migration report lists every merge and the operator confirms (Q-4).
- Users without e-mail: needs gap G-3 (nullable e-mail for external-only users in Axentra) or, as a stop-gap, a
  reserved placeholder `<nodestro user id>@users.invalid` (RFC 2606 `.invalid`) flagged in `preferences`. Q-3.
- The identity key stays `(issuer, subject)`: the migration needs one Axentra OIDC provider entry per distinct
  `issuer` in `nodestro_users`, with exactly that issuer string (Axentra checks the discovery issuer exactly).

### 3.4 Role mapping

Nodestro: `owner`, `admin`, `editor`, `operator`, `viewer` with permissions `read/edit/run/admin`
(`identity.ROLE_PERMISSIONS`); `install` belongs only to the installation's operator.

| Nodestro role | Nodestro permissions | Axentra role (key) | Kind | Axentra tenant permissions |
| --- | --- | --- | --- | --- |
| owner | read, edit, run, admin | `tenant_owner` | built-in | all tenant permissions; last-owner guard |
| admin | read, edit, run, admin | `tenant_admin` | built-in | all tenant permissions |
| editor | read, edit, run | `editor` | custom (product `nodestro`) | `tenant:read`, `members:read`, `files:read`, `files:write`, `usage:read`, `notify:preferences` (+ `nodestro.*` after G-1) |
| operator | read, run | `operator` | custom | `tenant:read`, `members:read`, `files:read`, `usage:read`, `notify:preferences` (+ `nodestro.*` after G-1) |
| viewer | read | `viewer` | built-in | `tenant:read`, `members:read`, `records:read`, `files:read`, `usage:read`, `billing:read` |
| (operator of the installation, `install`) | install | platform `platform_admin` or product `product_owner` | built-in | only for Axentra Studio; Nodestro keeps `install` local |

Rules: Nodestro's `ROLE_PERMISSIONS` is re-keyed to the Axentra role keys and stays the source of Nodestro's
`read/edit/run/admin` until G-1 exists; `/api/auth/me` keeps answering the Nodestro names (`owner` ... `viewer`) so
the studio does not change. Custom roles `editor` and `operator` do not collide with built-in keys (`member`,
`viewer`, `tenant_owner`, `tenant_admin`, `product_*`). After G-1, Nodestro registers product permissions
`nodestro.workflows:read|edit`, `nodestro.runs:start|read`, `nodestro.admin:manage`,
`nodestro.approvals:decide`, the custom roles carry them, and Nodestro asks `Authorizer.has(...)` instead of its own
map (so custom roles made in Axentra Studio take effect in Nodestro).

### 3.5 API keys: `ndk_` -> `axk_`

- Formats: Nodestro `ndk_<12 hex>_<43 char secret>` (`serving._TOKEN`); Axentra `axk_<26 char id body>_<43 char
  secret>` (`access/api_keys._KEY_RE`). Both store `sha256(secret).hexdigest()` of the secret part only, compared
  with `hmac.compare_digest`. The hash column can therefore be copied unchanged.
- New keys are `axk_` keys. Existing `ndk_` keys keep working through `LegacyNdkVerifier` in Nodestro's adapter:
  parse `ndk_<id>_<secret>`, look up `nodestro_axentra_ids('api_key', id)`, read the `axentra_api_keys` row (platform
  scope, like `ApiKeyService.authenticate`), compare the hash, apply revocation/expiry, build the same `Principal`.
  Axentra itself does not learn the `ndk_` format (rule 1 of NODESTRO_REUSE; Axentra's resolver only routes `axk_`
  tokens to API keys, everything else is treated as a session token).
- Scopes `run`, `read`, `approve` map to `nodestro.runs:start`, `nodestro.runs:read`, `nodestro.approvals:decide`
  after G-1. Until then the scopes and the publication list live in `nodestro_api_key_grants`, and the Axentra row
  carries a placeholder tenant permission (Q-6). Publication restriction always stays Nodestro (resource grants).
- Rotation creates an `axk_` successor (`replaces` set); `ndk_` keys are never minted again. A report lists the
  remaining legacy keys; after an announced date (Q-6) the legacy verifier is switched off by flag.
- `serving.safe_text` and `sanitize.py` must redact `axk_` tokens in addition to `ndk_`. The studio docs (six
  languages, `docs/chapters/*/api-und-export.md`) and the SDK examples (`published.py` docstring) mention `ndk_...`.
- Scale note: published workflow APIs are answered with 405 on the server profile today (RUNBOOK, "Not yet"), so
  `ndk_` keys exist only in desktop/local installations (SQLite), which do not move to Axentra. M6 matters only if
  published APIs ship on the server before the migration, or for a desktop-to-server import.

### 3.6 Encrypted secrets: `nodestro:enc:v1:` -> `axs1` with a legacy key id

- Nodestro v1: AES-256-GCM, key per tenant = HKDF-SHA256(`NODESTRO_SECRET_KEY`, info =
  `b"nodestro tenant secrets v1\0" + tenant_id`), AAD = `tenant_id \0 field`, token = prefix +
  `b64url(nonce || ciphertext || tag)`; no key id, no rotation (`server_settings.SecretBox`).
- Axentra: AES-256-GCM with the keyring key directly, AAD = `axs1|<kid>|<context>`, token =
  `axs1.<kid>.<nonce>.<ct>` (`config/secrets.SecretBox`).
- The two constructions are different, so the legacy key must **not** be added to Axentra's keyring as a normal
  key (that would also reuse one key in two constructions). Instead `CompatSecretBox` gives the legacy material the
  key id `ndv1`: `NODESTRO_SECRET_KEY` stays configured, read-only, under that id in Nodestro's adapter; tokens
  starting with `nodestro:enc:v1:` are decrypted by the legacy code path; everything else goes to Axentra.
- Context for new values (binds tenant and field, as v1's AAD did; record id added):
  `nodestro|tenant:<axentra tenant id>|settings/app|providers.<provider>.api_key`.
- Re-encryption: lazily on read (decrypt v1, write `axs1` in the same document update with `replace_if`) **and** a
  batch command `nodestro secrets reencrypt` (idempotent, resumable, reports counts). A value that cannot be
  decrypted stays untouched and is reported (today's behaviour treats it as "missing, enter again"; the batch must
  not destroy it).
- Retirement: when the batch reports zero `nodestro:enc:v1:` values in all tenants (documents and MCP token
  stores on the server profile), the `ndv1` path is disabled by flag and, one release later, removed and
  `NODESTRO_SECRET_KEY` deleted. From then on Nodestro rotates with the Axentra keyring (add key in front, restart,
  re-encrypt, remove old key). Gap G-6: Axentra's docstring names `axentra secrets reencrypt`, but the CLI has only
  `keys generate` at this commit, and Axentra cannot know Nodestro's document fields anyway; Nodestro registers its
  own re-encrypt task.

### 3.7 Id formats

| Object | Nodestro | Axentra | Kept where |
| --- | --- | --- | --- |
| tenant | operator-chosen `[a-z0-9][a-z0-9_-]{0,62}` | `ten_<26>` + slug | Nodestro id in all `nodestro_*` tables and file paths; mapping table |
| user | `u_<24 hex>` | `usr_<26>` | Nodestro id inside documents (run authors, approvals); mapping table |
| session | none (hash is the key) | `ses_<26>` | - |
| API key | `<12 hex>` | `key_<26>` | mapping table (needed by the legacy verifier) |
| job | `bigserial` | jobs module (open) | not copied |
| file | sha256 prefix (16 hex) | `fil_<26>` | Nodestro input metadata stores both |

Reads that resolve a Nodestro id go through one cached function per process (`nodestro_axentra_ids` is small and
append-only).

### 3.8 Introducing row-level security on Nodestro tables (M10)

Nodestro isolates tenants in code (store bound to a tenant, `tenant_id` in every query) without RLS. Axentra's
pattern is FORCE RLS with `axentra_scope_allows(product_id, tenant_id)`. Because Nodestro tables keep Nodestro
tenant ids (D-3), they get their own policy function that uses the same scope settings plus one Nodestro setting:

```sql
CREATE FUNCTION nodestro_scope_allows(t text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT CASE current_setting('axentra.scope', true)
        WHEN 'platform' THEN true
        WHEN 'product' THEN current_setting('axentra.product_id', true) = current_setting('nodestro.product_id', true)
        WHEN 'tenant' THEN t = current_setting('nodestro.tenant_id', true)
        ELSE false END
$$;
ALTER TABLE nodestro_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE nodestro_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON nodestro_documents USING (nodestro_scope_allows(tenant_id)) WITH CHECK (nodestro_scope_allows(tenant_id));
```

Preconditions and order: (1) role split - the runtime role is no longer the table owner and has no `BYPASSRLS`
(Axentra's `Database.check_role` refuses otherwise); migrations run as a separate owner role; (2) every Nodestro
transaction sets the scope (`axentra.scope`, `nodestro.tenant_id`) with `set_config(..., true)` - easiest once
Nodestro's store runs on Axentra's `Database` (M10 after the pool switch); (3) cross-tenant work uses platform
scope explicitly: worker claim, reaper, leader housekeeping, schedule firing, backups; (4) one table group per PR
(documents; knowledge tables; jobs/events), the full Nodestro test suite run under the non-owner role with FORCE
RLS; (5) kill switch: a prepared `ALTER TABLE ... NO FORCE ROW LEVEL SECURITY` script (metadata only, instant).

### 3.9 Sequencing with zero or low downtime

Nodestro serving processes refuse a schema that is not exactly theirs (`require_current_schema`,
`storage.schema_mismatch`) and the compose stack runs a one-shot `migrate` (with `pg_dump` backup) before `api`
and `worker`. Today an upgrade is therefore "stop, back up, migrate, start" (low downtime, minutes). Zero downtime
needs expand/contract migrations and a schema gate that accepts "schema at least N and at most the newest
migration this release knows" (gap G-2 on the Axentra side, a Nodestro change too). The plan works with both:

1. **Expand** (release N): additive migrations only (Axentra tables, mapping tables, mirror triggers). Old code
   ignores them.
2. **Backfill** (job, idempotent, resumable, platform scope), then **reconcile** (counts and per-row hashes of
   tenants, users, memberships, sessions; differences reported as metrics and in a report).
3. **Mirror**: `AFTER INSERT/UPDATE/DELETE` triggers on `nodestro_tenants`, `nodestro_users`, `nodestro_memberships`,
   `nodestro_sessions` write the Axentra rows in the **same transaction** (the trigger function sets
   `axentra.scope = 'platform'` transaction-locally and resets it at the end, or runs as `SECURITY DEFINER` owned by
   a dedicated sync role with `BYPASSRLS`; Q-8). Triggers, not application dual-writes, because Nodestro's and
   Axentra's pools are different connections and an application dual-write could not be atomic.
4. **Shadow read** (flag `shadow`): the adapter answers from Nodestro and compares with Axentra (mismatch counter,
   sampled log without secrets).
5. **Switch** (flag `primary`): reads and writes through Axentra; reverse triggers keep the Nodestro tables current
   for the rollback window. Rolling restart; sessions survive because the hash is the same.
6. **Contract** (release N+2 or later, after the rollback window): remove triggers and old code paths; rename old
   tables to `nodestro_legacy_*`; drop them one release later after a final backup.

## 4. Compatibility for existing users, workflows and APIs

### 4.1 Cookies and login flow

| Item | Nodestro today | After migration |
| --- | --- | --- |
| Session cookie | `__Host-nodestro-session`, `HttpOnly; Secure; SameSite=Lax; Path=/`, `Max-Age` 12 h | **unchanged name and attributes** (Nodestro's routes set it); value is the same token, now resolved by Axentra |
| Login cookie | `__Host-nodestro-login` (`state`, 10 min) | unchanged name; value from `OidcService.start` |
| Login routes | `GET /api/auth/login?return_to&tenant&setup`, `GET /api/auth/callback` (303 redirects, `no-store`) | unchanged paths; `setup` (bootstrap) stays a Nodestro path; `tenant` hint stays |
| Redirect URI at the provider | `.../api/auth/callback` | unchanged (Axentra's `/v1/auth/oidc/{provider}/callback` is not used on this origin), so no change at the identity provider |
| Tenant switch | `POST /api/auth/switch` issues a new session, ends the old one | adapter: `start_session` + revoke old + new `nodestro_session_tenants` row (session fixation protection kept) |
| `GET /api/auth/me` | `user_id, name, email, tenant_id, role, permissions, tenants` | same shape; `user_id` stays the **Nodestro** user id (via mapping) during the migration so stored references and the studio keep working (Q-5 for later) |
| CSRF | Origin check (`SameOriginMiddleware`), no token | unchanged on `/api`; Axentra's `x-axentra-csrf` header applies only to Axentra's own HTTP routes, which are not mounted there |
| Existing sessions | - | copied with the hash (3.2): **no forced re-login**. Fallback if Q-2 decides otherwise: one re-login, at most 12 h of sessions lost |

Behaviour differences to check in tests: Axentra compares session expiry and idle time with the application clock,
Nodestro with `clock_timestamp()` (DB clock); Axentra writes `last_seen_at` at most once a minute (same as
Nodestro). Axentra refuses unknown identities without verified e-mail and with `allow_signup=false` (Nodestro lets
anyone log in and then answers `identity.no_tenant`); the adapter must keep Nodestro's behaviour: provider
`allow_signup = true` for the Nodestro provider, access still requires a membership.

### 4.2 Workflows, runs and published APIs

Workflows, runs, schedules and published APIs keep their ids, documents and URLs; nothing in `nodestro_documents`
is rewritten. Published workflow API keys: `ndk_` keys keep working (legacy verifier), new keys are `axk_`.
`Authorization: Bearer` and `X-API-Key` both stay accepted (Axentra accepts both too). The invalid-key limiter,
`WWW-Authenticate: Bearer error="invalid_token"`, `Idempotency-Key` and the 404-for-everything rule stay in
`ServingCore`.

### 4.3 Studio (nodestro-studio frontend)

`api/access.ts` reads `/api/auth/me`; `api/client.ts` reads `detail`, `code`, `params` from error bodies and
starts a login on `401` with `code == "access.login_required"`. Both stay valid as long as Nodestro's routes keep
their error format (4.5). No frontend change is required for any step of section 7. If the studio ever calls Axentra `/v1`
directly, it needs the CSRF header and must read RFC 9457 bodies (`code` is present there too, but the values
differ: `unauthenticated` vs `access.login_required`).

### 4.4 SDK contracts (nodestro-sdk)

`python/tests/test_contract.py` requires the committed `openapi/nodestro-api.json` to equal both
`nodestro_api.openapi.text()` and the running server's `/api/openapi.json`. Rule for every migration PR: **no
OpenAPI diff** in nodestro-api unless intended and released with a new SDK. Strings that change (an `ApiKeyOut.prefix`
of `axk_...` for new keys) are not schema changes, but the SDK docstring example and tests that use `ndk_test`
should accept both prefixes.

### 4.5 Error format differences

| | Nodestro `/api` | Nodestro published API | Axentra `/v1` |
| --- | --- | --- | --- |
| Body | `{"detail", "code", "params"}` (`api._error`) | `{"error": {"status","code","message","params"}}` | RFC 9457 `application/problem+json` with `type, title, status, detail, code, request_id` + extras |
| Codes | dotted (`access.login_required`, `identity.not_a_member`, `storage.*`) | dotted | flat (`unauthenticated`, `forbidden`, `not_found`, `validation_failed`, `conflict`, `rate_limited`, ...) |
| Exception base | `NodestroError(ValueError)` -> 400; `ValueError` -> 400; `KeyError` -> 404 | `ApiError` | `AxentraError` (not a `ValueError`) |

Consequence: an `AxentraError` escaping into a Nodestro route would become a 500 (Nodestro has no handler for it).
`ErrorBridge` translates at the adapter boundary: `Unauthenticated` -> `access.login_required` (401),
`Forbidden` -> `access.forbidden` (403), `NotFound` -> the Nodestro resource code (404, same answer for foreign and
unknown), `ValidationFailed` (422) -> Nodestro `bad_request`/specific code with **400** (studio and SDK expect
400), `Conflict` -> 409, `RateLimited` -> 429 with `Retry-After`, `QuotaExceeded` -> a new `usage.quota_exceeded`
code (new texts in all six languages, `quality.test.ts` checks this). A test asserts that every Axentra error
class has a mapping.

### 4.6 Feature flags and dual read

One flag per function, read at start-up (Nodestro settings are immutable per process; a flag change is a rolling
restart):

| Flag | Values | Default in the first release with the code |
| --- | --- | --- |
| `NODESTRO_AXENTRA_AUDIT`, `NODESTRO_AXENTRA_USAGE` | `off`, `dual` | `off` |
| `NODESTRO_AXENTRA_SECRETS` | `off`, `write_axs1`, `only_axs1` | `off` |
| `NODESTRO_AXENTRA_IDENTITY` | `off`, `shadow`, `primary`, `only` | `off` |
| `NODESTRO_AXENTRA_API_KEYS` | `off`, `shadow`, `primary`, `only`; `NODESTRO_LEGACY_NDK_KEYS=on/off` | `off`, `on` |
| `NODESTRO_AXENTRA_FILES` | `off`, `write_both`, `read_axentra_first`, `only` | `off` |
| `NODESTRO_AXENTRA_JOBS` | `off`, `primary` (switch only with a drained queue) | `off` |

`shadow` = serve from Nodestro, compare with Axentra; `primary` = serve from Axentra with reverse mirror;
`only` = mirror removed (point of no easy return). Each flag value is logged at start-up and exported as a metric so operators see the state.

## 5. Version pins

### 5.1 How Nodestro pins today

- Python dependencies between components are `git+https://github.com/peterkarlhuber/<repo>.git@<40-char SHA>`
  (e.g. nodestro-api -> nodestro-runtime `ac96c6f7...`, nodestro-runtime -> orkexa `34679404...`).
- `nodestro-studio/platform/versions.json` lists `platform` version, every component with `commit`, `version`,
  `pyproject` path and `studio_dependency`, and the released products (`nodestro-desktop`, `nodestro-server`) with
  their studio commit.
- `nodestro-studio/scripts/check_versions.py` (Makefile `check-versions`, `platform-local`; workflow
  `.github/workflows/platform.yml`) checks: full SHAs only; every `git+https://github.com/peterkarlhuber/...`
  reference in the studio and in each component's pyproject (at the pinned commit) names the `versions.json`
  commit; each component's `project.version` equals `versions.json`; every `studio_dependency` component is pinned
  by the studio.
- `nodestro-server/studio.json` pins the studio commit the image is built from; the image copies
  `platform/versions.json` into `/opt/nodestro/meta/`; `nodestro-local-docker/scripts/check-pins.sh` checks its own
  `components.json` and runs the studio's `check_versions.py`.

### 5.2 Adding Axentra as a pinned dependency

- Pyproject: `axentra[oidc] @ git+https://github.com/peterkarlhuber/axentra.git@<sha>` as an **optional extra**
  (`server`/`postgres`) of nodestro-runtime (database, secrets, usage, audit, storage) and nodestro-api (identity,
  OIDC), so the desktop bundle never contains it. `axentra[s3]` only if the server uses S3. Axentra's `server`
  extra (FastAPI app) is not needed unless `/v1` is mounted (Q-7). Note: Axentra's core pulls `argon2-cffi`
  (password hashing) even though Nodestro has no passwords.
- `versions.json`: `"axentra": {"commit": "<sha>", "version": "<x.y.z>", "pyproject": "pyproject.toml",
  "studio_dependency": true}` (true because the studio installs nodestro-api's server extra; if the studio pins
  only through nodestro-api, set false).
- `check_versions.py` works for Axentra with one caveat: Axentra uses `dynamic = ["version"]` (hatch, from
  `src/axentra/_version.py`), so `project.version` is `None` and a `version` entry would fail the check. Either omit
  `version` for axentra (the script then skips the comparison) or teach the script to read `_version.py` (preferred,
  Q-10). Its `REFERENCE` pattern already matches `peterkarlhuber/axentra`.
- One Axentra commit per platform version: runtime, api and studio must name the same SHA (enforced by the script).

### 5.3 Update order for an Axentra bump

1. Axentra: release commit on `master`, CI green, `CHANGELOG.md` lists library-API changes; a "consumers" row in
   Nodestro's compatibility matrix is prepared (Axentra's own `docs/COMPATIBILITY.md` stays about Axentra Studio).
2. nodestro-runtime: bump the axentra pin; run its full suite (PostgreSQL 17) + adapter contract tests.
3. nodestro-api: bump runtime **and** axentra pins (same Axentra SHA); full suite; OpenAPI unchanged.
4. nodestro-studio: bump all pins and `platform/versions.json` (platform minor bump); `make check-versions`.
5. nodestro-server: `studio.json` -> new studio commit; image build; e2e acceptance; migration rehearsal on a copy
   of production data (section 8).
6. nodestro-local-docker / nodestro-desktop: check only that they still build without Axentra (no pin change).

An Axentra migration that changes `axentra_*` tables is announced in the Axentra changelog; Nodestro's `migrate`
applies it with its backup step. Axentra is pre-1.0 (minor releases may break, VERSIONING.md), so Nodestro pins
exact SHAs and its adapter contract tests are the safety net (Q-11: Axentra library API stability promise before
M5).

### 5.4 Compatibility matrix (to be kept in nodestro-studio `platform/`)

| Nodestro platform | runtime / api commits | Axentra version @ commit | Axentra schema (`axentra` namespace) | Nodestro schema | Python | PostgreSQL | Flags state | Tested | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.2.0 (today) | `ac96c6f7` / `4e2c8cdc` | - | - | 6 | 3.10, 3.13 | 17 | - | - | current |
| next (M1) | tbd | 0.x @ tbd | 0005 or newer | 6 | 3.11, 3.12, 3.13 | 16, 17 | all `off` | tbd | planned |

A row is added only after the full Nodestro and Axentra suites and the server e2e ran on that combination.

### 5.5 Python version alignment

Axentra: `requires-python >= 3.11`, CI 3.11/3.12/3.13 (ADR 0002). Nodestro runtime, api, studio and sdk:
`>= 3.10`, CI 3.10 and 3.13; production images 3.13. Python 3.10 reached end of life in October 2026, and
Nodestro's MCP dependency already requires 3.11 (`mcp>=2.3; python_version >= '3.11'`). Step M1: raise
`requires-python` to `>= 3.11` in nodestro-runtime, nodestro-api and nodestro-studio (CI matrix 3.11, 3.12, 3.13;
ruff `target-version = "py311"`, mypy `python_version = "3.11"`; drop the `tomli` fallback in
`check_versions.py`; drop the MCP marker). nodestro-sdk does not depend on Axentra and may keep 3.10 for clients,
but should follow for the same EOL reason (Q-12). The desktop bundle (CPython 3.13) is unaffected.

## 6. Regression tests

### 6.1 Existing suites that must stay green in every phase

- nodestro-runtime: `test_identity_store.py`, `test_storage_postgres.py`, `test_postgres_pool.py`,
  `test_storage_contract.py`, `test_jobs.py`, `test_server_settings.py`, `test_tenant_workspace.py`,
  `test_mcp_tenants.py`, `test_run_fencing.py`, `test_reliability.py`, `test_sanitize.py`, `test_architecture.py`,
  `test_damaged_documents_postgres.py`, `test_replace_if_postgres.py`, `test_postgres_import.py`, all tool-approval
  suites (`test_tool_approval_audit.py` in particular), plus the rest of the suite.
- nodestro-api: `test_identity.py` (with `stub_oidc.py`), `test_permissions.py`, `test_hardening.py`,
  `test_published_api.py`, `test_published_release.py`, `test_worker.py`, `test_server.py`,
  `test_server_command.py`, `test_files.py`, `test_inputs.py`, `test_tool_approvals_api.py`, plus the rest; the
  committed `openapi/nodestro-api.json` check.
- nodestro-server: `tests/e2e/test_acceptance.py` (refuses incomplete config, OIDC login through Dex, wrong password
  gets no session, cross-origin refused, tenant isolation, worker killed mid-run, backup and restore).
- nodestro-studio: frontend unit tests (`api/access.test.tsx`, `api/client.test.ts`, `api/isolation.test.ts`,
  `i18n/quality.test.ts`), e2e scripts (`smoke`, `journeys`, `i18n`, `a11y`, `api`), `check_versions.py`.
- nodestro-sdk: `python/tests/test_contract.py`, `test_http.py`, `test_client.py`; TypeScript `test/*.test.ts`.
- Axentra: its full suite (unchanged by this plan), including `tests/unit/test_architecture.py`, which guarantees
  that Axentra never imports Nodestro.

### 6.2 New tests per area

| Area | New tests |
| --- | --- |
| Adapter contract | Nodestro's identity-store, API-key and secret-box tests parametrized over legacy and Axentra adapters (pattern of `test_storage_contract.py`); every public method of the old class covered |
| Backfill and mirror | idempotent re-run; counts and hashes equal after backfill; trigger mirror in the same transaction (rollback of the Nodestro write leaves no Axentra row); concurrent writes during backfill; slug normalization and collisions; e-mail merge and placeholder cases |
| Sessions | a cookie issued before the switch is accepted after it (hash `bytea` -> hex); expiry and idle limits identical; removed member loses access on the next request; tenant switch rotates the token; logout everywhere |
| OIDC | the full `test_identity.py` attack set against the Axentra-backed router: state single use, login CSRF from another browser, tampered `iss/aud/exp/nonce/azp`, `alg=none`/HS256, unverified e-mail, `return_to` open-redirect cases, bootstrap once and race |
| Roles | permission matrix per Nodestro role before and after mapping is identical; last-owner guard through `tenant_owner`; custom roles `editor`/`operator` grant no admin rights |
| API keys | `ndk_` and `axk_` both accepted; revoked/expired refused at once; rotation of an `ndk_` key yields `axk_`; legacy flag off refuses `ndk_`; scopes and publication grants; tenant isolation; invalid-key limiter; both prefixes redacted in logs and errors |
| Secrets | v1 decrypt, lazy re-encrypt, batch re-encrypt idempotent and resumable, unreadable value untouched and reported, tenant/field binding (a value copied to another tenant or field fails), keyring rotation after retirement |
| Errors | every `AxentraError` class mapped; no 500 from an Axentra error; status codes the studio and SDK expect |
| Usage and audit | duplicate usage entries ignored (idempotency key); `Decimal` amounts; audit rows carry no arguments or secrets; audit in the same transaction where the adapter shares a connection |
| Files | copy per tenant, SHA-256 verified; read Axentra first with disk fallback; quotas; content types Nodestro accepts (`.html`, `.js`, `.sh`, `.php`, `.ps1`, `.bat` are blocked by Axentra storage today, gap G-7); download only as attachment |
| Jobs (M11) | at most one active job per `(tenant, kind, ref)`; no retry after lease loss (run marked interrupted); cancel queued/running; one leader; each schedule slot once across the switch; drain procedure |
| RLS (M10) | every Nodestro table refuses cross-tenant reads with a forged query under the runtime role; worker and housekeeping in platform scope; the whole Nodestro suite under a non-owner role |
| Pins | `check_versions.py` with the axentra entry; image contains `versions.json` with axentra; desktop build contains no axentra |
| Rollback | each flag switched back (`primary` -> `shadow` -> `off`) with live traffic in a staging copy; restore from the pre-step backup |
| Performance | session resolution latency (p50/p99) before/after; connections per process (two pools until M10) below `max_connections` |

### 6.3 Security re-review (each phase ends with one)

Threat model update for the changed boundary; review of: session fixation and token handling (hash copy, tenant
switch), login CSRF and redirect handling, RLS scope settings (no leakage across pooled connections: only
`set_config(..., true)`), trigger functions (`SECURITY DEFINER` search_path pinned), mapping-table integrity, legacy
key path (timing, enumeration, rate limit), key material handling (`NODESTRO_SECRET_KEY` and Axentra keyring both
present only during the window), file content-type policy, error translation (no existence oracle introduced),
logs and audit redaction (`axk_`, `ndk_`, `axs1.` values), dependency audit of the new dependency tree
(`pip-audit`), and the secret scan of release artifacts (`scan_secrets.py` extended with `axk_`).

## 7. Recommended order of switching functions

Every step is its own PR set (Axentra prerequisite PRs, Nodestro adapter PR, migration PR, flag flip), each closed
by a regression and security phase (section 6) and a backup. Prerequisites are generic Axentra features; they are
useful without Nodestro and are tracked like any other Axentra work.

| Step | Scope | Depends on | Risk | Effort |
| --- | --- | --- | --- | --- |
| P | Axentra prerequisites G-1 ... G-8 (section 9), each a normal Axentra PR | - | low for Axentra | M (sum) |
| M1 | Python >= 3.11 in Nodestro; axentra pinned as optional extra; `versions.json`/`check_versions.py`; nothing used | P (G-2 not needed) | low | S |
| M2 | Axentra schema next to Nodestro's: `migrate` runs Nodestro's runner, then Axentra's (one backup before both); product `nodestro` created; `ax.start()` in api/worker; role split owner/runtime | M1 | low | S |
| M3 | Audit and usage dual-write (append-only, idempotent, no reads on hot paths) | M2 | low | S |
| M4 | Secrets: `CompatSecretBox`, new writes `axs1`, lazy + batch re-encrypt, then retire v1 (gives Nodestro key rotation) | M2, G-6 | medium | M |
| M5 | Identity and tenancy: mapping tables, backfill, mirror triggers, shadow, switch, OIDC client swap; bootstrap stays | M2, G-1 (optional), G-3, G-5 decision | high | L |
| M6 | API keys: `axk_` for new keys, legacy `ndk_` verifier, grants table (only if published APIs exist on the server) | M5 | medium | M |
| M7 | Notifications (new: run failed, approval needed) and metrics/tracing; optional readiness check | M5 | low | S/M |
| M8 | Files: input files to Axentra storage (removes the shared data volume between api and worker) | M5, G-7 | medium | M/L |
| M9 | Migration runner unification: Nodestro migrations as namespace `nodestro` in `MigrationRunner`, adoption of versions 1-6 | M2, G-2 | medium | M |
| M10 | Pool unification (Nodestro store on `axentra.data.Database`) and RLS on `nodestro_*` tables | M9 | high | L |
| M11 | Jobs, leader lock, schedules: switch with a drained queue | G-8, M10 | high | L |
| M12 | Contract: remove mirrors, legacy tables, legacy decrypt, legacy `ndk_` path (announced), old code | all, rollback windows passed | medium | M |

Why this order: append-only writes first (nothing can be read wrong); secrets next because the value is high
(rotation) and the blast radius is one field type; identity is the largest step but has the best existing test
corpus; jobs last because they carry side effects and cost (a duplicate or lost run is visible to customers) and
Axentra's jobs module does not exist yet. M7 (notifications/metrics) is additive and can move earlier.

## 8. Rollback and parallel operation

- **Strangler pattern.** Nodestro's interfaces (`IdentityStore`, `SessionResolver`, `ApiKeys`, `SecretBox`,
  `_Blobs`, `JobQueue`) stay; implementations are swapped behind them, chosen by flag at start-up. The old
  implementation stays in the code until M12.
- **Dual-write windows.** Identity: triggers both ways (Nodestro -> Axentra before the switch, Axentra -> Nodestro
  after it) for at least one release after `primary`. Audit/usage: dual-write is permanent until reads move.
  Files: write both until Axentra storage is primary and verified. Jobs: no dual-write (a job must never run twice);
  drain instead: stop enqueue (maintenance flag), wait for running jobs (lease 60 s, `max_runs`), switch, resume.
- **Backups before each step.** `nodestro-api migrate --backup-dir` (`pg_dump --format=custom`) before every
  migration; additionally a snapshot of the data volume before M8 (files); rehearsal of every step on a restored copy of
  production with the reconciliation report; restore tested (`test_acceptance.py` backup/restore and Axentra's
  `docs/operations/BACKUP_RESTORE.md`).
- **Kill switches.** Flags back to `off`/`shadow` (rolling restart); legacy `ndk_` flag; `NO FORCE ROW LEVEL
  SECURITY` script per table group; mirror triggers can be disabled with `ALTER TABLE ... DISABLE TRIGGER`.
- **Forward-only schema.** Neither runner has down-migrations; rollback is "flag back" (schema stays, expand-only)
  or, as last resort, restore from the pre-step backup with a documented data-loss window (writes since the
  backup). Contract migrations (drops) happen only after the rollback window.
- **Observability of the parallel run.** Mismatch counters (shadow reads), mirror lag/drift (reconciliation job),
  legacy usage counters (`ndk_` logins, `nodestro:enc:v1:` decrypts), flag state metric.

## 9. Gaps in Axentra that the migration needs (all generic)

Status as of 2026-11-02; see also [EMBEDDING](../architecture/EMBEDDING.md).

| Id | Gap | Why Nodestro needs it | Effort | Status |
| --- | --- | --- | --- | --- |
| G-1 | Product-registered permissions (e.g. `nodestro.runs:start`) usable in custom roles and API keys | Nodestro's `read/edit/run/admin` and key scopes as real Axentra permissions | M | Done: `ax.permissions.register(...)`, HTTP declaration with `permissions:manage`, migration `0008`; see SECURITY_MODEL.md "Product-defined permissions" |
| G-2 | Migration runner: pre-migration backup hook, "schema too new" refusal, a serving gate (`require_current_schema` equivalent with a compatible range), optional non-transactional steps | Nodestro's runner has these; unification (M9) must not lose them | M | Done except a declared compatible range: `before_apply` hook, refusal of a newer schema (`allow_newer`), `require_current`/`database.require_current_schema` gate, `-- axentra:no-transaction` steps, `axentra migrate --check` |
| G-3 | Users without e-mail (external identity only) | Nodestro users without verified e-mail | S/M | Done: migration `0007`, `allow_signup_without_email`, `link_by_verified_email`, `create_external_user`/`link_identity` |
| G-4 | Provider-level option "login allowed without membership, access decided by product" (or keep `allow_signup=true`) and DB-clock comparisons for sessions | Same login semantics as Nodestro | S | Done: login never required membership; session, setup-token and invitation expiry on the DB clock |
| G-5 | "Claim an ownerless tenant" one-time token (tenant bootstrap), or accept it stays Nodestro | Nodestro's bootstrap links | S | Open |
| G-6 | Re-encryption task registry (`axentra secrets reencrypt` with product-registered fields); the CLI command named in `config/secrets.py` does not exist yet | Nodestro's encrypted document fields | S | Done for columns (`axentra secrets reencrypt`, `register_encrypted_column`); no hook for legacy formats or JSON fields |
| G-7 | Per-product content-type policy in storage (store code/HTML as inert attachments instead of refusing) | Nodestro accepts `.html`, `.js`, `.sh`, `.php`, `.ps1`, `.bat` inputs (`file_formats.CODE_EXTENSIONS`) | S | Done: `settings.storage.blocked_types = "store_inert"` or `inert_extensions` per product, `GET`/`PUT /v1/products/{pid}/storage/policy`; see modules/STORAGE.md |
| G-8 | Jobs module with Nodestro's semantics: unique active job per `(tenant, kind, ref)`, "never retry, interrupt on lease loss", lease fencing, cancel request, leader lock, idempotent schedule slots, event streams | M11 | L (planned anyway, P0 in TODO) | Jobs module exists; semantics differ on several points |

## 10. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| R-1 | Users logged out or locked out at the identity switch | medium | high | hash copy (no re-login), shadow phase, reverse mirror, flag back; announce a possible single re-login |
| R-2 | Wrong tenant/role mapping grants too much | low | critical | permission-matrix test before/after, reconciliation report, security re-review, custom roles with minimal Axentra permissions |
| R-3 | Account merge by e-mail joins two different people | low | high | report and operator confirmation (Q-4), no automatic merge without it |
| R-4 | Loss of tenant secrets during re-encryption | low | high | never overwrite unreadable values, backup, `ndv1` path kept until zero v1 values |
| R-5 | Published `ndk_` keys stop working | low | high | legacy verifier, hash copy, contract tests, legacy flag default `on` |
| R-6 | Mirror drift between `nodestro_*` and `axentra_*` | medium | medium | same-transaction triggers, reconciliation job and metrics, idempotent backfill |
| R-7 | RLS breaks cross-tenant jobs (worker claim, reaper, housekeeping) | medium | high | explicit platform scope, full suite under non-owner role, `NO FORCE` kill switch |
| R-8 | Duplicate or lost runs at the jobs switch | medium | critical | drain, no dual-write, lease fencing tests, last slot per schedule copied |
| R-9 | Axentra pre-1.0 breaking change in the library API | medium | medium | SHA pins, adapter contract tests, Q-11 stability promise, one Axentra SHA per platform |
| R-10 | Connection exhaustion (two pools per process until M10) | medium | medium | size `pool_max` x processes, metrics, M10 merges pools |
| R-11 | AxentraError surfaces as 500 / codes change for studio and SDK | medium | medium | `ErrorBridge` with completeness test, no OpenAPI diff rule |
| R-12 | Storage refuses Nodestro input types | high (today) | medium | G-7 before M8, file-type regression tests |
| R-13 | Longer upgrade downtime (two runners, backfill) | medium | low | backfill as online job, expand-only migrations, rehearsal timing |
| R-14 | Python 3.11 bump breaks users on 3.10 | low | low | 3.10 is EOL; release note; SDK may lag (Q-12) |
| R-15 | Scope creep: Nodestro product work blocked by migration | medium | medium | separate project, every step optional and stoppable after M3/M4 with value delivered |

## 11. Effort summary

| Block | Effort |
| --- | --- |
| Axentra prerequisites G-1 ... G-7 | M (each S/M) |
| G-8 jobs/events module | L (part of Axentra's own roadmap) |
| M1 + M2 + M3 | S each |
| M4 secrets | M |
| M5 identity and tenancy | L |
| M6 API keys | M |
| M7 notifications, metrics | S/M |
| M8 files | M/L |
| M9 runner, M10 pool + RLS | M, L |
| M11 jobs | L |
| M12 contract/cleanup | M |

S = up to a few days, M = one to two weeks, L = several weeks, each including tests, review and the security phase.

## 12. Open questions for Peter

1. **Q-1** Is Nodestro going to adopt Axentra at all, and which profile (server only, as assumed here)?
2. **Q-2** Copy sessions at the identity switch (no re-login, recommended) or accept one forced re-login?
3. **Q-3** Users without verified e-mail: add G-3 to Axentra (recommended) or use `@users.invalid` placeholders?
4. **Q-4** May users of different issuers with the same verified e-mail be merged into one Axentra user?
5. **Q-5** Should `/api/auth/me` eventually expose Axentra user and tenant ids, or keep Nodestro ids for good?
6. **Q-6** Deadline for legacy `ndk_` keys, and until G-1: which placeholder Axentra permission do Nodestro keys carry?
7. **Q-7** Should Axentra's `/v1` API and Axentra Studio be available for Nodestro operators (separate internal
   origin), or is Axentra purely a library inside Nodestro?
8. **Q-8** Mirror triggers: transaction-local scope switch inside the trigger, or a `SECURITY DEFINER` function owned
   by a sync role with `BYPASSRLS`?
9. **Q-9** Backfill historic usage entries into Axentra, or start metering from the switch date?
10. **Q-10** Should Axentra move to a static `project.version`, or should `check_versions.py` read `_version.py`?
11. **Q-11** Will Axentra declare a stable library API subset (or reach 1.0) before Nodestro starts M5?
12. **Q-12** Does nodestro-sdk keep Python 3.10 support for clients after the platform moves to 3.11?
13. **Q-13** Should tenant bootstrap become an Axentra feature (G-5) or stay Nodestro-only?
14. **Q-14** Is zero downtime a requirement (needs expand/contract and a relaxed schema gate), or is the current
    "stop, back up, migrate, start" acceptable for the switch releases?

## 13. Summary of recommendations

1. Treat the migration as an optional, separate project; Axentra continues without it.
2. Library mode in the same database, one product `nodestro`, Nodestro tenants as Axentra tenants, new Axentra ids
   with mapping tables, Nodestro product tables untouched.
3. Keep every external contract of Nodestro (cookies, `/api/auth/*`, error format, OpenAPI, `ndk_` keys) and put
   Axentra behind adapters with per-function flags.
4. Start with append-only functions (audit, usage), then secrets (key rotation), then identity; jobs last and only
   after Axentra's jobs module exists with Nodestro's "never retry side effects" semantics.
5. Close the generic Axentra gaps G-1 ... G-8 first; they benefit every Axentra product.
6. Each step: backup, rehearsal on a production copy, shadow/compare, switch, rollback window, then contract.
