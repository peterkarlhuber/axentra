# Nodestro reuse analysis for Axentra

Status: analysis (read-only), 2026-11-01. Author: Claude (on behalf of the Axentra project).

## 1. Purpose and rules

Axentra is a new, independent, generic and modular SaaS backend foundation in Python (identity, access/RBAC, API
keys, tenancy, data/PostgreSQL, storage, jobs/events/webhooks, config/secrets, usage, billing, notify,
audit/observability, search/realtime). This document records which parts of the Nodestro repositories are worth
porting, which are worth only as a design reference, and which should not be taken over.

The analysis is based on the code, tests, SQL migrations, CI workflows and ADRs at the commits listed in section 2,
not only on READMEs. Line numbers refer to those commits.

Rules that apply to everything below:

1. **No runtime dependency.** Axentra never imports, installs, pins or calls `nodestro-*` or `orkexa` packages,
   images, Git URLs or services. Everything Axentra takes over is copied in, renamed (`nodestro_*` tables,
   `NODESTRO_*` variables, `ndk_` prefix, `__Host-nodestro-*` cookies, `nodestro:enc:v1:` envelope, the
   `NodestroError` class, and so on) and owned by Axentra from then on.
2. **License.** Every examined repository is MIT licensed with the line `Copyright (c) 2026 Peter Karlhuber`
   (`LICENSE` in each repository; `orkexa/LICENSE` has the same line). MIT allows copying and adapting as long as
   the copyright notice and the permission notice are kept.
3. **Attribution policy.** A file of Axentra that contains code ported (copied or adapted) from Nodestro starts with:

   ```python
   # Portions adapted from <repo>/<path> at <full commit sha>,
   # Copyright (c) 2026 Peter Karlhuber, MIT License.
   ```

   for example `# Portions adapted from nodestro-runtime/src/nodestro_runtime/jobs.py at
   a42b6724702821849af478ee9dd0bfa13617e28b, Copyright (c) 2026 Peter Karlhuber, MIT License.` Axentra's
   repository additionally keeps a `THIRD_PARTY_NOTICES` (or `PROVENANCE.md`) entry listing each ported file with the
   source path and SHA, plus the full MIT text of the Nodestro copyright holder. Components marked "Concept only"
   carry no header (no code is copied), but the design reference may be named in the ADR/docs.
4. **Decisions** use four values: **Adopt** (port nearly verbatim, renaming only), **Adapt** (port with
   structural changes), **Concept only** (reimplement the idea, copy no code), **Do not adopt**.

## 2. Examined repositories

All repositories were checked out at their default branch `master` (the working branch
`claude/project-thread-wj7vfx` points at the same commit as `origin/master` in every repository; nothing was
modified).

| Repository | Examined commit (HEAD = origin/master) | Python | License / holder |
| --- | --- | --- | --- |
| nodestro-api | `e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea` | `>=3.10`, CI 3.10 + 3.13 | MIT, Peter Karlhuber |
| nodestro-runtime | `a42b6724702821849af478ee9dd0bfa13617e28b` | `>=3.10`, CI 3.10 + 3.13 | MIT, Peter Karlhuber |
| nodestro-server | `42e95af25ad20466c4b78211272eeefd45b2c57b` | image Python 3.13 | MIT, Peter Karlhuber |
| nodestro-sdk | `05080f69ee8337c3043167e2ef9b694b61370b27` | `>=3.10`, CI 3.10 + 3.13; Node 20 + 22 | MIT, Peter Karlhuber |
| nodestro-studio | `8e18caecea17b2fab5a837359a324896b565c313` | `>=3.10`, CI 3.10 + 3.13 | MIT, Peter Karlhuber |
| nodestro-local-docker (glance) | `b98df28a22cde11634ec903e653cfb51f649f665` | image Python 3.13 | MIT, Peter Karlhuber |
| nodestro-desktop (glance) | `80df14d0a1b9a534ac6873b67aa9a6f3539b49eb` | bundled CPython 3.13 | MIT, Peter Karlhuber |
| orkexa (dependency only, not a source) | `34679404e42dd0ae8eecfe53be21180450be5923` | - | MIT, Peter Karlhuber |

Note on pins: nodestro-api pins nodestro-runtime at `ac96c6f76f2042592ed9b3df73316ec5a0467c5b`
(`nodestro-api/pyproject.toml`), and nodestro-studio pins nodestro-api at `4e2c8cdc...`; the analysis uses the
newer HEADs above. Ported code must cite the HEAD SHA it was actually copied from.

Architecture records used: `nodestro-studio/docs/adr/0001-operating-profiles.md`, `0002-storage-backends.md`,
`0003-identity-and-tenants.md`, `0004-jobs-workers-scheduler.md` (plus 0005-0007 for context).

General observation: Nodestro's server-side "platform" code is unusually well isolated and tested, but it is
written for one product (workflow runs). Its generic parts sit next to product types (`Run`, `RunEvent`,
`RunManager`, `Workspace`, orkexa `FileStore`/`Index`). The generic mechanisms below can be lifted; the product
coupling must be cut at every port.

---

## 3. Components

### 3.1 OpenID Connect login (authorization code + PKCE, state, nonce, login CSRF binding)

- **Source repo and file:** `nodestro-api/src/nodestro_api/identity.py` (`OidcSettings` L102-113, `OidcClient`
  L116-252, `auth_router` L422-525, `safe_return_path` L90-96, `secure_url` L80-83, `ALGORITHMS` L65). Tests:
  `nodestro-api/tests/test_identity.py`, stub provider `nodestro-api/tests/stub_oidc.py`.
- **Examined commit SHA:** `e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea`.
- **Current responsibility:** Browser login against an operator-provided OIDC provider. `/api/auth/login` creates
  a PKCE verifier (`secrets.token_urlsafe(48)`), a nonce (`token_urlsafe(24)`) and a server-side login state, sets
  the `__Host-nodestro-login` cookie holding the `state` and redirects (303, `Cache-Control: no-store`).
  `/api/auth/callback` consumes the state once (`take_login_state`), checks the cookie with
  `secrets.compare_digest` (L460), exchanges the code with `client_secret_basic` + `code_verifier`, verifies the ID
  token and creates a session. Also `/me`, `/switch` (tenant switch issues a new session and ends the old one,
  L503-514) and `/logout`.
- **Dependencies:** direct: FastAPI/Starlette, `httpx` (no redirects followed, 10 s timeout), `PyJWT[crypto]`
  (`PyJWKSet`). Nodestro-specific: `nodestro_runtime.identity_store.IdentityStore`, `NodestroError`, `TENANT_ID`
  regex, `Principal`/`PUBLIC`/`READ` from `permissions.py`, error messages mentioning "Nodestro".
- **Suitability for Axentra:** High. The flow is small, standards-conforming and covered by adversarial tests.
- **Decision:** **Adapt.**
- **Required adaptations:**
  - Rename cookies (`__Host-axentra-session`, `__Host-axentra-login`), routes under Axentra's prefix, error codes
    (`identity.*` can stay as a namespace).
  - Make the OIDC client async (`httpx.AsyncClient`) or keep it sync but run in a threadpool; add a TTL for the
    cached discovery document and JWKS (currently cached forever, refreshed only on unknown `kid`, L233-252).
  - Support several providers (per tenant or per installation), `private_key_jwt`/`client_secret_post` as options,
    optional `prompt`/`login_hint`, and RP-initiated logout (`end_session_endpoint`), which Nodestro lacks.
  - Decide whether `nonce` and `code_verifier` stay in plain text in `login_states` (Nodestro hashes only the
    `state`, migration `0003_identity.sql`); acceptable because rows live 10 minutes and are deleted on use, but
    Axentra may encrypt them with the secret box.
  - Keep `email` only when `email_verified is True` (L472) and never use e-mail as an identity key (identity is
    `(issuer, subject)`).
  - Return problem documents in Axentra's format (section 3.12).
- **Security aspects (keep all of them):**
  - PKCE `S256` (L160-175); `state` and `nonce` are 256-bit/192-bit random values; nonce compared in constant time
    (L226).
  - ID token: only asymmetric algorithms (`ALGORITHMS`, never `none`/HS*), `jwt.decode` with `audience=client_id`,
    `issuer`, `leeway=60`, required claims `exp, iat, iss, aud, sub` (L215-225); `azp` must equal the client id when
    `aud` has several entries (L228-230).
  - Discovery: the document's `issuer` must equal the configured issuer exactly; `authorization_endpoint`,
    `token_endpoint`, `jwks_uri` must be https (http only on loopback for development) (L130-147, `secure_url`).
  - Login CSRF: the callback is accepted only from the browser holding the `__Host-...-login` cookie whose value
    equals `state` (A-01; test `test_a_callback_url_from_another_browser_logs_nobody_in`). The state is consumed
    before the cookie check, so a leaked callback URL is worthless for the attacker too.
  - Login cookie: `HttpOnly; Secure; SameSite=Lax; Path=/`, `Max-Age=600` (login lifetime), cleared on success and
    failure.
  - Open redirect prevention: `safe_return_path` accepts only same-site paths (`/` prefix, not `//` or `/\`, no
    control characters, no scheme before `?`, max 2000 chars).
  - Login grants nothing by itself: no membership means `403 identity.no_tenant`; no default admin, no passwords;
    first owner via one-time bootstrap token (section 3.2).
  - `redirect_uri` comes from configuration (`ServerSettings.redirect_uri`), never from the request's `Host`.
- **Required tests (port and extend `test_identity.py`):** anonymous refused; cookie attributes (`HttpOnly`,
  `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`); state single use; tampered claims (`iss`, `aud`, `exp`,
  `nonce`, `azp`) refused; forged/unsigned (`alg=none`, HS256 with public key) refused; wrong PKCE verifier refused
  by the stub provider; https-only issuer; return-path cases; login CSRF from another browser; login cookie mismatch
  and clearing; bootstrap once; race of two users for one token; JWKS rotation (unknown `kid` refetch once).
  Reuse the idea of `stub_oidc.py` (an `httpx.MockTransport` provider that checks PKCE and signs with its own RSA
  key) - rewritten for Axentra.
- **License and provenance:** MIT, Copyright (c) 2026 Peter Karlhuber; header citing
  `nodestro-api/src/nodestro_api/identity.py` at `e7fb1db...` on every adapted file (also for the test stub).
- **Possible later Nodestro migration:** Nodestro's `auth_router` could be replaced by Axentra's identity router
  mounted with Nodestro's cookie names and prefix; `SessionResolver` would map Axentra's principal to Nodestro's
  `Principal`. Because cookie names differ, a migration either keeps Nodestro's names via configuration or forces one
  re-login (sessions are short-lived: 12 h).

### 3.2 Sessions, users, memberships, bootstrap tokens (identity store)

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/identity_store.py` (`IdentityStore` L81-332),
  migration `nodestro-runtime/src/nodestro_runtime/migrations/postgres/0003_identity.sql`; session resolution in
  `nodestro-api/src/nodestro_api/identity.py` (`SessionResolver` L258-276, cookie helpers L279-293). Tests:
  `nodestro-runtime/tests/test_identity_store.py`.
- **Examined commit SHA:** `a42b6724702821849af478ee9dd0bfa13617e28b` (runtime), `e7fb1db...` (api).
- **Current responsibility:** Tenants, OIDC users `(issuer, subject)`, memberships with one role per tenant,
  server-side sessions bound to one user and one tenant, login states, one-time bootstrap tokens, cleanup.
- **Dependencies:** `PostgresDatabase` (`_query`, `_write`, `_transaction` - private methods of
  `storage_postgres.py`), `NodestroError`, `TENANT_ID`, pydantic. No orkexa dependency.
- **Suitability:** High. Generic and compact.
- **Decision:** **Adapt.**
- **Required adaptations:** rename tables (`axentra_*`); make roles data-driven (Nodestro hard-codes
  `owner/admin/editor/operator/viewer` in a SQL `CHECK` and a `Literal`); separate tenants into their own module
  (tenancy, section 3.5); expose a public DB API instead of `database._query`; add session metadata (created IP /
  user agent for audit, optional), "log out everywhere" already exists (`end_sessions`); add an audit event per
  login/logout/role change (section 3.13); optionally add a cap on concurrent sessions per user.
- **Security aspects:**
  - Session token `secrets.token_urlsafe(32)` (256 bits); stored only as `sha256(token)` in `bytea token_hash`
    (L32-33, L194-203). Login states and bootstrap tokens are hashed the same way.
  - Validation in one query joining memberships (L205-224): unknown, expired (`expires_at > clock_timestamp()`),
    idle (`last_seen_at > clock_timestamp() - idle_timeout`) or membership removed means no session. Role is read
    live on every request, so a role change applies at once.
  - Defaults: absolute lifetime 12 h, idle timeout 2 h, login lifetime 10 min (L84-95); `last_seen_at` written at
    most once a minute (L220-223) to avoid a write per request.
  - Token length guard (`len(token) > 256` refused) before hashing.
  - Last-owner protection under `SELECT ... FROM tenants ... FOR UPDATE` (L162-172).
  - Bootstrap token: works once, before expiry (24 h), only while the tenant has no owner; consumed with a
    conditional `UPDATE ... WHERE used_at IS NULL AND expires_at > clock_timestamp() RETURNING` and tenant row lock
    (L297-321); race-tested (`test_two_users_racing_for_one_token_get_one_owner`).
  - Removing a member deletes that member's sessions in the tenant in the same transaction (L156-160).
  - Session cookie `__Host-` prefix, `HttpOnly; Secure; SameSite=Lax; Path=/`, no `Domain`, `Max-Age` =
    session lifetime (identity.py L279-280). A tenant switch rotates the session token.
  - All time comparisons use the database clock (`clock_timestamp()`), not the process clock.
- **Required tests:** port `test_identity_store.py` (nothing by default; tenant id validation; login upsert;
  sessions need a membership and follow the role; expiry and idle timeout; last owner; login state single use and
  expiry; bootstrap once / refused with owner / expired / race). Add: hash-only storage assertion (no plain token in
  any column), cleanup, concurrent `last_seen` updates.
- **License and provenance:** MIT, Peter Karlhuber; headers citing `identity_store.py` and `0003_identity.sql` at
  `a42b672...`.
- **Possible later Nodestro migration:** schema is nearly identical; a one-off SQL migration can copy
  `nodestro_tenants/users/memberships` into Axentra tables (sessions need not be migrated). Nodestro's
  `IdentityStore` would become a thin adapter over Axentra's identity service.

### 3.3 Access control: permissions, principal, route registry (deny by default)

- **Source repo and file:** `nodestro-api/src/nodestro_api/permissions.py` (`Permission` L58-63, `Principal`
  L70-82, `Access` L116-147, `StreamAccess` L154-191, `classify`/`check_routes` L259-308); role map
  `ROLE_PERMISSIONS` in `identity.py` L56-63. Tests: `nodestro-api/tests/test_permissions.py`, role tests in
  `test_identity.py` (`test_roles_grant_their_permissions`, `test_no_tenant_sees_another_tenants_resources`).
- **Examined commit SHA:** `e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea`.
- **Current responsibility:** Every route declares exactly one requirement as a FastAPI dependency
  (`dependencies=READ|EDIT|RUN|ADMIN|INSTALL|PUBLIC`). The dependency resolves the principal via
  `app.state.principal_resolver`; missing resolver or principal gives `401 access.login_required`, missing
  permission `403 access.forbidden`. `check_routes(app)` walks all routes (including included routers and
  WebSockets; FastAPI >= 0.162 `iter_route_contexts` handled, L236-256) and refuses to build an app with an
  undeclared route; only routes of a specific route class under the key-authenticated prefix are exempt.
  `StreamAccess` re-checks a long-lived SSE stream's principal every 15 s and fails closed.
- **Dependencies:** FastAPI internals (`fastapi.routing.iter_route_contexts`, `APIRoute`, `params.Depends`),
  `nodestro_runtime.profile` (desktop/local owner), `serving.KEY_AUTHENTICATED_ROUTES`.
- **Suitability:** High for the mechanism; the permission set is product-specific.
- **Decision:** **Adapt** (mechanism Adopt, permission model redesigned).
- **Required adaptations:** replace the five fixed permissions with Axentra's permission strings
  (`resource:action`, e.g. `members:write`, `api_keys:manage`) and data-driven roles (system roles plus optional
  custom roles per tenant); keep "exactly one requirement or explicitly public" but allow a requirement to be a
  set/expression; principal type must distinguish user session vs API key vs service account; drop desktop
  `LOCAL_OWNER`; keep the startup route check and a CI test that lists every route with its requirement; keep
  `StreamAccess` for SSE/WebSocket.
- **Security aspects:** deny by default (no resolver = refuse); fail-closed route registry
  (`RouteAccessError`); the same 404 answer for unknown and foreign tenants on switch (identity.py L508-510);
  streams re-validated (A-04) and end when the principal is gone, changed user/tenant or lost permission; the
  OpenAPI document and Swagger UI require `read` on a server (`server_app._api_reference` L264-273).
- **Required tests:** every route classified; a route without a requirement stops app creation; double
  declarations refused; WebSocket routes checked; key-authenticated exemption works only for the listed route
  class; per-role permission matrix; cross-tenant access to every resource class returns 404/403; stream ends after
  membership removal.
- **License and provenance:** MIT, Peter Karlhuber; header citing `permissions.py` at `e7fb1db...`.
- **Possible later Nodestro migration:** Nodestro's five permissions map to Axentra permission strings
  (`read -> nodestro:read` etc.); `READ/EDIT/...` constants can be re-exported as Axentra requirements, keeping
  route decorators unchanged.

### 3.4 Same-origin CSRF check, auth log redaction, proxy headers

- **Source repo and file:** `nodestro-api/src/nodestro_api/identity.py` (`SameOriginMiddleware` L325-353,
  `RedactAuthSecrets`/`redact_auth_logs` L296-322); `nodestro-api/src/nodestro_api/local_access.py` (loopback,
  host and forwarding-header checks for the desktop, L1-52, L190-254); `nodestro-api/src/nodestro_api/server.py`
  (`uvicorn.run(..., proxy_headers=True, server_header=False)` L655-665); runbook
  `nodestro-server/docs/RUNBOOK.md` "TLS reverse proxy" (L221-249).
- **Examined commit SHA:** `e7fb1db...` (api), `42e95af...` (server).
- **Current responsibility:** For `POST/PUT/PATCH/DELETE` the `Origin` header must equal the configured public
  origin exactly, otherwise `403 access.cross_site`; exempt prefixes (key-authenticated APIs) skip the check.
  A missing `Origin` is also refused (test `test_cross_site_changes_are_refused`). The log filter rewrites
  `setup=`, `code=`, `state=` query values to `[redacted]` in `uvicorn.access` records (args and msg).
- **Dependencies:** Starlette ASGI types only. `local_access.py` is desktop-specific.
- **Suitability:** High for `SameOriginMiddleware` and the log filter; `local_access` only as a concept.
- **Decision:** `SameOriginMiddleware` **Adopt** (renamed, problem format changed); `RedactAuthSecrets`
  **Adopt** (extend the parameter list); `local_access` **Concept only**; proxy handling **Concept only**.
- **Required adaptations:** allow a list of trusted origins (studio plus admin UI); allow `Sec-Fetch-Site:
  same-origin` as an additional signal; make "missing Origin" policy explicit (refuse for cookie-authenticated
  requests, allow for bearer/API-key requests, which carry no ambient credentials); also guard WebSocket
  handshakes (Origin check); extend redaction to `token=`, `access_token=`, `id_token=`, `api_key=`, and to the
  `Authorization`/`Cookie` headers if headers are ever logged.
  Proxy trust: Nodestro relies on uvicorn's `proxy_headers=True`, whose trusted peers come from uvicorn's
  `forwarded_allow_ips` (default `127.0.0.1`, env `FORWARDED_ALLOW_IPS`), not from Nodestro configuration.
  `request.client.host` (used as the key of the invalid-API-key limiter, serving.py L793/L804) therefore depends on
  an implicit setting. Axentra should have an explicit `AXENTRA_TRUSTED_PROXIES` (CIDR list) and its own middleware
  (or `ProxyHeadersMiddleware` configured from it), and never derive security decisions from `X-Forwarded-Host`.
- **Security aspects:** Origin check is an anti-CSRF layer on top of `SameSite=Lax` (both needed; Lax still
  sends cookies on top-level `POST` navigations from some contexts in older browsers and on same-site subdomains);
  public origin must be https (http only on loopback: `server_app.create_tenant_app` L148-149); `server_header=False`
  hides the server banner; access logs never contain one-time secrets (D-02, test
  `test_setup_tokens_and_sign_in_codes_never_reach_the_access_log`). The desktop's `local_access` adds DNS
  rebinding protection via a `Host` allow-list and refuses forwarded requests - useful concept for Axentra's local
  dev mode only.
- **Required tests:** cross-site and missing-Origin refusal for cookie requests; exempt prefixes; bearer requests
  without Origin accepted; WebSocket with foreign Origin closed (1008); log records with `?code=...&state=...`
  redacted in `args` and `msg`; trusted-proxy matrix (untrusted peer's `X-Forwarded-For` ignored).
- **License and provenance:** MIT, Peter Karlhuber; header citing `identity.py` at `e7fb1db...` for the middleware
  and log filter.
- **Possible later Nodestro migration:** drop-in replacement (same constructor shape `origin=..., exempt=[...]`).

### 3.5 Tenancy (tenant ids, tenant-scoped stores, per-tenant contexts)

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/storage_postgres.py` (`TENANT_ID` regex L53,
  `PostgresStore.__init__` tenant check L539-547, every query filters on `tenant_id`);
  `nodestro-api/src/nodestro_api/identity.py` (`TenantWorkspaces` L359-389);
  `nodestro-api/src/nodestro_api/server_app.py` (`TenantFiles.open` L119-133: files below
  `<data_root>/tenants/<tenant id>`); `nodestro-runtime/src/nodestro_runtime/postgres_tables.py`
  (`tenant_storage` L355-378). ADR-0003. Tests: `test_storage_postgres.py`
  (`test_tenants_never_see_each_others_documents`, `test_a_rolled_back_transaction_of_one_tenant_keeps_the_others`,
  `test_the_table_refuses_an_empty_tenant`), `test_tenant_workspace.py`, api `test_identity.py`
  (`test_no_tenant_sees_another_tenants_resources`).
- **Examined commit SHA:** `a42b672...` (runtime), `e7fb1db...` (api).
- **Current responsibility:** Shared-schema multi-tenancy: one database, `tenant_id` column with
  `CHECK (tenant_id <> '')` on every table, tenant id validated as `[a-z0-9][a-z0-9_-]{0,62}`; a store object is
  bound to one tenant so a query without a tenant cannot be written; per-tenant application context opened lazily
  and cached (`TenantWorkspaces`).
- **Dependencies:** for `TenantWorkspaces`, the product's `Nodestro` context; for files, the local data directory.
- **Suitability:** The pattern is good; the code is small. PostgreSQL Row-Level Security is not used.
- **Decision:** **Adapt** (tenant-bound repository pattern and id regex), `TenantWorkspaces` **Concept only**.
- **Required adaptations:** Axentra should add defense in depth with PostgreSQL RLS (`SET LOCAL
  app.tenant_id = ...` per transaction, policies on every tenant table) on top of tenant-bound repositories; a
  tenant table with status (active/suspended/deleted), plan reference and settings; tenant deletion/export jobs;
  tenant-scoped object-storage prefixes instead of local directories.
- **Security aspects:** tenant ids validated before any query and before building file paths (prevents path
  traversal through tenant ids); `COLLATE "C"` on ids; a store cannot be created for an invalid tenant; errors for
  foreign tenants identical to "not found".
- **Required tests:** isolation matrix per resource type; invalid tenant ids (`""`, `../x`, upper case, 64 chars);
  rollback isolation; RLS policy tests (a connection with tenant A set cannot read B even with a forged query).
- **License and provenance:** MIT, Peter Karlhuber; headers citing `storage_postgres.py` at `a42b672...` where the
  regex/check is copied.
- **Possible later Nodestro migration:** Nodestro tenant ids already satisfy the regex; Nodestro could adopt
  Axentra's tenant service and keep its per-tenant `Nodestro` context factory.

### 3.6 PostgreSQL access layer and migration runner

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/storage_postgres.py` (`PostgresDatabase`
  L139-530: pool L156-214, `_configure` L216-227, idle check L238-242, `transaction` L280-310, read retry on lost
  connection L312-330, `_write` L332-341, session advisory locks L345-408, `migrate` L427-518,
  `require_current_schema` L520-530; `postgres_migrations` L125-132; constants `MIGRATION_LOCK`
  `0x6E6F646573747230`, `DOCUMENT_LOCK_CLASS` L56-58). Migrations
  `nodestro-runtime/src/nodestro_runtime/migrations/postgres/0001..0006_*.sql`. Operator side:
  `nodestro-api/src/nodestro_api/server.py` (`migrate` L352-370 with `--backup-dir`/`--backup-taken`, `dump`
  L373-397), `nodestro-server/compose/compose.yaml` (`migrate` one-shot service before `api`/`worker`). Tests:
  `test_storage_postgres.py`, `test_postgres_pool.py`, `postgres_support.py`.
- **Examined commit SHA:** `a42b6724702821849af478ee9dd0bfa13617e28b`.
- **Current responsibility:** psycopg 3 connection pool (`psycopg_pool.ConnectionPool`, autocommit connections,
  `min_size=1`, `max_size` default 8 / `NODESTRO_DATABASE_POOL_SIZE`), per-connection `statement_timeout` (30 s)
  and `idle_in_transaction_session_timeout` (300 s) and optional `search_path` schema, a probe connection that fails
  fast on wrong credentials, health-check-on-idle (connections idle > 2 s are checked), retry of reads on a broken
  connection (never writes), reentrant thread-local transactions serialized per process, and forward-only SQL
  migrations.
- **Migration runner details (to replicate):**
  1. Files named `NNNN_name.sql` (regex `(\d{4})_[a-z0-9_]+\.sql`) loaded with `importlib.resources` from the
     package (`test_the_wheel_ships_the_migrations`); target = highest number.
  2. One transaction: `SET LOCAL statement_timeout = 0`, then `SELECT pg_advisory_xact_lock(MIGRATION_LOCK)`
     *before* any DDL (because `CREATE ... IF NOT EXISTS` is not safe against a concurrent creator), optional
     `CREATE SCHEMA IF NOT EXISTS`, `CREATE TABLE IF NOT EXISTS nodestro_schema_migrations (version integer PRIMARY
     KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`.
  3. `current == target` returns; `current > target` refuses (`storage.schema_too_new`); gaps refuse
     (`storage.migration_missing`) before anything is written.
  4. A non-empty database requires a `before_migration(current, target)` hook (backup); missing hook
     `storage.backup_required`, failing hook `storage.backup_failed`; the CLI implements it with
     `pg_dump --format=custom --no-owner`, password passed in `PGPASSWORD`, never on the command line.
  5. Steps run in a savepoint; each inserts its row into the migrations table; `ANALYZE` after upgrading; any failure
     rolls back everything (`storage.migration_failed`).
  6. Serving processes call `require_current_schema()` and refuse to start on mismatch (`storage.schema_mismatch`);
     only the dedicated `migrate` command changes the schema.
- **Dependencies:** `psycopg[binary,pool]>=3.2`, `NodestroError`, `storage.BeforeMigration`, `DamagedDocuments`.
- **Suitability:** High; generic infrastructure with very good tests (dropped connections, concurrent migrators,
  timeouts, session locks).
- **Decision:** **Adopt** (`PostgresDatabase` core and migration runner, renamed), with the adaptations below.
- **Required adaptations:** rename lock keys, tables and env variables; make the migration source pluggable per
  Axentra module (module-qualified versions, e.g. one migrations table with `(module, version)` or a global ordered
  list), since Axentra is modular; allow non-transactional steps (`CREATE INDEX CONCURRENTLY` cannot run in a
  transaction; Nodestro does not support it); public query/execute API instead of underscore methods; optional
  async variant (`psycopg.AsyncConnection`/`AsyncConnectionPool`) if Axentra's API is async; document PgBouncer
  constraints (session advisory locks and `SET` need session pooling or a direct connection); replace "serialize all
  transactions of one process under one RLock" (L182-184) with true concurrent transactions if Axentra needs write
  throughput (Nodestro chose serialization to mirror SQLite semantics).
- **Security aspects:** credentials only from the libpq connection string / `PG*` variables / `~/.pgpass`, never
  from app settings; schema name validated (`[a-z_][a-z0-9_]{0,62}`) and quoted with `sql.Identifier`; statement
  timeouts prevent runaway queries; `pg_dump` password not on the command line and `NODESTRO_*` variables removed
  from its environment; all values parameterized (the one interpolated identifier in `find` is regex-checked).
- **Required tests:** port `test_storage_postgres.py` migration cases (fresh without backup, idempotent, unmigrated
  refused, backup first, missing backup refused, failing backup / failing step leave DB unchanged, missing step,
  newer schema refused, not inside a transaction, concurrent processes apply once, wheel ships migrations) and
  `test_postgres_pool.py` (dropped connection replaced, every pooled connection dropped, statement time limit,
  defaults/env, unreachable DB fails at once, ping, leader lock lost with connection, lock counting). Keep the test
  harness pattern: one random schema per test, `AXENTRA_TEST_POSTGRES` DSN, `AXENTRA_REQUIRE_POSTGRES=1` in CI turns
  a missing DB into a failure.
- **License and provenance:** MIT, Peter Karlhuber; header citing `storage_postgres.py` at `a42b672...`.
- **Possible later Nodestro migration:** Nodestro could import Axentra's database layer as a vendored copy only if
  the no-runtime-dependency rule is relaxed for Nodestro (the rule binds Axentra, not Nodestro). Otherwise Nodestro
  can port Axentra's improved version back; table names stay Nodestro's because migrations are per module.

### 3.7 Document store (JSONB key/value with tenant scope)

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/storage.py` (`DocumentStore` protocol
  L86-144, `SQLiteStore` L185-527, `DamagedDocuments` L147-178); `storage_postgres.py` (`PostgresStore`
  L533-711); migrations `0001_documents.sql`, `0005_find_indexes.sql`, `0006_partial_find_indexes.sql`. Tests:
  `test_storage_contract.py` (same cases on SQLite and PostgreSQL), `test_replace_if_postgres.py`,
  `test_damaged_documents_postgres.py`.
- **Examined commit SHA:** `a42b672...`.
- **Current responsibility:** Pydantic models stored as JSON documents per `(tenant_id, collection, id)`, with
  `get/put/list/find/items/list_prefix/delete/delete_prefix/search_raw`, `replace_if` (compare-and-swap on a
  top-level field, optional deadline in DB time), `lock(collection, key)` via `pg_advisory_xact_lock(class,
  hashtext(json))`, and reentrant transactions. JSONB cannot hold U+0000: such documents keep exact JSON in `raw`.
- **Dependencies:** pydantic; SQLite for the desktop; PostgreSQL as above.
- **Suitability:** Medium. Convenient for a product with many small document types, but a SaaS foundation needs
  typed relational tables for identity, billing, jobs, audit. `find` uses an expression index per field (only two
  fields indexed). `search_raw` is a substring scan.
- **Decision:** **Concept only** (offer an optional "settings/document" table for schemaless per-tenant
  configuration; take `replace_if` and the per-key advisory lock idea), not the store as Axentra's data layer.
- **Required adaptations:** if adopted for settings: typed repositories over SQL tables; drop SQLite support (or
  keep only for tests); hash collisions of `hashtext` (32-bit) just over-serialize - acceptable, but document it.
- **Security aspects:** field names regex-checked before interpolation (`_FIELD`); tenant filter in every query;
  damaged documents are skipped and reported, not crashing listings.
- **Required tests:** contract test pattern (run one suite against every backend) is worth replicating for any
  Axentra storage interface (`test_storage_contract.py` fixture parametrization).
- **License and provenance:** no code copied unless `replace_if`/`lock` are ported; then header citing
  `storage_postgres.py` at `a42b672...`.
- **Possible later Nodestro migration:** not needed; Nodestro keeps its document store on top of Axentra's database
  layer.

### 3.8 Job queue, leases, reaper, leader lock, schedule firings, event log

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/jobs.py` (`JobQueue` L109-219: `enqueue`
  L118-126, `claim` L128-138, `heartbeat` L140-148, `finish` L150-159, `request_cancel` L161-179,
  `reap_expired` L181-190, `cleanup` L213-219; `PostgresEventLog` L222-285; `QueuedRuns` L288-317; `RunWorker`
  L324-484; `reap` L502-527; `orphaned_runs` L530-543; `LeaderLock` L546-568; `ScheduleFirings` L571-601;
  `SCHEDULER_LOCK = 0x6E6F64657374726F` L60). Migration `0004_jobs.sql`. Worker process:
  `nodestro-api/src/nodestro_api/worker.py` (`WorkerSettings` L55-80: lease 60 s, poll 1 s, reap every 15 s, cleanup
  every 600 s; `fire_schedules` L125-135, `clean_up` L137-152, `serve` L154-). ADR-0004. Tests:
  `nodestro-runtime/tests/test_jobs.py`, `nodestro-api/tests/test_worker.py`,
  `nodestro-server/tests/e2e/test_acceptance.py::test_a_worker_killed_in_the_middle_of_a_run`.
- **Examined commit SHA:** `a42b672...` (runtime), `e7fb1db...` (api).
- **Current responsibility:** PostgreSQL-backed queue for workflow runs with exactly-one-active-job per
  `(tenant, kind, ref)`, competing workers, leases renewed by heartbeat, cancellation, reaping of dead workers'
  jobs (marked `interrupted`, never retried automatically - deliberate, because runs have side effects and cost),
  scheduler leader election, idempotent schedule slots, and a run-event table read by any API replica.
- **SQL patterns (to replicate):**
  - Table: `id bigserial`, `tenant_id, kind, ref`, `status CHECK IN ('queued','running','done','failed',
    'cancelled','interrupted')`, `payload jsonb`, `attempts`, `worker`, `lease_until timestamptz`,
    `cancel_requested boolean`, `error`, timestamps. Partial unique index
    `ON (tenant_id, kind, ref) WHERE status IN ('queued','running')`; partial indexes `(kind, id) WHERE status =
    'queued'` and `(lease_until) WHERE status = 'running'`.
  - Enqueue (dedupe): `INSERT ... ON CONFLICT (tenant_id, kind, ref) WHERE status IN ('queued','running') DO
    NOTHING RETURNING ...`.
  - Claim: `UPDATE jobs SET status='running', worker=%s, attempts=attempts+1, started_at=clock_timestamp(),
    lease_until=clock_timestamp()+%s WHERE id = (SELECT id FROM jobs WHERE status='queued' AND kind = ANY(%s) ORDER
    BY id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING ...`.
  - Heartbeat: `UPDATE ... SET lease_until = clock_timestamp() + %s WHERE id=%s AND worker=%s AND
    status='running' RETURNING ...` (no row = lease lost; the worker abandons the run and stores nothing more).
  - Finish: conditional on `worker` and `status='running'`; returns whether it was still the owner.
  - Reap: `UPDATE ... SET status='interrupted' ... WHERE id IN (SELECT id ... WHERE status='running' AND
    lease_until < clock_timestamp() FOR UPDATE SKIP LOCKED) RETURNING ...`.
  - Cancel: queued jobs become `cancelled` at once; running ones get `cancel_requested=true`, read by the next
    heartbeat.
  - Leader: `pg_try_advisory_lock(key)` on a dedicated non-pooled session connection; `acquire()` re-checks the
    connection (`SELECT 1`) every time and re-takes the lock if the connection was lost
    (`PostgresDatabase.try_session_lock/holds_session_lock`, storage_postgres.py L368-408); in-process hold count
    like PostgreSQL.
  - Schedule firing: `INSERT INTO schedule_firings (tenant_id, schedule_id, slot) ... ON CONFLICT DO NOTHING`;
    rowcount 1 means "this process fires the slot"; naive datetimes refused.
  - Event log: buffered `executemany INSERT ... ON CONFLICT DO NOTHING` keyed `(tenant_id, run_id, seq)`; terminal
    events flushed immediately; readers poll `seq > after` (the API polls every 0.25 s, `engine.py` `remote_poll`
    L916). ADR-0004 point 6 mentions `NOTIFY`; the code does not use `LISTEN/NOTIFY` (no match in runtime source).
  - Worker capacity: `max_runs` (2) and `max_waiting` (1) with `check_capacity`; dedicated thread pool for queue
    calls so lease renewal never waits behind user work (C-08).
  - Housekeeping only by the leader: expired sessions/login states, finished jobs older than retention, events older
    than 2 days.
- **Dependencies:** `PostgresDatabase`; Nodestro-specific: `Run`, `RunEvent`, `RunManager` hooks
  (`dispatch`, `remote_cancel`, `remote_events`, `execute_claimed`, `abandon`, `lost_fence`, `interrupt`),
  `tool_approvals.WaitingSlots`, `RUN_JOB`, `orphaned_runs` reads `nodestro_documents` runs.
- **Suitability:** The SQL core (`JobQueue`, `LeaderLock`, `ScheduleFirings`) is generic and excellent; the worker
  and event log are product-coupled.
- **Decision:** `JobQueue` + migration **Adapt**; `LeaderLock` and `ScheduleFirings` **Adopt**;
  `PostgresEventLog` **Adapt** (generic "event stream" table); `RunWorker`, `QueuedRuns`, `reap`/`orphaned_runs`
  **Concept only**.
- **Required adaptations:** generic job handlers registry (`kind -> handler`), payload schema per kind; add
  `run_after timestamptz` (delayed jobs, backoff), `max_attempts`, `priority`, `idempotency_key`, `dedupe_key`
  separate from `ref`, and an explicit retry policy per kind (Nodestro never retries; Axentra jobs such as webhook
  delivery and e-mail must retry with exponential backoff + jitter, while side-effecting jobs can opt into
  "interrupt, never retry"); claim index on `(kind, priority, run_after, id) WHERE status='queued'`; optional
  `LISTEN/NOTIFY` wake-up (`pg_notify` in the enqueue transaction) with polling as fallback; batch claim
  (`LIMIT n`); dead-letter status; metrics (queue depth, lease losses). Webhooks (Nodestro has none) are built on
  this queue: outbox table written in the business transaction, delivery job with HMAC-signed payload, retries and
  per-endpoint circuit breaker.
- **Security aspects:** jobs carry `tenant_id` (`CHECK <> ''`) and workers open the tenant's context from it; lease
  fencing (only the owning worker may renew/finish) prevents a reaped worker from overwriting results; reaped side-
  effecting work is never replayed silently; payload is JSON, never pickled code.
- **Required tests:** port `test_jobs.py` queue cases: at most one active job per work item; concurrent workers
  never claim the same job (multi-connection test); only the owner renews/finishes; cancel queued vs running;
  expired lease reaped once and never claimed again; one leader among processes and leadership lost with its
  connection (`test_postgres_pool.py::test_the_leader_lock_is_lost_with_its_connection_and_taken_again`); each
  schedule slot fires once across processes; event buffering/flush. Add: retry/backoff, `run_after`, dead letter,
  NOTIFY wake-up, kill-the-worker e2e (as in nodestro-server e2e).
- **License and provenance:** MIT, Peter Karlhuber; headers citing `jobs.py` and `0004_jobs.sql` at `a42b672...`,
  `worker.py` at `e7fb1db...` if its loop structure (`_every`) is copied.
- **Possible later Nodestro migration:** Nodestro's run jobs become one Axentra job kind with retry policy "never,
  interrupt on lease loss"; `QueuedRuns`/`RunWorker` stay Nodestro code on top of Axentra's queue. Table rename via
  a migration that copies active jobs (or drain the queue before switching).

### 3.9 Configuration and secrets (server settings, SecretBox)

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/server_settings.py` (`ServerSettings`
  L46-134, `_origin` L141-162, `SecretBox` L165-217, `ENCRYPTED_PREFIX = "nodestro:enc:v1:"` L40); usage in
  `workspace.py` (`_key_field` L163-165, `_providers`/`_seal` L535-560) and `mcp/vault.py` (desktop vault key from
  `NODESTRO_VAULT_KEY`). Runbook `nodestro-server/docs/RUNBOOK.md` (L33, L92, L413). Tests:
  `nodestro-runtime/tests/test_server_settings.py`, `test_tenant_workspace.py`
  (`test_tenant_provider_keys_are_encrypted_and_server_variables_are_not_shared`).
- **Examined commit SHA:** `a42b672...`.
- **Current responsibility:** Validated, immutable startup configuration from the environment, with `X_FILE`
  variants for container secrets (both forms set = error), all problems reported at once (`profile.invalid` with
  `problems=[{field,value,reason}]`), secrets excluded from `repr`. `SecretBox` encrypts per-tenant secrets with
  AES-256-GCM; per-tenant key = HKDF-SHA256(master, salt=None, info=`b"nodestro tenant secrets v1\0" + tenant_id`,
  length 32); 12-byte random nonce; AAD = `f"{tenant_id}\0{field}"`; token = prefix +
  `urlsafe_b64(nonce || ciphertext||tag)`. Decryption failure = `secrets.unreadable`; callers treat unreadable as
  "missing, enter again".
- **Known limitation:** **no central key rotation.** The envelope has no key identifier and `SecretBox` holds one
  key; changing `NODESTRO_SECRET_KEY` makes every stored secret unreadable (module docstring L21-24; runbook L33
  "there is no rotation yet", L413 "Not yet: rotation of `NODESTRO_SECRET_KEY`").
- **Dependencies:** `cryptography>=42` (lazy import), `NodestroError`. No orkexa dependency.
- **Suitability:** High; small and correct. Needs rotation and a keyring for Axentra.
- **Decision:** `ServerSettings` pattern **Adapt** (Axentra uses a typed settings model, e.g. pydantic-settings,
  but keeps `_FILE`, all-problems-at-once and secure-origin validation); `SecretBox` **Adapt**.
- **Required adaptations (secret encryption):**
  - Envelope `axentra:enc:v2:<kid>:<b64url(nonce||ct||tag)>` where `kid` names the master key; a keyring
    (`AXENTRA_SECRET_KEYS` = ordered list of `kid=base64key`, first is active) so decryption tries the named key and
    encryption always uses the active one.
  - Rotation command / background job that re-encrypts all values with the active key, with progress and a
    "no value left on old key" check before a key can be retired.
  - Keep HKDF per tenant (domain-separated `info` with Axentra prefix and version) and AAD binding tenant + field
    (prevents copy-paste between tenants/fields); consider including the record id in AAD.
  - Optional KMS backend (envelope with a data key wrapped by AWS KMS / GCP KMS / Vault Transit) behind the same
    interface.
  - Minimum key size 32 bytes; base64 with url-safe alphabet accepted (as in `from_env` L107-120).
- **Security aspects:** AEAD with random 96-bit nonce (safe for the expected number of encryptions per tenant key);
  no plaintext fallback (`decrypt` refuses non-prefixed values); secrets never returned by display APIs, never
  logged; `X_FILE` support for Docker/Kubernetes secrets; startup refuses incomplete/unsafe config with no override
  switch (ADR-0001 point 3).
- **Required tests:** port `test_server_settings.py` (complete settings, secrets not in `repr`, every missing setting
  listed at once, unsafe values refused, loopback http allowed, `_FILE` vs direct conflict, secrets bound to tenant
  and field). Add: rotation (old kid decrypts, new kid encrypts, re-encrypt job idempotent), unknown kid error,
  tampered ciphertext/AAD fails, known-answer vectors.
- **License and provenance:** MIT, Peter Karlhuber; header citing `server_settings.py` at `a42b672...`.
- **Possible later Nodestro migration:** Axentra's v2 decrypt can also accept Nodestro's v1 envelope (no kid:
  implied `kid=legacy`, with HKDF info `b"nodestro tenant secrets v1\0"`) during a migration window; a re-encrypt
  job then moves Nodestro's provider keys and MCP tokens to v2. This finally gives Nodestro key rotation.

### 3.10 API keys (format, hashing, scopes, rotation, verification)

- **Source repo and file:** `nodestro-api/src/nodestro_api/serving.py` (`KEY_PREFIX="ndk"`, `_TOKEN` L72-73,
  `hash_secret` L161-163, `new_key` L166-170, `parse_token` L173-175, `secret_matches` L178-179, `KeyIdentity`
  L182-190, `ServingCore.authenticate` L790-818, `authorize` L820-834, `safe_text` key redaction L131-138);
  `nodestro-api/src/nodestro_api/api_keys.py` (`ApiKey` L25-36, `ApiKeys` L64-162). Tests:
  `nodestro-api/tests/test_published_api.py`, `test_hardening.py`.
- **Examined commit SHA:** `e7fb1db...`.
- **Current responsibility:** Machine credentials for published workflow APIs. Token format
  `ndk_<id>_<secret>`, `id = secrets.token_hex(6)` (12 lower-case hex chars), `secret = secrets.token_urlsafe(32)`
  (43 chars, 256 bits), regex `^ndk_([a-z0-9]{12})_([A-Za-z0-9_-]{32,64})$`. Stored: id, name, `secret_hash =
  sha256(secret).hexdigest()`, scopes (`run`, `read`, `approve`), publication ids, created/last used/revoked,
  `replaces`. Shown once. Lookup by id, then `hmac.compare_digest(sha256(secret), stored_hash)`. Accepted as
  `Authorization: Bearer <key>` or `X-API-Key`. Revoked keys stay listed; delete only after revoke; rotation creates
  a new key with the same name/scopes and revokes the old one under a lock. `last_used_at` written at most once a
  minute.
- **Dependencies:** `DocumentStore` (`api_keys` collection), `NodestroError`, publications (`store.get_raw
  ("publications", ...)`), `ServingCore` (product). On the server profile published APIs are not available yet
  (runbook L413: answered with 405); keys are not tenant-bound in practice.
- **Suitability:** High for format/hashing/verification; the scope and resource model is product-specific.
- **Decision:** **Adapt.**
- **Required adaptations:** prefix `axk_` (optionally `axk_live_`/`axk_test_`) so secret scanners can match it
  (register the pattern with GitHub secret scanning); tenant-bound keys (table `api_keys(tenant_id, id, name,
  secret_hash, scopes text[], created_by, created_at, expires_at, last_used_at, revoked_at, replaces)` in SQL, not a
  document collection); scopes = Axentra permission strings; optional expiry; consider HMAC-SHA256 with a server
  pepper (`hmac(pepper, secret)`) instead of plain SHA-256 so a DB dump alone does not allow offline checks - plain
  SHA-256 is acceptable for 256-bit random secrets (no need for bcrypt/argon2); rotation with an optional overlap
  window (old key valid for N minutes) as an option, Nodestro revokes at once; service accounts as key owners;
  audit events for create/rotate/revoke/use-from-new-IP.
- **Security aspects:** secret never stored or logged; key id is not secret (shown as `prefix`); constant-time
  compare; revocation checked on every request and re-read under the lock before `last_used_at` is written (no
  resurrection of revoked keys, api_keys.py L149-162); failure rate limit per client address (30 per minute, 429
  with `Retry-After`) to slow guessing; same 404 for "key not allowed" and "unknown publication" (no enumeration);
  `WWW-Authenticate: Bearer error="invalid_token"`; error texts sent to clients pass `safe_text`, which replaces
  `ndk_` tokens and known credential patterns.
- **Required tests:** format and parsing (rejects wrong prefix, short secret, upper-case id); hash-only storage;
  shown once; revoked rejected immediately; rotation race (two rotations give one new key, second gets
  `apikey.revoked`); delete requires revoke; scope enforcement; tenant isolation of keys; failure limiter; key
  redaction in error messages and logs.
- **License and provenance:** MIT, Peter Karlhuber; header citing `serving.py` and `api_keys.py` at `e7fb1db...`.
- **Possible later Nodestro migration:** Axentra's verifier can accept `ndk_` tokens as a legacy prefix with the
  same SHA-256 hash, so existing Nodestro keys keep working when Nodestro moves its key table to Axentra's (copy
  id, hash, scopes; map publications to resource-scoped grants).

### 3.11 Rate limiting and idempotency

- **Source repo and file:** `nodestro-api/src/nodestro_api/serving.py` (`_Window` L710-734, `ApiLimits`
  L195-217, `check_limits` L986-1021, idempotency in `launch` L1103-1187, `_prune_idempotency` L774-788).
  Runbook: no login rate limit in the server, proxy `limit_req` advised (RUNBOOK L246-247).
- **Examined commit SHA:** `e7fb1db...`.
- **Current responsibility:** In-process sliding-window counter (deque of timestamps per key, swept every period
  so the table cannot grow without bound), used for invalid-key attempts per client, requests per key per minute,
  new runs per key and publication; concurrency/waiting/daily-cost limits computed from stored runs.
  `Idempotency-Key` (max 200 chars): record key `publication:key_id:sha256(idempotency_key)`, request fingerprint
  `sha256(json.dumps([release_id, payload], sort_keys=True))`, 24 h retention; same key + different body = `409
  idempotency.conflict`; replay returns the original run with `Idempotent-Replayed: true`; a failure to store the
  record after the run started is logged, not answered with 500 (so the client does not retry into a duplicate).
- **Dependencies:** `DocumentStore`, product run manager.
- **Suitability:** The idempotency design is reusable; the limiter is per process only (wrong for several API
  replicas).
- **Decision:** Idempotency **Concept only** (reimplement as a generic middleware/dependency on a SQL table with a
  unique key); `_Window` **Do not adopt** for production (keep only as an in-memory fallback for tests/single
  process); Axentra needs a shared limiter (PostgreSQL or Redis token bucket / GCRA).
- **Required adaptations:** shared storage; limits per tenant/plan (ties into usage and billing); login endpoint
  limits inside the app; idempotency record states `in_progress/completed` to handle concurrent duplicates across
  replicas (Nodestro serializes with an `asyncio.Lock` in one process, L1118).
- **Security aspects:** unbounded growth prevented (A-09); fingerprints use hashes, not raw bodies; limiter keyed on
  client address requires correct proxy trust (section 3.4).
- **Required tests:** sliding window boundary; sweeping; idempotent replay; conflict on changed body; concurrent
  duplicates across two app instances; `Retry-After` header.
- **License and provenance:** no code copied (concept); if `_Window` is copied for tests, header citing
  `serving.py` at `e7fb1db...`.
- **Possible later Nodestro migration:** Nodestro's published API limits could call Axentra's limiter and
  idempotency service; `ApiLimits` stays product configuration.

### 3.12 Problems and error handling

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/problems.py` (`Problem` L20-23,
  `NodestroError(ValueError)` L26-36; L51-118 map orkexa messages to codes - product-specific);
  `nodestro-api/src/nodestro_api/api.py` (`install_error_handlers` L112-151: `NodestroError -> 400`,
  `ValueError/PermissionError -> 400`, `KeyError -> 404`, `ApiError`, `AccessError`); published API format
  `serving.ApiError` L110-125 (`{"error": {"status","code","message","params"}}`) and `_error_of` L141-158 (never
  leaks internals: 500 `internal` with "details are in the server log"); `KeyAuthenticatedRoute` L1459-1479.
  Frontend mapping: `nodestro-studio/frontend/src/lib/errors.tsx`, `src/i18n/locales/<lang>/errors.json`.
- **Examined commit SHA:** `a42b672...` (runtime), `e7fb1db...` (api), `8e18cae...` (studio).
- **Current responsibility:** Every error carries a stable dotted `code` plus `params`; the English message is
  technical; the UI renders `errors.<code>` in the user's language with params, falling back to a generic sentence
  and showing the original under "technical details".
- **Dependencies:** orkexa (for the pattern table), FastAPI.
- **Suitability:** The code + params + i18n contract is a very good fit; two different wire formats and mapping
  `KeyError`/`ValueError` globally to 404/400 are not.
- **Decision:** **Concept only** (code + params contract, i18n mapping, no internals in 500s); wire format
  redesigned.
- **Required adaptations:** one format for all Axentra APIs: RFC 9457 `application/problem+json` with `type`,
  `title`, `status`, `detail`, `instance`, plus extension members `code` and `params` (and `errors[]` for field
  validation, as `serving.field_errors` produces); a single `AxentraError` hierarchy with explicit HTTP status
  instead of inheriting `ValueError`; do not map arbitrary `KeyError`/`ValueError` globally (they can hide bugs);
  request id / trace id in every problem.
- **Security aspects:** unknown exceptions become a generic 500 with the detail only in the server log; messages
  sent to clients are sanitized (`safe_text`); identical errors for "not found" and "not yours".
- **Required tests:** every registered error code has an English UI text (Nodestro's `quality.test.ts` checks
  backend codes have specific sentences); 500 never contains exception text; validation errors list fields.
- **License and provenance:** concept; no header unless `field_errors` is copied (then `serving.py` at `e7fb1db...`).
- **Possible later Nodestro migration:** Nodestro's frontend already maps `code`/`params`; reading `code` from an
  RFC 9457 body is a small client change.

### 3.13 Audit trail and observability

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/tool_approvals.py` (audit trail L115-169:
  `ToolApprovalEvent`, `record_audit`, `audit_events`, `MAX_AUDIT = 5000`; `audit()` L485-510 stores only
  `arguments_hash`, never arguments); `tool_journal.py` (write-ahead note of each tool call, digest of arguments);
  `nodestro-api/src/nodestro_api/server_app.py` (`DatabaseHealth` L216-261: at most one DB ping in flight on a
  daemon thread, 2 s timeout, `/api/health` 200/503); `nodestro_runtime/traces.py` is the import of exported run
  traces (not tracing/observability). No OpenTelemetry, Prometheus or structured logging exists (no match in the
  sources or `pyproject.toml` files).
- **Examined commit SHA:** `a42b672...`, `e7fb1db...`.
- **Current responsibility:** Domain-specific audit (tool approvals) in the document store, capped at 5000 entries
  per tenant (older ones deleted when read); health endpoint; Python `logging`.
- **Dependencies:** `DocumentStore`, approval domain types.
- **Suitability:** Low as code; good principles (actor, kind, outcome, hashes instead of sensitive values,
  identical health semantics for the load balancer).
- **Decision:** Audit **Concept only**; `DatabaseHealth` **Adapt** (small, generic); traces **Do not adopt**.
- **Required adaptations:** append-only SQL audit table (`tenant_id, at, actor_type, actor_id, action, target_type,
  target_id, outcome, ip, user_agent, request_id, details jsonb`), no deletion by reads, retention by policy job,
  optional hash chain for tamper evidence; OpenTelemetry tracing/metrics, JSON logs with request id; readiness vs
  liveness endpoints; health check pattern (single in-flight check, bounded timeout, never blocks the request pool).
- **Security aspects:** never store secrets or raw arguments in audit (hash them); health endpoint public but
  reveals only `ok/unreachable`.
- **Required tests:** audit written for identity, membership, API key, secret and billing actions; audit rows
  immutable for app roles (DB grants); health under a hanging DB returns 503 within timeout and does not pile up
  checks (`test_identity.py::test_the_server_health_check_reports_the_database`).
- **License and provenance:** header citing `server_app.py` at `e7fb1db...` if `DatabaseHealth` is ported.
- **Possible later Nodestro migration:** Nodestro's approval audit can write to Axentra's audit table with
  `action = "tool_approval.<kind>"`.

### 3.14 Secret redaction (sanitizer)

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/sanitize.py` (`SECRET_KEY` L26-31, `_SECRETS`
  L33-48, `_ASSIGNMENT` L50-54, `_PERSONAL` L55-62, `Sanitizer` L80-164, `redact_secrets` L207-209;
  `sanitize_run` L167-204 is product-specific). Related: `nodestro-server/scripts/scan_secrets.py` (release
  artifact scanner, stdlib only). Tests: `nodestro-runtime/tests/test_sanitize.py`,
  `nodestro-server/scripts/test_scan_secrets.py`.
- **Examined commit SHA:** `a42b672...` (runtime), `42e95af...` (server).
- **Current responsibility:** Pattern-based replacement of credentials (Anthropic, OpenAI, AWS AKIA/ASIA and session
  tokens, Bedrock keys, GitHub, Slack, Google `AIza`, JWTs, bearer tokens, PEM private keys, `password=`-style
  assignments, values of secret-named JSON keys) and optional personal data (e-mail, IBAN, Luhn-checked cards,
  phones, IPv4) with consistent placeholders (`[API_KEY_1]`), and a second pass that removes every credential found
  wherever it reappears.
- **Dependencies:** `schemas.SanitizeReport` (product), otherwise stdlib `re`.
- **Suitability:** High as a utility for log filters, error messages and data exports.
- **Decision:** `Sanitizer`, patterns and `redact_secrets` **Adopt** (drop `sanitize_run`); `scan_secrets.py`
  **Adapt** for Axentra's release pipeline.
- **Required adaptations:** add Axentra's own key prefix (`axk_...`) and session cookie values; a logging filter that
  applies `redact_secrets` to structured log fields; make the pattern list extensible per module; not thread-safe as
  an instance (Nodestro serializes with `_SANITIZER_LOCK` in serving.py L128-138) - create one instance per call.
- **Security aspects:** best-effort only (documented as incomplete); never the primary control - secrets must not
  be logged in the first place.
- **Required tests:** port `test_sanitize.py` cases for each pattern; false-positive checks (Luhn, phone length);
  idempotence (already replaced placeholders untouched).
- **License and provenance:** MIT, Peter Karlhuber; header citing `sanitize.py` at `a42b672...` and
  `scan_secrets.py` at `42e95af...`.
- **Possible later Nodestro migration:** identical API (`Sanitizer(personal_data=...)`, `.text`, `.value`), so
  Nodestro could switch imports to its own copy of Axentra's improved pattern list.

### 3.15 File storage (input files, blobs, format detection, archives)

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/input_files.py` (`_Blobs` L150-168:
  content-addressed by sha256, id = first 16 hex chars; `InputFiles.add` L192-239; reference counting and
  `cleanup` L326-408), `file_formats.py` (`detect` L213-, content vs extension check, `inspect_archive` L603-:
  max 5000 entries, 512 MB unpacked, 25 MB per member, compression ratio > 100 refused, unsafe paths/links/encrypted
  entries flagged; `MAX_UPLOAD_MB = 50`), `file_delivery.py` (how files reach AI agents - product-specific),
  `workspace.py` (data directory and lock), `postgres_tables.PostgresFileStore` (bytes as `bytea` in
  `nodestro_files`); orkexa `LocalFileStore` (`orkexa/src/orkexa/files.py`: directory `0o700`, files `0o600`,
  atomic write via `O_CREAT|O_EXCL` temp file + replace). Upload body limit: `serving.read_body` L274-295 (80 MB,
  `Content-Length` and streamed size checked).
- **Examined commit SHA:** `a42b672...`, orkexa `34679404...`.
- **Current responsibility:** Upload, validate, deduplicate, extract and retain workflow input files on the local
  disk of the data directory (also on the server, per tenant directory); knowledge files in PostgreSQL `bytea`.
- **Dependencies:** orkexa `LocalFileStore`/`StoredFile` (must not be used by Axentra), document extraction
  (`documents.py`, PDF/Office), product references (runs, schedules, batches).
- **Suitability:** Low as code (local disk, product references, orkexa base class). The validation ideas are
  valuable.
- **Decision:** **Concept only** (storage abstraction with S3-compatible and local backends written fresh);
  archive/format safety checks **Adapt** if Axentra offers file inspection.
- **Required adaptations:** object-storage interface (`put/get/delete/presign`), tenant-prefixed keys, metadata
  table in SQL (`tenant_id, id, name, media_type, size, sha256, created_by, created_at, retention`), presigned
  upload/download with short expiry, server-side encryption, malware scanning hook, quotas tied to usage.
- **Security aspects to keep:** content-vs-extension verification (magic bytes, valid UTF-8/JSON, Office part
  check); refuse empty files; zip-bomb limits; never unpack archives to disk or execute content; cleaned file names
  (`_clean_name`); owner-only file permissions and atomic writes for the local backend; body size limits enforced
  on `Content-Length` and on the streamed body.
- **Required tests:** mismatched extension refused; zip-bomb and path traversal (`../`, absolute, symlink) entries;
  size limits; dedupe by hash; tenant isolation of object keys; presigned URL expiry.
- **License and provenance:** concept; header citing `file_formats.py` at `a42b672...` if detection/archive checks
  are ported.
- **Possible later Nodestro migration:** Nodestro's `_Blobs` could be backed by Axentra's object storage interface
  (content-addressed keys under a tenant prefix), removing the shared data volume requirement on servers.

### 3.16 Usage metering and cost tracking

- **Source repo and file:** `nodestro-runtime/src/nodestro_runtime/usage_log.py` (`UsageEntry`, `UsageLog`
  `usage_log` collection), `cost_tracking.py` (`PricedTracker(BudgetTracker)`: price modes `standard`/`strict`,
  costs computed once at request end and never re-priced), `pricing.py`, `pricing_sync.py`;
  `serving.check_limits` (daily budget per publication).
- **Examined commit SHA:** `a42b672...`.
- **Current responsibility:** A ledger of AI requests outside runs (tokens, model, cost) and budget enforcement for
  AI calls via orkexa.
- **Dependencies:** orkexa `UsageRecord`, `BudgetTracker`, pricing tables; `engine.usage_of`.
- **Suitability:** Low as code (AI/LLM-specific, orkexa-bound). Principles are good: immutable cost at record time,
  "strict mode" refusing unpriced usage, one entry per operation and model so nothing is counted twice.
- **Decision:** **Concept only** (usage) ; billing: **Do not adopt** (Nodestro has no billing).
- **Required adaptations:** generic metering: `usage_events(tenant_id, meter, quantity numeric, unit, occurred_at,
  idempotency_key UNIQUE, dimensions jsonb)` append-only, hourly/daily aggregates, quota checks, export to the
  billing provider (Stripe metered billing or similar) via the job queue; decimal arithmetic (Nodestro uses
  `Decimal` in cost tracking).
- **Security aspects:** idempotent ingestion; tenants can read only their own usage; price changes never alter
  recorded amounts.
- **Required tests:** duplicate event ignored; aggregation correctness; quota enforcement at boundaries.
- **License and provenance:** concept only; no header.
- **Possible later Nodestro migration:** Nodestro's `UsageLog.record` could additionally emit Axentra usage events
  (`meter = "ai.tokens.input"` etc.).

### 3.17 Search and realtime (SSE)

- **Source repo and file:** search: `nodestro-runtime/src/nodestro_runtime/postgres_tables.py` (`PostgresIndex`
  L131-250, `search_words` L50-53 NFKD + diacritics removal, `_tsquery` L61-64 prefix OR query, `ts_rank`);
  migration `0002_knowledge_memory.sql` (`search tsvector GENERATED ALWAYS AS (to_tsvector('simple',
  search_text)) STORED`, GIN index); `nodestro-api/src/nodestro_api/search.py` (global product search).
  Realtime: `serving.ServingCore.events` L1320- (SSE with `Last-Event-ID`, first event is the full status,
  keep-alives), `jobs.PostgresEventLog`, `permissions.StreamAccess`, engine `remote_poll = 0.25`.
- **Examined commit SHA:** `a42b672...`, `e7fb1db...`.
- **Current responsibility:** Knowledge chunk full-text search per tenant/namespace; SSE run event streams that
  any API replica can serve by polling the event table.
- **Dependencies:** orkexa `Index`/`Chunk`/`Hit` base classes (search), `RunEvent`/`RunManager` (SSE).
- **Suitability:** Medium as concept.
- **Decision:** Search **Concept only** (generated `tsvector` column with `simple` config + app-side
  normalization, GIN index, prefix queries); SSE **Concept only** (resume with `Last-Event-ID`, snapshot first,
  periodic access re-check, keep-alive, events persisted with per-stream `seq`).
- **Required adaptations:** generic event stream table `(tenant_id, stream, seq, type, data, created_at)`,
  `LISTEN/NOTIFY` fan-out with polling fallback, WebSocket option; search: per-module indexing API, optional
  `unaccent` and language configs, pgvector later.
- **Security aspects:** stream authorization re-checked every 15 s (A-04); tenant filter in every search query;
  `to_tsquery` input built only from normalized word characters (no user-supplied operators).
- **Required tests:** reconnect with `Last-Event-ID` gets missing events exactly once; stream ends on access loss;
  search tenant isolation; diacritics-insensitive matching.
- **License and provenance:** concept; header citing `postgres_tables.py` at `a42b672...` if `search_words`/
  `_tsquery` are copied.
- **Possible later Nodestro migration:** Nodestro's run event log could become an Axentra event stream
  (`stream = "run:<id>"`).

### 3.18 Notify, webhooks, billing

- **Source:** none. No e-mail sending, webhook delivery (outgoing HMAC-signed requests) or billing code exists in
  nodestro-api or nodestro-runtime at the examined commits (searched for `webhook`, `smtplib`, `hmac.new`).
- **Decision:** **Do not adopt** (nothing to adopt); Axentra designs these fresh on top of its job queue (3.8),
  secrets (3.9), audit (3.13) and usage (3.16).

### 3.19 Deployment (nodestro-server)

- **Source repo and file:** `nodestro-server/compose/compose.yaml`, `image/Dockerfile`, `image/install.py`,
  `docs/RUNBOOK.md`, `scripts/dev-secrets.py`, `scripts/scan_secrets.py`, `scripts/e2e.sh`,
  `tests/e2e/test_acceptance.py`, `.github/workflows/{ci,publish,release}.yml`. There is **no Helm chart or
  Kubernetes manifest** (RUNBOOK lists Kubernetes as untested).
- **Examined commit SHA:** `42e95af25ad20466c4b78211272eeefd45b2c57b`.
- **Current responsibility:** Development/e2e stack: PostgreSQL 17 (password from file secret, `pg_isready`
  health), Dex v2.44.0 as OIDC provider, Docker-in-Docker sandbox with TLS client certs, model stub, one-shot
  `migrate` service (`migrate --backup-dir`), `api` and `worker` services from one image (`x-server` anchor), all
  ports on `127.0.0.1`, secrets via Compose `secrets:` + `*_FILE` variables. Image: multi-stage, base images pinned
  by digest, Node build of the studio, venv in `/opt/nodestro/venv`, `tini` entrypoint, non-root uid 10001,
  docker CLI downloaded with SHA-256 check, BuildKit secrets for tokens/CA, third-party license bundle, release
  artifact secret scan.
- **Dependencies:** Nodestro image contents, Docker sandbox (product-specific), Dex config template.
- **Suitability:** Good template for Axentra's own dev stack and image hygiene.
- **Decision:** **Concept only** (structure: migrate-then-serve one-shot, api/worker from one image, file
  secrets, digest-pinned bases, non-root, tini, health checks, Dex for OIDC e2e); `dev-secrets.py` and
  `scan_secrets.py` **Adapt**.
- **Required adaptations:** Axentra adds a Helm chart (Deployment for api, Deployment for worker, Job/hook for
  migrate, Secret mounts, PodDisruptionBudget, probes on `/health`), and object storage (MinIO) in the dev stack;
  no Docker-in-Docker.
- **Security aspects:** secrets never in image layers (BuildKit secrets), never on command lines; ports bound to
  loopback; API behind a TLS proxy, never published directly (RUNBOOK L244); container users non-root; secret scan
  of release artifacts including image tarballs.
- **Required tests:** e2e acceptance like `test_acceptance.py` (refuses incomplete config, ready, anonymous
  refused, OIDC login via Dex, wrong password gets no session, cross-origin refused, tenant isolation, worker
  killed mid-job, backup and restore with `pg_dump`).
- **License and provenance:** MIT, Peter Karlhuber; headers on adapted scripts citing `42e95af...`.
- **Possible later Nodestro migration:** Nodestro's compose can include Axentra's services if Nodestro adopts
  Axentra components.

### 3.20 SDK structure and OpenAPI contract (nodestro-sdk)

- **Source repo and file:** `nodestro-sdk/Makefile`, `openapi/nodestro-api.json`,
  `python/src/nodestro_client/{_http.py,client.py,published.py,errors.py,models.py}`,
  `python/tests/test_contract.py`, `typescript/src/{http.ts,client.ts,published.ts,errors.ts,generated/openapi.ts}`,
  `typescript/package.json`; generator `nodestro-api/src/nodestro_api/openapi.py` (`document()` builds the app on a
  temporary data directory and returns `app.openapi()`; `text()` = `json.dumps(indent=2, sort_keys=True,
  ensure_ascii=False)`); committed copy `nodestro-api/openapi/nodestro-api.json` checked by a test.
- **Examined commit SHA:** `05080f69ee8337c3043167e2ef9b694b61370b27` (sdk), `e7fb1db...` (api).
- **Current responsibility:** Plain HTTP clients in Python (httpx, sync, `TypedDict` models generated with
  `datamodel-codegen --output-model-type typing.TypedDict --target-python-version 3.10`) and TypeScript (ES modules,
  `fetch`, types from `openapi-typescript 7.8.0`, vitest), sharing behavior: retries only for safe methods (and
  idempotency-keyed starts) on connection errors and 502/503/504 (3 attempts, exponential backoff 0.5 s doubling,
  cap 8 s, +-25 % jitter), redirects refused (`http_redirect`, so keys never go elsewhere), one error class with
  `status/code/params`, percent-encoded path segments refusing `.`/`..`, base URL without credentials/query.
  Contract tests: committed OpenAPI equals the pinned API's `nodestro_api.openapi.text()` and the running server's
  `/api/openapi.json` (paths and component schemas); CI checks the generated types are current.
- **Dependencies:** none at runtime besides httpx / fetch.
- **Suitability:** High as a pattern.
- **Decision:** **Adapt** (repository layout, Makefile targets `contract`/`generate`, contract tests, `_http.py`
  retry/redirect/path rules).
- **Required adaptations:** Axentra's OpenAPI document generated from its own app factory; RFC 9457 error parsing;
  async Python client option; auth helpers for API keys and OAuth client credentials.
- **Security aspects:** no redirects followed with credentials; no retries of non-idempotent requests; path
  injection prevented; README warns against embedding keys in browser code.
- **Required tests:** contract equality, generated types current, retry policy unit tests, redirect refusal,
  path segment encoding, package consumer test (`scripts/check_typescript_package.sh`).
- **License and provenance:** MIT, Peter Karlhuber; headers citing `nodestro-sdk/python/src/nodestro_client/_http.py`
  (and TS counterparts) at `05080f6...`.
- **Possible later Nodestro migration:** none needed; independent clients.

### 3.21 Studio frontend architecture (UI inspiration only)

- **Source repo and file:** `nodestro-studio/frontend/package.json`, `vite.config.ts`,
  `src/i18n/{index.ts,resources.ts,i18n.test.tsx,quality.test.ts}`, `src/i18n/locales/<lang>/*.json`,
  `src/styles/midnight-citron.css`, `src/styles/app.css`, `src/api/{client.ts,access.ts,retry.ts}`,
  `src/lib/errors.tsx`, `src/test/setup.ts`, `e2e/*.mjs`; docs `docs/i18n/`.
- **Examined commit SHA:** `8e18caecea17b2fab5a837359a324896b565c313`.
- **Current responsibility:** React 19.1 + TypeScript 5.8 + Vite 6 single-page app; routing `react-router-dom` 7;
  server state `@tanstack/react-query` 5; client state `zustand` 5; icons `lucide-react`; i18next 26 /
  react-i18next 17 with six languages (de, en, es, fr, pt-BR, it), one JSON file per area and language, English in
  the main chunk and other languages lazy-loaded chunks, browser language detection, user choice in
  `localStorage` (`nodestro-language`) and backend settings; quality tests for key parity, plural forms, untranslated
  texts and backend error codes. Theme: semantic CSS custom properties `--nd-*` ("Midnight Citron 1.0"), dark default
  on `:root, [data-theme="dark"]`, light on `[data-theme="light"]`, components use only role tokens. Tests: vitest
  with jsdom, Testing Library, `TZ=UTC`, German as test language; e2e Node scripts (smoke, i18n, a11y with
  axe-core). `api/access.ts` hides controls by permission from `/api/auth/me` while the API stays authoritative.
- **Dependencies:** none relevant to Axentra's backend.
- **Suitability:** inspiration for an Axentra admin UI (the separate `axentra-studio` repository).
- **Decision:** **Concept only** (no code or tokens copied; brand colors are Nodestro's).
- **Required adaptations:** Axentra's own token namespace (`--ax-*`), same role-based token approach, same i18n
  contract (error `code` + `params` -> `errors.<code>`), same lazy-loaded language bundles and quality tests.
- **Security aspects:** UI permission checks are cosmetic; CSRF is handled by same-origin + cookies; no secrets in
  the browser.
- **License and provenance:** concept only; if any file is copied later, header citing the studio path at
  `8e18cae...`.
- **Possible later Nodestro migration:** n/a.

### 3.22 Other repositories (glance)

- **nodestro-local-docker** (`b98df28...`): single-user container built from nodestro-server's Dockerfile target
  `local`; access key and launch cookie (`nodestro-api/src/nodestro_api/launch.py`: one-time or reusable launch
  secret exchanged for an `HttpOnly; SameSite=Strict` cookie, `hmac.compare_digest`) - **Concept only** for a
  possible Axentra "local dev mode"; not relevant otherwise.
- **nodestro-desktop** (`80df14d...`): Tauri 2 shell bundling CPython 3.13 (ADR-0005) - **Do not adopt**.

---

## 4. Summary

| # | Component | Source (repo/file) | Decision | Main reasons / key adaptation |
| --- | --- | --- | --- | --- |
| 3.1 | OIDC login (PKCE, state, nonce, login CSRF cookie) | api `identity.py` | Adapt | Rename, async, JWKS TTL, multi-provider, RFC 9457 |
| 3.2 | Sessions, users, memberships, bootstrap | runtime `identity_store.py`, `0003_identity.sql` | Adapt | Data-driven roles, public DB API, audit |
| 3.3 | Permissions, principal, route registry | api `permissions.py` | Adapt | `resource:action` permissions, key/service principals |
| 3.4 | SameOrigin middleware, log redaction | api `identity.py` | Adopt | Origin list, WebSocket, explicit missing-Origin policy |
| 3.4 | Proxy trust / local access | api `server.py`, `local_access.py` | Concept only | Explicit trusted-proxy CIDRs |
| 3.5 | Tenancy | runtime `storage_postgres.py`, api `identity.py` | Adapt | Add RLS, tenant lifecycle |
| 3.6 | PostgreSQL layer + migration runner | runtime `storage_postgres.py` | Adopt | Per-module migrations, non-transactional steps |
| 3.7 | Document store | runtime `storage.py`, `storage_postgres.py` | Concept only | Typed SQL tables instead |
| 3.8 | Job queue / leases / reaper | runtime `jobs.py`, `0004_jobs.sql` | Adapt | Retries, `run_after`, handlers, NOTIFY |
| 3.8 | LeaderLock, ScheduleFirings | runtime `jobs.py` | Adopt | Rename |
| 3.8 | RunWorker, QueuedRuns, event log | runtime `jobs.py`, api `worker.py` | Concept only / Adapt (event log) | Product-coupled |
| 3.9 | Settings + SecretBox | runtime `server_settings.py` | Adapt | Key ids, keyring, rotation job, KMS option |
| 3.10 | API keys | api `serving.py`, `api_keys.py` | Adapt | `axk_` prefix, tenant-bound SQL table, optional pepper |
| 3.11 | Rate limiting | api `serving.py` `_Window` | Do not adopt (prod) | Per-process only; shared limiter needed |
| 3.11 | Idempotency keys | api `serving.py` `launch` | Concept only | Generic SQL-backed middleware |
| 3.12 | Problems / errors | runtime `problems.py`, api `api.py`, `serving.py` | Concept only | RFC 9457 + `code`/`params` |
| 3.13 | Audit | runtime `tool_approvals.py`, `tool_journal.py` | Concept only | Append-only SQL audit |
| 3.13 | DB health check | api `server_app.py` `DatabaseHealth` | Adapt | Readiness/liveness split |
| 3.13 | Traces import | runtime `traces.py` | Do not adopt | Product feature, not observability |
| 3.14 | Secret redaction | runtime `sanitize.py`, server `scan_secrets.py` | Adopt / Adapt | Add Axentra patterns, log filter |
| 3.15 | File storage | runtime `input_files.py`, `file_formats.py`, `file_delivery.py` | Concept only | Object storage; reuse safety checks |
| 3.16 | Usage / cost tracking | runtime `usage_log.py`, `cost_tracking.py` | Concept only | Generic metering, orkexa-bound today |
| 3.17 | Search / SSE realtime | runtime `postgres_tables.py`, api `serving.py` | Concept only | Generic event streams, NOTIFY |
| 3.18 | Notify, webhooks, billing | (none) | Do not adopt | Not present in Nodestro |
| 3.19 | Deployment | server `compose.yaml`, `Dockerfile`, scripts | Concept only / Adapt (scripts) | Add Helm, MinIO |
| 3.20 | SDK + OpenAPI contract | sdk, api `openapi.py` | Adapt | Contract tests, retry rules |
| 3.21 | Studio frontend | studio `frontend/` | Concept only | Token/i18n approach for admin UI |
| 3.22 | Local docker / desktop | local-docker, desktop | Concept only / Do not adopt | - |

## 5. Python version decision input

What Nodestro declares and tests at the examined commits:

| Repository | `requires-python` | CI matrix | Other |
| --- | --- | --- | --- |
| nodestro-runtime | `>=3.10` | `["3.10", "3.13"]` (ubuntu-latest, PostgreSQL 17 service); docker/other jobs 3.13 only; `pip-audit` on 3.13 | classifiers list only 3.10 and 3.13; `ruff target-version = "py310"`; `mypy python_version = "3.10"`, strict; `mcp>=2.3` only for `python_version >= '3.11'` (MCP unavailable on 3.10) |
| nodestro-api | `>=3.10` | `["3.10", "3.13"]` with PostgreSQL 17; network tests and audit on 3.13 | same ruff/mypy targets |
| nodestro-sdk (Python) | `>=3.10` | `["3.10", "3.13"]`; TypeScript on Node 20 and 22 | generated models target 3.10 |
| nodestro-studio | `>=3.10` | `ci.yml` and `platform.yml` `["3.10", "3.13"]` | `tomli` for `< 3.11` |
| nodestro-server / local-docker | image `python:3.13-slim` (digest-pinned) | lint/tests on 3.13 | production runtime is 3.13 only |
| nodestro-desktop | bundled CPython 3.13 | 3.13 | ADR-0005: "the same minor version CI tests, 3.13" |

Observations for Axentra:

- Nodestro tests only the two ends of its range (3.10 and 3.13); 3.11 and 3.12 are untested, and 3.14 is not tested
  at all. Its deployed artifacts (server image, local Docker, desktop) all run 3.13.
- **Python 3.10 reached end of life in October 2026** (PEP 619; final security release), i.e. it is already EOL
  at the time of this analysis (2026-11-01). 3.11 reaches EOL in October 2027, 3.12 in October 2028, 3.13 in
  October 2029; 3.14 (released October 2025) is supported until October 2030.
- Code ported from Nodestro is written for 3.10 (`from __future__ import annotations`, `X | Y` unions, no
  `typing.Self`, no `ExceptionGroup`/`TaskGroup`); it runs unchanged on 3.11+. Axentra can use 3.11+ features
  (`TaskGroup`, `tomllib`, `ExceptionGroup`, `typing.Self`) or 3.12+ features (PEP 695 generics, `@override`)
  freely, which does not hinder porting.
- Dependencies used by the ported code (psycopg 3.2+, cryptography 42+, PyJWT 2.9+, FastAPI, httpx, pydantic 2)
  support 3.11-3.14.
- Recommendation input (decision is Axentra's): `requires-python = ">=3.12"` with a CI matrix of 3.12, 3.13 and
  3.14 (all supported minors tested, not just the ends), images on 3.13 or 3.14; `ruff target-version = "py312"`,
  `mypy python_version = "3.12"`. Choosing `>=3.11` would buy one more year of compatibility for only one year of
  remaining upstream support. Supporting 3.10 is not advisable for a new project.
