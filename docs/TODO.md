# Open work

The central, versioned list of open work for Axentra. Priorities: **P0** blocks the next release,
**P1** needed for a production-ready 1.0, **P2** important improvement, **P3** nice to have.
Studio has its own list in its repository; items here mention Studio only where the backend is
involved. Remove an item in the change that completes it.

Last full review: 2026-11-06 against master at 6f73952 (TODO abatement round).
Before that: 2026-11-06 against `fea2fd0` (TODO abatement round 2).
Before that: 2026-11-05 against `b7ddac0` (quality round 3 close-out; TODO consolidated).
Release blockers: none. No item is P0, and none blocks the next planned preview (the Nodestro desktop candidate,
nodestro-desktop DSK-001); the P1 items are needed for a production-ready 1.0, not for a scheduled release.
Before that: 2026-11-04 (`0.1.0.dev0`, internal backend audit round 3 against `e7c06d0`: no regressions; AX3-01
key bounding, AX3-02, AX2-07 and the Dependabot config fixed in the PR that updates this line; new items marked AX3-NN;
login and setup audit events record ip, request id and actor since the round-3 follow-up, UX round 3 handover).
Earlier: 2026-11-03 (internal backend audit round 2: CI on `master` is green again and
the security review rounds are closed, so both items were removed; new items from the audit and the DX review
are marked AX2-NN / DX-NN; AX2-05 and AX2-08 were decided and fixed, so their items were removed; Studio-facing backend items from the UX
round 2 are marked AXS-BN).

## MUP-ONA

Open packages of the cross-repository security and database-backend plan MUP-ONA ([plan](https://github.com/peterkarlhuber/nodestro-studio/blob/master/docs/architecture/mup-ona/MUP-ONA.md)) that touch
Axentra. Axentra stays independent (no runtime or test dependency on orkexa or Nodestro). Each item is removed in
the change that completes its package.

No package is open.

## TABRION

Packages of the Tabrion ecosystem consolidation plan (migration plan, document 06; backlog, document 09) that touch
Axentra, referenced as "TABRION <WP-ID>". Axentra gets no runtime dependency on Tabrion before MIG-AXE-3. A done
package stays listed until the package that replaces it is done.

| Pri | Package | Status | Item |
|---|---|---|---|
| P1 | TABRION MIG-AXE-0 | Done (this change) | Finding B-06-1: database errors carried the values of the server's `DETAIL` text (for example the email of a unique violation) into logs, trace spans, stored error texts and CLI output. Local fix in `axentra.core.db_errors`: `safe_message` / `safe_error_text` (kind, SQLSTATE, constraint), `DbErrorRedactionFilter`, and `install_db_error_redaction`, which wraps the log record factory process-wide (called by `Axentra`, `create_app`, `configure_logging`, `JobWorker` and the CLI) and adds the filter to `axentra.http`, `uvicorn.error` and `logging.lastResort`. OpenTelemetry spans record a redacted exception; job and notification `last_error` and CLI operator errors use the safe text. Problem details unchanged. Security review accepted with conditions; M-1..M-3 and L-1..L-7 fixed in this change. Regression tests: `tests/integration/test_db_error_logging.py` (kept), `tests/unit/test_db_errors_local.py` (local internals)
| P1 | TABRION MIG-AXE-3 | Open | **TABRION MIG-AXE-3 replaces this local filter**: `axentra.core.db_errors` is replaced by `tabrion.errors` (`safe_message`, `classify`, `DbErrorRedactionFilter`) once Tabrion `v0.1.0` is final, installed process-wide as today (record factory); `tests/unit/test_db_errors_local.py` goes with the module, the regression tests in `tests/integration/test_db_error_logging.py` stay unchanged and must stay green. The PR lists every place that turns a database error into text (grep) and gets a security review. Review follow-up (L-2): a lint or grep rule against f-strings and `str(exc)` in logging calls. Re-review residuals (accepted, see `tabrion-planung/reviews/mig-axe-0-security-review.md`): R-1 values in the primary message of pre-formatted messages (e.g. 22P02) are kept, covered by the same lint rule; R-2 `extra=` values are not redacted (Axentra's JSON formatter allow-lists keys, so Axentra itself is unaffected); R-4 non-database lines starting with `HINT:`/`DETAIL:`/`CONTEXT:` are stripped; R-5 about 3 µs per record, add a fast path; R-6 products that replace the record factory without chaining skip it (handler filters still apply)

## Security and external review

Items that need an independent or external review. The audit rounds so far were internal (no independent security
review, no penetration test).

| Pri | Area | Item |
|---|---|---|
| P1 | tests | **Needs external review.** Provider adapters never exercised against live services: Stripe (only `httpx.MockTransport`), S3 (only moto; no MinIO/AWS), SMTP (only an in-process `aiosmtpd`), OIDC (only an in-process stub IdP). Needs a sandbox run without paid calls, reviewed together with the first production-like deployment (see "Release and verification") |

## Release and verification

| Pri | Area | Item |
|---|---|---|
| P1 | operations | No production deployment has been carried out; no production-like environment exists |
| P1 | tests | No load or performance tests; no capacity figures for the API, workers, SSE or the job queue |
| P2 | build | The Taskboard demo stack (`docker-compose.taskboard.yml`) is built in CI but never started; the single- and multi-product stacks are started and smoke-tested by `scripts/compose_smoke.sh` in CI (TODO abatement round 4) |
| P2 | platform | Only Linux is tested (CI `ubuntu-latest`); macOS and Windows are untested for the library, CLI and SDKs |
| P3 | build | **Decided (owner, 2026-11-05), not implemented.** Dependency updates are merged by hand: weekly grouped Dependabot pull requests (Actions; pip and npm minor/patch; Docker digests), cooldown 3 days (7 for pip and npm majors; security updates not delayed), ignored majors listed with reasons in `.github/dependabot.yml`. Owner decision: protect `master` with required CI checks (only jobs of `ci.yml` that run on every pull request) and block force pushes and deletion, with no required approvals and "up to date" off so agent pull requests keep working; auto-merge stays off. Node.js 24 LTS is the next common Node.js version for the TypeScript SDK and its CI (today `engines >=20`, CI 22), coordinated in Q1 2027 after a compatibility check. Both are separate work orders (nodestro-studio ST-052, ST-054). Dependency round 2026-11-05 |

## Backend

| Pri | Area | Item |
|---|---|---|
| P1 | identity | Data subject tooling: user data export and erasure/anonymization across users, memberships, audit |
| P2 | identity | OIDC providers without `email_verified` (Entra ID v2 usually omits it): an explicit, per-provider opt-in (e.g. single-tenant directories only, or mapping a verified-email claim) instead of refusing with `email_not_verified`; must not reopen the "nOAuth" takeover. Documented in `modules/IDENTITY.md`, no setting yet |
| P2 | identity | MFA for password logins: TOTP (design ready in `architecture/MFA_TOTP_DESIGN.md`: enrollment, recovery codes, two-step login, step-up, admin reset, Studio screens, tests; not implemented) and WebAuthn/passkeys later. An implementation is new authentication code and needs an independent security review before it ships |
| P3 | realtime | WebSockets (only SSE exists, polling-based) |
| P2 | search | Optional vector/semantic search through an adapter (e.g. pgvector with an embedding step; order section 4 L) |
| P2 | search | External search adapters (OpenSearch, Meilisearch, ...) implementing `SearchAdapter`; only `PostgresSearchAdapter` exists, and an external engine's audit event cannot be atomic with its write |
| P2 | search | Fuzzy matching (`pg_trgm`), accent folding (`unaccent`), per-tenant or per-document language. Both extensions must be created by a superuser, so they need an installation decision (optional extension with a fallback, or a documented prerequisite). Prefix matching (`match=prefix`) exists since the TODO abatement round |
| P3 | search | Product-wide search across tenants: needs a permission design (who may search every tenant at once, how hits name their tenant). Batch indexing, delete by kind and `metadata` filters exist since TODO abatement round 4. A reindex job does not apply to `PostgresSearchAdapter` (products push their documents; a kind is replaced with delete by kind plus batches); an external adapter would need one |
| P2 | identity | Identity providers are managed only through configuration (`[[oidc]]`); no API (and therefore no Studio view) to list, add or disable providers |
| P3 | migrations | Runner follow-ups (plan G-2; the backup hook, newer-schema refusal, serving gate, `-- axentra:no-transaction` steps, per-migration lock/statement timeouts and `axentra migrate --dry-run` exist): a declared forward-compatible range per namespace (today any unknown applied version fails the gate) and Python (data backfill) migrations |
| P3 | notify | SMS and push adapters (email is the only channel) |
| P3 | usage | `UsageService.record_batch` (`POST .../usage/events/batch`, up to 100 entries under one authorization, meters in one query) lowers 4 meters from 68 to 55 statements; the rest is per entry (idempotency key, counter upserts, quota check, audit). A set-based write of counters and events would cut it further |
| P2 | identity | Optional stricter OIDC auto-linking: require `allowed_email_domains` for linking existing accounts, or skip it for platform admins (review 2026-11-01, I5; documented as a design decision in SECURITY_MODEL.md). Linking can now be turned off per provider (`link_by_verified_email = false`) |
| P2 | identity | Users without an email address: the HTTP API exists since TODO abatement round 4 (`POST /v1/users/external`, `GET/POST/DELETE /v1/users/{uid}/identities`), but Studio has no view for it yet. OIDC login states still use the host clock (login throttling windows use the database clock since round 4) |
| P2 | identity | First password for OIDC-only users through a fresh IdP re-authentication (`prompt=login`/`max_age`) or an emailed link instead of the session-age window (review 2026-11-01, F3 follow-up). The emailed password-reset link exists now but is sent only to users who already have a password |
| P2 | events | Webhook deliveries share the job queue and worker slots with all other kinds; attempts are now time-bounded, but a separate concurrency pool or a per-product cap for deliveries is still missing (AX2-02 follow-up; in progress in a parallel order) |
| P3 | events | Webhook URLs accept any port; decide whether to restrict them (for example 443 and >= 1024). Legacy IPv4 notations are refused at creation since audit round 3 (AX2-07) |
| P3 | events | Schedules whose creator lost access keep firing (their jobs now run without permissions); optionally disable a user's schedules when the user loses product access. API keys of such a creator are refused and listed with `creator_has_access = false` since the TODO abatement round (AX2-01 follow-up) |

## Developer experience (Phase 4)

| Pri | Area | Item |
|---|---|---|
| P2 | api | `/v1` gained additive fields and endpoints in the TODO abatement round (product invitations, `GET /v1/users/{uid}/memberships`, `GET .../jobs/kinds`, `GET .../search/kinds`, `sort=name` for tenants, key states, problem `reason` members, `auth.password_policy` in `/v1/meta`; in round 4 `POST /v1/users/external` and identities, search batches, delete by kind and `metadata`, `GET /v1/me?tenants=`, the caller's inbox routes and the `query_too_expensive` reason), but `API_VERSION` is still `1.0`, so a client cannot require them through the compatibility rule. Bump the minor to `1.1` with the next release (owner decision; the SDKs' `API_VERSION` follows) |
| P2 | sdk | Publish `@axentra/sdk` (npm) and `axentra-client` (PyPI); release process and provenance |
| P3 | branding | The product name collides with an unrelated company that owns `axentra.dev` (problem type URIs no longer use that domain, DX-41); decide on naming/branding before a public release |

## Hardening (Phase 5)

| Pri | Area | Item |
|---|---|---|
| P1 | build | Reproducible container builds: compare the digests of two independent builds and remove what differs (timestamps, file order). The build tools, hatchling included, come from hash-pinned locks since TODO abatement round 4 (`deploy/locks/build.txt`), and the `python:3.13-slim` base is digest-pinned with a CI check since audit round 2 (OPS2-12) |
| P2 | tests | Cross-repository compatibility: Studio's contract and e2e jobs (multi- and single-product mode) run only for the commit pinned in Studio's `api/BACKEND_REF` and only on Studio pull requests; nothing on the Axentra side triggers them for a new Axentra commit (Studio's pin must be moved to a pushed commit that contains this round's changes) |

## Nodestro (Phase 6)

| Pri | Area | Item |
|---|---|---|
| P2 | integration | `docs/integrations/NODESTRO_MIGRATION_PLAN.md`: generic gaps G-1 (product-defined permissions), G-3, G-4, G-6 (re-encryption registry) and G-7 (per-product content-type policy) are done; G-2 follow-ups are listed above. Phase 6 is done on the Axentra side (see ROADMAP.md). Nodestro uses Axentra as a library in its server profile (Python 3.11+ only via an extra marker; see nodestro-runtime docs/AXENTRA.md) |
| Rejected | integration | G-5 (claim token for ownerless tenants): rejected for now. Nodestro's setup links must keep working in every identity mode and across a rollback, so they stay in Nodestro's table and travel through Axentra's OIDC login as host context (`start(context=...)`); a generic claim token is worth adding only for a product without its own store |
| Rejected | jobs | G-8 "jobs module with Nodestro's semantics" (configurable at-most-once delivery, unique active key per `(tenant, kind, ref)`, interrupt-on-lease-loss callbacks, product capacity gates): rejected by architecture decision 2026-11-02. Nodestro's no-duplicate guarantee lives in its run fence, interrupted state, tool journal and approval checkpoints, not in the queue, so these options would be Nodestro semantics in a generic module that no other product needs; Nodestro keeps its run queue permanently (M11 closed; nodestro-runtime `docs/AXENTRA.md`). Axentra jobs stay at least once (`max_attempts=1` for no retry); evidence: `tests/integration/test_job_delivery_semantics.py` |
| Rejected | identity | Endpoint that revokes all of the caller's sessions except the current one (Studio's "Sign out all other sessions"): not needed for now. A user has a handful of sessions; Studio sends `DELETE /v1/auth/sessions/{id}` per session (bounded concurrency, never the session marked `current`, `404` counted as done, partial failures reported), which also keeps one `identity.session.revoke` audit event per session. Worth adding only for atomicity or users with very many sessions |
| P3 | notify | Inbox channel: an Axentra Studio page. The HTTP routes `.../notify/inbox/me` exist since TODO abatement round 4 (a host such as Nodestro can also serve it through its own API) |

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
