# Roadmap

Every phase covers the backend (this repository) **and** Axentra Studio
([peterkarlhuber/axentra-studio](https://github.com/peterkarlhuber/axentra-studio)); Studio grows
with each backend module. Open items in detail: [TODO.md](TODO.md).

Status as of 2026-11-02. Evidence for every phase: [AXENTRA_IMPLEMENTATION_REPORT.md](AXENTRA_IMPLEMENTATION_REPORT.md).

| Phase | Scope | Status |
|---|---|---|
| 0 | Architecture, branding, foundations | done |
| 1 | Backend foundation + Studio v1 | done (backend PRs #1, #2) |
| 2 | Infrastructure modules + UI | done (backend PRs #3-#5; search module added later, no vector search) |
| 3 | SaaS business services + UI | done (backend PR #4) |
| 4 | Developer experience + complete Studio | done for the backend (PR #7); open items in TODO.md |
| 5 | Hardening and acceptance | in progress (PRs #8, #9; open verification items in TODO.md) |
| 6 | Nodestro integration preparation (analysis only) | plan written |

## Phase 0: Architecture, branding and foundations (done)

Architecture overview, ADRs, Nodestro reuse analysis, security and data model, API conventions,
versioning and compatibility strategy, CI for both repositories, development environment,
single/multi-product decision, frontend architecture, design system from the logo, UX and
navigation, UI test strategy, integration strategy.

## Phase 1: Backend foundation + Studio v1 (done)

Backend: core, identity (users, passwords, sessions, setup, throttling, OIDC login),
tenancy, access (roles, API keys), data (records, migrations, RLS), config and secrets, basic
audit, FastAPI API `/v1`, local Docker environment (Dockerfile, compose for both modes).
Studio: login/logout, shell, dashboard, products, tenants/organizations, users and memberships,
roles and permissions, settings, light/dark mode, branding, responsive layout.

Implemented in this repository: everything listed for the backend.

## Phase 2: Infrastructure modules + UI (done)

Storage (local, S3-compatible), events/jobs/webhooks, usage metering, first realtime channel
(server-sent events), more audit and observability (metrics, tracing). Studio: files, jobs and
events, usage overview and charts, audit and monitoring views. Module documentation:
`docs/modules/*`, `docs/operations/OBSERVABILITY.md`. Search: tenant-scoped PostgreSQL full-text
search with a pluggable adapter interface (`docs/modules/SEARCH.md`); vector search and external
adapters are open (see TODO.md).

## Phase 3: SaaS business services + UI (done)

Billing (plans, subscriptions), entitlements, notifications, usage extensions, provider adapters
with test doubles. Studio: plans, subscriptions, entitlements, quotas, notifications, provider
configuration. Module documentation: `docs/modules/BILLING.md`, `NOTIFY.md`, `USAGE.md`.

## Phase 4: Developer experience + complete Studio (done for the backend)

Python SDK (hand-maintained, contract-tested) and TypeScript SDK (generated from the committed
OpenAPI) - both in `sdk/`, see docs/sdk/ - complete OpenAPI, CLI
extensions, configuration examples, a demo SaaS application, installation/development/deployment/
backup documentation, single- and multi-product example configurations. Studio polished and
complete in German and English.

## Phase 5: Hardening and acceptance (in progress)

Architecture, unit, PostgreSQL integration, contract, SDK and isolation tests; single- and
multi-product deployment tests; concurrency and worker-restart tests; migration and
backup/restore tests; reproducible containers; security and dependency scans; frontend unit,
end-to-end, accessibility and responsive tests; screenshots; cross-repository compatibility tests.

Already started: backup/restore integration test, product-table template test, container build
and compose validation in CI, dependency audit and bandit in CI. Backend hardening done: key
rotation with `axentra secrets reencrypt`, record audit events, request body and rate limits,
production default for API docs, product migration discovery for `axentra migrate`.

## Phase 6: Nodestro integration preparation (plan written, analysis only)

The migration plan [integrations/NODESTRO_MIGRATION_PLAN.md](integrations/NODESTRO_MIGRATION_PLAN.md)
describes how Nodestro could adopt Axentra, based on
[NODESTRO_REUSE.md](architecture/NODESTRO_REUSE.md). No code changes in Nodestro, and no
dependency of Axentra on Nodestro. The migration itself is a separate, optional future project,
not a prerequisite for any Axentra release; the generic Axentra gaps it lists (G-1 to G-8) are
tracked like any other Axentra work.
