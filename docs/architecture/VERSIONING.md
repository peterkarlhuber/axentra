# Versioning and compatibility

Axentra has three version numbers that move independently:

| What | Where | Rule |
|---|---|---|
| Package version | `src/axentra/_version.py`, `axentra --version`, `meta.version` | [SemVer 2.0](https://semver.org/) for the Python package (library API, CLI, configuration, migrations). Pre-1.0 (`0.y.z`), minor releases may break; breaking changes are listed in the changelog |
| HTTP API major | URL path `/v1` | A breaking HTTP change needs a new path (`/v2`); `/v1` stays served for at least one minor release after `/v2` ships |
| HTTP API minor | `meta.api_version.minor`, header `Axentra-API-Version: 1.0` | Bumped for additive changes: new endpoints, new optional request fields, new response fields, new enum values documented as open |

`axentra.API_VERSION` (currently `(1, 0)`) is the single source for the API version. Database
migrations are forward-only and checksummed; a package release never edits an applied migration.

## What counts as breaking (HTTP)

Removing or renaming an endpoint, field or enum value; making an optional field required;
changing a type, a status code or an error `code`; tightening validation of existing input;
changing authorization so that previously allowed calls fail. Clients must ignore unknown
response fields and unknown open enum values, so adding them is not breaking.

## Contract artifacts

- **Committed OpenAPI.** `openapi/axentra-v1.json` is generated from the code with
  `axentra openapi export` (multi-product mode, all modules enabled) and committed. CI runs
  `axentra openapi export --check`, which fails when the committed file differs from the code
  ("drift check"). Every API change therefore shows up in review as a diff of this file.
- **SDKs are generated from the committed file**, never from a running server: Studio generates
  its TypeScript types with `openapi-typescript` from a vendored copy (`api/openapi.json`, with its
  origin recorded in `api/SOURCE`). The SDKs in `sdk/` follow the same rule (see below).
- **Contract tests on both sides.** Axentra: `tests/unit/test_openapi.py` (drift, unique
  operation ids) and the HTTP integration tests, which exercise the documented status codes and
  shapes. Studio: tests against the vendored contract and
  its compatibility check (`src/api/compat.ts`).

## SDKs: generation and synchronization

Both SDKs live in this repository (`sdk/typescript`, `sdk/python`) and are versioned with it.
Each declares the API version it was built for and refuses an incompatible server with the rule
above (same major, server minor >= SDK minor) in `checkCompatibility()` / `check_compatibility()`.

| | TypeScript (`@axentra/sdk`) | Python (`axentra-client`) |
|---|---|---|
| Source of truth | The committed `openapi/axentra-v1.json` | Hand-written resource methods (`_async/client.py`; the sync client is generated from it by `scripts/unasync.py`) |
| Generation | `npm run generate`: openapi-typescript (pinned) writes `src/schema.d.ts` and `src/generated.ts` (`GENERATED_API_VERSION` from `info.version`, contract SHA-256). The client is generic over the generated `paths`, so there is no per-endpoint code | None for the API surface; models in `models.py` follow the contract by hand |
| Staleness check | CI `sdk-typescript` runs `npm run generate:check`, which fails when the generated files differ from what the committed OpenAPI produces | Unit tests: every path the client calls must exist in the committed OpenAPI; `API_VERSION` must equal `info.version`; the sync client must match `unasync` output |
| Contract tests | `npm run test:e2e` against a live server | `tests/integration` (in-process server, real PostgreSQL) and `tests/e2e` (live server) |
| New endpoints | Picked up by regenerating: `axentra openapi export`, then `npm run generate`, commit both | Reachable at once via `request_json()`; typed methods are added by hand with a contract test |

`scripts/sdk-e2e.sh` (CI job `sdk-e2e`) starts a PostgreSQL-backed `axentra serve` with a
temporary database, bootstraps an admin, a product, a tenant and an API key through the API and
runs both SDKs' e2e suites against it, so every change to the server is checked against both
clients. An API change therefore touches, in one pull request: the code, `openapi/axentra-v1.json`,
the regenerated TypeScript types, and (if the Python client should expose it) the Python client.
When `API_VERSION` gets a new minor, the SDKs that start relying on the new endpoints bump the
minor they require (TypeScript: automatically through regeneration).

## Compatibility with Axentra Studio

Studio is a separate repository and release ([ADR 0012](../adr/0012-studio-separation.md)).

1. Each Studio build declares the API version it needs: `REQUIRED_API = { major, minor }`.
2. At startup Studio calls `GET /v1/meta` and refuses to run, with a clear message, when
   `api_version.major` differs or `api_version.minor` is lower than required. A newer minor on
   the server is fine.
3. Studio sends `Axentra-Client: axentra-studio/<version>; api=<major.minor>` (optional; for logs).
4. Combinations that were actually tested together are recorded in
   [docs/COMPATIBILITY.md](../COMPATIBILITY.md) with versions and commits on both sides. Update it
   whenever either side merges a change that affects the contract.

## Release checklist (package)

1. `CHANGELOG.md`: move "Unreleased" to the version, note API minor bumps and breaking changes.
2. Bump `_version.py`; bump `API_VERSION` if the HTTP contract changed; regenerate the OpenAPI.
3. All CI jobs green (lint, types, architecture, contract drift, tests on 3.11/3.12/3.13 with
   PostgreSQL 15/16/17, package, container, security).
4. Update `docs/COMPATIBILITY.md` with the Studio version tested against the release.
