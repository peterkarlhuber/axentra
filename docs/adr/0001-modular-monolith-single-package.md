# ADR 0001: Modular monolith in a single package

Status: accepted (Phase 0)

## Context

Axentra bundles identity, tenancy, access, data, audit and (planned) storage, events/jobs,
usage, billing and notifications. These modules share one database, one security context and
one transaction boundary: an authorization check, the data change and its audit event must
commit together. Options were one package per module (`axentra-identity`, `axentra-tenancy`,
...) or one package with internal modules.

## Decision

One installable Python package, `axentra`, with internal modules (`axentra.identity`,
`axentra.tenancy`, ...) and **extras** for heavy or optional dependencies: `server` (FastAPI,
uvicorn), `oidc`, `s3`, `otel`, `all`, `dev`. The core install (pydantic, psycopg, cryptography,
argon2-cffi) works as a library without any web framework. Modules can be switched off at runtime
(`modules = [...]`); identity, tenancy, access and audit cannot.

Module boundaries are enforced inside the package: import-linter contracts, an architecture test
(`tests/unit/test_architecture.py`) and the CI package job (see
[OVERVIEW](../architecture/OVERVIEW.md#layering-rules)).

## Why not multiple packages

- Modules depend on each other's tables and on one migration sequence; separate packages would
  need cross-package version constraints for every schema change.
- One version, one changelog, one OpenAPI contract, one compatibility matrix with Studio.
- Shared transactions are trivial in-process and would need distributed coordination across
  services.
- Splitting later is still possible because boundaries are already enforced; merging packages
  back is harder.

## Consequences

- Installing `axentra` installs the code of all modules (small), but not their heavy
  dependencies unless the extra is chosen.
- A module cannot be released independently; releases are coordinated.
- Discipline is required: domain modules must not import the HTTP layer, and CI checks it.
