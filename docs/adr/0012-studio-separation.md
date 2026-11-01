# ADR 0012: Axentra Studio is a separate client

Status: accepted (Phase 0)

## Context

Axentra needs an admin UI, but must stay usable headless, embeddable as a library, and
independent of any frontend stack. A UI bundled in the backend tempts private endpoints and
couples release cycles.

## Decision

- Axentra Studio lives in its own repository (`peterkarlhuber/axentra-studio`) with its own
  releases.
- Studio uses only the public, versioned HTTP API, typed from the committed OpenAPI document
  (vendored copy, generated TypeScript types). There are no Studio-only endpoints.
- Axentra never depends on Studio (import-linter contract, architecture test, CI check of
  installed packages). Studio authenticates like any browser client (session cookie + CSRF), and
  its origin must be listed in `security.allowed_origins`.
- Compatibility is checked at runtime (`/v1/meta` API version) and recorded in
  [docs/COMPATIBILITY.md](../COMPATIBILITY.md) ([VERSIONING](../architecture/VERSIONING.md)).

## Consequences

- Everything Studio can do, any API client can do with the same permissions; security never
  relies on the UI.
- API changes needed by Studio go through the normal contract process (OpenAPI diff, API minor).
- Two repositories must be kept in step; the compatibility matrix and contract tests make that
  visible.
