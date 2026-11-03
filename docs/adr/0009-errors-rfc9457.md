# ADR 0009: RFC 9457 problem details with stable codes

Status: accepted (Phase 0)

## Context

Clients (Studio, SDKs) must react to errors programmatically and show useful messages, without
the API leaking internals.

## Decision

- Every error response is `application/problem+json` (RFC 9457) with `type`
  (`urn:axentra:problem:<code>`, see the amendment below), `title`, `status`, `detail`, plus `code` (stable,
  machine-readable) and `request_id`. Validation errors add `errors: [{loc, msg}]`.
- Domain code raises `axentra.core.errors` classes, each with a fixed `code` and HTTP status
  (`validation_failed` 422, `unauthenticated` 401, `forbidden` 403, `not_found` 404, `conflict`
  409, `precondition_failed` 412, `payload_too_large` 413, `rate_limited` 429, `quota_exceeded`
  429, `mode_not_supported` 409, ...).
- `detail` is redacted; 5xx responses never carry exception text, SQL or stack traces (logged
  server-side with the request id instead). `429` responses carry `Retry-After`.

## Consequences

- Clients switch on `code`, not on `detail` text; new codes are additive (API minor bump).
- Domain modules stay independent of HTTP while still defining the status.

## Amendment (2026-11-03): problem type URIs

The `type` URIs were `https://axentra.dev/problems/<code>`. That domain belongs to an unrelated
company and answers `404` (DX review round 2, DX-41), so the URIs pointed clients at a third party.
They are now `urn:axentra:problem:<code>`:

- RFC 9457 allows `type` URIs that are not dereferenceable; a URN cannot be mistaken for a link,
  stays stable across hosting or documentation moves, and names no domain the project does not own.
- `about:blank` would drop the per-code identity; a `tag:` URI needs an authority the project owns
  (it has no own domain yet); a repository documentation URL would tie the identifier to a branch
  and file path. The `axentra` URN namespace is not IANA-registered; it is used as a private,
  opaque identifier.
- Compatibility: clients switch on `code` (this ADR); Axentra Studio and both SDKs never read
  `type` (only test fixtures and help examples show it). A client that matched the old prefix
  must match `urn:axentra:problem:` or, better, `code`.
- The product name collides with that company's; branding is tracked in `docs/TODO.md`.
