# ADR 0009: RFC 9457 problem details with stable codes

Status: accepted (Phase 0)

## Context

Clients (Studio, SDKs) must react to errors programmatically and show useful messages, without
the API leaking internals.

## Decision

- Every error response is `application/problem+json` (RFC 9457) with `type`
  (`https://axentra.dev/problems/<code>`), `title`, `status`, `detail`, plus `code` (stable,
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
