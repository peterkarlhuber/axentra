# Axentra HTTP API conventions (v1)

This document is the binding contract for every HTTP endpoint of Axentra. The machine-readable
contract is the committed OpenAPI document `openapi/axentra-v1.json`, generated from the code
(`axentra openapi export`) and checked for drift in CI. Clients (the TypeScript SDK, the Python
SDK and Axentra Studio) must rely only on what that document describes.

## Base path and versioning

- All endpoints live under `/v1`. A breaking change requires a new major path (`/v2`) and a
  migration note; `/v1` stays served for at least one minor release after `/v2` ships.
- Additive changes (new endpoints, new optional fields, new enum values documented as open)
  bump the API minor version (`api_version` in `GET /v1/meta`, e.g. `1.3`).
- Every response carries `Axentra-API-Version: <major.minor>`.
- Clients send `Axentra-Client: <name>/<version>; api=<major.minor>` (optional). Clients must
  call `GET /v1/meta` at startup and refuse to run with a clear message when
  `api_version.major` differs or `api_version.minor` is lower than the minor they were built for.

## Identifiers

Opaque, prefixed, URL-safe strings: `prd_` product, `ten_` tenant, `usr_` user, `mem_` membership,
`inv_` invitation, `rol_` custom role, `key_` API key, `ses_` session, `aud_` audit event,
`rec_` record, `fil_` file, `job_` job, `evt_` event, `whk_` webhook, `dlv_` delivery,
`pln_` plan, `sub_` subscription, `tpl_` template, `msg_` message, `sdoc_` search document. Clients must not parse them.

## Authentication

- Browser sessions: `POST /v1/auth/login/password` or the OIDC flow
  (`GET /v1/auth/oidc/{provider}/start` -> IdP -> `/v1/auth/oidc/{provider}/callback`) set an
  `HttpOnly; Secure; SameSite=Lax` session cookie (`__Host-axentra-session`; on plain-HTTP
  loopback development `axentra-session`). The database stores only a SHA-256 hash of the token.
- Changing requests authenticated by cookie must send `X-Axentra-CSRF: <csrf_token>` (from
  `GET /v1/auth/session`) and, when present, an `Origin` from `security.allowed_origins`.
- Machines: `Authorization: Bearer axk_<id>_<secret>` (API key, product scoped, optionally tenant
  scoped, explicit permission list). Keys are shown exactly once.
- Unauthenticated requests to protected endpoints: `401`. Authenticated but not permitted:
  `403`. Resources outside the caller's product/tenant scope: `404` (no existence oracle).

## Scoping

Product and tenant scope are explicit in the path:
`/v1/products/{product_id}/...` and `/v1/products/{product_id}/tenants/{tenant_id}/...`.
The server always checks that the authenticated principal may act in that scope; supplying a
foreign id never grants access. In single-product mode there is exactly one product; its id is
reported by `GET /v1/meta` (`product`).

## Requests and responses

- JSON (`application/json`), UTF-8, `snake_case` fields, timestamps RFC 3339 UTC.
- Lists: `GET ...?limit=50&cursor=<opaque>` -> `{"items": [...], "next_cursor": "..." | null}`;
  `limit` 1..200 (default 50). Filters are plain query parameters documented per endpoint;
  `sort` takes a documented field, prefixed with `-` for descending.
- Optimistic concurrency: resources with a `version` integer accept `If-Match: <version>` on
  `PUT/PATCH/DELETE`; a mismatch returns `412`.
- Idempotency: creating endpoints with side effects that cost money or count usage accept
  `Idempotency-Key`; repeating the key with the same body returns the original result.

## Errors

RFC 9457 problem details, `application/problem+json`:

```json
{"type": "https://axentra.dev/problems/not_found", "title": "Not found", "status": 404,
 "code": "not_found", "detail": "...", "request_id": "req_..."}
```

`code` is stable and machine readable. The codes a client can receive:

| Status | Codes |
| ------ | ----- |
| 400 | `bad_request` (unreadable request), `validation_failed`, `invalid_cursor` (malformed or tampered `cursor`), `invalid_signature` (billing provider webhook) |
| 401 | `unauthenticated` |
| 403 | `forbidden`, `reauthentication_required` |
| 404 | `not_found`, `module_disabled` |
| 405 | `method_not_allowed` |
| 409 | `conflict`, `setup_already_completed`, `email_taken`, `mode_not_supported`, `payment_provider_not_configured` |
| 412 | `precondition_failed` |
| 413 | `payload_too_large` |
| 415 | `unsupported_media_type` |
| 422 | `validation_failed` |
| 429 | `rate_limited`, `quota_exceeded` |
| 5xx | `internal` (never with details) |
| other | `error` (a framework-level HTTP error without a more specific code) |

More specific codes may be added within a status (for example `setup_already_completed` and
`email_taken` are conflicts); a client that does not know a code handles it by its HTTP status.
Validation errors add `errors: [{loc, msg}]`. Details never contain secrets, tokens, SQL or stack
traces.

## Correlation

Every response carries `X-Request-ID` (incoming value is accepted if it matches
`[A-Za-z0-9._-]{1,64}`, otherwise a new one is generated). Audit events and logs record it.
