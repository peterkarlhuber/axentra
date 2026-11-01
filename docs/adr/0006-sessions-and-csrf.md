# ADR 0006: Server-side sessions with CSRF header and origin checks

Status: accepted (Phase 0)

## Context

Browser clients (Studio, product frontends) need login sessions that can be revoked immediately
(logout, disabled user, password change, admin action). Stateless JWTs in the browser cannot be
revoked without a server-side list and tempt storage in JavaScript-readable places.

## Decision

- Opaque random session tokens (256 bit), stored only as SHA-256 hashes, with absolute and idle
  expiry and revocation.
- Delivered as an `HttpOnly; SameSite=Lax` cookie, `Secure` and `__Host-` prefixed on HTTPS.
- Each session has a CSRF token, returned by login and `GET /v1/auth/session`. Cookie-authenticated
  `POST/PUT/PATCH/DELETE` requests must send it in `X-Axentra-CSRF`, and their `Origin` (if sent)
  must be the public URL or an allowed origin. Login and setup check the origin (login CSRF).
- The same token may be sent as `Authorization: Bearer` by non-browser clients; then no CSRF token
  is needed.

## Consequences

- One database lookup per request (with `last_seen_at` written at most once a minute).
- Cross-site frontends must be listed in `security.allowed_origins` and use credentialed CORS.
- Revocation is immediate.
