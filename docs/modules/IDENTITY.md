# Identity

The identity module answers "who is this?": users, password logins, server-side sessions, the
first-run setup, and logins through an external OpenID Connect provider (Keycloak, Microsoft
Entra ID, Google, Auth0, Dex, ...). It does **not** decide what a user may do — that is the access
module (roles, memberships, authorizer). A login by itself grants nothing.

Code: `src/axentra/identity/` (`service.py` users/sessions/passwords/setup, `oidc.py` OpenID
Connect), HTTP: `src/axentra/api/routes/auth.py`, `users.py`.

## Concepts

- **User** (`axentra_users`): email (unique, case-insensitive, **optional**), name, locale,
  preferences, `status` `active|disabled`, optional Argon2id password hash, optional platform role
  (`platform_admin`, `platform_viewer`). A user created by an OIDC login has no password
  (`has_password: false`). An address (of a user, a tenant or product invitation, a verified
  OIDC or external-user email) is stored trimmed with a lowercased domain and is refused with
  `422 validation_failed` when it has white space, control or format characters (CR/LF, NUL,
  U+2028 ...) or one of `,;<>"()`: no mail could be sent to it.
- **Users without an email address** (`email: null`, migration `0007`): created by an OIDC login
  whose provider sends no verified email (only with `allow_signup_without_email`), by an OIDC
  login with `link_by_verified_email = false` whose address belongs to another user, or by
  `create_user(email=None)` / `create_external_user(...)` in library code. They cannot log in with
  a password or set one, and cannot accept an invitation (invitations are bound to an address);
  add them to tenants with `set_member(user_id=...)`. Notifications to them by user id are
  recorded as `suppressed` with `last_error = "the recipient has no email address"`. Audit events
  and actor labels use the name (or the id) instead of the address.
- **External identity** (`axentra_user_identities`): the pair (issuer, subject) of an OIDC
  provider, linked to exactly one user. The email address is never the identity key.
- **Session** (`axentra_sessions`): the browser holds a random 256-bit token in an `HttpOnly`,
  `SameSite=Lax` cookie (`__Host-axentra-session` on https, `axentra-session` on plain-http
  development); the database stores only its SHA-256 hash and a per-session CSRF token. Clients
  that cannot use cookies (SDKs, CLI) may send the token as `Authorization: Bearer`.
- **Setup token**: one-time token printed by `axentra admin setup-token`; `POST /v1/auth/setup`
  creates the first platform admin with it.
- **Login state** (`axentra_login_states`): one row per started OIDC login, ten minutes.

## Passwords

Argon2id (`argon2-cffi` defaults; hashes are upgraded on login when parameters change). Policy:
`security.password_min_length` (default 12), at most 1024 characters, not equal to the email,
at least four distinct characters. `GET /v1/meta` publishes the lengths (`auth.password_policy:
{min_length, max_length}`) so clients can check before sending. A refused password answers `422
validation_failed` with `reason` (`too_short`, `too_long`, `equals_email`, `too_simple`),
`min_length` and `errors: [{loc: ["body", "password"], msg}]` (`new_password` for a password change),
so a client can mark the field. Unknown accounts are verified against a dummy hash so the
timing stays similar. Failed logins are throttled per IP and per account in one-minute windows stored in
PostgreSQL (`security.login_rate_per_minute`), so the limit holds across API processes. The
throttle counts atomically *before* the password is verified and gives the attempt back after a
successful login (`IdentityService.hit()` / `refund()`; the older `throttle()` + `count_failure()`
pair is check-then-count and kept only for compatibility). Anyone who knows an email can block
password logins of that account for up to a minute (see SECURITY_MODEL.md, "Rate limiting"). Password
login can be switched off with `security.password_login = false` (OIDC only).

**First password for OIDC-only users.** `POST /v1/me/password` needs the current password,
except for users who have none. Those may set one only within `security.fresh_login_minutes`
(default 5) of the session's login (`403` `reauthentication_required` otherwise; log in again
through the provider and retry), and never with `security.first_password = "disabled"`. This keeps
a stolen session from becoming a permanent password login that bypasses the identity provider.

## Password reset and email verification

Both send a single-use link by email (migration 0013, table `axentra_account_tokens`). Only the
SHA-256 of a token is stored; a token is bound to its purpose and to the address it was sent to,
expires (`security.password_reset_minutes`, default 30; `security.email_verification_hours`, default
48), and a new link spends the older open one. The link is
`<notify.account_url>/reset-password?token=axpwr_...` or `.../verify-email?token=axemv_...`
(`notify.account_url` defaults to the origin of `notify.invitation_accept_url`, then to
`security.public_url`; Studio serves both pages).

**Reset.** `POST /v1/auth/password-reset {email, product_id?}` (public, Origin checked) always
answers `202` with an empty body and does the work after the response: whether the address has an
account is never revealed, neither by the answer nor by its timing. An email goes out only to an
active user who has a password and no reset link from the last minute; users without a password
(OIDC-only) never get one, so a reset cannot create a password that bypasses the identity
provider. `POST /v1/auth/password-reset/confirm {token, new_password}` sets the password (the
policy above; a refused password answers `422` and keeps the link usable), spends every open reset
link of the user, marks the address verified (the link arrived there) and **ends all sessions** of
the user. Changing the password with `POST /v1/me/password` also spends open reset links.

**Verification.** `POST /v1/me/email-verification {product_id?}` (signed in) sends a link: `202`,
`409` when the address is already verified or no product of the user can send email, `429` with
`Retry-After` within a minute of the last link. `POST /v1/auth/email-verification/confirm {token}`
(public, no session needed: the link may be opened in another browser) marks the address verified.
`User.email_verified` reports the state. Addresses confirmed by an identity provider
(`email_verified` claim) at sign-up are verified from the start.

**Delivery.** The emails use the built-in sensitive templates `password_reset` and
`email_verification` (see NOTIFY.md; `ax.on_account_email`), sent with the notification settings
of one product: `product_id` from the request when the user belongs to that product (otherwise it
is ignored, so a product's admins learn nothing about other accounts), else the configured product
in single mode, else the oldest active product the user belongs to (as an operator, or as a member of an active
tenant). A user with no such product gets no
reset email (the request is still `202`) and a `409` for verification. Sensitive templates keep
the link out of the message log, so product admins cannot read it.

**Refusals.** Every refused token (unknown, malformed, spent, expired, other purpose, disabled
user, changed address, password removed since) answers the same `400 invalid_token` "the link is
invalid, expired or was already used". Reset requests count per client IP (three times
`security.login_rate_per_minute`, the same budget for known and unknown addresses); the confirm
endpoints count per IP (`login_rate_per_minute`) and give successful attempts back. Both answer
`403` when `security.password_login` is off (verification works without it).

**Audit.** `identity.password.reset_request` (success with the delivering product; `denied` with
`reason` `unknown_email`, `user_disabled`, `no_password`, `cooldown` or `no_delivery_product`,
never with the address), `identity.password.reset` (with `sessions_ended`),
`identity.email.verification_request` and `identity.email.verify`. All are platform-level events.

## Sessions

- Absolute lifetime `security.session_ttl_hours` (default 12), idle timeout
  `security.session_idle_minutes` (default 120; `last_seen_at` is updated at most once a minute).
- **Database clock.** `expires_at` is computed as `now() + ttl` in PostgreSQL, and absolute and
  idle expiry are checked against PostgreSQL's `now()`, never the API host's clock, so clock skew
  between hosts cannot lengthen or shorten sessions. Setup tokens and invitations follow the same
  rule. Login throttling windows and the ten-minute OIDC login state still use the host clock.
- Changing requests with the session cookie need the `X-Axentra-CSRF` header (from
  `GET /v1/auth/session`) and an allowed `Origin`.
- **Revocation semantics.** A session ends on logout, on revocation (own sessions via
  `DELETE /v1/auth/sessions/{id}`, an admin via the users API), when the user is disabled (all
  sessions are revoked and every later request is refused immediately, because each request
  checks the user status), when the password is changed (all *other* sessions), and on expiry.
  Revocation is effective on the next request; there are no long-lived self-contained tokens.
- **OIDC and sessions are independent.** An OIDC login only *starts* an Axentra session. Logging
  out of Axentra does not log the user out at the identity provider (no RP-initiated logout yet),
  and ending the session or disabling the account at the provider does not end an existing
  Axentra session (no back-channel logout yet): it ends at its idle/absolute expiry, or when an
  Axentra admin disables the user or revokes the sessions. Keep `session_ttl_hours` short if
  provider-side deprovisioning must take effect quickly.

## First-run setup

`axentra admin setup-token` prints a one-time token (default 60 minutes,
`security.setup_token_ttl_minutes`). `POST /v1/auth/setup` with the token, email, name and
password creates the first `platform_admin` and starts a session. The token works once and only
while no platform admin exists.

## OpenID Connect

Authorization code flow with PKCE (`S256`), `state` and `nonce`.

1. `GET /v1/auth/oidc/{provider}/start?return_to=...` creates a login state. A login that carries
   an invitation uses `POST /v1/auth/oidc/{provider}/start` with the JSON body
   `{"return_to": ..., "invitation": "<token>"}` instead (Origin checked like the password login):
   same login state and login cookie, answered with `200 {"redirect_url": ...}` (the provider URL,
   or the login page with `?login_error=`) for the frontend to navigate to, so the token is in no
   URL that a proxy log, the browser history or a `Referer` could record. The `GET` start refuses
   an invitation (security review round 4, R4-1): it is a plain link without an `Origin` check, so
   a cross-site page could otherwise make a browser with an identity provider session accept an
   invitation it never saw. `GET .../start?invitation=<token>` (any non-blank value) starts no
   login (no state, no login cookie, no provider redirect) and redirects to the login page with
   `?login_error=invitation_requires_post`; an empty `invitation=` is ignored. The login state holds a random
   `state` (256 bit), `nonce` (192 bit) and PKCE `code_verifier` (384 bit). The database stores the
   SHA-256 hash of `state`; nonce, verifier and invitation token are encrypted with the secret box
   (context bound to the state hash). The browser gets the login cookie (`__Host-axentra-login`
   on https, `axentra-login` on plain-http development; `HttpOnly`, `SameSite=Lax`, `Path=/`,
   `Max-Age=600`) holding the `state`, and a `302` to the provider (`GET`) or the provider URL in
   the body (`POST`).
2. The provider redirects to `GET /v1/auth/oidc/{provider}/callback?code=...&state=...`. Axentra
   consumes the state exactly once (`DELETE ... RETURNING`), **then** checks in constant time that
   the browser's login cookie equals `state` (login CSRF: a callback URL started in another
   browser logs nobody in, and is spent afterwards), checks provider and expiry, exchanges the
   code at the token endpoint (with `code_verifier`), verifies the ID token, finds or creates the
   user, starts a session (`auth_method = "oidc:<provider id>"`), clears the login cookie and
   redirects (`302`) to `return_to`.

**ID token checks:** signature with a key from the provider's JWKS; only asymmetric algorithms
(`RS*`, `PS*`, `ES*`, `EdDSA`; never `none` or `HS*`); a JWK's `alg`, when present, must match;
`iss` equals the configured issuer exactly; `aud` contains `client_id`; `exp`, `iat`, `iss`, `aud`,
`sub` required; 60 s leeway; `iat` at most `id_token_max_age_seconds` (default 600) in the past,
plus 2 minutes of clock skew (an old or replayed token is refused; MUP-ONA VB-3); `nonce` equals the
login's nonce (constant-time); `azp`, when present
or when `aud` has several entries, must equal `client_id`. Only the ID token is used (no userinfo
call).

**Discovery:** `<issuer>/.well-known/openid-configuration`, cached for one hour. Its `issuer` must
equal the configured issuer exactly; `authorization_endpoint`, `token_endpoint` and `jwks_uri` must
be https. Plain http is accepted only for loopback hosts (`localhost`, `127.0.0.1`, `::1`) outside
production. The JWKS is cached for one hour and read again when a token names an unknown `kid`
(key rotation), at most once every 10 seconds. Provider requests use a 10 s timeout, follow no
redirects, ask for an uncompressed answer and accept at most 1 MiB: the answer is read as a stream and
the request ends as soon as more arrives (or a larger `Content-Length` is announced), so a provider
cannot make Axentra read or buffer more (MUP-ONA VB-3).

**Accounts:**

- A known (issuer, subject) logs in as its user (even if the email changed at the provider).
- Otherwise the email is used only when the ID token says `email_verified: true` (the boolean,
  not the string). A verified email of an existing user links the identity to that user
  (`link_by_verified_email = true`, the default). **Not for platform users:** when the existing
  user has a platform role (`platform_admin` or `platform_viewer`), the login is refused with
  `explicit_link_required` and nothing is linked or created (owner decision I5, 2026-11-14). A platform
  admin links the identity explicitly (`POST /v1/users/{user_id}/identities` with the issuer and
  subject); the next login then succeeds. `link_platform_users_by_verified_email = true` restores the
  old behavior for a provider.
- With `link_by_verified_email = false`, an unknown identity is **never** linked to an existing
  user by email. It gets a new user: with the address when it is free, or **without an address**
  when another user already has it (needs `allow_signup`; otherwise `signup_disabled`). The
  existing account is never touched; the identity row keeps the verified address for reference,
  and an operator can link identities explicitly (see Library usage).
- An identity without a verified email creates a user without an address only when the provider
  has both `allow_signup = true` and `allow_signup_without_email = true` (not combinable with
  `allowed_email_domains`); otherwise the login is refused with `email_not_verified`.
- An unknown verified email creates a user when the provider has `allow_signup = true`, or when an
  open invitation exists for that email. With an invitation token on `start` (only the `POST`
  body's `invitation`), the invitation is
  also accepted right after the login (tenant membership with the invited role), and the callback
  adds `invitation_accepted=<tenant id>` to the `return_to` query so the frontend does not ask for
  a second confirmation (Studio checks that `/v1/me` lists that tenant before it shows "accepted").
  A product team invitation (`axpinv_...`) works the same way: the operator joins the product
  team and the callback adds `product_invitation_accepted=<product id>` instead.
  If accepting fails, the login still succeeds without the parameter and the frontend can call
  `POST /v1/invitations/accept`.
- `allowed_email_domains` (case-insensitive, exact domain, no subdomains) is checked on **every**
  login, so a verified email in an allowed domain is required each time.
- A disabled user is refused.

**`return_to`:** a path starting with a single `/` (not `//`, no backslash, no control characters
or spaces, no `:` before `?`), or an absolute `http(s)` URL whose origin is listed in
`security.allowed_origins` (or is `security.public_url`), e.g. Axentra Studio on its own origin.
Anything else becomes `/`. Maximum 2000 characters. `return_to` is stored in plain text and goes
back to the browser, so it never keeps a secret (`OidcService.stored_return_to`,
`axentra.core.redaction.strip_secret_params`): query parameters whose percent-decoded name looks
like a secret (`token`, `*_token`, `invitation`, `setup`, `password`, ...) or whose value holds one
in any encoding (an `axinv_`/`axk_` token, a JWT, or a nested URL with such a parameter, e.g.
`return_to=%2Fx%3Ftoken%3D...`) are removed, whatever the path and its spelling (case, trailing
or repeated slashes, percent-encoding), other parameters keep their exact spelling; a fragment
holding a secret is dropped, a path holding one makes `return_to` its origin's `/`. An Axentra
invitation token removed from a `token`/`invitation` parameter is dropped and never used as the
login's invitation (security review round 4, R4-1): only the `POST` start's `invitation` field
carries one.

**Errors** never echo provider text. The browser is redirected to the login page with
`?login_error=<code>`: `security.login_page` (default `/login`) on the origin of `return_to` when
`return_to` is an absolute URL, otherwise `security.login_page` as configured (it may itself be
an absolute URL). The login's checked `return_to` (secret query parameters already removed) comes
along as `&return_to=<path>`, relative to the login page's origin, so a deep link such as an
invitation accept page survives a failed login; it is left out when it is `/` or when it is a path
on the API origin while `login_page` is an absolute URL elsewhere. Codes:

| code | meaning |
| --- | --- |
| `login_expired` | unknown, used or expired state; the browser lacks the matching login cookie |
| `access_denied` | the provider sent `error=` (user cancelled, consent refused, ...) |
| `provider_unavailable` | discovery/JWKS/token endpoint unreachable or misconfigured |
| `login_failed` | the token endpoint refused the code, or the ID token failed a check |
| `email_not_verified` | a verified email is needed (new identity, or `allowed_email_domains`) |
| `domain_not_allowed` | the email domain is not in `allowed_email_domains` |
| `signup_disabled` | no account and no open invitation, `allow_signup = false` |
| `explicit_link_required` | the verified email belongs to a platform user, whom only an explicit link connects (I5) |
| `account_disabled` | the user is disabled |
| `rate_limited` | too many login starts from this IP (6 x `login_rate_per_minute` per minute) |
| `invitation_requires_post` | the `GET` start got an `invitation`; send it in the body of the `POST` start |

Refused callbacks (after a state was found) are audited as `identity.login` with
`outcome = denied`, `details = {method: "oidc", provider, reason}`. Details go to the server log.

**MFA** is delegated to the identity provider: enforce it there (Keycloak authentication flows,
Entra ID Conditional Access, Google Workspace 2SV, Auth0 MFA). Axentra does not read `amr`/`acr`
yet.
Password logins have no second factor yet; the planned TOTP design (enrollment, recovery codes,
step-up, admin reset) is in [architecture/MFA_TOTP_DESIGN.md](../architecture/MFA_TOTP_DESIGN.md).

### Configuration

Redirect URI to register at the provider (exactly):
`<security.public_url>/v1/auth/oidc/<id>/callback`. Production requires `client_secret_ref`
(`env:NAME` or `file:/run/secrets/name`) and an https issuer.

```toml
[security]
public_url = "https://api.example.com"
allowed_origins = ["https://studio.example.com"]
login_page = "/login"            # on the return_to origin, e.g. https://studio.example.com/login

# Keycloak (realm "acme"): confidential client, standard flow, PKCE S256 enabled
[[oidc]]
id = "keycloak"
name = "Acme SSO"
issuer = "https://sso.example.com/realms/acme"
client_id = "axentra"
client_secret_ref = "env:AXENTRA_OIDC_KEYCLOAK_SECRET"
allow_signup = false

# Microsoft Entra ID (single tenant). Redirect URI type "Web".
[[oidc]]
id = "entra"
name = "Microsoft"
issuer = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id = "<application-id>"
client_secret_ref = "file:/run/secrets/entra_client_secret"
scopes = ["openid", "email", "profile"]
allowed_email_domains = ["example.com"]

# Google
[[oidc]]
id = "google"
name = "Google"
issuer = "https://accounts.google.com"
client_id = "<id>.apps.googleusercontent.com"
client_secret_ref = "env:AXENTRA_OIDC_GOOGLE_SECRET"
allowed_email_domains = ["example.com"]

# Auth0 (note the trailing slash: the issuer must match the discovery document exactly)
[[oidc]]
id = "auth0"
name = "Auth0"
issuer = "https://example.eu.auth0.com/"
client_id = "<client-id>"
client_secret_ref = "env:AXENTRA_OIDC_AUTH0_SECRET"
token_endpoint_auth_method = "client_secret_post"
allow_signup = true
```

Fields: `id` (lowercase, digits, dashes; part of the redirect URI), `name` (shown on the login
page via `GET /v1/meta`), `issuer`, `client_id`, `client_secret_ref` / `client_secret` (inline only
outside production), `scopes` (default `openid email profile`), `allow_signup` (default false),
`allowed_email_domains`, `link_by_verified_email` (default true), `allow_signup_without_email`
(default false, needs `allow_signup`), `token_endpoint_auth_method` (`client_secret_basic` default,
`client_secret_post`, or `none` for a public client using PKCE only), `id_token_max_age_seconds`
(default 600, 60 to 86400: the oldest accepted ID token `iat`, plus 2 minutes of clock skew).

Provider notes: Entra ID v2 ID tokens usually carry no `email_verified` claim. Axentra then
neither links nor creates a user by email, so a first Entra login is refused with
`email_not_verified` unless the claim is emitted (optional claims / claims mapping). There is
deliberately no setting that trusts an unverified `email` claim: in multi-tenant Entra apps the
claim is user-editable, and trusting it enables account takeover by email ("nOAuth"). An opt-in
for single-tenant directories (or a mapping to `xms_edov`/`verified_primary_email`) is an open item
in [TODO](../TODO.md). Keycloak,
Google and Auth0 send `email_verified` by default. The
issuer must be written exactly as in the discovery document (Auth0: trailing slash; Keycloak and
Google: none).

## Library usage

```python
from axentra import load_settings
from axentra.platform import Axentra

ax = Axentra.from_settings(load_settings())
ax.start()
new = ax.identity.login_password("alice@example.com", "...", ip="203.0.113.7", user_agent="cli")
principal, info = ax.identity.resolve_session(new.token)

# OIDC without the HTTP layer (e.g. a custom web framework):
started = ax.oidc.start("keycloak", return_to="/app", ip="203.0.113.7")
# -> redirect to started.authorization_url, bind started.state to the browser (cookie)
result = ax.oidc.finish("keycloak", state=state, code=code, error=None,
                        browser_state=cookie_value, ip="203.0.113.7", user_agent="...")
# -> result.session.token is the session token, result.return_to the target
```

Imports and migrations create or link external identities explicitly (platform admins or a
system principal; audited as `identity.external.create` / `identity.external.link`; an identity
that exists is refused with `409`):

```python
from axentra.core.context import Principal

system = Principal.system("import")
user = ax.identity.create_external_user(
    system, provider="https://sso.example.com/realms/acme", subject="248289761001",
    email="jane@example.com", email_verified=True, name="Jane",
)  # email_verified=False (or no email): the user has no address
ax.identity.link_identity(system, user.id, provider="https://login.example.org", subject="abc")
ax.identity.list_identities(user.id)
```

`provider` is the issuer string an OIDC login uses (`oidc[].issuer`).

`ax.oidc` is `None` when no providers are configured. Tests inject an `httpx` transport with
`ax.oidc.use_transport(transport)`; no network is used then.

## HTTP endpoints

| Method | Path | Auth | Result |
| --- | --- | --- | --- |
| POST | `/v1/auth/setup` | public (setup token) | `SessionInfo` + cookie |
| POST | `/v1/auth/login/password` | public (Origin checked) | `SessionInfo` + cookie |
| POST | `/v1/auth/password-reset` | public (Origin checked) | `202` always (no account oracle) |
| POST | `/v1/auth/password-reset/confirm` | public (Origin checked, token) | `204`; `400 invalid_token`, `422` policy |
| POST | `/v1/auth/email-verification/confirm` | public (Origin checked, token) | `204`; `400 invalid_token` |
| POST | `/v1/me/email-verification` | session | `202`; `409` verified or no product, `429` cooldown |
| GET | `/v1/auth/oidc/{provider}/start` | public | `302` to provider + login cookie; `404` unknown provider |
| POST | `/v1/auth/oidc/{provider}/start` | public (Origin checked) | `{redirect_url}` + login cookie; `404` unknown provider, `403` foreign Origin |
| GET | `/v1/auth/oidc/{provider}/callback` | public (state + login cookie) | `302` to `return_to` + session cookie, or `302` to login page `?login_error=` |
| GET | `/v1/auth/session` | session | `SessionInfo {user, session_id, csrf_token, expires_at, platform_role}` |
| POST | `/v1/auth/logout` | session | `204` |
| GET | `/v1/auth/sessions` | session | `Session[]` (own, active) |
| DELETE | `/v1/auth/sessions/{session_id}` | session | `204` |

Users endpoints (`/v1/me`, `/v1/users`) are described in the OpenAPI document.

## Guarantees

- Session tokens, setup tokens, password reset and email verification tokens and OIDC `state` are
  stored only as SHA-256 hashes; OIDC nonce,
  PKCE verifier and invitation token are encrypted at rest and deleted on use or after expiry
  (expired rows are removed on the next login start and by `purge_expired`).
- A login state is usable once, by the browser that started it, within ten minutes.
- `code`, `state`, `*token`, `setup` and `invitation` query values are redacted in the
  `uvicorn.access` log (a logging filter installed by `create_app` and `configure_logging`), also
  when they are percent-encoded inside another parameter (`return_to=%2Fx%3Ftoken%3D...`, any
  depth, either hex case), together with token-like strings in any encoding; Axentra's own
  request log records only the path.
- No invitation token is stored in `axentra_login_states.return_to`, in a redirect `Location` or in
  the audit trail (see `return_to` above); every response, including the start and callback
  redirects, carries `Referrer-Policy: no-referrer`.

## Security notes

- Login CSRF is prevented by the login cookie bound to `state`; open redirects by the `return_to`
  rules; mix-up of tokens between logins by `nonce`; code interception by PKCE.
- Starting a second login in the same browser replaces the login cookie: the first tab's
  callback then fails with `login_expired`.
- The OIDC client is synchronous (`httpx.Client`), run in FastAPI's threadpool.

## Limitations / TODO

- No RP-initiated logout (`end_session_endpoint`), no back-channel/front-channel logout.
- No `private_key_jwt` client authentication, no `prompt`/`login_hint`/`acr_values` parameters.
- No per-tenant providers: providers are configured per installation.
- `amr`/`acr` (MFA evidence) are not evaluated.
- No built-in second factor for password logins (design: architecture/MFA_TOTP_DESIGN.md).
- No UI or HTTP API for linking several identities to one user or for unlinking (library only:
  `create_external_user`, `link_identity`).
