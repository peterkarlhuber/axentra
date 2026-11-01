# Identity

The identity module answers "who is this?": users, password logins, server-side sessions, the
first-run setup, and logins through an external OpenID Connect provider (Keycloak, Microsoft
Entra ID, Google, Auth0, Dex, ...). It does **not** decide what a user may do — that is the access
module (roles, memberships, authorizer). A login by itself grants nothing.

Code: `src/axentra/identity/` (`service.py` users/sessions/passwords/setup, `oidc.py` OpenID
Connect), HTTP: `src/axentra/api/routes/auth.py`, `users.py`.

## Concepts

- **User** (`axentra_users`): email (unique, case-insensitive), name, locale, preferences,
  `status` `active|disabled`, optional Argon2id password hash, optional platform role
  (`platform_admin`, `platform_viewer`). A user created by an OIDC login has no password
  (`has_password: false`).
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
at least four distinct characters. Unknown accounts are verified against a dummy hash so the
timing stays similar. Failed logins are throttled per IP and per account in one-minute windows stored in
PostgreSQL (`security.login_rate_per_minute`), so the limit holds across API processes. Password
login can be switched off with `security.password_login = false` (OIDC only).

## Sessions

- Absolute lifetime `security.session_ttl_hours` (default 12), idle timeout
  `security.session_idle_minutes` (default 120; `last_seen_at` is updated at most once a minute).
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

1. `GET /v1/auth/oidc/{provider}/start?return_to=...&invitation=...` creates a login state:
   `state` (256 bit), `nonce` (192 bit) and PKCE `code_verifier` (384 bit). The database stores the
   SHA-256 hash of `state`; nonce, verifier and invitation token are encrypted with the secret box
   (context bound to the state hash). The browser gets the login cookie (`__Host-axentra-login`
   on https, `axentra-login` on plain-http development; `HttpOnly`, `SameSite=Lax`, `Path=/`,
   `Max-Age=600`) holding the `state`, and a `302` to the provider.
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
`sub` required; 60 s leeway; `nonce` equals the login's nonce (constant-time); `azp`, when present
or when `aud` has several entries, must equal `client_id`. Only the ID token is used (no userinfo
call).

**Discovery:** `<issuer>/.well-known/openid-configuration`, cached for one hour. Its `issuer` must
equal the configured issuer exactly; `authorization_endpoint`, `token_endpoint` and `jwks_uri` must
be https. Plain http is accepted only for loopback hosts (`localhost`, `127.0.0.1`, `::1`) outside
production. The JWKS is cached for one hour and read again when a token names an unknown `kid`
(key rotation), at most once every 10 seconds. Provider requests use a 10 s timeout, follow no
redirects and accept at most 1 MiB.

**Accounts:**

- A known (issuer, subject) logs in as its user (even if the email changed at the provider).
- Otherwise the email is used only when the ID token says `email_verified: true` (the boolean,
  not the string). A verified email of an existing user links the identity to that user.
- An unknown verified email creates a user when the provider has `allow_signup = true`, or when an
  open invitation exists for that email. With `invitation=<token>` on `start`, the invitation is
  also accepted right after the login (tenant membership with the invited role); if accepting
  fails, the login still succeeds and the frontend can call `POST /v1/invitations/accept`.
- `allowed_email_domains` (case-insensitive, exact domain, no subdomains) is checked on **every**
  login, so a verified email in an allowed domain is required each time.
- A disabled user is refused.

**`return_to`:** a path starting with a single `/` (not `//`, no backslash, no control characters
or spaces, no `:` before `?`), or an absolute `http(s)` URL whose origin is listed in
`security.allowed_origins` (or is `security.public_url`), e.g. Axentra Studio on its own origin.
Anything else becomes `/`. Maximum 2000 characters.

**Errors** never echo provider text. The browser is redirected to the login page with
`?login_error=<code>`: `security.login_page` (default `/login`) on the origin of `return_to` when
`return_to` is an absolute URL, otherwise `security.login_page` as configured (it may itself be
an absolute URL). Codes:

| code | meaning |
| --- | --- |
| `login_expired` | unknown, used or expired state; the browser lacks the matching login cookie |
| `access_denied` | the provider sent `error=` (user cancelled, consent refused, ...) |
| `provider_unavailable` | discovery/JWKS/token endpoint unreachable or misconfigured |
| `login_failed` | the token endpoint refused the code, or the ID token failed a check |
| `email_not_verified` | a verified email is needed (new identity, or `allowed_email_domains`) |
| `domain_not_allowed` | the email domain is not in `allowed_email_domains` |
| `signup_disabled` | no account and no open invitation, `allow_signup = false` |
| `account_disabled` | the user is disabled |
| `rate_limited` | too many login starts from this IP (6 x `login_rate_per_minute` per minute) |

Refused callbacks (after a state was found) are audited as `identity.login` with
`outcome = denied`, `details = {method: "oidc", provider, reason}`. Details go to the server log.

**MFA** is delegated to the identity provider: enforce it there (Keycloak authentication flows,
Entra ID Conditional Access, Google Workspace 2SV, Auth0 MFA). Axentra does not read `amr`/`acr`
yet.

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
`allowed_email_domains`, `token_endpoint_auth_method` (`client_secret_basic` default,
`client_secret_post`, or `none` for a public client using PKCE only).

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

`ax.oidc` is `None` when no providers are configured. Tests inject an `httpx` transport with
`ax.oidc.use_transport(transport)`; no network is used then.

## HTTP endpoints

| Method | Path | Auth | Result |
| --- | --- | --- | --- |
| POST | `/v1/auth/setup` | public (setup token) | `SessionInfo` + cookie |
| POST | `/v1/auth/login/password` | public (Origin checked) | `SessionInfo` + cookie |
| GET | `/v1/auth/oidc/{provider}/start` | public | `302` to provider + login cookie; `404` unknown provider |
| GET | `/v1/auth/oidc/{provider}/callback` | public (state + login cookie) | `302` to `return_to` + session cookie, or `302` to login page `?login_error=` |
| GET | `/v1/auth/session` | session | `SessionInfo {user, session_id, csrf_token, expires_at, platform_role}` |
| POST | `/v1/auth/logout` | session | `204` |
| GET | `/v1/auth/sessions` | session | `Session[]` (own, active) |
| DELETE | `/v1/auth/sessions/{session_id}` | session | `204` |

Users endpoints (`/v1/me`, `/v1/users`) are described in the OpenAPI document.

## Guarantees

- Session tokens, setup tokens and OIDC `state` are stored only as SHA-256 hashes; OIDC nonce,
  PKCE verifier and invitation token are encrypted at rest and deleted on use or after expiry
  (expired rows are removed on the next login start and by `purge_expired`).
- A login state is usable once, by the browser that started it, within ten minutes.
- `code`, `state`, `*token`, `setup` and `invitation` query values are redacted in the
  `uvicorn.access` log (a logging filter installed by `create_app` and `configure_logging`);
  Axentra's own request log records only the path.

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
- No UI for linking several identities to one user or for unlinking.
