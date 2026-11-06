# MFA with TOTP: design (not implemented)

Status: **design only**. Axentra has no built-in second factor yet; installations that need MFA
enforce it at their OpenID Connect provider (modules/IDENTITY.md). This document fixes the design so
that the implementation can follow it without reopening the decisions. Tracked in
[TODO](../TODO.md) (identity, MFA).

Scope: TOTP (RFC 6238) for **password** logins, recovery codes, step-up at login, admin reset, and
the Studio screens. WebAuthn/passkeys are a later, separate item; the tables below leave room for
them (`kind`). OIDC logins are not challenged by Axentra: the provider is responsible for their
second factor (reading `amr`/`acr` is a separate TODO).

## Data model (migration `00NN_mfa.sql`)

Global tables without row-level security, like `axentra_users` and `axentra_sessions`; the
identity service is the only reader and writer.

```sql
CREATE TABLE axentra_mfa_factors (
    id text PRIMARY KEY,                       -- mfa_...
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('totp')),
    secret_enc text NOT NULL,                  -- SecretBox ciphertext of the 20-byte TOTP secret
    label text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    confirmed_at timestamptz,                  -- NULL: enrollment not finished, never accepted at login
    last_used_step bigint,                     -- replay protection: highest accepted time step
    last_used_at timestamptz
);
CREATE UNIQUE INDEX axentra_mfa_factors_one_totp ON axentra_mfa_factors (user_id)
    WHERE kind = 'totp' AND confirmed_at IS NOT NULL;

CREATE TABLE axentra_mfa_recovery_codes (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    code_hash text NOT NULL,                   -- SHA-256 of the normalized code (high-entropy codes)
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz
);
CREATE INDEX axentra_mfa_recovery_open ON axentra_mfa_recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE axentra_mfa_challenges (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,           -- SHA-256 of the challenge token given to the client
    ip text,
    user_agent text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,           -- 5 minutes
    attempts int NOT NULL DEFAULT 0,
    used_at timestamptz
);

ALTER TABLE axentra_sessions ADD COLUMN mfa_at timestamptz;  -- when this session passed a second factor
```

- The TOTP secret is encrypted with the installation keyring (`SecretBox`, as for other secrets);
  `axentra secrets reencrypt` gets an `EncryptedColumn` for `secret_enc`. Without the keyring a
  restored database cannot verify codes (documented in BACKUP_RESTORE.md).
- Recovery codes: 10 codes of 10 characters from a 32-letter alphabet without look-alikes (50 bits
  each), shown once, stored as SHA-256 (no slow hash needed at that entropy, consistent with session
  and account tokens). Generating a new set deletes the old one.

## TOTP parameters

SHA-1, 6 digits, 30-second step (the parameters every authenticator app supports); accepted window
`-1..+1` steps. A code is accepted only if its step is greater than `last_used_step`, which is
updated in the same transaction (`SELECT ... FOR UPDATE` on the factor), so a code cannot be used
twice, not even concurrently. Comparison with `hmac.compare_digest`. Implemented in
`identity/totp.py` with the standard library only (`hmac`, `hashlib`, `base64`, `struct`), tested
against the RFC 6238 test vectors.

## Enrollment (own account, fresh session)

| Endpoint | Behavior |
|---|---|
| `POST /v1/me/mfa/totp` | Requires the current password (or, for a password-less user, is refused: the IdP owns MFA). Creates an unconfirmed factor (replacing an older unconfirmed one) and returns `{factor_id, secret (base32), otpauth_uri}` once. Studio renders the URI as a QR code locally (no third-party service). |
| `POST /v1/me/mfa/totp/{id}/confirm` `{code}` | Confirms with a valid code, sets `confirmed_at`, sets `mfa_at` on the current session, revokes all other sessions of the user, returns 10 recovery codes once. Audit `identity.mfa.enroll`. Notify: a security email "two-step sign-in was turned on". |
| `GET /v1/me/mfa` | `{totp: {enabled, created_at, last_used_at}, recovery_codes_left}`. |
| `POST /v1/me/mfa/recovery-codes` `{password, code}` | New set (old ones invalid). Audit `identity.mfa.recovery_codes`. |
| `DELETE /v1/me/mfa/totp` `{password, code}` | Turns MFA off (code or recovery code). Audit `identity.mfa.disable`, security email. |

Unconfirmed factors older than one hour are deleted by `maintenance purge`.

## Login with a second factor

1. `POST /v1/auth/login/password` checks the password exactly as today (throttling, uniform
   errors). If the user has a confirmed TOTP factor, it does **not** create a session. It answers
   `200 {"mfa_required": true, "challenge": "<token>", "methods": ["totp", "recovery_code"]}` and
   sets no cookie. The challenge token is 32 random bytes; only its hash is stored; it expires after
   5 minutes.
2. `POST /v1/auth/login/mfa` `{challenge, code}` or `{challenge, recovery_code}`: verifies the
   challenge (unused, unexpired, `attempts < 5`), increments `attempts` first, then checks the code.
   On success it marks the challenge used, creates the session exactly like a password login with
   `mfa_at = now()`, and audits `identity.login` with `details.mfa = "totp" | "recovery_code"`.
   A used recovery code is marked `used_at`; when two or fewer are left the response says so.
3. Failures answer one uniform `401 invalid_mfa_code`; a challenge with 5 failures is spent and the
   login starts over. Failures count against the same login throttle buckets (per account and per
   IP) as wrong passwords, so an attacker who knows the password cannot brute-force the 10^6 code
   space through new challenges.

The password step's answer differs between MFA and non-MFA users only **after** the password was
proven, so it does not enable user enumeration.

API clients (SDKs, CLI) get the same two-step flow; the Python and TypeScript SDKs expose
`login_password()` returning either a session or an `MfaChallenge`.

## Step-up (re-authentication for sensitive actions)

`mfa_at` on the session lets sensitive operations demand a recent second factor:

- Turning MFA off, regenerating recovery codes and changing the password require a valid code in
  the request (above), whatever the session age.
- Platform admins: an installation setting `identity.mfa_required_for_platform_admins` (default
  `false`; enabling it is a stricter, opt-in setting) refuses platform-admin permissions for
  sessions without `mfa_at`, with `403 mfa_required`, so a platform admin is forced to enroll.
- `POST /v1/auth/step-up` `{code}` sets `mfa_at = now()` on the current session; endpoints can
  require `mfa_at` within `identity.step_up_minutes` (default 10). Initially used for: creating
  platform-level API keys, granting the platform admin role, and the admin MFA reset below.

## Admin reset (lost phone and lost recovery codes)

`DELETE /v1/users/{user_id}/mfa` (permission `users:manage`, platform scope; product admins cannot
reset MFA of users they manage): deletes the user's factors and recovery codes, revokes all of
their sessions, audits `identity.mfa.reset` with the admin as actor, and sends the user a security
email. The admin's own session must have passed step-up. An admin cannot reset their own MFA
(another admin must, or the operator uses the CLI). CLI for the last-admin case:
`axentra admin mfa-reset <email>` (requires database access, audited as system actor).

A password reset by email link does **not** remove MFA: the next login still asks for the code.

## Studio

- Profile, "Two-step sign-in": enroll (QR code rendered locally, manual key, confirm code),
  recovery codes (show once, copy, download as text), regenerate, turn off.
- Login: a second step "Enter the code from your authenticator app" with a link "Use a recovery
  code"; the challenge token stays in memory only.
- Users page (platform admin): "Reset two-step sign-in" with a confirmation dialog.
- All six locales and help pages (signing-in, profile, users); a11y specs for the new dialogs; the
  e2e flow computes TOTP codes in the test from the enrolled secret.

## Tests the implementation needs

- RFC 6238 vectors; window `-1..+1`; replay of the same code refused; concurrent use of one code
  accepts exactly one request.
- Enrollment: wrong password, wrong code, unconfirmed factor not accepted at login, other sessions
  revoked, recovery codes shown once and hashed at rest, secret encrypted at rest.
- Login: no session or cookie before the second step; expired, used and foreign challenges refused
  uniformly; 5 failed attempts spend the challenge; throttle shared with password failures;
  recovery code works once; OIDC login unaffected.
- Step-up and `mfa_required_for_platform_admins`; admin reset (permission, audit, sessions revoked,
  product admin refused, self-reset refused); password reset keeps MFA.
- Backup/restore: codes verify after a restore with the keyring, `secrets reencrypt` covers the
  column.
