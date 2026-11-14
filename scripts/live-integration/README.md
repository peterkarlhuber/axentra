# Live integration checks (opt-in)

Real, non-mock checks of Axentra's integrations against locally run services, with synthetic data
only. They start a real `axentra serve` (and `axentra worker` / `axentra notify-dispatch` where the
work happens there) against a fresh PostgreSQL database per check and talk to it over HTTP.

**Not part of CI and not collected by pytest** (the files are `check_*.py` under `scripts/`). Nothing
here touches a paid service, a real payment or a real account.

| Check | Service (compose.yml, pinned by digest) | Kind |
|---|---|---|
| `check_smtp.py` | Mailpit with STARTTLS (19125) and implicit TLS (19465), throwaway CA | live |
| `check_s3.py` | SeaweedFS S3 API (19333) | live |
| `check_oidc.py` | Keycloak 26.0 dev mode (19180), realm created by `keycloak_setup.py` | live |
| `check_oidc_i5.py` | Keycloak, as above; needs a source tree with decision I5 (`LC_AXENTRA_SRC`) | live |
| `check_webhooks.py` | in-process HTTP receiver on 127.0.0.1:19290 | live |
| `check_stripe_mock.py` | stripe/stripe-mock (19111) | **MOCK** (request shapes only) |
| `stripe_test_mode.py` | real Stripe **test mode** + Stripe CLI | live, manual; see [STRIPE_TEST_MODE.md](STRIPE_TEST_MODE.md) |

Axentra ports used: 19201 to 19206.

## Run

```bash
export LC_PYTHON=/path/to/venv/bin/python     # Axentra's dependencies + boto3 (axentra[s3])
export LC_PG_ADMIN_URL=postgresql://postgres:...@127.0.0.1:5432/postgres   # a local superuser URL
scripts/live-integration/run.sh                 # all checks; or: run.sh smtp oidc
LC_KEEP=1 scripts/live-integration/run.sh s3    # keep the containers afterwards
LC_AXENTRA_SRC=/path/to/other/worktree/src scripts/live-integration/run.sh oidc-i5   # test another source tree
```

`run.sh` without arguments runs `smtp s3 oidc webhooks stripe-mock`; `oidc-i5` is run on request
(it needs the I5 implementation: platform users are not linked by verified email).

The runner generates a throwaway CA (`make_certs.sh`, valid 3 days), starts the services, creates the
role `lc_ax` (NOSUPERUSER, NOBYPASSRLS) and one database `lc_*` per check (dropped and recreated each
run), runs the checks and writes evidence to `evidence/` (or `$LC_EVIDENCE`):
`<check>-results.txt` (PASS/FAIL/NOTE lines), `<check>-*.json`, the Axentra server/worker logs and the
container logs. Exit status 0 only when every check passed.

## What each check covers

- **SMTP**: invitation, password reset and email verification sent by `notify-dispatch` over STARTTLS
  with AUTH and `smtp_ca_file` (verification on); untrusted CA refused (`CERTIFICATE_VERIFY_FAILED`,
  nothing delivered); implicit TLS port (documents that SMTPS is not implemented); tokens from the
  received mails confirmed through the API; no token or SMTP password in any log.
- **S3**: upload/download (session and signed token, tampering), keys `<prefix>/<product>/<tenant>/<file>`,
  tenant isolation, quota (429), delete, behaviour while the S3 container is stopped (status, problem
  body, logs), recovery, `s3_presigned_downloads`.
- **OIDC**: full authorization-code flow through Keycloak's real login form (PKCE S256 required by the
  client), signup/no-signup, replayed callback, login CSRF (callback in another browser), nonce
  mismatch, unverified email, HS256-signed ID token refused, provider error, open-redirect `return_to`,
  and the observed account linking for the platform admin's address (product decision I5: observed,
  not asserted). `check_oidc_i5.py`: platform admin refused with `explicit_link_required`, explicit
  link via `POST /v1/users/{id}/identities` then success, normal users still linked by verified
  email, `link_platform_users_by_verified_email = true` restores auto-linking.
- **Webhooks**: signature (independent HMAC + `axentra.events.verify_signature`), headers/body,
  HTTP 500 / timeout / connection refused / DNS failure with retries, backoff timing and final `dead`,
  no redirect following, redeliver, secret rotation with two signatures, SSRF guard (loopback,
  RFC 1918, link-local/metadata, IPv6 loopback and mapped forms, `*.internal`, credentials in URL).
- **Stripe (MOCK)**: Axentra's Stripe requests validated by stripe-mock; `StripeProvider.API_BASE` is a
  class constant, so this check runs the app in process and overrides it to a recording proxy. The
  webhook events in this check are simulated (signed locally). It is not a Stripe test-mode run.

Keycloak dev mode sets `Secure` cookies on plain http; `check_oidc.py` lets its httpx "browser" send
them to loopback hosts (as real browsers do for `127.0.0.1`).
