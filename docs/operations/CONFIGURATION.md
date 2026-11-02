# Configuration reference

All settings live in one validated object (`axentra.config.Settings`). Sources, later ones win:

1. Defaults (below).
2. A TOML file: `--config path` on the CLI, `load_settings(path)` in code, or `AXENTRA_CONFIG=path`.
3. Environment variables `AXENTRA__<SECTION>__<KEY>` (double underscores; case-insensitive):
   `AXENTRA__DATABASE__POOL_MAX=20`, top-level keys as `AXENTRA__MODE=multi`.
4. Keyword overrides passed to `load_settings(..., **overrides)` (library use).

Environment values are parsed as JSON when possible, so lists, numbers and booleans work:
`AXENTRA__SECURITY__ALLOWED_ORIGINS='["https://studio.example.com"]'`,
`AXENTRA__SECURITY__PASSWORD_LOGIN=false`. A string that happens to be valid JSON (for example a
product name `2026`) must be written as a JSON string: `'"2026"'`. Unknown keys are errors.

## Secret references

Fields ending in `_ref` hold a reference, never the secret:

| Reference | Reads |
|---|---|
| `env:NAME` | environment variable `NAME` (error if unset) |
| `file:/run/secrets/name` | file content, trailing newline removed (Docker/Kubernetes secrets) |

Other providers (Vault, cloud KMS) can be plugged into `axentra.config.secrets.PROVIDERS` in
library use.

## Startup validation

`Settings.validate_security()` runs whenever an `Axentra` instance is created (API, CLI,
library). In `environment = "production"` it refuses to start when:

- `security.public_url` is not `https://`;
- `security.master_keys` is set inline, or `security.master_keys_ref` is missing;
- `security.allowed_origins` contains anything but explicit `https://` origins;
- an OIDC provider has an inline `client_secret` or a non-https `issuer`;
- `events.webhook_allow_http` is set;
- `events.webhook_allow_private_targets` is set (it switches the webhook SSRF guard off) without the
  explicit override `events.webhook_allow_private_targets_in_production = true`;
- `billing.provider = "fake"`.

In every environment: `allowed_origins` must not contain `*`, and `billing.live_payments`
requires `billing.provider = "stripe"`. At `Axentra.start()`, the database role is checked: a
superuser or `BYPASSRLS` role is refused in production unless `database.allow_superuser = true`.

## Top level

| Key | Env | Default | Meaning |
|---|---|---|---|
| `environment` | `AXENTRA__ENVIRONMENT` | `"development"` | `development`, `test` or `production`. Production enables the checks above |
| `mode` | `AXENTRA__MODE` | `"single"` | `single` or `multi` ([DEPLOYMENT_MODELS](../architecture/DEPLOYMENT_MODELS.md)) |
| `modules` | `AXENTRA__MODULES` | all known modules | Enabled modules; routers of disabled modules are not mounted. Known: `identity`, `tenancy`, `access`, `data`, `audit`, `storage`, `events`, `usage`, `billing`, `notify`, `search`, `realtime`. `identity`, `tenancy`, `access`, `audit` cannot be disabled. Only modules that are installed have an effect |
| `features` | `AXENTRA__FEATURES__<NAME>` | `{}` | Free feature flags (`name = true`), read with `Settings.feature(name)` |

## `[product]` (single-product mode)

| Key | Env | Default | Meaning |
|---|---|---|---|
| `slug` | `AXENTRA__PRODUCT__SLUG` | `"default"` | Slug of the one product; created on first start (`^[a-z0-9][a-z0-9-]{1,62}$`) |
| `name` | `AXENTRA__PRODUCT__NAME` | `"Default product"` | Its display name at creation |

## `[database]`

| Key | Env | Default | Meaning |
|---|---|---|---|
| `url` | `AXENTRA__DATABASE__URL` | `postgresql://axentra@127.0.0.1:5432/axentra` | Connection URL (development convenience; prefer `url_ref`) |
| `url_ref` | `AXENTRA__DATABASE__URL_REF` | none | Secret reference for the URL; overrides `url` |
| `migration_url` | `AXENTRA__DATABASE__MIGRATION_URL` | none (= the runtime URL) | Separate owner connection for migrations (development convenience; prefer `migration_url_ref`) |
| `migration_url_ref` | `AXENTRA__DATABASE__MIGRATION_URL_REF` | none | Secret reference for the migration URL; overrides `migration_url` |
| `extra_migrations` | `AXENTRA__DATABASE__EXTRA_MIGRATIONS` | `[]` | Product migration sources for `axentra migrate`: `"package.module:attribute"` (a list of `Migration` or a callable returning one) |
| `migration_entry_points` | `AXENTRA__DATABASE__MIGRATION_ENTRY_POINTS` | `true` | Also apply migrations that installed packages publish in the `axentra.migrations` entry point group |
| `pool_min` | `AXENTRA__DATABASE__POOL_MIN` | `1` | Minimum pooled connections per process |
| `pool_max` | `AXENTRA__DATABASE__POOL_MAX` | `10` | Maximum pooled connections per process |
| `statement_timeout_ms` | `AXENTRA__DATABASE__STATEMENT_TIMEOUT_MS` | `30000` | `statement_timeout` per connection (0 = none) |
| `allow_superuser` | `AXENTRA__DATABASE__ALLOW_SUPERUSER` | `false` | Allow a role that bypasses RLS in production. Never set this in production |

## `[security]`

| Key | Env | Default | Meaning |
|---|---|---|---|
| `public_url` | `AXENTRA__SECURITY__PUBLIC_URL` | `http://127.0.0.1:8080` | External base URL. `https://` enables `Secure`/`__Host-` cookies and HSTS; always an allowed `Origin` |
| `allowed_origins` | `AXENTRA__SECURITY__ALLOWED_ORIGINS` | `[]` | Browser origins allowed for credentialed CORS and cookie requests (product frontends, Studio) |
| `trusted_proxies` | `AXENTRA__SECURITY__TRUSTED_PROXIES` | `[]` | Peer IPs/CIDRs whose `X-Forwarded-For` is honoured |
| `session_ttl_hours` | `AXENTRA__SECURITY__SESSION_TTL_HOURS` | `12` | Absolute session lifetime (1-720) |
| `session_idle_minutes` | `AXENTRA__SECURITY__SESSION_IDLE_MINUTES` | `120` | Idle timeout (>= 5) |
| `password_login` | `AXENTRA__SECURITY__PASSWORD_LOGIN` | `true` | Enable email/password login |
| `password_min_length` | `AXENTRA__SECURITY__PASSWORD_MIN_LENGTH` | `12` | Minimum password length (>= 8) |
| `login_rate_per_minute` | `AXENTRA__SECURITY__LOGIN_RATE_PER_MINUTE` | `10` | Failed logins per account per minute; per IP three times this |
| `fresh_login_minutes` | `AXENTRA__SECURITY__FRESH_LOGIN_MINUTES` | `5` | How recent the login must be for a user without a password (OIDC-only) to set one |
| `first_password` | `AXENTRA__SECURITY__FIRST_PASSWORD` | `fresh_login` | `fresh_login` or `disabled` (OIDC-only users can never set a password) |
| `master_keys_ref` | `AXENTRA__SECURITY__MASTER_KEYS_REF` | none | Secret reference to the keyring `kid:base64key[,...]` (first key active). Required in production |
| `master_keys` | `AXENTRA__SECURITY__MASTER_KEYS` | none | Inline keyring; refused in production. Without either, development uses `./var/dev-keyring`, test an ephemeral key |
| `setup_token_ttl_minutes` | `AXENTRA__SECURITY__SETUP_TOKEN_TTL_MINUTES` | `60` | Lifetime of first-run setup tokens (>= 5) |
| `max_body_bytes` | `AXENTRA__SECURITY__MAX_BODY_BYTES` | `10485760` (10 MiB) | Largest request body (413 above it); file uploads use `storage.max_file_bytes` instead |
| `rate_limit_per_minute` | `AXENTRA__SECURITY__RATE_LIMIT_PER_MINUTE` | none (off) | Requests per minute per credential (per IP when anonymous); in-memory, per process |
| `rate_limit_ip_per_minute` | `AXENTRA__SECURITY__RATE_LIMIT_IP_PER_MINUTE` | none (off) | Requests per minute per client IP, whatever the credential |
| `rate_limit_burst` | `AXENTRA__SECURITY__RATE_LIMIT_BURST` | = the per-minute budget | Token bucket size |
| `api_docs` | `AXENTRA__SECURITY__API_DOCS` | `disabled` in production, else `public` | `/v1/docs` and `/v1/openapi.json`: `public`, `authenticated` or `disabled` |

Generate keyring entries with `axentra keys generate --kid k1`. Rotation (with
`axentra secrets reencrypt [--dry-run] [--batch-size N]`):
[SECURITY_MODEL](../architecture/SECURITY_MODEL.md#secrets-and-the-keyring). Rate limits and the
body limit: [SECURITY_MODEL](../architecture/SECURITY_MODEL.md#rate-limiting).

## `[[oidc]]` (list of providers)

The settings exist; the OIDC login endpoints are being added in Phase 1. As a list, the whole
value is set at once from the environment: `AXENTRA__OIDC='[{"id": "corp", ...}]'`.

| Key | Default | Meaning |
|---|---|---|
| `id` | required | Lowercase alphanumeric with dashes; appears in URLs |
| `name` | required | Button label |
| `issuer` | required | Issuer URL (`https://` in production) |
| `client_id` | required | OAuth client id |
| `client_secret_ref` | none | Secret reference for the client secret |
| `client_secret` | none | Inline secret; refused in production |
| `scopes` | `["openid", "email", "profile"]` | Requested scopes |
| `allow_signup` | `false` | Create unknown users on first login; otherwise only existing or invited users |
| `allowed_email_domains` | `[]` | Restrict logins to these email domains (empty: any) |

## Sections for modules in development

These sections are accepted and validated now; they take effect when the corresponding module
(Phase 2/3) is merged. Documentation of their behavior will be in `docs/modules/*`.

`[storage]`

| Key | Default |
|---|---|
| `backend` | `"local"` (`local` or `s3`) |
| `local_path` | `"./var/storage"` |
| `s3_bucket` | `""` |
| `s3_endpoint_url` | none |
| `s3_region` | `"eu-central-1"` |
| `s3_access_key_ref`, `s3_secret_key_ref` | none |
| `max_file_bytes` | `52428800` (50 MiB) |
| `allowed_content_types` | `[]` (all except always-blocked executable/HTML types) |
| `store_blocked_as_inert` | `false` (`true`: store executable/HTML/SVG/script uploads as inert `application/octet-stream` attachments instead of refusing them with 415) |
| `signed_url_ttl_seconds` | `300` (10-86400) |

`[notify]`

| Key | Default |
|---|---|
| `provider` | `"local"` (`local` or `smtp`) |
| `sender` | `"Axentra <no-reply@localhost>"` |
| `smtp_host` | `"localhost"` |
| `smtp_port` | `587` |
| `smtp_username` | none |
| `smtp_password_ref` | none |
| `smtp_starttls` | `true` |

`[billing]`

| Key | Default |
|---|---|
| `provider` | `"manual"` (`manual`, `fake`, `stripe`; `fake` refused in production) |
| `webhook_secret_ref` | none |
| `api_key_ref` | none |
| `live_payments` | `false` (requires `provider = "stripe"`) |

`[observability]`

| Key | Default | Note |
|---|---|---|
| `log_level` | `"INFO"` | Used by `axentra serve` now |
| `log_format` | `"json"` | `json` or `text`; used by `axentra serve` now |
| `otel_enabled` | `false` | module in development |
| `otel_service_name` | `"axentra"` | module in development |
| `metrics_enabled` | `true` | module in development |
| `audit_retention_days` | `365` | no scheduler applies it yet ([TODO](../TODO.md)) |
| `job_retention_days` | `30` | module in development |

## Effective configuration

`GET /v1/settings` (platform admins and viewers with `platform:settings`, read-only for product
managers) returns the effective non-secret settings, including the keyring's key ids (never key
material).
