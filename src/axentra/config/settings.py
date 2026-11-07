"""Axentra settings: one validated object built from a TOML file and environment variables.

Sources, later ones win:

1. Defaults below.
2. A TOML file (``AXENTRA_CONFIG=/etc/axentra/axentra.toml`` or ``load_settings(path=...)``).
3. Environment variables ``AXENTRA__<SECTION>__<KEY>`` (double underscores), e.g.
   ``AXENTRA__DATABASE__URL``. Values are parsed as JSON when possible (lists, numbers, bools).

Secrets are never written inline in production: fields ending in ``_ref`` take a reference
``env:NAME`` or ``file:/run/secrets/name`` (see :func:`axentra.config.secrets.resolve_secret`).

:meth:`Settings.validate_security` refuses to start a production instance with an insecure
configuration (missing keys, wildcard origins, plain HTTP cookies, a superuser database role).
"""

from __future__ import annotations

from enum import StrEnum
import json
import os
from pathlib import Path
import tomllib
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from axentra.core.errors import ConfigurationError

MODULES = (
    "identity",
    "tenancy",
    "access",
    "data",
    "audit",
    "storage",
    "events",
    "usage",
    "billing",
    "notify",
    "search",
    "realtime",
)


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class DeploymentMode(StrEnum):
    SINGLE = "single"
    MULTI = "multi"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DatabaseSettings(_Section):
    url: str = "postgresql://axentra@127.0.0.1:5432/axentra"
    url_ref: str | None = None
    """Reference to a secret holding the URL (``env:`` / ``file:``); overrides ``url``."""
    migration_url: str | None = None
    """Optional separate (owner) URL for migrations; defaults to ``url``."""
    migration_url_ref: str | None = None
    """Reference to a secret holding the migration URL (``env:`` / ``file:``); overrides ``migration_url``."""
    migration_lock_timeout_ms: int = Field(0, ge=0, le=3_600_000)
    """``lock_timeout`` for every migration (``0``: off, the server's setting). A migration that waits
    longer for a lock fails without being recorded, instead of queueing every query of the table
    behind its lock request; run ``axentra migrate`` again later. A file's own
    ``-- axentra:lock-timeout=<duration>`` header wins."""
    migration_statement_timeout_ms: int = Field(0, ge=0, le=86_400_000)
    """``statement_timeout`` for every migration (``0``: off); a file's own
    ``-- axentra:statement-timeout=<duration>`` header wins."""
    extra_migrations: list[str] = Field(default_factory=list)
    """Product migration sources applied by ``axentra migrate``: ``package.module:attribute``
    (a list of ``Migration`` or a callable returning one)."""
    migration_entry_points: bool = True
    """Also apply migrations published by installed packages in the ``axentra.migrations`` entry point group."""
    pool_min: int = Field(1, ge=0)
    pool_max: int = Field(10, ge=1)
    statement_timeout_ms: int = Field(30_000, ge=0)
    allow_superuser: bool = False
    """Superusers bypass row-level security; refused in production unless explicitly allowed."""
    allow_table_owner: bool | None = None
    """Allow an application role that owns the tables protected by row-level security (it could
    switch RLS off). ``None`` (default): refused in production, allowed in development and test.
    In production ``Axentra.start()`` refuses such a role unless this is set to ``true`` explicitly
    (then it starts with a warning): migrate with a separate owner role (``migration_url_ref``) and
    grant the runtime role with ``axentra db grant-runtime-role``. See :attr:`Settings.table_owner_allowed`."""
    require_current_schema: bool = False
    """``Axentra.start()`` refuses to start (``SchemaNotCurrent``) while a registered migration
    namespace has pending migrations or applied versions unknown to the code; ``/v1/health/ready``
    then also reports the schema state."""


class ProductSettings(_Section):
    """Single-product mode: the one product this instance serves (created on first start)."""

    slug: str = "default"
    name: str = "Default product"


class SecuritySettings(_Section):
    public_url: str = "http://127.0.0.1:8080"
    """External base URL of the API (used for OIDC redirect URIs and cookie security)."""
    allowed_origins: list[str] = Field(default_factory=list)
    """Browser origins allowed to make credentialed requests (Studio, product frontends)."""
    trusted_proxies: list[str] = Field(default_factory=list)
    """Peer IPs/CIDRs whose ``X-Forwarded-For``/``-Proto`` headers are honored."""
    session_ttl_hours: int = Field(12, ge=1, le=24 * 30)
    session_idle_minutes: int = Field(120, ge=5)
    password_login: bool = True
    password_min_length: int = Field(12, ge=8)
    login_rate_per_minute: int = Field(10, ge=1)
    """Failed-login budget per IP and per account per minute (the IP budget is three times this)."""
    fresh_login_minutes: int = Field(5, ge=1, le=60)
    """How recent the session's login must be for a user without a password (OIDC-only) to set a
    first password via ``POST /v1/me/password``."""
    first_password: Literal["fresh_login", "disabled"] = "fresh_login"  # noqa: S105 (a mode)
    """Whether users without a password (OIDC-only) may set one: ``fresh_login`` (default) within
    ``fresh_login_minutes`` of their login, ``disabled``: never (they keep logging in through their
    identity provider, so MFA and IdP-side deprovisioning always apply)."""
    master_keys_ref: str | None = None
    """Reference to the versioned encryption keyring (``kid:base64key,kid2:...``); first = active."""
    master_keys: str | None = None
    """Inline keyring; allowed only outside production."""
    setup_token_ttl_minutes: int = Field(60, ge=5)
    password_reset_minutes: int = Field(30, ge=5, le=24 * 60)
    """How long a password reset link works (single use). Reset needs ``password_login``."""
    email_verification_hours: int = Field(48, ge=1, le=24 * 14)
    """How long an email verification link works (single use)."""
    max_body_bytes: int = Field(10 * 1024 * 1024, ge=1024)
    """Largest request body accepted (413 above it). File uploads use ``storage.max_file_bytes`` instead."""
    rate_limit_per_minute: int | None = Field(None, ge=1)
    """Requests per minute per credential (API key or session; per IP for anonymous requests).
    ``None`` (default): off. Counted per process or in the database (``rate_limit_store``); see
    SECURITY_MODEL.md."""
    rate_limit_ip_per_minute: int | None = Field(None, ge=1)
    """Requests per minute per client IP regardless of credentials (``None``: off)."""
    rate_limit_burst: int | None = Field(None, ge=1)
    """Bucket size (burst); defaults to the per-minute budget. Only for ``rate_limit_store = "memory"``."""
    heavy_rate_limit_per_minute: int = Field(120, ge=0)
    """Expensive reads (full-text search queries, record lists) per minute per credential, counted
    separately from ``rate_limit_per_minute`` and ON by default; ``0`` turns it off. Counted in
    ``rate_limit_store`` like the general limit (the burst is one minute's budget)."""
    rate_limit_store: Literal["memory", "database"] = "memory"
    """Where the general rate limits are counted: ``memory`` (per process, no database write) or
    ``database`` (one-minute windows in PostgreSQL shared by all API processes; one write per
    request and limit)."""
    api_docs: Literal["public", "authenticated", "disabled"] | None = None
    """``/v1/docs`` and ``/v1/openapi.json``: ``None`` (default) means ``disabled`` in production and
    ``public`` otherwise; ``authenticated`` requires a session or API key."""
    login_page: str = "/login"
    """Where failed OIDC logins are sent (``?login_error=<code>``): a path on the origin of the login's
    ``return_to``, or an absolute URL used when that origin is unknown."""


class OidcProviderSettings(_Section):
    id: str
    name: str
    issuer: str
    client_id: str
    client_secret_ref: str | None = None
    client_secret: str | None = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    allow_signup: bool = False
    """Create unknown users on first login; otherwise only invited/existing users may log in."""
    allowed_email_domains: list[str] = Field(default_factory=list)
    link_by_verified_email: bool = True
    """Link an unknown identity to the existing user with the same verified email (account
    linking across providers). ``false``: never link by email; a new user is created instead
    (without an email address when the address belongs to another user; needs ``allow_signup``)."""
    allow_signup_without_email: bool = False
    """Together with ``allow_signup``: create a user without an email address for an unknown
    identity whose provider sends no verified email (otherwise ``email_not_verified``)."""
    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post", "none"] = (
        "client_secret_basic"  # noqa: S105 (a method name, not a secret)
    )
    """How the client authenticates at the token endpoint (``none``: public client, PKCE only)."""

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not v.replace("-", "").isalnum() or not v.islower():
            raise ValueError("provider id must be lowercase alphanumeric with dashes")
        return v

    @model_validator(mode="after")
    def _signup_without_email(self) -> OidcProviderSettings:
        if self.allow_signup_without_email and not self.allow_signup:
            raise ValueError("allow_signup_without_email requires allow_signup")
        if self.allow_signup_without_email and self.allowed_email_domains:
            raise ValueError("allow_signup_without_email cannot be combined with allowed_email_domains")
        return self


class StorageSettings(_Section):
    backend: Literal["local", "s3"] = "local"
    local_path: str = "./var/storage"
    s3_bucket: str = ""
    s3_endpoint_url: str | None = None
    s3_region: str = "eu-central-1"
    s3_access_key_ref: str | None = None
    s3_secret_key_ref: str | None = None
    max_file_bytes: int = Field(50 * 1024 * 1024, ge=1)
    allowed_content_types: list[str] = Field(default_factory=list)
    """Empty: all types except the always-blocked executable/HTML types."""
    signed_url_ttl_seconds: int = Field(300, ge=10, le=86_400)
    s3_prefix: str = ""
    """Optional key prefix inside the bucket (e.g. ``axentra``)."""
    s3_server_side_encryption: Literal["AES256", "aws:kms"] | None = None
    s3_presigned_downloads: bool = False
    """S3 only: download-url returns a presigned S3 URL instead of an Axentra-signed URL."""
    default_quota_bytes: int | None = Field(None, ge=0)
    """Per-tenant default when neither the tenant quota nor product settings set one (None: unlimited)."""
    default_quota_files: int | None = Field(None, ge=0)
    pending_upload_timeout_seconds: int = Field(3600, ge=60)
    """Uploads still pending after this time are treated as abandoned by the purge."""
    deleted_object_retention_hours: int = Field(0, ge=0, le=24 * 90)
    """Keep the stored object of a deleted or expired file this long before the purge removes it
    (0, default: delete it at once). Set it to at least the time between a database backup and
    the file storage copy that follows it, so a restored database finds the objects of files
    deleted in between (see docs/operations/BACKUP_RESTORE.md). Deleted files stay invisible
    either way; retained objects count as personal data until they are removed."""
    store_blocked_as_inert: bool = False
    """Accept executable/HTML/SVG/script uploads and store them as inert ``application/octet-stream``
    attachments instead of refusing them (415). Downloads are always attachments with ``nosniff``."""


class NotifySettings(_Section):
    provider: Literal["local", "smtp"] = "local"
    sender: str = "Axentra <no-reply@localhost>"
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password_ref: str | None = None
    smtp_starttls: bool = True
    smtp_ca_file: str | None = None
    """Optional CA bundle (PEM) to verify the SMTP server certificate (private CAs)."""
    smtp_timeout_seconds: float = Field(20.0, gt=0, le=300)
    max_attempts: int = Field(5, ge=1, le=50)
    """Delivery attempts before a message is marked ``failed``."""
    backoff_base_seconds: float = Field(30.0, ge=0)
    backoff_max_seconds: float = Field(3600.0, ge=0)
    lease_seconds: int = Field(120, ge=5)
    """How long a dispatcher owns a claimed message before another dispatcher may retry it."""
    content_retention_days: int = Field(30, ge=1)
    """Rendered subjects/bodies (and local mailbox entries) are erased after this many days."""
    message_retention_days: int = Field(180, ge=1)
    """Finished messages (incl. recipient addresses) are deleted after this many days."""
    tenant_send_limit_per_hour: int = Field(1000, ge=0, le=1_000_000)
    """Messages one tenant may send through :meth:`NotifyService.send` (``POST .../notify/send``) in any
    rolling hour; more are refused with ``429 rate_limited`` and ``Retry-After``. Counted in the database,
    so the limit holds across API processes. System sends (invitations, account emails) neither count nor
    are limited. ``0`` turns the limit off."""
    invitation_accept_url: str | None = None
    """Installation-wide link for invitation emails, used when a product has no own
    ``settings.invitation_accept_url``. ``{token}`` is replaced by the token, otherwise
    ``?token=``/``&token=`` is appended. ``None`` (default): ``<security.public_url>/accept-invitation``.
    Set it when the frontend that accepts invitations (e.g. Studio) is not served on the API origin.
    ``http``/``https`` only; ``https`` in production."""

    account_url: str | None = None
    """Base URL of the frontend that serves ``/reset-password`` and ``/verify-email`` (for example
    Studio), used in password reset and email verification emails. ``None`` (default): the origin of
    ``invitation_accept_url`` when set, else ``security.public_url``. ``http``/``https`` only;
    ``https`` in production. A path is kept (``https://example.com/app`` gives
    ``https://example.com/app/reset-password?token=...``)."""

    @field_validator("account_url")
    @classmethod
    def _account_url(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        v = v.strip().rstrip("/")
        parts = urlsplit(v)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.query
            or parts.fragment
            or any(c.isspace() for c in v)
        ):
            raise ValueError("notify.account_url must be an absolute http(s) URL without query or fragment")
        return v

    @field_validator("invitation_accept_url")
    @classmethod
    def _invitation_accept_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or not parts.hostname or any(c.isspace() for c in v):
            raise ValueError("notify.invitation_accept_url must be an absolute http(s) URL")
        if parts.fragment and "{token}" not in v:
            # ``?token=`` would be appended after the fragment and never reach the page's query.
            raise ValueError("notify.invitation_accept_url may contain a fragment only with {token}")
        return v


class BillingSettings(_Section):
    provider: Literal["manual", "fake", "stripe"] = "manual"
    """``manual``/``fake`` never move money; ``stripe`` needs explicit keys and ``live_payments``."""
    webhook_secret_ref: str | None = None
    api_key_ref: str | None = None
    live_payments: bool = False


class ObservabilitySettings(_Section):
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"
    otel_enabled: bool = False
    otel_service_name: str = "axentra"
    metrics_enabled: bool = True
    metrics_token_ref: str | None = None
    """Bearer token (``env:``/``file:`` reference) required by ``GET /metrics``. Without it,
    metrics are served openly outside production and disabled (404) in production."""
    otel_endpoint: str | None = None
    """OTLP/HTTP traces endpoint; default: the exporter's ``OTEL_EXPORTER_OTLP_*`` environment."""
    audit_retention_days: int = Field(365, ge=1)
    job_retention_days: int = Field(30, ge=1)


class EventsSettings(_Section):
    """Job queue, workers, schedules, events, outgoing webhooks and event streams (module ``events``)."""

    lease_seconds: int = Field(60, ge=1, le=3600)
    """How long a claimed job stays reserved for its worker without a heartbeat."""
    poll_interval_seconds: float = Field(1.0, gt=0, le=60)
    """Worker polling interval (LISTEN/NOTIFY wakes workers earlier)."""
    listen_notify: bool = True
    reap_interval_seconds: float = Field(15.0, gt=0)
    scheduler_interval_seconds: float = Field(5.0, gt=0)
    default_max_attempts: int = Field(5, ge=1, le=100)
    backoff_base_seconds: float = Field(2.0, gt=0)
    backoff_max_seconds: float = Field(3600.0, gt=0)
    webhook_max_attempts: int = Field(8, ge=1, le=50)
    webhook_backoff_base_seconds: float = Field(120.0, gt=0, le=86400)
    """Wait before the first webhook retry; it doubles with every further attempt (with jitter:
    between half and all of the step). Webhooks have their own schedule, independent of the job
    ``backoff_*`` settings, so that a receiver outage of a few hours does not lose deliveries.
    With the defaults (8 attempts) the 7 retries span about 2 to 4.2 hours."""
    webhook_backoff_max_seconds: float = Field(21600.0, gt=0, le=7 * 86400)
    """Upper bound of a single wait between two webhook attempts (before jitter)."""
    webhook_timeout_seconds: float = Field(10.0, gt=0, le=60)
    webhook_response_max_bytes: int = Field(4096, ge=0, le=65536)
    webhook_allow_private_targets: bool = False
    """Allow webhook URLs that resolve to private, loopback or link-local addresses (tests/dev only)."""
    webhook_allow_http: bool = False
    """Allow plain-http webhook URLs outside production (never in production)."""
    webhook_allow_private_targets_in_production: bool = False
    """Explicit override that lets ``webhook_allow_private_targets`` be used in production (for
    installations whose webhook receivers live on a private network). Without it production refuses
    to start with private targets allowed, because that switches the SSRF guard off."""
    sse_poll_seconds: float = Field(1.0, gt=0, le=30)
    sse_reauth_seconds: float = Field(15.0, gt=0, le=300)
    sse_keepalive_seconds: float = Field(15.0, gt=0, le=300)
    sse_max_seconds: float = Field(3600.0, gt=0)
    """A stream ends after this time; clients reconnect with ``Last-Event-ID``."""

    @model_validator(mode="after")
    def _webhook_backoff(self) -> EventsSettings:
        if self.webhook_backoff_max_seconds < self.webhook_backoff_base_seconds:
            raise ValueError("webhook_backoff_max_seconds must not be less than webhook_backoff_base_seconds")
        return self


class SearchSettings(_Section):
    """Full-text search (module ``search``), see docs/modules/SEARCH.md."""

    language: str = Field("simple", pattern=r"^[a-z_][a-z0-9_]{0,62}(\.[a-z_][a-z0-9_]{0,62})?$")
    """PostgreSQL text search configuration (``regconfig``) for indexing and queries, e.g.
    ``simple`` (no stemming, language independent), ``english`` or ``german``. Documents store the
    configuration they were indexed with; after a change, re-index them (upsert again)."""
    max_body_chars: int = Field(100_000, ge=1_000, le=1_000_000)
    """Longest document body accepted by the index (characters)."""
    max_offset: int = Field(1_000, ge=0, le=100_000)
    """Deepest result position reachable by paging (bounds the cost of deep pages)."""
    max_candidates: int = Field(10_000, ge=100, le=10_000_000)
    """Most matching documents ranked per query. A common term in a large tenant matches far more;
    then only this many matches (in index order, not the best ones) are ranked, so the cost of a query
    is bounded instead of growing with the tenant."""
    statement_timeout_ms: int = Field(5_000, ge=100, le=600_000)
    """Longest a search query may run in the database; a slower one is cancelled and answered with
    ``422 validation_failed`` (``reason`` ``query_too_expensive``)."""
    audit_index_writes: bool = True
    """Write an audit event for every index upsert/delete (without document content)."""


class Settings(_Section):
    environment: Environment = Environment.DEVELOPMENT
    mode: DeploymentMode = DeploymentMode.SINGLE
    modules: list[str] = Field(default_factory=lambda: list(MODULES))
    product: ProductSettings = Field(default_factory=ProductSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    oidc: list[OidcProviderSettings] = Field(default_factory=list)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    notify: NotifySettings = Field(default_factory=NotifySettings)
    billing: BillingSettings = Field(default_factory=BillingSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    events: EventsSettings = Field(default_factory=EventsSettings)
    search: SearchSettings = Field(default_factory=SearchSettings)
    features: dict[str, bool] = Field(default_factory=dict)
    """Optional feature flags (``features.<name> = true``), readable via :meth:`feature`."""

    @field_validator("modules")
    @classmethod
    def _modules(cls, v: list[str]) -> list[str]:
        unknown = sorted(set(v) - set(MODULES))
        if unknown:
            raise ValueError(f"unknown modules: {unknown}")
        for required in ("identity", "tenancy", "access", "audit"):
            if required not in v:
                raise ValueError(f"module {required!r} cannot be disabled")
        return [m for m in MODULES if m in v]

    def module_enabled(self, name: str) -> bool:
        return name in self.modules

    def feature(self, name: str, default: bool = False) -> bool:
        return self.features.get(name, default)

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def table_owner_allowed(self) -> bool:
        """Whether the application role may own the RLS-protected tables: ``database.allow_table_owner``
        when it is set, otherwise ``False`` in production and ``True`` in every other environment."""
        if self.database.allow_table_owner is not None:
            return self.database.allow_table_owner
        return not self.is_production

    @property
    def api_docs_mode(self) -> str:
        if self.security.api_docs is not None:
            return self.security.api_docs
        return "disabled" if self.is_production else "public"

    @property
    def invitation_accept_base(self) -> str:
        """Installation-wide base of invitation links (a product's own setting takes precedence)."""
        return self.notify.invitation_accept_url or (
            self.security.public_url.rstrip("/") + "/accept-invitation"
        )

    def account_link(self, path: str, token: str) -> str:
        """The link of a password reset (``/reset-password``) or verification (``/verify-email``) email."""
        base = self.notify.account_url
        if base is None and self.notify.invitation_accept_url:
            parts = urlsplit(self.notify.invitation_accept_url)
            base = f"{parts.scheme}://{parts.netloc}"
        base = (base or self.security.public_url).rstrip("/")
        return f"{base}{path}?token={quote(token, safe='')}"

    @property
    def secure_cookies(self) -> bool:
        return self.security.public_url.startswith("https://")

    def validate_security(self, *, keyring_injected: bool = False) -> None:
        """Refuse insecure production configurations. Called at startup by ``create_app``/CLI.

        ``keyring_injected=True``: the embedding application passes its own keyring to
        ``Axentra(..., keyring=...)``, so ``security.master_keys_ref`` is not required (inline
        ``security.master_keys`` stays refused in production)."""
        problems: list[str] = []
        if self.is_production:
            if not self.security.public_url.startswith("https://"):
                problems.append("security.public_url must use https in production")
            if self.security.master_keys:
                problems.append("security.master_keys must not be inline in production; use master_keys_ref")
            if not self.security.master_keys_ref and not keyring_injected:
                problems.append("security.master_keys_ref is required in production")
            if any(o == "*" or not o.startswith("https://") for o in self.security.allowed_origins):
                problems.append("security.allowed_origins must be explicit https origins in production")
            for p in self.oidc:
                if p.client_secret:
                    problems.append(f"oidc[{p.id}].client_secret must be a *_ref in production")
                if not p.issuer.startswith("https://"):
                    problems.append(f"oidc[{p.id}].issuer must use https")
            if self.events.webhook_allow_http:
                problems.append("events.webhook_allow_http is not allowed in production")
            if (
                self.events.webhook_allow_private_targets
                and not self.events.webhook_allow_private_targets_in_production
            ):
                problems.append(
                    "events.webhook_allow_private_targets disables the SSRF guard; in production it also needs"
                    " events.webhook_allow_private_targets_in_production = true"
                )
            accept_url = self.notify.invitation_accept_url
            if accept_url is not None and not accept_url.startswith("https://"):
                problems.append("notify.invitation_accept_url must use https in production")
            account_url = self.notify.account_url
            if account_url is not None and not account_url.startswith("https://"):
                problems.append("notify.account_url must use https in production")
            if self.billing.provider == "fake":
                problems.append("billing.provider 'fake' is not allowed in production")
        if self.billing.live_payments and self.billing.provider != "stripe":
            problems.append("billing.live_payments requires billing.provider = 'stripe'")
        if "*" in self.security.allowed_origins:
            problems.append("security.allowed_origins must not contain '*' (credentialed requests)")
        if problems:
            raise ConfigurationError("; ".join(problems))


def _parse_env_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _env_overrides(environ: dict[str, str]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, raw in environ.items():
        if not key.startswith("AXENTRA__"):
            continue
        parts = [p.lower() for p in key[len("AXENTRA__") :].split("__") if p]
        if not parts:
            continue
        node = data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ConfigurationError(f"conflicting environment override {key}")
        node[parts[-1]] = _parse_env_value(raw)
    return data


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings(
    path: str | Path | None = None, environ: dict[str, str] | None = None, **overrides: Any
) -> Settings:
    env = dict(os.environ if environ is None else environ)
    data: dict[str, Any] = {}
    file = path or env.get("AXENTRA_CONFIG")
    if file:
        try:
            data = tomllib.loads(Path(file).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigurationError(f"cannot read configuration file {file}: {exc}") from exc
    data = _deep_merge(data, _env_overrides(env))
    data = _deep_merge(data, overrides)
    try:
        return Settings.model_validate(data)
    except ValueError as exc:
        raise ConfigurationError(f"invalid configuration: {exc}") from exc
