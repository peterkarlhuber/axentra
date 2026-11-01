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

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    pool_min: int = Field(1, ge=0)
    pool_max: int = Field(10, ge=1)
    statement_timeout_ms: int = Field(30_000, ge=0)
    allow_superuser: bool = False
    """Superusers bypass row-level security; refused in production unless explicitly allowed."""


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
    """Failed-login budget per IP and per account per minute."""
    master_keys_ref: str | None = None
    """Reference to the versioned encryption keyring (``kid:base64key,kid2:...``); first = active."""
    master_keys: str | None = None
    """Inline keyring; allowed only outside production."""
    setup_token_ttl_minutes: int = Field(60, ge=5)
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
    webhook_timeout_seconds: float = Field(10.0, gt=0, le=60)
    webhook_response_max_bytes: int = Field(4096, ge=0, le=65536)
    webhook_allow_private_targets: bool = False
    """Allow webhook URLs that resolve to private, loopback or link-local addresses (tests/dev only)."""
    webhook_allow_http: bool = False
    """Allow plain-http webhook URLs outside production (never in production)."""
    sse_poll_seconds: float = Field(1.0, gt=0, le=30)
    sse_reauth_seconds: float = Field(15.0, gt=0, le=300)
    sse_keepalive_seconds: float = Field(15.0, gt=0, le=300)
    sse_max_seconds: float = Field(3600.0, gt=0)
    """A stream ends after this time; clients reconnect with ``Last-Event-ID``."""


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
    def secure_cookies(self) -> bool:
        return self.security.public_url.startswith("https://")

    def validate_security(self) -> None:
        """Refuse insecure production configurations. Called at startup by ``create_app``/CLI."""
        problems: list[str] = []
        if self.is_production:
            if not self.security.public_url.startswith("https://"):
                problems.append("security.public_url must use https in production")
            if self.security.master_keys:
                problems.append("security.master_keys must not be inline in production; use master_keys_ref")
            if not self.security.master_keys_ref:
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
