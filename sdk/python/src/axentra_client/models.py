"""Typed response models for the main Axentra resources.

Hand-maintained to match ``openapi/axentra-v1.json`` (the contract tests in ``tests/integration``
and ``tests/e2e`` check them against a real server). Following the API conventions, every model
ignores nothing and rejects nothing it does not know: unknown fields are kept (``extra="allow"``,
readable as attributes and via ``model_extra``) and enum-like fields are plain ``str`` so that
new values in a newer API minor never break parsing.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class AxentraModel(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Page(AxentraModel, Generic[T]):
    """One cursor page: ``items`` and ``next_cursor`` (``None`` on the last page)."""

    items: list[T]
    next_cursor: str | None = None


# -- meta ---------------------------------------------------------------------------------------


class ApiVersion(AxentraModel):
    major: int
    minor: int


class OidcProviderInfo(AxentraModel):
    id: str
    name: str


class AuthInfo(AxentraModel):
    password: bool
    oidc: list[OidcProviderInfo] = Field(default_factory=list)


class Product(AxentraModel):
    id: str
    slug: str
    name: str
    description: str = ""
    status: str
    settings: dict[str, Any] = Field(default_factory=dict)
    version: int
    created_at: datetime
    updated_at: datetime


class Meta(AxentraModel):
    name: str = "axentra"
    version: str
    api_version: ApiVersion
    mode: str
    environment: str
    modules: list[str]
    product: Product | None = None
    auth: AuthInfo
    setup_required: bool


# -- identity -----------------------------------------------------------------------------------


class User(AxentraModel):
    id: str
    email: str | None = None
    name: str
    locale: str
    status: str
    has_password: bool | None = None
    platform_role: str | None = None
    preferences: dict[str, Any] = Field(default_factory=dict)
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class SessionInfo(AxentraModel):
    user: User
    session_id: str
    csrf_token: str
    expires_at: datetime
    platform_role: str | None = None


class Session(AxentraModel):
    id: str
    user_id: str
    auth_method: str
    ip: str | None = None
    user_agent: str = ""
    current: bool = False
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


class Tenant(AxentraModel):
    id: str
    product_id: str
    slug: str
    name: str
    status: str
    settings: dict[str, Any] = Field(default_factory=dict)
    member_count: int | None = None
    version: int
    created_at: datetime
    updated_at: datetime


class TenantAccess(AxentraModel):
    tenant: Tenant
    role: str | None = None
    permissions: list[str]


class ProductAccess(AxentraModel):
    product: Product
    role: str | None = None
    permissions: list[str]
    tenants: list[TenantAccess] = Field(default_factory=list)


class Me(AxentraModel):
    actor_kind: str
    user: User | None = None
    platform_role: str | None = None
    platform_permissions: list[str] = Field(default_factory=list)
    products: list[ProductAccess] = Field(default_factory=list)


# -- tenancy and access -------------------------------------------------------------------------


class Membership(AxentraModel):
    """A tenant member."""

    id: str
    product_id: str
    tenant_id: str
    user_id: str
    email: str | None = None
    name: str
    role: str
    created_at: datetime


class ProductMember(AxentraModel):
    """A product operator."""

    product_id: str
    user_id: str
    email: str | None = None
    name: str
    role: str
    created_at: datetime


class Invitation(AxentraModel):
    id: str
    product_id: str
    tenant_id: str
    email: str
    role: str
    status: str
    invited_by: str | None = None
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class NewInvitation(AxentraModel):
    invitation: Invitation
    #: The one-time acceptance token; shown only in this response.
    token: str
    accept_url: str | None = None


class Role(AxentraModel):
    id: str | None = None
    key: str
    name: str
    description: str = ""
    scope: str
    permissions: list[str]
    builtin: bool
    version: int = 0


class ApiKey(AxentraModel):
    id: str
    product_id: str
    tenant_id: str | None = None
    name: str
    prefix: str
    permissions: list[str]
    status: str
    replaces: str | None = None
    created_by: str | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class NewApiKey(AxentraModel):
    key: ApiKey
    #: The full ``axk_...`` secret; shown only in this response.
    secret: str


# -- data ---------------------------------------------------------------------------------------


class Record(AxentraModel):
    id: str
    product_id: str
    tenant_id: str
    collection: str
    data: dict[str, Any]
    version: int
    created_by: str | None = None
    updated_by: str | None = None
    created_at: datetime
    updated_at: datetime


class FileInfo(AxentraModel):
    id: str
    product_id: str
    tenant_id: str
    name: str
    content_type: str
    size: int
    sha256: str | None = None
    status: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    version: int
    created_by: str | None = None
    expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class DownloadUrl(AxentraModel):
    url: str
    kind: str
    path: str | None = None
    expires_at: datetime


# -- usage --------------------------------------------------------------------------------------


class UsageEvent(AxentraModel):
    id: str
    product_id: str
    tenant_id: str
    meter: str
    quantity: Decimal
    idempotency_key: str
    occurred_at: datetime
    period_start: datetime
    recorded_at: datetime
    properties: dict[str, Any] = Field(default_factory=dict)
    reservation_id: str | None = None


class QuotaStatus(AxentraModel):
    meter: str
    used: Decimal
    reserved: Decimal
    limit: Decimal | None = None
    remaining: Decimal | None = None
    over_limit: bool
    enforcement: str
    source: str
    period_start: datetime
    period_end: datetime | None = None


class UsageRecordResult(AxentraModel):
    event: UsageEvent
    quota: QuotaStatus
    #: True when the Idempotency-Key was seen before and the original event was returned.
    replayed: bool


class MeterUsage(AxentraModel):
    meter: str
    name: str
    unit: str
    aggregation: str
    reset_period: str
    value: Decimal
    event_count: int
    reserved: Decimal
    limit: Decimal | None = None
    remaining: Decimal | None = None
    over_limit: bool
    enforcement: str
    source: str
    period_start: datetime
    period_end: datetime | None = None


class EffectiveLimit(AxentraModel):
    meter: str
    limit: Decimal | None = None
    enforcement: str
    period: str
    source: str


class Meter(AxentraModel):
    id: str
    product_id: str
    key: str
    name: str
    unit: str
    description: str = ""
    aggregation: str
    reset_period: str
    default_limit: Decimal | None = None
    default_enforcement: str
    active: bool
    version: int
    created_at: datetime
    updated_at: datetime


# -- billing ------------------------------------------------------------------------------------


class Price(AxentraModel):
    id: str
    amount_minor: int
    currency: str
    interval: str
    provider_price_id: str | None = None


class Plan(AxentraModel):
    id: str
    product_id: str
    key: str
    name: str
    description: str = ""
    active: bool
    free: bool
    trial_days: int
    prices: list[Price] = Field(default_factory=list)
    entitlements: dict[str, bool | int | float | None] = Field(default_factory=dict)
    version: int
    created_at: datetime
    updated_at: datetime


class Subscription(AxentraModel):
    id: str
    product_id: str
    tenant_id: str
    plan_id: str
    plan_key: str
    status: str
    price: Price | None = None
    provider: str
    provider_customer_id: str | None = None
    provider_subscription_id: str | None = None
    current_period_start: datetime
    current_period_end: datetime
    trial_end: datetime | None = None
    cancel_at_period_end: bool
    canceled_at: datetime | None = None
    version: int
    created_at: datetime
    updated_at: datetime


class Entitlements(AxentraModel):
    product_id: str
    tenant_id: str
    plan_key: str | None = None
    subscription_id: str | None = None
    subscription_status: str | None = None
    features: dict[str, bool] = Field(default_factory=dict)
    limits: dict[str, Decimal | None] = Field(default_factory=dict)
    overrides: dict[str, bool | int | float | None] = Field(default_factory=dict)


# -- notify -------------------------------------------------------------------------------------


class MessageContent(AxentraModel):
    subject: str | None = None
    text: str | None = None
    html: str | None = None


class Message(AxentraModel):
    id: str
    product_id: str
    tenant_id: str | None = None
    template_key: str
    template_version: int
    channel: str
    category: str
    recipient: str
    recipient_user_id: str | None = None
    locale: str
    status: str
    attempts: int
    max_attempts: int
    next_attempt_at: datetime | None = None
    last_error: str | None = None
    provider: str | None = None
    provider_message_id: str | None = None
    idempotency_key: str | None = None
    created_by: str | None = None
    subject: str | None = None
    content_state: str
    content: MessageContent | None = None
    sent_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


# -- audit --------------------------------------------------------------------------------------


class AuditEvent(AxentraModel):
    id: str
    occurred_at: datetime
    product_id: str | None = None
    tenant_id: str | None = None
    actor_kind: str
    actor_id: str
    actor_display: str
    action: str
    target_type: str
    target_id: str
    outcome: str
    details: dict[str, Any] = Field(default_factory=dict)
    ip: str | None = None
    request_id: str | None = None


__all__ = [
    "ApiKey",
    "ApiVersion",
    "AuditEvent",
    "AuthInfo",
    "AxentraModel",
    "DownloadUrl",
    "EffectiveLimit",
    "Entitlements",
    "FileInfo",
    "Invitation",
    "Me",
    "Membership",
    "Message",
    "MessageContent",
    "Meta",
    "Meter",
    "MeterUsage",
    "NewApiKey",
    "NewInvitation",
    "OidcProviderInfo",
    "Page",
    "Plan",
    "Price",
    "Product",
    "ProductAccess",
    "ProductMember",
    "QuotaStatus",
    "Record",
    "Role",
    "Session",
    "SessionInfo",
    "Subscription",
    "Tenant",
    "TenantAccess",
    "UsageEvent",
    "UsageRecordResult",
    "User",
]
