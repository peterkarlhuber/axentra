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
    email_verified: bool = False
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


class PermissionInfo(AxentraModel):
    name: str
    scope: str
    description: str = ""
    source: str = "builtin"
    read_like: bool = False
    default_roles: list[str] = Field(default_factory=list)
    declared_by: str | None = None
    retired_at: datetime | None = None


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
    stored_inert: bool = False
    original_content_type: str | None = None
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


# -- events, jobs, schedules, webhooks ----------------------------------------------------------


class Job(AxentraModel):
    id: str
    product_id: str
    tenant_id: str | None = None
    kind: str
    status: str
    payload: dict[str, Any] = Field(default_factory=dict)
    priority: int = 0
    run_after: datetime
    attempts: int = 0
    max_attempts: int
    lease_until: datetime | None = None
    worker: str | None = None
    cancel_requested: bool = False
    last_error: str | None = None
    result: Any = None
    idempotency_key: str | None = None
    schedule_id: str | None = None
    created_by: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class KindStats(AxentraModel):
    kind: str
    queued: int = 0
    running: int = 0
    succeeded: int = 0
    failed: int = 0
    dead: int = 0
    cancelled: int = 0


class JobStats(AxentraModel):
    counts: dict[str, int] = Field(default_factory=dict)
    failed_last_24h: int
    succeeded_last_24h: int
    oldest_queued_at: datetime | None = None
    by_kind: list[KindStats] = Field(default_factory=list)


class EnqueueableKind(AxentraModel):
    kind: str
    enqueue_permission: str | None = None


class EnqueueableKinds(AxentraModel):
    """``any_kind`` is true for ``jobs:manage`` holders, who may enqueue every kind; ``items``
    lists the kinds opened to the caller through their ``enqueue_permission``."""

    any_kind: bool
    items: list[EnqueueableKind] = Field(default_factory=list)


class Event(AxentraModel):
    id: str
    product_id: str
    tenant_id: str | None = None
    type: str
    data: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None
    actor_kind: str
    actor_id: str
    request_id: str | None = None
    occurred_at: datetime


class Schedule(AxentraModel):
    id: str
    product_id: str
    tenant_id: str | None = None
    name: str
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    interval_seconds: int | None = None
    cron: str | None = None
    enabled: bool
    priority: int = 0
    max_attempts: int
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    last_job_id: str | None = None
    version: int
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime


class WebhookEndpoint(AxentraModel):
    id: str
    product_id: str
    tenant_id: str | None = None
    url: str
    description: str = ""
    event_types: list[str] = Field(default_factory=list)
    enabled: bool
    has_previous_secret: bool = False
    previous_secret_expires_at: datetime | None = None
    version: int
    created_by: str | None = None
    creator_has_access: bool | None = None
    created_at: datetime
    updated_at: datetime


class NewWebhookSecret(AxentraModel):
    """A webhook endpoint with its signing ``secret``, returned once (create, rotate)."""

    endpoint: WebhookEndpoint
    secret: str


class Delivery(AxentraModel):
    id: str
    product_id: str
    tenant_id: str | None = None
    endpoint_id: str
    event_id: str | None = None
    event_type: str
    status: str
    attempts: int
    response_code: int | None = None
    response_body: str | None = None
    duration_ms: int | None = None
    last_error: str | None = None
    next_attempt_at: datetime | None = None
    job_id: str | None = None
    created_at: datetime
    updated_at: datetime
    delivered_at: datetime | None = None


# -- search -------------------------------------------------------------------------------------


class SearchHit(AxentraModel):
    """A match. ``title_highlight`` and ``body_highlight`` are HTML-escaped text in which only
    the matched words are wrapped in ``<mark>``."""

    id: str
    kind: str
    ref_id: str
    title: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    rank: float
    title_highlight: str
    body_highlight: str
    updated_at: datetime


class SearchDocument(AxentraModel):
    id: str
    product_id: str
    tenant_id: str
    kind: str
    ref_id: str
    title: str
    body: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    language: str
    version: int
    created_by: str | None = None
    updated_by: str | None = None
    created_at: datetime
    updated_at: datetime


class SearchKindCount(AxentraModel):
    kind: str
    count: int


# -- notify templates and preferences ----------------------------------------------------------


class TemplateVariant(AxentraModel):
    subject: str
    text: str
    html: str | None = None


class Template(AxentraModel):
    id: str | None = None
    product_id: str
    key: str
    channel: str
    category: str
    name: str
    description: str
    variables: list[str] = Field(default_factory=list)
    sample_data: dict[str, Any] = Field(default_factory=dict)
    variants: dict[str, TemplateVariant] = Field(default_factory=dict)
    sensitive: bool
    version: int
    #: True for Axentra's built-in templates (``invitation``, ...) that the product has not overridden.
    builtin: bool
    system_only: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RenderedContent(AxentraModel):
    locale: str
    subject: str
    text: str
    html: str | None = None


class Preferences(AxentraModel):
    product_id: str
    tenant_id: str | None = None
    user_id: str
    opted_out: list[str] = Field(default_factory=list)
    available_categories: list[str] = Field(default_factory=list)
    locked_categories: list[str] = Field(default_factory=list)
    version: int


class InboxEntry(AxentraModel):
    """One in-app notification of the caller (channel ``inbox``); ``subject``/``text`` are
    ``None`` once the content was purged."""

    id: str
    product_id: str
    tenant_id: str | None = None
    template_key: str
    category: str
    created_at: datetime
    read_at: datetime | None = None
    subject: str | None = None
    text: str | None = None
    content_state: str


# -- usage reservations and billing checkout ---------------------------------------------------


class Reservation(AxentraModel):
    id: str
    product_id: str
    tenant_id: str
    meter: str
    quantity: Decimal
    status: str
    period_start: datetime
    expires_at: datetime
    event_id: str | None = None
    committed_quantity: Decimal | None = None
    created_at: datetime
    updated_at: datetime


class CheckoutSession(AxentraModel):
    provider: str
    checkout_id: str | None = None
    #: Where to send the customer; ``None`` when the provider completed the change directly.
    url: str | None = None
    completed: bool
    subscription: Subscription


# -- users admin, product invitations ----------------------------------------------------------


class UserProductRole(AxentraModel):
    product_id: str
    product_slug: str
    product_name: str
    role: str
    created_at: datetime


class UserTenantRole(AxentraModel):
    product_id: str
    product_slug: str
    product_name: str
    tenant_id: str
    tenant_slug: str
    tenant_name: str
    tenant_status: str
    role: str
    created_at: datetime


class UserMemberships(AxentraModel):
    products: list[UserProductRole] = Field(default_factory=list)
    tenants: list[UserTenantRole] = Field(default_factory=list)


class ExternalIdentity(AxentraModel):
    provider: str
    subject: str
    email: str
    created_at: datetime


class ProductInvitation(AxentraModel):
    id: str
    product_id: str
    email: str
    role: str
    invited_by: str | None = None
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None
    status: str


class NewProductInvitation(AxentraModel):
    invitation: ProductInvitation
    #: Returned once; the invitee accepts with it (``product_invitations.accept``).
    token: str
    accept_url: str | None = None


# -- search batches and streams ----------------------------------------------------------------


class SearchBatchResult(AxentraModel):
    created: int
    updated: int
    documents: list[SearchDocument] = Field(default_factory=list)


class StreamMessage(AxentraModel):
    """One server-sent event of ``events.stream()`` / ``jobs.stream()``: ``id`` is the stream
    position (pass it as ``last_event_id`` to resume), ``event`` the event type (an event's type,
    ``job.<status>`` for job changes, or ``error`` when the server ended the stream), ``data`` the decoded JSON payload."""

    id: str | None = None
    event: str
    data: Any = None


__all__ = [
    "ApiKey",
    "ApiVersion",
    "AuditEvent",
    "AuthInfo",
    "AxentraModel",
    "CheckoutSession",
    "Delivery",
    "DownloadUrl",
    "EffectiveLimit",
    "EnqueueableKind",
    "EnqueueableKinds",
    "Entitlements",
    "Event",
    "ExternalIdentity",
    "FileInfo",
    "InboxEntry",
    "Invitation",
    "Job",
    "JobStats",
    "KindStats",
    "Me",
    "Membership",
    "Message",
    "MessageContent",
    "Meta",
    "Meter",
    "MeterUsage",
    "NewApiKey",
    "NewInvitation",
    "NewProductInvitation",
    "NewWebhookSecret",
    "OidcProviderInfo",
    "Page",
    "Plan",
    "Preferences",
    "Price",
    "Product",
    "ProductAccess",
    "ProductInvitation",
    "ProductMember",
    "QuotaStatus",
    "Record",
    "RenderedContent",
    "Reservation",
    "Role",
    "Schedule",
    "SearchBatchResult",
    "SearchDocument",
    "SearchHit",
    "SearchKindCount",
    "Session",
    "SessionInfo",
    "StreamMessage",
    "Subscription",
    "Template",
    "TemplateVariant",
    "Tenant",
    "TenantAccess",
    "UsageEvent",
    "UsageRecordResult",
    "User",
    "UserMemberships",
    "UserProductRole",
    "UserTenantRole",
    "WebhookEndpoint",
]
