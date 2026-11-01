from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from axentra.core.errors import AxentraError

SubscriptionStatus = Literal["trialing", "active", "past_due", "canceled", "incomplete"]
Interval = Literal["month", "year"]
ProviderName = Literal["manual", "fake", "stripe"]
EntitlementValue = bool | int | float | None


class Price(BaseModel):
    id: str
    amount_minor: int
    """Amount in the currency's minor unit (cents); 0 = free."""
    currency: str
    interval: Interval
    provider_price_id: str | None = None


class Plan(BaseModel):
    id: str
    product_id: str
    key: str
    name: str
    description: str
    active: bool
    trial_days: int
    prices: list[Price]
    free: bool
    entitlements: dict[str, EntitlementValue]
    """``feature.<name>: bool`` and ``limit.<meter key>: number | null`` (null = unlimited)."""
    version: int
    created_at: datetime
    updated_at: datetime


class Subscription(BaseModel):
    id: str
    product_id: str
    tenant_id: str
    plan_id: str
    plan_key: str
    status: SubscriptionStatus
    price: Price | None
    current_period_start: datetime
    current_period_end: datetime
    trial_end: datetime | None
    cancel_at_period_end: bool
    canceled_at: datetime | None
    provider: ProviderName
    provider_customer_id: str | None
    provider_subscription_id: str | None
    version: int
    created_at: datetime
    updated_at: datetime


class Entitlements(BaseModel):
    product_id: str
    tenant_id: str
    plan_key: str | None
    subscription_id: str | None
    subscription_status: SubscriptionStatus | None
    features: dict[str, bool]
    limits: dict[str, float | None]
    """Per meter key; null = unlimited. Usage quotas use these as defaults."""
    overrides: dict[str, EntitlementValue]


class CheckoutSession(BaseModel):
    provider: ProviderName
    checkout_id: str | None
    url: str | None
    """Where to send the customer (provider hosted page); null when nothing is left to do."""
    completed: bool
    subscription: Subscription


class WebhookResult(BaseModel):
    received: bool = True
    event_id: str
    outcome: Literal["applied", "duplicate", "stale", "ignored", "unmatched", "rejected_transition"]


class WebhookSignatureInvalid(AxentraError):
    code = "invalid_signature"
    status = 400
    title = "Invalid webhook signature"


class PaymentProviderNotConfigured(AxentraError):
    code = "payment_provider_not_configured"
    status = 409
    title = "Payment provider not configured"


class PaymentProviderError(AxentraError):
    """The provider rejected a call or could not be reached (rendered as a 500 to clients)."""

    code = "payment_provider_error"
    status = 502
    title = "Payment provider error"
