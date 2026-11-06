from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, PlainSerializer

Quantity = Annotated[Decimal, PlainSerializer(float, return_type=float, when_used="json")]
"""Decimal in Python, a JSON number on the wire."""

Aggregation = Literal["sum", "max", "last"]
ResetPeriod = Literal["none", "day", "month", "billing_period"]
Enforcement = Literal["hard", "soft"]
LimitSource = Literal["quota", "plan", "meter", "none"]
ReservationStatus = Literal["active", "committed", "released", "expired"]


class Meter(BaseModel):
    id: str
    product_id: str
    key: str
    name: str
    unit: str
    aggregation: Aggregation
    reset_period: ResetPeriod
    description: str
    default_limit: Quantity | None
    default_enforcement: Enforcement
    active: bool
    version: int
    created_at: datetime
    updated_at: datetime


class UsageEvent(BaseModel):
    id: str
    product_id: str
    tenant_id: str
    meter: str
    quantity: Quantity
    idempotency_key: str
    occurred_at: datetime
    recorded_at: datetime
    period_start: datetime
    properties: dict[str, Any]
    reservation_id: str | None


class EffectiveLimit(BaseModel):
    meter: str
    limit: Quantity | None
    """``None``: unlimited."""
    enforcement: Enforcement
    source: LimitSource
    period: ResetPeriod


class QuotaStatus(BaseModel):
    meter: str
    period_start: datetime
    period_end: datetime | None
    used: Quantity
    reserved: Quantity
    limit: Quantity | None
    remaining: Quantity | None
    enforcement: Enforcement
    source: LimitSource
    over_limit: bool


class RecordResult(BaseModel):
    event: UsageEvent
    replayed: bool
    """True when the idempotency key was seen before and the original event is returned."""
    quota: QuotaStatus


class UsageEntry(BaseModel):
    """One entry of :meth:`axentra.usage.UsageService.record_batch`."""

    meter: str
    quantity: Any
    idempotency_key: str
    occurred_at: datetime | None = None
    properties: dict[str, Any] | None = None


class Reservation(BaseModel):
    id: str
    product_id: str
    tenant_id: str
    meter: str
    quantity: Quantity
    status: ReservationStatus
    period_start: datetime
    expires_at: datetime
    event_id: str | None
    committed_quantity: Quantity | None
    created_at: datetime
    updated_at: datetime


class MeterUsage(BaseModel):
    """Current-period usage of one meter in one tenant (with its effective limit)."""

    meter: str
    name: str
    unit: str
    aggregation: Aggregation
    reset_period: ResetPeriod
    period_start: datetime
    period_end: datetime | None
    value: Quantity
    event_count: int
    reserved: Quantity
    limit: Quantity | None
    remaining: Quantity | None
    enforcement: Enforcement
    source: LimitSource
    over_limit: bool


class TenantMeterTotal(BaseModel):
    tenant_id: str
    meter: str
    value: Quantity
    event_count: int


class TimePoint(BaseModel):
    day: date
    value: Quantity
    event_count: int


class TimeSeries(BaseModel):
    meter: str
    unit: str
    aggregation: Aggregation
    tenant_id: str | None
    since: date
    until: date
    points: list[TimePoint]
