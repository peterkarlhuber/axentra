from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Header, Query, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, IfMatch, Limit, parse_if_match
from axentra.core.errors import Forbidden, ValidationFailed
from axentra.core.pagination import Page
from axentra.usage.models import (
    EffectiveLimit,
    Meter,
    MeterUsage,
    RecordResult,
    Reservation,
    TenantMeterTotal,
    TimeSeries,
    UsageEvent,
)
from axentra.usage.service import UNSET

router = APIRouter(prefix="/v1/products/{product_id}", tags=["usage"])
T = "/tenants/{tenant_id}/usage"

Number = Decimal


class MeterCreate(BaseModel):
    key: str = Field(min_length=1, max_length=63, description="e.g. api_calls, storage_bytes")
    name: str = Field(default="", max_length=200)
    unit: str = Field(default="", max_length=40)
    aggregation: Literal["sum", "max", "last"] = "sum"
    reset_period: Literal["none", "day", "month", "billing_period"] = "month"
    description: str = Field(default="", max_length=2000)
    default_limit: Number | None = None
    default_enforcement: Literal["hard", "soft"] = "hard"


class MeterUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    unit: str | None = Field(default=None, max_length=40)
    description: str | None = Field(default=None, max_length=2000)
    default_limit: Number | None = None
    default_enforcement: Literal["hard", "soft"] | None = None
    active: bool | None = None


class UsageRecord(BaseModel):
    meter: str = Field(max_length=63)
    quantity: Number
    occurred_at: datetime | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    enforce: bool = Field(
        default=True,
        description="false records without the hard-limit check; needs usage:manage on the product",
    )


class QuotaSet(BaseModel):
    limit: Number | None = Field(description="null = unlimited")
    enforcement: Literal["hard", "soft"] = "hard"


class ReservationCreate(BaseModel):
    meter: str = Field(max_length=63)
    quantity: Number
    ttl_seconds: int = Field(default=300, ge=1, le=86_400)


class ReservationCommit(BaseModel):
    quantity: Number | None = Field(default=None, description="Actual usage; default the reserved quantity")
    properties: dict[str, Any] = Field(default_factory=dict)


IdempotencyKey = Header(alias="Idempotency-Key", max_length=200, description="Unique per tenant")


# -- meters --


@router.get("/usage/meters", response_model=list[Meter])
def list_meters(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[Meter]:
    return ax.usage.list_meters(principal, product_id)


@router.post("/usage/meters", response_model=Meter, status_code=201)
def create_meter(product_id: str, body: MeterCreate, principal: CurrentPrincipal, ax: Ax) -> Meter:
    return ax.usage.create_meter(principal, product_id, **body.model_dump())


@router.get("/usage/meters/{meter_id}", response_model=Meter)
def get_meter(
    product_id: str, meter_id: str, principal: CurrentPrincipal, ax: Ax, response: Response
) -> Meter:
    m = ax.usage.get_meter(principal, product_id, meter_id)
    response.headers["ETag"] = f'"{m.version}"'
    return m


@router.patch(
    "/usage/meters/{meter_id}",
    response_model=Meter,
    summary="Edit a meter (key, aggregation and reset period are immutable)",
)
def update_meter(
    product_id: str,
    meter_id: str,
    body: MeterUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Meter:
    return ax.usage.update_meter(
        principal,
        product_id,
        meter_id,
        name=body.name,
        unit=body.unit,
        description=body.description,
        default_limit=body.default_limit if "default_limit" in body.model_fields_set else UNSET,
        default_enforcement=body.default_enforcement,
        active=body.active,
        if_match=parse_if_match(if_match),
    )


@router.delete("/usage/meters/{meter_id}", status_code=204, summary="Delete a meter without recorded usage")
def delete_meter(
    product_id: str, meter_id: str, principal: CurrentPrincipal, ax: Ax, if_match: IfMatch = None
) -> Response:
    ax.usage.delete_meter(principal, product_id, meter_id, if_match=parse_if_match(if_match))
    return Response(status_code=204)


# -- product-wide statistics --


@router.get(
    "/usage/summary", response_model=Page[TenantMeterTotal], summary="Usage totals per tenant and meter"
)
def product_summary(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    since: date | None = None,
    until: date | None = None,
    meter: str | None = Query(None, max_length=63),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[TenantMeterTotal]:
    return ax.usage.product_totals(
        principal, product_id, since=since, until=until, meter=meter, limit=limit, cursor=cursor
    )


@router.get(
    "/usage/timeseries", response_model=TimeSeries, summary="Daily usage of a meter across all tenants"
)
def product_timeseries(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    meter: str = Query(max_length=63),
    since: date | None = None,
    until: date | None = None,
) -> TimeSeries:
    return ax.usage.timeseries(principal, product_id, meter, since=since, until=until)


# -- tenant usage --


@router.post(
    T + "/events",
    response_model=RecordResult,
    status_code=201,
    summary="Record usage (idempotent; 200 when the Idempotency-Key was seen before)",
    responses={429: {"description": "A hard quota would be exceeded"}},
)
def record_usage(
    product_id: str,
    tenant_id: str,
    body: UsageRecord,
    principal: CurrentPrincipal,
    ax: Ax,
    response: Response,
    idempotency_key: str = IdempotencyKey,
) -> RecordResult:
    args = (
        principal,
        product_id,
        tenant_id,
        body.meter,
        body.quantity,
        idempotency_key,
        body.occurred_at,
        body.properties,
    )
    if body.enforce:
        result = ax.usage.check_and_record(*args)
    else:
        if not ax.authz.has(principal, "usage:manage", product_id):
            raise Forbidden("recording without quota enforcement needs usage:manage")
        result = ax.usage.record(*args)
    if result.replayed:
        response.status_code = 200
    return result


@router.get(T + "/events", response_model=Page[UsageEvent])
def list_usage_events(
    product_id: str,
    tenant_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    meter: str | None = Query(None, max_length=63),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[UsageEvent]:
    return ax.usage.list_events(
        principal, product_id, tenant_id, meter=meter, since=since, until=until, limit=limit, cursor=cursor
    )


@router.get(
    T + "/summary", response_model=list[MeterUsage], summary="Current-period usage and limits per meter"
)
def tenant_summary(
    product_id: str,
    tenant_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    at: datetime | None = Query(None, description="Any time inside the wanted period (default now)"),
) -> list[MeterUsage]:
    if at is not None and at.tzinfo is None:
        raise ValidationFailed("at must include a timezone")
    return ax.usage.summary(principal, product_id, tenant_id, at=at)


@router.get(T + "/timeseries", response_model=TimeSeries, summary="Daily usage of a meter in a tenant")
def tenant_timeseries(
    product_id: str,
    tenant_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    meter: str = Query(max_length=63),
    since: date | None = None,
    until: date | None = None,
) -> TimeSeries:
    return ax.usage.timeseries(principal, product_id, meter, tenant_id=tenant_id, since=since, until=until)


@router.get(
    T + "/quotas", response_model=list[EffectiveLimit], summary="Effective limit per meter and its source"
)
def list_quotas(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> list[EffectiveLimit]:
    return ax.usage.limits(principal, product_id, tenant_id)


@router.put(T + "/quotas/{meter}", response_model=EffectiveLimit, summary="Set the tenant's quota override")
def set_quota(
    product_id: str, tenant_id: str, meter: str, body: QuotaSet, principal: CurrentPrincipal, ax: Ax
) -> EffectiveLimit:
    return ax.usage.set_quota(
        principal, product_id, tenant_id, meter, limit=body.limit, enforcement=body.enforcement
    )


@router.delete(
    T + "/quotas/{meter}",
    response_model=EffectiveLimit,
    summary="Remove the override (plan/meter default applies)",
)
def delete_quota(
    product_id: str, tenant_id: str, meter: str, principal: CurrentPrincipal, ax: Ax
) -> EffectiveLimit:
    return ax.usage.delete_quota(principal, product_id, tenant_id, meter)


@router.post(
    T + "/reservations",
    response_model=Reservation,
    status_code=201,
    summary="Reserve quantity against the limit",
    responses={429: {"description": "A hard quota would be exceeded"}},
)
def create_reservation(
    product_id: str,
    tenant_id: str,
    body: ReservationCreate,
    principal: CurrentPrincipal,
    ax: Ax,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=200),
) -> Reservation:
    return ax.usage.reserve(
        principal,
        product_id,
        tenant_id,
        body.meter,
        body.quantity,
        ttl_seconds=body.ttl_seconds,
        idempotency_key=idempotency_key,
    )


@router.get(T + "/reservations/{reservation_id}", response_model=Reservation)
def get_reservation(
    product_id: str, tenant_id: str, reservation_id: str, principal: CurrentPrincipal, ax: Ax
) -> Reservation:
    return ax.usage.get_reservation(principal, product_id, tenant_id, reservation_id)


@router.post(
    T + "/reservations/{reservation_id}/commit",
    response_model=RecordResult,
    summary="Record the actual usage (idempotent)",
)
def commit_reservation(
    product_id: str,
    tenant_id: str,
    reservation_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    body: ReservationCommit | None = None,
) -> RecordResult:
    body = body or ReservationCommit()
    return ax.usage.commit_reservation(
        principal, product_id, tenant_id, reservation_id, quantity=body.quantity, properties=body.properties
    )


@router.post(T + "/reservations/{reservation_id}/release", response_model=Reservation)
def release_reservation(
    product_id: str, tenant_id: str, reservation_id: str, principal: CurrentPrincipal, ax: Ax
) -> Reservation:
    return ax.usage.release_reservation(principal, product_id, tenant_id, reservation_id)
