from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, IfMatch, Limit, parse_if_match
from axentra.billing.models import (
    CheckoutSession,
    Entitlements,
    EntitlementValue,
    Plan,
    Subscription,
    WebhookResult,
)
from axentra.billing.service import MAX_WEBHOOK_BYTES
from axentra.core.errors import PayloadTooLarge
from axentra.core.pagination import Page

router = APIRouter(prefix="/v1", tags=["billing"])
P = "/products/{product_id}/billing"
T = "/products/{product_id}/tenants/{tenant_id}/billing"


class PriceIn(BaseModel):
    id: str | None = Field(default=None, max_length=40, description="Keep an existing price")
    amount_minor: int = Field(ge=0, le=10**10, description="Minor units (cents); 0 = free")
    currency: str = Field(min_length=3, max_length=3)
    interval: Literal["month", "year"] = "month"
    provider_price_id: str | None = Field(
        default=None, max_length=255, description="e.g. the Stripe price id"
    )


class PlanCreate(BaseModel):
    key: str = Field(min_length=1, max_length=63)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    active: bool = True
    trial_days: int = Field(default=0, ge=0, le=365)
    prices: list[PriceIn] = Field(default_factory=list, max_length=20, description="Empty = free plan")
    entitlements: dict[str, EntitlementValue] = Field(
        default_factory=dict, description='e.g. {"feature.sso": true, "limit.api_calls": 10000}'
    )


class PlanUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None
    trial_days: int | None = Field(default=None, ge=0, le=365)
    prices: list[PriceIn] | None = Field(default=None, max_length=20)
    entitlements: dict[str, EntitlementValue] | None = None


class SubscriptionCreate(BaseModel):
    plan: str = Field(max_length=63, description="Plan key or id")
    price_id: str | None = Field(default=None, max_length=40)


class SubscriptionCancel(BaseModel):
    at_period_end: bool = True


class SubscriptionStatusSet(BaseModel):
    status: Literal["trialing", "active", "past_due", "canceled", "incomplete"]


class CheckoutCreate(BaseModel):
    plan: str = Field(max_length=63)
    price_id: str | None = Field(default=None, max_length=40)
    success_url: str = Field(max_length=2000)
    cancel_url: str = Field(max_length=2000)


class OverridesSet(BaseModel):
    entitlements: dict[str, EntitlementValue] = Field(description="Replaces the overrides; {} removes them")


# -- plans --


@router.get(P + "/plans", response_model=list[Plan])
def list_plans(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[Plan]:
    return ax.billing.list_plans(principal, product_id)


@router.post(P + "/plans", response_model=Plan, status_code=201)
def create_plan(product_id: str, body: PlanCreate, principal: CurrentPrincipal, ax: Ax) -> Plan:
    data = body.model_dump()
    return ax.billing.create_plan(principal, product_id, **data)


@router.get(P + "/plans/{plan_id}", response_model=Plan)
def get_plan(product_id: str, plan_id: str, principal: CurrentPrincipal, ax: Ax, response: Response) -> Plan:
    plan = ax.billing.get_plan(principal, product_id, plan_id)
    response.headers["ETag"] = f'"{plan.version}"'
    return plan


@router.patch(P + "/plans/{plan_id}", response_model=Plan)
def update_plan(
    product_id: str,
    plan_id: str,
    body: PlanUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Plan:
    return ax.billing.update_plan(
        principal,
        product_id,
        plan_id,
        name=body.name,
        description=body.description,
        active=body.active,
        trial_days=body.trial_days,
        prices=[p.model_dump() for p in body.prices] if body.prices is not None else None,
        entitlements=body.entitlements,
        if_match=parse_if_match(if_match),
    )


@router.delete(P + "/plans/{plan_id}", status_code=204, summary="Delete a plan no subscription uses")
def delete_plan(
    product_id: str, plan_id: str, principal: CurrentPrincipal, ax: Ax, if_match: IfMatch = None
) -> Response:
    ax.billing.delete_plan(principal, product_id, plan_id, if_match=parse_if_match(if_match))
    return Response(status_code=204)


@router.get(P + "/subscriptions", response_model=Page[Subscription])
def list_subscriptions(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    status: Literal["trialing", "active", "past_due", "canceled", "incomplete"] | None = None,
    plan: str | None = Query(None, max_length=63),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Subscription]:
    return ax.billing.list_subscriptions(
        principal, product_id, status=status, plan=plan, limit=limit, cursor=cursor
    )


# -- tenant --


@router.get(T + "/plans", response_model=list[Plan], summary="Active plans the tenant can choose")
def tenant_plans(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> list[Plan]:
    return ax.billing.list_plans(principal, product_id, tenant_id)


@router.get(T + "/subscription", response_model=Subscription)
def get_subscription(
    product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax, response: Response
) -> Subscription:
    sub = ax.billing.get_subscription(principal, product_id, tenant_id)
    response.headers["ETag"] = f'"{sub.version}"'
    return sub


@router.post(
    T + "/subscription",
    response_model=Subscription,
    status_code=201,
    summary="Subscribe directly (free plans or manual provider)",
)
def create_subscription(
    product_id: str, tenant_id: str, body: SubscriptionCreate, principal: CurrentPrincipal, ax: Ax
) -> Subscription:
    return ax.billing.create_subscription(
        principal, product_id, tenant_id, plan=body.plan, price_id=body.price_id
    )


@router.post(T + "/subscription/change-plan", response_model=Subscription)
def change_plan(
    product_id: str,
    tenant_id: str,
    body: SubscriptionCreate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Subscription:
    return ax.billing.change_plan(
        principal,
        product_id,
        tenant_id,
        plan=body.plan,
        price_id=body.price_id,
        if_match=parse_if_match(if_match),
    )


@router.post(T + "/subscription/cancel", response_model=Subscription)
def cancel_subscription(
    product_id: str,
    tenant_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    body: SubscriptionCancel | None = None,
) -> Subscription:
    return ax.billing.cancel(
        principal, product_id, tenant_id, at_period_end=(body or SubscriptionCancel()).at_period_end
    )


@router.post(T + "/subscription/resume", response_model=Subscription)
def resume_subscription(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> Subscription:
    return ax.billing.resume(principal, product_id, tenant_id)


@router.post(
    T + "/subscription/status", response_model=Subscription, summary="Set the status (manual provider only)"
)
def set_subscription_status(
    product_id: str,
    tenant_id: str,
    body: SubscriptionStatusSet,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Subscription:
    return ax.billing.set_status(
        principal, product_id, tenant_id, body.status, if_match=parse_if_match(if_match)
    )


@router.post(
    T + "/checkout", response_model=CheckoutSession, status_code=201, summary="Start a checkout for a plan"
)
def create_checkout(
    product_id: str, tenant_id: str, body: CheckoutCreate, principal: CurrentPrincipal, ax: Ax
) -> CheckoutSession:
    return ax.billing.create_checkout(
        principal,
        product_id,
        tenant_id,
        plan=body.plan,
        price_id=body.price_id,
        success_url=body.success_url,
        cancel_url=body.cancel_url,
    )


@router.get(T + "/entitlements", response_model=Entitlements)
def get_entitlements(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> Entitlements:
    return ax.billing.get_entitlements(principal, product_id, tenant_id)


@router.put(
    T + "/entitlements/overrides",
    response_model=Entitlements,
    summary="Replace per-tenant entitlement overrides",
)
def set_overrides(
    product_id: str, tenant_id: str, body: OverridesSet, principal: CurrentPrincipal, ax: Ax
) -> Entitlements:
    return ax.billing.set_overrides(principal, product_id, tenant_id, body.entitlements)


# -- webhooks (public; authenticated by the provider signature) --


@router.post(
    "/billing/webhooks/{provider}",
    response_model=WebhookResult,
    summary="Payment provider webhook (Stripe-Signature HMAC; public route)",
    responses={400: {"description": "Invalid signature"}},
)
async def billing_webhook(provider: str, request: Request, ax: Ax) -> WebhookResult:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_WEBHOOK_BYTES:
        raise PayloadTooLarge("webhook payload is too large")
    body = await request.body()
    return await run_in_threadpool(
        ax.billing.handle_webhook, provider, body, request.headers.get("stripe-signature")
    )
