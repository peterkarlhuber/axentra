"""HTTP API of the events module: jobs, schedules, events, webhooks and SSE streams."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import datetime
import json
import time
from typing import Any

import anyio
from fastapi import APIRouter, Header, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from axentra.api.context import Ax, CurrentPrincipal, resolve_principal
from axentra.api.routes.common import Cursor, IfMatch, Limit, parse_if_match
from axentra.core.context import Principal
from axentra.core.errors import AxentraError
from axentra.core.pagination import Page
from axentra.events.jobs import job_scope
from axentra.events.models import (
    Delivery,
    EnqueueableKinds,
    Event,
    Job,
    JobStats,
    JobStatus,
    NewWebhookSecret,
    Schedule,
    StreamItem,
    WebhookEndpoint,
)
from axentra.events.streams import current_position, parse_position
from axentra.platform import Axentra

router = APIRouter(prefix="/v1/products/{product_id}", tags=["events"])

IdemHeader = Header(
    None, alias="Idempotency-Key", max_length=200, description="Repeat-safe key; overrides the body field"
)


# -- request bodies -------------------------------------------------------------------------------


class JobCreate(BaseModel):
    kind: str = Field(min_length=1, max_length=100)
    payload: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str | None = None
    priority: int = Field(0, ge=-100, le=100)
    run_after: datetime | None = None
    delay_seconds: float = Field(0, ge=0, le=31_622_400)
    max_attempts: int | None = Field(None, ge=1, le=100)
    idempotency_key: str | None = Field(None, min_length=1, max_length=200)


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=100)
    payload: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str | None = None
    interval_seconds: int | None = Field(None, ge=10, le=31_622_400)
    cron: str | None = Field(None, max_length=200, description="5 fields, UTC: minute hour dom month dow")
    enabled: bool = True
    priority: int = Field(0, ge=-100, le=100)
    max_attempts: int = Field(5, ge=1, le=100)


class ScheduleUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    kind: str | None = Field(None, min_length=1, max_length=100)
    payload: dict[str, Any] | None = None
    interval_seconds: int | None = Field(None, ge=10, le=31_622_400)
    cron: str | None = Field(None, max_length=200)
    enabled: bool | None = None
    priority: int | None = Field(None, ge=-100, le=100)
    max_attempts: int | None = Field(None, ge=1, le=100)


class EventCreate(BaseModel):
    type: str = Field(min_length=1, max_length=150)
    data: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(None, min_length=1, max_length=200)


class WebhookCreate(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    event_types: list[str] = Field(min_length=1, max_length=50)
    description: str = Field("", max_length=1000)
    tenant_id: str | None = Field(None, description="Only deliver events of this tenant")
    enabled: bool = True


class WebhookUpdate(BaseModel):
    url: str | None = Field(None, min_length=8, max_length=2000)
    event_types: list[str] | None = Field(None, min_length=1, max_length=50)
    description: str | None = Field(None, max_length=1000)
    enabled: bool | None = None


class SecretRotate(BaseModel):
    grace_seconds: int = Field(0, ge=0, le=604_800)


# -- streams (SSE) ---------------------------------------------------------------------------------

_STREAM_DOC = (
    "Server-sent events. Each message has `id` (the stream position; send it back as `Last-Event-ID` "
    "to resume), `event` and JSON `data`. Without `Last-Event-ID` the stream starts with new items. "
    "Authorization is re-checked periodically; the stream ends with an `error` event when access is "
    "lost and closes after `events.sse_max_seconds` (reconnect to continue)."
)


def _sse(item_id: str | None, event: str, data: Any) -> bytes:
    lines = []
    if item_id:
        lines.append(f"id: {item_id}")
    lines.append(f"event: {event}")
    lines.append("data: " + json.dumps(data, separators=(",", ":"), default=str))
    return ("\n".join(lines) + "\n\n").encode()


def _reauthenticate(request: Request) -> Principal:
    if hasattr(request.state, "principal"):
        del request.state.principal
    return resolve_principal(request)


def _stream(
    request: Request,
    ax: Axentra,
    principal: Principal,
    product_id: str,
    tenant_id: str | None,
    last_event_id: str | None,
    poll: Callable[[int], list[StreamItem]],
    table: str,
) -> StreamingResponse:
    ax.events.authorize_stream(principal, product_id, tenant_id)
    if last_event_id:
        start = parse_position(last_event_id)
    else:
        start = current_position(ax.db, job_scope(product_id, tenant_id), table)
    ev = ax.settings.events

    async def gen() -> AsyncIterator[bytes]:
        position = start
        started = last_auth = last_send = time.monotonic()
        yield b"retry: 3000\n\n"
        while True:
            now = time.monotonic()
            if now - started >= ev.sse_max_seconds or await request.is_disconnected():
                return
            if now - last_auth >= ev.sse_reauth_seconds:
                last_auth = now
                try:
                    p = await run_in_threadpool(_reauthenticate, request)
                    await run_in_threadpool(ax.events.authorize_stream, p, product_id, tenant_id)
                except AxentraError as exc:
                    yield _sse(None, "error", {"code": exc.code, "detail": exc.detail})
                    return
            items = await run_in_threadpool(poll, position)
            for item in items:
                position = parse_position(item.position)
                if item.type:
                    yield _sse(item.position, item.type, item.data)
                    last_send = time.monotonic()
            if items:
                continue
            if time.monotonic() - last_send >= ev.sse_keepalive_seconds:
                yield b": keep-alive\n\n"
                last_send = time.monotonic()
            await anyio.sleep(ev.sse_poll_seconds)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.get(
    "/events/stream",
    summary="Stream new events (SSE)",
    description=_STREAM_DOC,
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
def stream_events(
    product_id: str,
    request: Request,
    principal: CurrentPrincipal,
    ax: Ax,
    tenant_id: str | None = Query(None, max_length=64),
    types: str | None = Query(
        None, max_length=1000, description="Comma-separated type patterns, e.g. invoice.*"
    ),
    last_event_id: str | None = Header(None, alias="Last-Event-ID", max_length=64),
) -> StreamingResponse:
    patterns = [t.strip() for t in types.split(",") if t.strip()] if types else None
    return _stream(
        request,
        ax,
        principal,
        product_id,
        tenant_id,
        last_event_id,
        lambda pos: ax.events.poll(product_id, tenant_id, pos, types=patterns),
        "axentra_events",
    )


@router.get(
    "/jobs/stream",
    summary="Stream job status changes (SSE)",
    description=_STREAM_DOC
    + " Only the latest state of a job is guaranteed; intermediate states may be skipped.",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
def stream_jobs(
    product_id: str,
    request: Request,
    principal: CurrentPrincipal,
    ax: Ax,
    tenant_id: str | None = Query(None, max_length=64),
    last_event_id: str | None = Header(None, alias="Last-Event-ID", max_length=64),
) -> StreamingResponse:
    return _stream(
        request,
        ax,
        principal,
        product_id,
        tenant_id,
        last_event_id,
        lambda pos: ax.jobs.poll_changes(product_id, tenant_id, pos),
        "axentra_jobs",
    )


# -- jobs ----------------------------------------------------------------------------------------


@router.get("/jobs", response_model=Page[Job], summary="List jobs (newest first)")
def list_jobs(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    status: JobStatus | None = None,
    kind: str | None = Query(None, max_length=100),
    tenant_id: str | None = Query(None, max_length=64),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Job]:
    return ax.jobs.list(
        principal, product_id, tenant_id=tenant_id, status=status, kind=kind, limit=limit, cursor=cursor
    )


@router.get("/jobs/stats", response_model=JobStats, summary="Job counts per status and recent failures")
def job_stats(
    product_id: str, principal: CurrentPrincipal, ax: Ax, tenant_id: str | None = Query(None, max_length=64)
) -> JobStats:
    return ax.jobs.stats(principal, product_id, tenant_id=tenant_id)


@router.get(
    "/jobs/kinds",
    response_model=EnqueueableKinds,
    summary="Job kinds the caller may enqueue (in the product or one tenant)",
)
def enqueueable_kinds(
    product_id: str, principal: CurrentPrincipal, ax: Ax, tenant_id: str | None = Query(None, max_length=64)
) -> EnqueueableKinds:
    """Lists the kinds declared (or registered) in the answering API process that the caller may
    enqueue with `POST .../jobs`: with `jobs:manage` every known kind (`any_kind: true`; other
    kinds are accepted too), otherwise the kinds declared with an `enqueue_permission` the caller
    holds in `tenant_id`. Needs access to the scope, no particular permission."""
    return ax.jobs.enqueueable_kinds(principal, product_id, tenant_id=tenant_id)


@router.post("/jobs", response_model=Job, status_code=201, summary="Enqueue a job")
def enqueue_job(
    product_id: str,
    body: JobCreate,
    principal: CurrentPrincipal,
    ax: Ax,
    idempotency_key: str | None = IdemHeader,
) -> Job:
    return ax.jobs.enqueue(
        principal,
        product_id,
        body.kind,
        body.payload,
        tenant_id=body.tenant_id,
        priority=body.priority,
        run_after=body.run_after,
        delay_seconds=body.delay_seconds,
        max_attempts=body.max_attempts,
        idempotency_key=idempotency_key or body.idempotency_key,
    )


@router.get("/jobs/{job_id}", response_model=Job)
def get_job(product_id: str, job_id: str, principal: CurrentPrincipal, ax: Ax) -> Job:
    return ax.jobs.get(principal, product_id, job_id)


@router.post("/jobs/{job_id}/retry", response_model=Job, summary="Re-queue a failed or dead job")
def retry_job(product_id: str, job_id: str, principal: CurrentPrincipal, ax: Ax) -> Job:
    return ax.jobs.retry(principal, product_id, job_id)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=Job,
    summary="Cancel a queued job, or request cancellation of a running one",
)
def cancel_job(product_id: str, job_id: str, principal: CurrentPrincipal, ax: Ax) -> Job:
    return ax.jobs.cancel(principal, product_id, job_id)


# -- schedules -----------------------------------------------------------------------------------


@router.get("/schedules", response_model=Page[Schedule])
def list_schedules(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    tenant_id: str | None = Query(None, max_length=64),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Schedule]:
    return ax.schedules.list(principal, product_id, tenant_id=tenant_id, limit=limit, cursor=cursor)


@router.post("/schedules", response_model=Schedule, status_code=201)
def create_schedule(product_id: str, body: ScheduleCreate, principal: CurrentPrincipal, ax: Ax) -> Schedule:
    return ax.schedules.create(principal, product_id, **body.model_dump())


@router.get("/schedules/{schedule_id}", response_model=Schedule)
def get_schedule(
    product_id: str, schedule_id: str, principal: CurrentPrincipal, ax: Ax, response: Response
) -> Schedule:
    s = ax.schedules.get(principal, product_id, schedule_id)
    response.headers["ETag"] = f'"{s.version}"'
    return s


@router.patch("/schedules/{schedule_id}", response_model=Schedule)
def update_schedule(
    product_id: str,
    schedule_id: str,
    body: ScheduleUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Schedule:
    return ax.schedules.update(
        principal,
        product_id,
        schedule_id,
        changes=body.model_dump(exclude_unset=True),
        if_match=parse_if_match(if_match),
    )


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(
    product_id: str, schedule_id: str, principal: CurrentPrincipal, ax: Ax, if_match: IfMatch = None
) -> Response:
    ax.schedules.delete(principal, product_id, schedule_id, if_match=parse_if_match(if_match))
    return Response(status_code=204)


# -- events --------------------------------------------------------------------------------------


@router.get("/events", response_model=Page[Event], summary="List events (newest first)")
def list_events(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    tenant_id: str | None = Query(None, max_length=64),
    type: str | None = Query(None, max_length=150, description="Exact type, or a prefix ending in *"),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Event]:
    return ax.events.list(principal, product_id, tenant_id=tenant_id, type=type, limit=limit, cursor=cursor)


@router.post(
    "/tenants/{tenant_id}/events",
    response_model=Event,
    status_code=201,
    summary="Publish an event in a tenant",
)
def publish_event(
    product_id: str,
    tenant_id: str,
    body: EventCreate,
    principal: CurrentPrincipal,
    ax: Ax,
    idempotency_key: str | None = IdemHeader,
) -> Event:
    return ax.events.publish(
        principal, product_id, tenant_id, body.type, body.data, idempotency_key or body.idempotency_key
    )


@router.get("/events/{event_id}", response_model=Event)
def get_event(product_id: str, event_id: str, principal: CurrentPrincipal, ax: Ax) -> Event:
    return ax.events.get(principal, product_id, event_id)


# -- webhooks ------------------------------------------------------------------------------------


@router.get("/webhooks", response_model=Page[WebhookEndpoint])
def list_webhooks(
    product_id: str, principal: CurrentPrincipal, ax: Ax, limit: Limit = None, cursor: Cursor = None
) -> Page[WebhookEndpoint]:
    return ax.webhooks.list(principal, product_id, limit=limit, cursor=cursor)


@router.post(
    "/webhooks",
    response_model=NewWebhookSecret,
    status_code=201,
    summary="Create a webhook endpoint (the signing secret is shown only in this response)",
)
def create_webhook(
    product_id: str, body: WebhookCreate, principal: CurrentPrincipal, ax: Ax
) -> NewWebhookSecret:
    return ax.webhooks.create(principal, product_id, **body.model_dump())


@router.get("/webhooks/{webhook_id}", response_model=WebhookEndpoint)
def get_webhook(
    product_id: str, webhook_id: str, principal: CurrentPrincipal, ax: Ax, response: Response
) -> WebhookEndpoint:
    w = ax.webhooks.get(principal, product_id, webhook_id)
    response.headers["ETag"] = f'"{w.version}"'
    return w


@router.patch("/webhooks/{webhook_id}", response_model=WebhookEndpoint)
def update_webhook(
    product_id: str,
    webhook_id: str,
    body: WebhookUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> WebhookEndpoint:
    return ax.webhooks.update(
        principal,
        product_id,
        webhook_id,
        changes=body.model_dump(exclude_unset=True, exclude_none=True),
        if_match=parse_if_match(if_match),
    )


@router.delete("/webhooks/{webhook_id}", status_code=204)
def delete_webhook(
    product_id: str, webhook_id: str, principal: CurrentPrincipal, ax: Ax, if_match: IfMatch = None
) -> Response:
    ax.webhooks.delete(principal, product_id, webhook_id, if_match=parse_if_match(if_match))
    return Response(status_code=204)


@router.post(
    "/webhooks/{webhook_id}/rotate-secret",
    response_model=NewWebhookSecret,
    summary="Rotate the signing secret (shown once; optional grace period signs with both)",
)
def rotate_webhook_secret(
    product_id: str, webhook_id: str, body: SecretRotate, principal: CurrentPrincipal, ax: Ax
) -> NewWebhookSecret:
    return ax.webhooks.rotate_secret(principal, product_id, webhook_id, grace_seconds=body.grace_seconds)


@router.post(
    "/webhooks/{webhook_id}/test",
    response_model=Delivery,
    summary="Send a signed axentra.ping now and return the recorded delivery",
)
def test_webhook(product_id: str, webhook_id: str, principal: CurrentPrincipal, ax: Ax) -> Delivery:
    return ax.webhooks.test(principal, product_id, webhook_id)


@router.get("/webhooks/{webhook_id}/deliveries", response_model=Page[Delivery])
def list_deliveries(
    product_id: str,
    webhook_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    status: str | None = Query(None, pattern="^(pending|succeeded|failed|dead)$"),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Delivery]:
    return ax.webhooks.list_deliveries(
        principal, product_id, webhook_id, status=status, limit=limit, cursor=cursor
    )


@router.get("/webhooks/{webhook_id}/deliveries/{delivery_id}", response_model=Delivery)
def get_delivery(
    product_id: str, webhook_id: str, delivery_id: str, principal: CurrentPrincipal, ax: Ax
) -> Delivery:
    return ax.webhooks.get_delivery(principal, product_id, webhook_id, delivery_id)


@router.post(
    "/webhooks/{webhook_id}/deliveries/{delivery_id}/redeliver",
    response_model=Delivery,
    status_code=202,
    summary="Queue a delivery again",
)
def redeliver(
    product_id: str, webhook_id: str, delivery_id: str, principal: CurrentPrincipal, ax: Ax
) -> Delivery:
    return ax.webhooks.redeliver(principal, product_id, webhook_id, delivery_id)
