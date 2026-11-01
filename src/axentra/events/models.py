"""Data models of the events module (jobs, schedules, events, webhooks, deliveries)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

JobStatus = Literal["queued", "running", "succeeded", "failed", "dead", "cancelled"]
JOB_STATUSES: tuple[JobStatus, ...] = ("queued", "running", "succeeded", "failed", "dead", "cancelled")
FINISHED_STATUSES = ("succeeded", "failed", "dead", "cancelled")
DeliveryStatus = Literal["pending", "succeeded", "failed", "dead"]


class Job(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    status: JobStatus
    priority: int = 0
    run_after: datetime
    attempts: int = 0
    max_attempts: int
    lease_until: datetime | None = None
    worker: str | None = None
    cancel_requested: bool = False
    last_error: str | None = None
    idempotency_key: str | None = None
    result: Any = None
    schedule_id: str | None = None
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class KindStats(BaseModel):
    kind: str
    queued: int = 0
    running: int = 0
    succeeded: int = 0
    failed: int = 0
    dead: int = 0
    cancelled: int = 0


class JobStats(BaseModel):
    """Dashboard summary of the jobs of a product (optionally one tenant)."""

    counts: dict[str, int]
    failed_last_24h: int
    succeeded_last_24h: int
    oldest_queued_at: datetime | None
    by_kind: list[KindStats]


class Schedule(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    name: str
    kind: str
    payload: dict[str, Any]
    interval_seconds: int | None
    cron: str | None
    enabled: bool
    priority: int
    max_attempts: int
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_job_id: str | None
    version: int
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class Event(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    type: str
    data: dict[str, Any]
    idempotency_key: str | None
    actor_kind: str
    actor_id: str
    request_id: str | None
    occurred_at: datetime


class WebhookEndpoint(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    url: str
    description: str
    event_types: list[str]
    enabled: bool
    version: int
    has_previous_secret: bool = False
    previous_secret_expires_at: datetime | None = None
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class NewWebhookSecret(BaseModel):
    """Returned exactly once, at creation and rotation."""

    endpoint: WebhookEndpoint
    secret: str


class Delivery(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    endpoint_id: str
    event_id: str | None
    event_type: str
    status: DeliveryStatus
    attempts: int
    response_code: int | None
    response_body: str | None
    duration_ms: int | None
    last_error: str | None
    next_attempt_at: datetime | None
    job_id: str | None
    created_at: datetime
    updated_at: datetime
    delivered_at: datetime | None


class StreamItem(BaseModel):
    """One item of an event or job stream; ``position`` is the SSE id (``Last-Event-ID``)."""

    position: str
    type: str
    data: dict[str, Any]
