"""The persistent job queue in PostgreSQL and its authorized service.

Adapted from peterkarlhuber/nodestro-runtime src/nodestro_runtime/jobs.py at
a42b6724702821849af478ee9dd0bfa13617e28b (MIT, Copyright (c) 2026 Peter Karlhuber):
claim with ``FOR UPDATE SKIP LOCKED``, leases renewed by heartbeats, conditional finish, reaping
of expired leases, cancellation of queued and running jobs. Axentra adds products/tenants,
priorities, delayed jobs, retries with capped exponential backoff and jitter, dead letters,
idempotency keys, results and manual retry.

Guarantees (see docs/modules/EVENTS_AND_JOBS.md): a job is executed **at least once** while it
has attempts left; two workers never hold the same job at the same time (the lease fences
``complete``/``fail``), but a worker that loses its lease may still be running its handler when
another worker starts the next attempt. Handlers must therefore be idempotent. There is no
exactly-once execution.
"""

from __future__ import annotations

import builtins
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
import json
import logging
import random
import re
from typing import TYPE_CHECKING, Any

from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.access.permissions import (
    BY_NAME,
    PRODUCT,
    TENANT,
    is_product_permission_name,
    validate_permissions,
)
from axentra.audit.log import AuditLog
from axentra.config.settings import Settings
from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.core.redaction import redact, redact_text
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.events.models import FINISHED_STATUSES, JOB_STATUSES, Job, JobStats, KindStats, StreamItem
from axentra.events.streams import assign_positions

if TYPE_CHECKING:
    from axentra.events.worker import JobContext

logger = logging.getLogger(__name__)

Handler = Callable[["JobContext"], Any]

KIND = re.compile(r"^[a-z][a-z0-9_.:-]{0,99}$")
#: Kinds reserved for Axentra itself; they cannot be enqueued through the public API.
RESERVED_PREFIX = "axentra."
MAX_PAYLOAD_BYTES = 64_000
MAX_RESULT_BYTES = 64_000
MAX_ERROR_CHARS = 2000
NOTIFY_CHANNEL = "axentra_jobs"
#: ``created_by`` of jobs fired by a schedule: ``schedule:<schedule id>``.
SCHEDULE_CREATOR_PREFIX = "schedule:"
#: ``last_error`` prefix of jobs the worker skipped without running them (see :meth:`JobService.skip_reason`).
SKIPPED_PREFIX = "skipped: "


class PermanentJobError(Exception):
    """Raise from a handler to fail the job at once (status ``failed``), without further retries."""


class RetryJob(Exception):
    """Raise from a handler to retry later; ``delay_seconds`` overrides the computed backoff."""

    def __init__(self, message: str = "retry requested", *, delay_seconds: float | None = None) -> None:
        super().__init__(message)
        self.delay_seconds = delay_seconds


class JobCancelled(Exception):
    """Raise from a handler after :meth:`JobContext.cancel_requested` to end the job as cancelled."""


def backoff_delay(attempt: int, base: float, cap: float, *, rng: random.Random | None = None) -> float:
    """Capped exponential backoff with "equal jitter": between half and all of ``base * 2**(n-1)``."""
    step = float(min(cap, base * (2 ** max(0, min(attempt - 1, 60)))))
    r = float((rng or random).random())
    return step / 2 + r * step / 2


def format_error(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return redact_text(text)[:MAX_ERROR_CHARS]


def _json_size(value: Any) -> int:
    return len(json.dumps(value, default=str, separators=(",", ":")))


def check_kind(kind: str) -> str:
    if not isinstance(kind, str) or not KIND.match(kind):
        raise ValidationFailed("kind must be 1-100 characters: lowercase letters, digits and _ . : -")
    return kind


def check_payload(payload: dict[str, Any] | None, limit: int = MAX_PAYLOAD_BYTES) -> dict[str, Any]:
    payload = payload or {}
    if not isinstance(payload, dict):
        raise ValidationFailed("payload must be a JSON object")
    if _json_size(payload) > limit:
        raise ValidationFailed(f"payload is larger than {limit} bytes")
    return payload


def check_idempotency_key(key: str | None) -> str | None:
    if key is None:
        return None
    if not (1 <= len(key) <= 200) or not key.isprintable():
        raise ValidationFailed("idempotency key must be 1-200 printable characters")
    return key


@dataclass(frozen=True, slots=True)
class JobKindSpec:
    """Who may enqueue a job kind through the API and what its handler may do.

    - ``enqueue_permission``: a permission that lets callers *without* ``jobs:manage`` enqueue this
      kind for a tenant (typically ``events:publish``). ``None`` (the default): only ``jobs:manage``
      holders (product operators) may enqueue it through the API.
    - ``permissions``: the permission set of the handler's principal. ``None``: all built-in
      product and tenant permissions (trusted kinds only; product-defined permissions must be
      listed explicitly). Required when ``enqueue_permission`` is set.
    """

    kind: str
    enqueue_permission: str | None = None
    permissions: frozenset[str] | None = None


#: The handler principal's permissions when a kind declares none.
DEFAULT_HANDLER_PERMISSIONS = frozenset(PRODUCT | TENANT)


def job_scope(product_id: str, tenant_id: str | None) -> DbScope:
    return DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)


def _job(row: Row) -> Job:
    return Job.model_validate(row)


def public_job(job: Job) -> Job:
    """The job as shown to API callers: payload and result redacted."""
    return job.model_copy(update={"payload": redact(job.payload), "result": redact(job.result)})


class JobQueue:
    """Low-level queue operations (no authorization). Workers and other modules use this."""

    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    @property
    def lease_seconds(self) -> float:
        return float(self.settings.events.lease_seconds)

    # -- enqueue -------------------------------------------------------------------------------

    def enqueue_in_tx(
        self,
        tx: Tx,
        product_id: str,
        tenant_id: str | None,
        kind: str,
        payload: dict[str, Any] | None = None,
        *,
        priority: int = 0,
        run_after: datetime | None = None,
        delay_seconds: float = 0,
        max_attempts: int | None = None,
        idempotency_key: str | None = None,
        schedule_id: str | None = None,
        created_by: str | None = None,
        backoff_base_seconds: float | None = None,
        backoff_max_seconds: float | None = None,
    ) -> tuple[Job, bool]:
        """Insert a job in the caller's transaction; returns ``(job, created)``.

        With an ``idempotency_key`` that already exists for (product, tenant, kind) the existing
        job is returned with ``created=False`` and nothing is inserted."""
        check_kind(kind)
        payload = check_payload(payload)
        check_idempotency_key(idempotency_key)
        if not -100 <= priority <= 100:
            raise ValidationFailed("priority must be between -100 and 100")
        if delay_seconds < 0 or delay_seconds > 366 * 86400:
            raise ValidationFailed("delay_seconds must be between 0 and one year")
        if run_after is not None and run_after.tzinfo is None:
            raise ValidationFailed("run_after needs a time zone")
        attempts = max_attempts if max_attempts is not None else self.settings.events.default_max_attempts
        if not 1 <= attempts <= 100:
            raise ValidationFailed("max_attempts must be between 1 and 100")
        ev = self.settings.events
        row = tx.one(
            "INSERT INTO axentra_jobs (id, product_id, tenant_id, kind, payload, priority, run_after, max_attempts,"
            " backoff_base_seconds, backoff_max_seconds, idempotency_key, schedule_id, created_by)"
            " VALUES (%s, %s, %s, %s, %s, %s, coalesce(%s::timestamptz, clock_timestamp()) + make_interval(secs => %s),"
            " %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (product_id, tenant_key, kind, idempotency_key) WHERE idempotency_key IS NOT NULL"
            " DO NOTHING RETURNING *",
            (
                new_id("job"),
                product_id,
                tenant_id,
                kind,
                Jsonb(payload),
                priority,
                run_after,
                float(delay_seconds),
                attempts,
                backoff_base_seconds or ev.backoff_base_seconds,
                backoff_max_seconds or ev.backoff_max_seconds,
                idempotency_key,
                schedule_id,
                created_by,
            ),
        )
        if row is None:
            existing = tx.one_or_404(
                "SELECT * FROM axentra_jobs WHERE product_id = %s AND tenant_key = %s AND kind = %s"
                " AND idempotency_key = %s",
                (product_id, tenant_id or "", kind, idempotency_key),
                what="job",
            )
            return _job(existing), False
        tx.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, kind))
        return _job(row), True

    def enqueue(
        self,
        product_id: str,
        tenant_id: str | None,
        kind: str,
        payload: dict[str, Any] | None = None,
        **kw: Any,
    ) -> Job:
        with self.db.transaction(job_scope(product_id, tenant_id)) as tx:
            job, _ = self.enqueue_in_tx(tx, product_id, tenant_id, kind, payload, **kw)
        return job

    # -- worker side ---------------------------------------------------------------------------

    def claim(self, worker: str, kinds: list[str]) -> Job | None:
        """The next due queued job of ``kinds`` (priority, then due time), now running for ``worker``."""
        if not kinds:
            return None
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "UPDATE axentra_jobs SET status = 'running', worker = %s, attempts = attempts + 1,"
                " started_at = clock_timestamp(), lease_until = clock_timestamp() + make_interval(secs => %s)"
                " WHERE status = 'queued' AND id = (SELECT id FROM axentra_jobs WHERE status = 'queued'"
                " AND run_after <= clock_timestamp() AND kind = ANY(%s)"
                " ORDER BY priority DESC, run_after, id LIMIT 1 FOR UPDATE SKIP LOCKED)"
                " RETURNING *",
                (worker, self.lease_seconds, list(kinds)),
            )
        return _job(row) if row else None

    def heartbeat(self, job_ids: list[str], worker: str) -> dict[str, bool]:
        """Renew the leases of ``worker``'s jobs; returns ``{job_id: cancel_requested}`` for those
        still owned. A missing id means the lease was lost (the job was reaped or finished)."""
        if not job_ids:
            return {}
        with self.db.transaction(DbScope.platform()) as tx:
            rows = tx.all(
                "UPDATE axentra_jobs SET lease_until = clock_timestamp() + make_interval(secs => %s)"
                " WHERE id = ANY(%s) AND worker = %s AND status = 'running' RETURNING id, cancel_requested",
                (self.lease_seconds, list(job_ids), worker),
            )
        return {r["id"]: bool(r["cancel_requested"]) for r in rows}

    def complete(self, job_id: str, worker: str, result: Any = None) -> bool:
        """Mark a running job of ``worker`` succeeded; ``False`` when it no longer owned the job."""
        if result is not None and _json_size(result) > MAX_RESULT_BYTES:
            result = {"truncated": True, "note": f"result larger than {MAX_RESULT_BYTES} bytes"}
        with self.db.transaction(DbScope.platform()) as tx:
            n = tx.execute(
                "UPDATE axentra_jobs SET status = 'succeeded', result = %s, finished_at = clock_timestamp(),"
                " lease_until = NULL WHERE id = %s AND worker = %s AND status = 'running'",
                (Jsonb(result) if result is not None else None, job_id, worker),
            )
        return n == 1

    def fail(
        self,
        job_id: str,
        worker: str,
        error: str,
        *,
        permanent: bool = False,
        cancelled: bool = False,
        delay_seconds: float | None = None,
    ) -> str | None:
        """End an attempt that did not succeed; returns the new status or ``None`` (lease lost).

        ``queued`` (retry after backoff) while attempts remain, ``dead`` when they are used up,
        ``failed`` for permanent errors and ``cancelled`` when cancellation was requested."""
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT attempts, max_attempts, cancel_requested, backoff_base_seconds, backoff_max_seconds"
                " FROM axentra_jobs WHERE id = %s AND worker = %s AND status = 'running' FOR UPDATE",
                (job_id, worker),
            )
            if row is None:
                return None
            error = redact_text(error)[:MAX_ERROR_CHARS]
            if cancelled or row["cancel_requested"]:
                status = "cancelled"
            elif permanent:
                status = "failed"
            elif row["attempts"] >= row["max_attempts"]:
                status = "dead"
            else:
                status = "queued"
            if status == "queued":
                delay = (
                    delay_seconds
                    if delay_seconds is not None
                    else backoff_delay(
                        row["attempts"], row["backoff_base_seconds"], row["backoff_max_seconds"]
                    )
                )
                tx.execute(
                    "UPDATE axentra_jobs SET status = 'queued', worker = NULL, lease_until = NULL, last_error = %s,"
                    " run_after = clock_timestamp() + make_interval(secs => %s) WHERE id = %s",
                    (error, max(0.0, float(delay)), job_id),
                )
                tx.execute("SELECT pg_notify(%s, '')", (NOTIFY_CHANNEL,))
            else:
                tx.execute(
                    "UPDATE axentra_jobs SET status = %s, lease_until = NULL, last_error = %s,"
                    " finished_at = clock_timestamp() WHERE id = %s",
                    (status, error, job_id),
                )
        return status

    def reap_expired(self) -> list[Job]:
        """Jobs whose lease expired (their worker died or hung): re-queued with backoff while attempts
        remain, otherwise ``dead`` (``cancelled`` when cancellation had been requested)."""
        with self.db.transaction(DbScope.platform()) as tx:
            rows = tx.all(
                "UPDATE axentra_jobs SET"
                " status = CASE WHEN cancel_requested THEN 'cancelled' WHEN attempts >= max_attempts THEN 'dead'"
                " ELSE 'queued' END,"
                " run_after = CASE WHEN NOT cancel_requested AND attempts < max_attempts THEN clock_timestamp()"
                " + make_interval(secs => least(backoff_max_seconds, backoff_base_seconds"
                " * power(2, greatest(attempts - 1, 0))) * (0.5 + random() * 0.5)) ELSE run_after END,"
                " finished_at = CASE WHEN NOT cancel_requested AND attempts < max_attempts THEN NULL"
                " ELSE clock_timestamp() END,"
                " worker = NULL, lease_until = NULL,"
                " last_error = 'lease expired: the worker stopped renewing its lease'"
                " WHERE id IN (SELECT id FROM axentra_jobs WHERE status = 'running'"
                " AND lease_until < clock_timestamp() FOR UPDATE SKIP LOCKED)"
                " RETURNING *"
            )
            if rows:
                tx.execute("SELECT pg_notify(%s, '')", (NOTIFY_CHANNEL,))
        jobs = [_job(r) for r in rows]
        for j in jobs:
            logger.warning("reaped job %s (%s) after lease expiry -> %s", j.id, j.kind, j.status)
        return jobs

    def purge_finished(self, older_than_days: int) -> dict[str, int]:
        """Retention: delete finished jobs, events, deliveries and firings older than the limit."""
        days = float(older_than_days)
        with self.db.transaction(DbScope.platform()) as tx:
            jobs = tx.execute(
                "DELETE FROM axentra_jobs WHERE status IN ('succeeded', 'failed', 'dead', 'cancelled')"
                " AND finished_at < now() - make_interval(days => %s)",
                (int(days),),
            )
            deliveries = tx.execute(
                "DELETE FROM axentra_webhook_deliveries WHERE status IN ('succeeded', 'dead')"
                " AND updated_at < now() - make_interval(days => %s)",
                (int(days),),
            )
            events = tx.execute(
                "DELETE FROM axentra_events WHERE occurred_at < now() - make_interval(days => %s)"
                " AND NOT EXISTS (SELECT 1 FROM axentra_webhook_deliveries d WHERE d.event_id = axentra_events.id"
                " AND d.status IN ('pending', 'failed'))",
                (int(days),),
            )
            firings = tx.execute(
                "DELETE FROM axentra_schedule_firings WHERE fired_at < now() - make_interval(days => %s)",
                (int(days),),
            )
        return {"jobs": jobs, "events": events, "deliveries": deliveries, "firings": firings}

    def get(self, job_id: str) -> Job | None:
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            row = tx.one("SELECT * FROM axentra_jobs WHERE id = %s", (job_id,))
        return _job(row) if row else None


class JobService:
    """Authorized job operations plus the handler registry (``ax.jobs``)."""

    def __init__(self, db: Database, settings: Settings, authz: Authorizer, audit: AuditLog) -> None:
        self.db = db
        self.settings = settings
        self.authz = authz
        self.audit = audit
        self.queue = JobQueue(db, settings)
        self.handlers: dict[str, Handler] = {}
        self.kinds: dict[str, JobKindSpec] = {}
        self.skip_callbacks: dict[str, Callable[[Job, str], None]] = {}
        self.max_runtime: dict[str, float] = {}

    # -- registry ------------------------------------------------------------------------------

    def register(
        self,
        kind: str,
        handler: Handler,
        *,
        replace: bool = False,
        enqueue_permission: str | None = None,
        permissions: Iterable[str] | None = None,
        max_runtime_seconds: float | None = None,
    ) -> None:
        """Register the handler of a job kind (in every worker process that should run it).

        ``enqueue_permission`` and ``permissions`` declare the kind (see :class:`JobKindSpec` and
        :meth:`declare`). Without them only ``jobs:manage`` holders can enqueue the kind through
        the API and the handler holds all product and tenant permissions.

        ``max_runtime_seconds``: the worker stops renewing the lease of a job of this kind once its
        handler ran that long, so a hung handler loses the job (``ctx.lease_lost``) and the attempt
        is retried after the lease expires (at least once). ``None``: no limit."""
        check_kind(kind)
        if kind in self.handlers and not replace:
            raise ValueError(f"a handler for job kind {kind!r} is already registered")
        if max_runtime_seconds is not None and max_runtime_seconds <= 0:
            raise ValueError("max_runtime_seconds must be positive")
        if max_runtime_seconds is None:
            self.max_runtime.pop(kind, None)
        else:
            self.max_runtime[kind] = float(max_runtime_seconds)
        if enqueue_permission is not None or permissions is not None:
            self.declare(kind, enqueue_permission=enqueue_permission, permissions=permissions, replace=True)
        self.handlers[kind] = handler

    def declare(
        self,
        kind: str,
        *,
        enqueue_permission: str | None = None,
        permissions: Iterable[str] | None = None,
        replace: bool = False,
    ) -> JobKindSpec:
        """Declare a job kind without (or before) registering its handler.

        The API process needs the declaration to let tenant members enqueue a kind; the worker
        needs it to confine the handler's principal. Declare the same kinds in both (``register``
        with the same arguments does it in processes that also run the handler).

        A kind open to ``enqueue_permission`` must declare the handler's ``permissions``
        explicitly: job payloads come from callers and are untrusted."""
        check_kind(kind)
        if kind.startswith(RESERVED_PREFIX) and enqueue_permission is not None:
            raise ValueError(f"job kinds starting with {RESERVED_PREFIX!r} cannot be opened to the API")
        if kind in self.kinds and not replace:
            raise ValueError(f"job kind {kind!r} is already declared")
        if enqueue_permission is not None:
            pdef = BY_NAME.get(enqueue_permission)
            # Product-defined names are accepted by syntax (kinds are not bound to one product);
            # they work only in products that declare them.
            if (pdef is None and not is_product_permission_name(enqueue_permission)) or (
                pdef is not None and pdef.scope == "platform"
            ):
                raise ValueError(
                    f"enqueue_permission must be a product or tenant permission: {enqueue_permission!r}"
                )
            if permissions is None:
                raise ValueError(
                    "a job kind that callers without jobs:manage may enqueue must declare the handler's permissions"
                )
        perms = None if permissions is None else validate_permissions(set(permissions), any_product_name=True)
        spec = JobKindSpec(kind=kind, enqueue_permission=enqueue_permission, permissions=perms)
        self.kinds[kind] = spec
        return spec

    def handler_permissions(self, kind: str) -> frozenset[str]:
        spec = self.kinds.get(kind)
        if spec is None or spec.permissions is None:
            return DEFAULT_HANDLER_PERMISSIONS
        return spec.permissions

    def _enqueuer(self, created_by: str | None) -> Principal | None:
        """The user or API key that enqueued a job through :meth:`enqueue`, or that created the
        schedule which fired it (``schedule:<id>``); ``None`` for jobs enqueued in process."""
        if not created_by:
            return None
        if created_by.startswith(SCHEDULE_CREATOR_PREFIX):
            schedule_id = created_by.removeprefix(SCHEDULE_CREATOR_PREFIX)
            with self.db.transaction(DbScope.platform(), read_only=True) as tx:
                row = tx.one("SELECT created_by FROM axentra_schedules WHERE id = %s", (schedule_id,))
            if row is None:
                # The schedule is gone, so its creator cannot be checked: fail closed.
                return Principal(actor=Actor(ActorKind.USER, created_by))
            creator = row["created_by"]
            if creator and creator.startswith(SCHEDULE_CREATOR_PREFIX):
                return Principal(actor=Actor(ActorKind.USER, created_by))
            return self._enqueuer(creator)
        return self.authz.actor_principal(created_by)

    def principal_for(self, job: Job) -> Principal:
        """The principal a job's handler acts as.

        A system actor confined to the job's product (and tenant), never with platform permissions,
        holding the kind's declared permissions (:meth:`handler_permissions`). For jobs that a user
        or API key enqueued through :meth:`enqueue`, the set is further reduced to what that caller
        holds *now* in the job's scope, so a job never does more than its enqueuer could (and nothing
        once the enqueuer lost access). Jobs fired by a schedule follow the same rule with the
        schedule's creator."""
        from axentra.events.worker import job_principal

        perms = self.handler_permissions(job.kind)
        if not job.kind.startswith(RESERVED_PREFIX):
            enqueuer = self._enqueuer(job.created_by)
            if enqueuer is not None:
                try:
                    perms = perms & self.authz.grant(enqueuer, job.product_id, job.tenant_id).permissions
                except (Forbidden, NotFound):
                    perms = frozenset()
        return job_principal(job, perms)

    def skip_reason(self, job: Job) -> str | None:
        """Why a claimed job must not run, or ``None``. A job of an archived product or a suspended
        tenant is not run (the same status rule :meth:`Authorizer.grant` applies to every request
        and to the handler's principal); the worker ends it as ``failed`` with the reason, so it is
        kept and can be retried once the product or tenant is active again."""
        from axentra.events.worker import job_principal

        try:
            self.authz.grant(job_principal(job, frozenset()), job.product_id, job.tenant_id)
        except Forbidden:
            return "the product or tenant is not active"
        except NotFound:
            return "the product or tenant no longer exists"
        return None

    def on_skip(self, kind: str, callback: Callable[[Job, str], None]) -> None:
        """Run ``callback(job, reason)`` when the worker skips a job of ``kind`` (see
        :meth:`skip_reason`), for kinds that keep their own state next to the job."""
        self.skip_callbacks[kind] = callback

    def handler(self, kind: str) -> Callable[[Handler], Handler]:
        """Decorator form of :meth:`register`."""

        def deco(fn: Handler) -> Handler:
            self.register(kind, fn)
            return fn

        return deco

    # -- authorization helpers -----------------------------------------------------------------

    def _require_row(self, principal: Principal, perm: str, product_id: str, tenant_id: str | None) -> None:
        try:
            self.authz.require(principal, perm, product_id, tenant_id)
        except NotFound:
            raise NotFound("job not found") from None

    def _require_enqueue(
        self, principal: Principal, product_id: str, tenant_id: str | None, kind: str
    ) -> None:
        """``jobs:manage`` enqueues any kind; other callers only kinds declared with an
        ``enqueue_permission`` they hold in the tenant (see :meth:`declare`)."""
        if tenant_id is None:
            self.authz.require(principal, "jobs:manage", product_id)
            return
        grant = self.authz.grant(principal, product_id, tenant_id)
        if "jobs:manage" in grant.permissions:
            return
        spec = self.kinds.get(kind)
        if spec is None or spec.enqueue_permission is None:
            self.authz.refuse(
                principal,
                grant,
                "jobs:manage",
                product_id,
                tenant_id,
                f"missing permission jobs:manage (job kind {kind} is not open to tenant callers)",
            )
        if spec.enqueue_permission not in grant.permissions:
            self.authz.refuse(principal, grant, spec.enqueue_permission, product_id, tenant_id)

    # -- API operations ------------------------------------------------------------------------

    def enqueue(
        self,
        principal: Principal,
        product_id: str,
        kind: str,
        payload: dict[str, Any] | None = None,
        *,
        tenant_id: str | None = None,
        priority: int = 0,
        run_after: datetime | None = None,
        delay_seconds: float = 0,
        max_attempts: int | None = None,
        idempotency_key: str | None = None,
    ) -> Job:
        check_kind(kind)
        if kind.startswith(RESERVED_PREFIX):
            raise ValidationFailed(f"job kinds starting with {RESERVED_PREFIX!r} are reserved")
        self._require_enqueue(principal, product_id, tenant_id, kind)
        with self.db.transaction(job_scope(product_id, tenant_id)) as tx:
            job, created = self.queue.enqueue_in_tx(
                tx,
                product_id,
                tenant_id,
                kind,
                payload,
                priority=priority,
                run_after=run_after,
                delay_seconds=delay_seconds,
                max_attempts=max_attempts,
                idempotency_key=idempotency_key,
                created_by=principal.actor.id,
            )
            if not created:
                self._check_replay(principal, job, payload or {}, priority)
            if created:
                self.audit.record(
                    tx,
                    principal,
                    "events.job.enqueue",
                    target_type="job",
                    target_id=job.id,
                    product_id=product_id,
                    tenant_id=tenant_id,
                    details={"kind": kind},
                )
        return public_job(job)

    def _check_replay(self, principal: Principal, job: Job, payload: dict[str, Any], priority: int) -> None:
        """An Idempotency-Key replay returns the stored job only for the same request (kind,
        tenant, payload, priority) from its enqueuer or from a caller who may read jobs; anything
        else is ``409`` (without revealing the stored job)."""
        if job.payload != payload or job.priority != priority:
            raise Conflict("the idempotency key was already used for a different request")
        if job.created_by != principal.actor.id and not self.authz.has(
            principal, "jobs:read", job.product_id, job.tenant_id
        ):
            raise Conflict("the idempotency key was already used by another caller")

    def get(self, principal: Principal, product_id: str, job_id: str) -> Job:
        job = self._load(principal, product_id, job_id)
        self._require_row(principal, "jobs:read", product_id, job.tenant_id)
        return public_job(job)

    def _load(self, principal: Principal, product_id: str, job_id: str) -> Job:
        # Relation to the product first (404 for strangers), then the row, then the permission.
        self.authz.grant(principal, product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_jobs WHERE id = %s AND product_id = %s",
                (job_id, product_id),
                what="job",
            )
        return _job(row)

    def list(
        self,
        principal: Principal,
        product_id: str,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        kind: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Job]:
        self.authz.require(principal, "jobs:read", product_id, tenant_id)
        if status is not None and status not in JOB_STATUSES:
            raise ValidationFailed(f"status must be one of {', '.join(JOB_STATUSES)}")
        n = clamp_limit(limit)
        sql = "SELECT * FROM axentra_jobs WHERE product_id = %s"
        params: list[Any] = [product_id]
        if tenant_id is not None:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        if status is not None:
            sql += " AND status = %s"
            params.append(status)
        if kind is not None:
            sql += " AND kind = %s"
            params.append(kind)
        after = decode_cursor(cursor, ("str",))
        if after:
            sql += " AND id < %s"
            params.append(after[0])
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(n + 1)
        with self.db.transaction(job_scope(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [public_job(_job(r)) for r in rows[:n]]
        nxt = encode_cursor([items[-1].id]) if len(rows) > n and items else None
        return Page[Job](items=items, next_cursor=nxt)

    def stats(self, principal: Principal, product_id: str, *, tenant_id: str | None = None) -> JobStats:
        self.authz.require(principal, "jobs:read", product_id, tenant_id)
        where = "product_id = %s"
        params: list[Any] = [product_id]
        if tenant_id is not None:
            where += " AND tenant_id = %s"
            params.append(tenant_id)
        with self.db.transaction(job_scope(product_id, tenant_id), read_only=True) as tx:
            groups = tx.all(
                f"SELECT kind, status, count(*) AS n FROM axentra_jobs WHERE {where} GROUP BY kind, status"
                " ORDER BY kind",
                params,
            )
            summary = tx.one(
                "SELECT count(*) FILTER (WHERE status IN ('failed', 'dead') AND finished_at > now() - interval '24 hours')"
                " AS failed_24h,"
                " count(*) FILTER (WHERE status = 'succeeded' AND finished_at > now() - interval '24 hours')"
                " AS succeeded_24h,"
                f" min(created_at) FILTER (WHERE status = 'queued') AS oldest FROM axentra_jobs WHERE {where}",
                params,
            )
        counts = dict.fromkeys(JOB_STATUSES, 0)
        kinds: dict[str, KindStats] = {}
        for g in groups:
            counts[g["status"]] += int(g["n"])
            ks = kinds.setdefault(g["kind"], KindStats(kind=g["kind"]))
            setattr(ks, g["status"], int(g["n"]))
        assert summary is not None
        return JobStats(
            counts=counts,
            failed_last_24h=int(summary["failed_24h"]),
            succeeded_last_24h=int(summary["succeeded_24h"]),
            oldest_queued_at=summary["oldest"],
            by_kind=list(kinds.values()),
        )

    def retry(self, principal: Principal, product_id: str, job_id: str) -> Job:
        """Manually re-queue a ``failed`` or ``dead`` job with a fresh attempt budget."""
        job = self._load(principal, product_id, job_id)
        self._require_row(principal, "jobs:manage", product_id, job.tenant_id)
        with self.db.transaction(job_scope(product_id, job.tenant_id)) as tx:
            row = tx.one(
                "UPDATE axentra_jobs SET status = 'queued', attempts = 0, run_after = clock_timestamp(),"
                " worker = NULL, lease_until = NULL, finished_at = NULL, cancel_requested = false"
                " WHERE id = %s AND product_id = %s AND status IN ('failed', 'dead') RETURNING *",
                (job_id, product_id),
            )
            if row is None:
                raise Conflict("only failed or dead jobs can be retried")
            tx.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, row["kind"]))
            self.audit.record(
                tx,
                principal,
                "events.job.retry",
                target_type="job",
                target_id=job_id,
                product_id=product_id,
                tenant_id=job.tenant_id,
                details={"kind": job.kind, "previous_status": job.status},
            )
        return public_job(_job(row))

    def cancel(self, principal: Principal, product_id: str, job_id: str) -> Job:
        """Queued jobs are cancelled at once; running jobs get ``cancel_requested`` for their handler."""
        job = self._load(principal, product_id, job_id)
        self._require_row(principal, "jobs:manage", product_id, job.tenant_id)
        return public_job(self.cancel_internal(product_id, job_id, principal=principal))

    def cancel_internal(self, product_id: str, job_id: str, *, principal: Principal | None = None) -> Job:
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_jobs WHERE id = %s AND product_id = %s FOR UPDATE",
                (job_id, product_id),
                what="job",
            )
            if row["status"] == "queued":
                row = tx.one_or_404(
                    "UPDATE axentra_jobs SET status = 'cancelled', finished_at = clock_timestamp()"
                    " WHERE id = %s RETURNING *",
                    (job_id,),
                )
            elif row["status"] == "running":
                row = tx.one_or_404(
                    "UPDATE axentra_jobs SET cancel_requested = true WHERE id = %s RETURNING *", (job_id,)
                )
            else:
                raise Conflict(f"the job is already {row['status']}")
            self.audit.record(
                tx,
                principal or Principal.system("jobs"),
                "events.job.cancel",
                target_type="job",
                target_id=job_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
                details={"kind": row["kind"], "status": row["status"]},
            )
        return _job(row)

    # -- streams -------------------------------------------------------------------------------

    def poll_changes(
        self, product_id: str, tenant_id: str | None, after: int, *, limit: int = 100
    ) -> builtins.list[StreamItem]:
        """Job changes after a stream position (no authorization; callers authorize first)."""
        assign_positions(self.db)
        sql = "SELECT * FROM axentra_jobs WHERE product_id = %s"
        params: list[Any] = [product_id]
        if tenant_id is not None:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        sql += " AND change_pos > %s ORDER BY change_pos LIMIT %s"
        params += [after, limit]
        with self.db.transaction(job_scope(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        out = []
        for r in rows:
            job = public_job(_job(r))
            out.append(
                StreamItem(
                    position=str(r["change_pos"]), type="job." + job.status, data=job.model_dump(mode="json")
                )
            )
        return out


__all__ = [
    "DEFAULT_HANDLER_PERMISSIONS",
    "FINISHED_STATUSES",
    "Handler",
    "JobCancelled",
    "JobKindSpec",
    "JobQueue",
    "JobService",
    "PermanentJobError",
    "RetryJob",
    "backoff_delay",
]
