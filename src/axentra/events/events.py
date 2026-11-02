"""Events: a transactional outbox plus in-process subscribers dispatched through the job queue.

``publish_in_tx(tx, ...)`` stores the event **and** its dispatch job in the caller's transaction,
so an event exists if and only if the product's own writes committed. A worker then runs the
dispatch job, which fans out (idempotently) one job per matching in-process subscriber and one
delivery per matching webhook endpoint. Every hop is at-least-once; subscribers and webhook
receivers must deduplicate by event id.
"""

from __future__ import annotations

import builtins
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.core.context import Principal
from axentra.core.errors import Conflict, NotFound, ValidationFailed
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, Row, Tx
from axentra.events.jobs import RESERVED_PREFIX, JobService, check_idempotency_key, job_scope
from axentra.events.models import Event, StreamItem
from axentra.events.streams import assign_positions

if TYPE_CHECKING:
    from axentra.events.worker import JobContext

logger = logging.getLogger(__name__)

EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.:-]{0,149}$")
TYPE_PATTERN = re.compile(r"^[a-z0-9_.:*-]{1,150}$")
MAX_DATA_BYTES = 64_000
DISPATCH_KIND = "axentra.event.dispatch"
HANDLE_KIND = "axentra.event.handle"

EventHandler = Callable[["JobContext", Event], Any]
FanOut = Callable[[Tx, Event], None]


def check_type(event_type: str) -> str:
    if not isinstance(event_type, str) or not EVENT_TYPE.match(event_type):
        raise ValidationFailed("type must be 1-150 characters: lowercase letters, digits and _ . : -")
    return event_type


def check_pattern(pattern: str) -> str:
    if not isinstance(pattern, str) or not TYPE_PATTERN.match(pattern):
        raise ValidationFailed("event type patterns use lowercase letters, digits, _ . : - and * wildcards")
    return pattern


def type_matches(event_type: str, patterns: builtins.list[str]) -> bool:
    return any(fnmatchcase(event_type, p) for p in patterns)


@dataclass(frozen=True)
class Subscriber:
    name: str
    pattern: str
    handler: EventHandler


def _event(row: Row) -> Event:
    return Event.model_validate(row)


class EventService:
    def __init__(self, db: Database, authz: Authorizer, audit: AuditLog, jobs: JobService) -> None:
        self.db = db
        self.authz = authz
        self.audit = audit
        self.jobs = jobs
        self.subscribers: dict[str, Subscriber] = {}
        self.fanouts: list[FanOut] = []
        jobs.register(DISPATCH_KIND, self._dispatch)
        jobs.register(HANDLE_KIND, self._handle)

    # -- subscribers ---------------------------------------------------------------------------

    def subscribe(self, type_pattern: str, handler: EventHandler, *, name: str | None = None) -> Subscriber:
        """Run ``handler(ctx, event)`` in a worker for every event whose type matches the glob
        ``type_pattern`` (e.g. ``invoice.*``). ``name`` identifies the subscriber durably (jobs refer
        to it); register the same subscribers in every worker process."""
        check_pattern(type_pattern)
        sub_name = (
            name or f"{getattr(handler, '__module__', 'x')}.{getattr(handler, '__qualname__', 'handler')}"
        )
        if not re.match(r"^[A-Za-z0-9_.:<>-]{1,200}$", sub_name):
            raise ValueError("subscriber names use letters, digits and _ . : - (max 200)")
        if sub_name in self.subscribers:
            raise ValueError(f"a subscriber named {sub_name!r} is already registered")
        sub = Subscriber(sub_name, type_pattern, handler)
        self.subscribers[sub_name] = sub
        return sub

    def unsubscribe(self, name: str) -> None:
        self.subscribers.pop(name, None)

    # -- publishing ----------------------------------------------------------------------------

    def publish_in_tx(
        self,
        tx: Tx,
        product_id: str,
        tenant_id: str | None,
        type: str,
        data: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        actor: Principal | None = None,
    ) -> Event:
        """Store an event in the caller's transaction (transactional outbox). No authorization:
        the caller has authorized the surrounding change. ``tx`` must be scoped to the product or
        tenant (or platform). Repeating an ``idempotency_key`` returns the existing event."""
        check_type(type)
        data = data or {}
        if not isinstance(data, dict):
            raise ValidationFailed("data must be a JSON object")
        if len(json.dumps(data, default=str)) > MAX_DATA_BYTES:
            raise ValidationFailed(f"event data is larger than {MAX_DATA_BYTES} bytes")
        check_idempotency_key(idempotency_key)
        scope = tx.scope
        if scope.kind != "platform" and (
            scope.product_id != product_id or (scope.kind == "tenant" and scope.tenant_id != tenant_id)
        ):
            raise ValueError("the transaction scope does not cover this product/tenant")
        eid = new_id("evt")
        row = tx.one(
            "INSERT INTO axentra_events (id, product_id, tenant_id, type, data, idempotency_key, actor_kind,"
            " actor_id, request_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (product_id, tenant_key, idempotency_key) WHERE idempotency_key IS NOT NULL"
            " DO NOTHING RETURNING *",
            (
                eid,
                product_id,
                tenant_id,
                type,
                Jsonb(data),
                idempotency_key,
                actor.actor.kind.value if actor else "system",
                actor.actor.id if actor else "",
                actor.request_id if actor else None,
            ),
        )
        if row is None:
            existing = tx.one_or_404(
                "SELECT * FROM axentra_events WHERE product_id = %s AND tenant_key = %s AND idempotency_key = %s",
                (product_id, tenant_id or "", idempotency_key),
                what="event",
            )
            return _event(existing)
        self.jobs.queue.enqueue_in_tx(
            tx,
            product_id,
            tenant_id,
            DISPATCH_KIND,
            {"event_id": eid},
            priority=10,
            idempotency_key=eid,
            max_attempts=20,
        )
        return _event(row)

    def publish(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str | None,
        type: str,
        data: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Event:
        """Authorized publish in its own transaction (``events:publish`` in the tenant; product-level
        events need ``jobs:manage``). Types starting with ``axentra.`` are reserved."""
        check_type(type)
        if type.startswith(RESERVED_PREFIX):
            raise ValidationFailed(f"event types starting with {RESERVED_PREFIX!r} are reserved")
        if tenant_id is None:
            self.authz.require(principal, "jobs:manage", product_id)
        else:
            self.authz.require(principal, "events:publish", product_id, tenant_id)
        with self.db.transaction(job_scope(product_id, tenant_id)) as tx:
            event = self.publish_in_tx(
                tx, product_id, tenant_id, type, data, idempotency_key=idempotency_key, actor=principal
            )
            if idempotency_key is not None:
                # A replay returns the stored event only for the same request from the same caller
                # (or a caller who may read events); anything else is 409 without the stored event.
                if event.type != type or event.data != (data or {}):
                    raise Conflict("the idempotency key was already used for a different request")
                if event.actor_id != principal.actor.id and not self.authz.has(
                    principal, "jobs:read", product_id, tenant_id
                ):
                    raise Conflict("the idempotency key was already used by another caller")
            return event

    # -- reading -------------------------------------------------------------------------------

    def get(self, principal: Principal, product_id: str, event_id: str) -> Event:
        self.authz.grant(principal, product_id)
        with self.db.transaction(job_scope(product_id, None), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_events WHERE id = %s AND product_id = %s",
                (event_id, product_id),
                what="event",
            )
        try:
            self.authz.require(principal, "jobs:read", product_id, row["tenant_id"])
        except NotFound:
            raise NotFound("event not found") from None
        return _event(row)

    def list(
        self,
        principal: Principal,
        product_id: str,
        *,
        tenant_id: str | None = None,
        type: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Event]:
        self.authz.require(principal, "jobs:read", product_id, tenant_id)
        n = clamp_limit(limit)
        sql = "SELECT * FROM axentra_events WHERE product_id = %s"
        params: builtins.list[Any] = [product_id]
        if tenant_id is not None:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        if type is not None:
            if type.endswith("*"):
                prefix = check_pattern(type)[:-1]
                sql += " AND starts_with(type, %s)"
                params.append(prefix)
            else:
                sql += " AND type = %s"
                params.append(check_type(type))
        after = decode_cursor(cursor, ("str",))
        if after:
            sql += " AND id < %s"
            params.append(after[0])
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(n + 1)
        with self.db.transaction(job_scope(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [_event(r) for r in rows[:n]]
        return Page[Event](
            items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > n and items else None
        )

    def authorize_stream(self, principal: Principal, product_id: str, tenant_id: str | None) -> None:
        """The permission check of event and job streams (repeated periodically by the stream)."""
        self.authz.require(principal, "jobs:read", product_id, tenant_id)

    def poll(
        self,
        product_id: str,
        tenant_id: str | None,
        after: int,
        *,
        types: builtins.list[str] | None = None,
        limit: int = 100,
    ) -> builtins.list[StreamItem]:
        """Events after a stream position (no authorization; see :meth:`authorize_stream`)."""
        assign_positions(self.db)
        sql = "SELECT * FROM axentra_events WHERE product_id = %s"
        params: builtins.list[Any] = [product_id]
        if tenant_id is not None:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        sql += " AND pos > %s ORDER BY pos LIMIT %s"
        params += [after, limit]
        with self.db.transaction(job_scope(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        out = []
        for r in rows:
            if types and not type_matches(r["type"], types):
                # Still advance the position past filtered events.
                out.append(StreamItem(position=str(r["pos"]), type="", data={}))
                continue
            out.append(
                StreamItem(
                    position=str(r["pos"]),
                    type=r["type"],
                    data=_event(r).model_dump(mode="json"),
                )
            )
        return out

    # -- dispatch (job handlers) ---------------------------------------------------------------

    def _dispatch(self, ctx: JobContext) -> dict[str, Any]:
        event_id = str(ctx.job.payload.get("event_id", ""))
        with ctx.transaction() as tx:
            row = tx.one("SELECT * FROM axentra_events WHERE id = %s", (event_id,))
            if row is None:
                return {"skipped": "event no longer exists"}
            event = _event(row)
            handlers = 0
            for sub in list(self.subscribers.values()):
                if fnmatchcase(event.type, sub.pattern):
                    self.jobs.queue.enqueue_in_tx(
                        tx,
                        event.product_id,
                        event.tenant_id,
                        HANDLE_KIND,
                        {"event_id": event.id, "subscriber": sub.name},
                        idempotency_key=f"{event.id}:{sub.name}"[:200],
                    )
                    handlers += 1
            for fan in self.fanouts:
                fan(tx, event)
        return {"subscribers": handlers}

    def _handle(self, ctx: JobContext) -> Any:
        name = str(ctx.job.payload.get("subscriber", ""))
        sub = self.subscribers.get(name)
        if sub is None:
            raise LookupError(f"no subscriber named {name!r} is registered in this worker")
        with ctx.transaction(read_only=True) as tx:
            row = tx.one(
                "SELECT * FROM axentra_events WHERE id = %s", (str(ctx.job.payload.get("event_id")),)
            )
        if row is None:
            return {"skipped": "event no longer exists"}
        return sub.handler(ctx, _event(row))


__all__ = ["EventService", "Subscriber", "check_type", "type_matches"]
