"""Recurring schedules that enqueue jobs, the scheduler leader lock and slot firings.

Adapted from peterkarlhuber/nodestro-runtime src/nodestro_runtime/jobs.py (``LeaderLock``,
``ScheduleFirings``) at a42b6724702821849af478ee9dd0bfa13617e28b (MIT, Copyright (c) 2026 Peter
Karlhuber).

- Exactly one process fires schedules at a time: the holder of a session-level PostgreSQL
  advisory lock on a dedicated connection (:class:`LeaderLock`). When the leader dies its
  connection closes, the lock is released and another worker takes over at its next tick.
- Every slot of a schedule fires at most once: firing inserts ``(schedule_id, slot)`` into
  ``axentra_schedule_firings`` (primary key) in the same transaction that enqueues the job and
  advances ``next_run_at``. Overlapping leaders therefore cannot fire a slot twice.
- Missed slots (all workers down) are coalesced: the overdue slot fires once and the schedule
  continues with the next slot after now.
"""

from __future__ import annotations

import builtins
import contextlib
from datetime import datetime
import logging
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.core.clock import utcnow
from axentra.core.context import Principal
from axentra.core.errors import NotFound, PreconditionFailed, ValidationFailed
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Row
from axentra.events.cron import CronExpr, next_interval_slot
from axentra.events.jobs import RESERVED_PREFIX, JobQueue, check_kind, check_payload, job_scope
from axentra.events.models import Schedule

logger = logging.getLogger(__name__)

#: Advisory lock key of the scheduler leader ("axsched" folded into 63 bits).
SCHEDULER_LOCK = 0x61787363686564
MIN_INTERVAL_SECONDS = 10


def next_slot(after: datetime, *, interval_seconds: int | None, cron: str | None) -> datetime:
    if cron is not None:
        return CronExpr.parse(cron).next_after(after)
    assert interval_seconds is not None
    return next_interval_slot(after, interval_seconds)


def _validate_timing(interval_seconds: int | None, cron: str | None) -> None:
    if (interval_seconds is None) == (cron is None):
        raise ValidationFailed("give exactly one of interval_seconds or cron")
    if interval_seconds is not None and not MIN_INTERVAL_SECONDS <= interval_seconds <= 31_622_400:
        raise ValidationFailed(f"interval_seconds must be between {MIN_INTERVAL_SECONDS} and 31622400")
    if cron is not None:
        CronExpr.parse(cron).next_after(utcnow())


class LeaderLock:
    """A session-level advisory lock held on a dedicated (non-pooled) connection."""

    def __init__(self, url: str, key: int = SCHEDULER_LOCK) -> None:
        self.url = url
        self.key = key
        self._conn: psycopg.Connection[Any] | None = None

    @property
    def held(self) -> bool:
        return self._conn is not None

    def acquire(self) -> bool:
        """``True`` while this process is the leader; re-checks the connection every call."""
        if self._conn is not None:
            try:
                self._conn.execute("SELECT 1")
                return True
            except psycopg.Error:
                logger.warning("scheduler leader connection lost; re-electing")
                self._drop()
        try:
            conn = psycopg.connect(self.url, autocommit=True, connect_timeout=10)
        except psycopg.Error:
            logger.warning("scheduler cannot connect for the leader lock", exc_info=True)
            return False
        row = conn.execute("SELECT pg_try_advisory_lock(%s)", (self.key,)).fetchone()
        if row and row[0]:
            self._conn = conn
            return True
        conn.close()
        return False

    def _drop(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(psycopg.Error):
                self._conn.close()
        self._conn = None

    def release(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(psycopg.Error):
                self._conn.execute("SELECT pg_advisory_unlock(%s)", (self.key,))
        self._drop()


def _schedule(row: Row) -> Schedule:
    return Schedule.model_validate(row)


class ScheduleService:
    def __init__(self, db: Database, authz: Authorizer, audit: AuditLog, queue: JobQueue) -> None:
        self.db = db
        self.authz = authz
        self.audit = audit
        self.queue = queue

    # -- firing (scheduler, no authorization) --------------------------------------------------

    def fire_due(self, now: datetime | None = None, *, limit: int = 100) -> list[str]:
        """Fire every due slot once; returns the ids of the enqueued jobs. Safe to run concurrently."""
        now = now or utcnow()
        fired: list[str] = []
        with self.db.transaction(DbScope.platform()) as tx:
            rows = tx.all(
                "SELECT * FROM axentra_schedules WHERE enabled AND next_run_at <= %s"
                " ORDER BY next_run_at LIMIT %s FOR UPDATE SKIP LOCKED",
                (now, limit),
            )
            for row in rows:
                slot = row["next_run_at"]
                try:
                    nxt = next_slot(
                        max(now, slot), interval_seconds=row["interval_seconds"], cron=row["cron"]
                    )
                except ValidationFailed:
                    nxt = None
                inserted = tx.execute(
                    "INSERT INTO axentra_schedule_firings (schedule_id, slot, product_id, tenant_id)"
                    " VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                    (row["id"], slot, row["product_id"], row["tenant_id"]),
                )
                job_id = row["last_job_id"]
                if inserted == 1:
                    job, _ = self.queue.enqueue_in_tx(
                        tx,
                        row["product_id"],
                        row["tenant_id"],
                        row["kind"],
                        row["payload"],
                        priority=row["priority"],
                        max_attempts=row["max_attempts"],
                        idempotency_key=f"schedule:{row['id']}:{slot.isoformat()}",
                        schedule_id=row["id"],
                        created_by=f"schedule:{row['id']}",
                    )
                    job_id = job.id
                    tx.execute(
                        "UPDATE axentra_schedule_firings SET job_id = %s WHERE schedule_id = %s AND slot = %s",
                        (job.id, row["id"], slot),
                    )
                    fired.append(job.id)
                tx.execute(
                    "UPDATE axentra_schedules SET next_run_at = %s, last_run_at = %s, last_job_id = %s"
                    " WHERE id = %s",
                    (nxt, slot if inserted == 1 else row["last_run_at"], job_id, row["id"]),
                )
        return fired

    # -- CRUD ----------------------------------------------------------------------------------

    def _check_kind(self, kind: str) -> None:
        check_kind(kind)
        if kind.startswith(RESERVED_PREFIX):
            raise ValidationFailed(f"job kinds starting with {RESERVED_PREFIX!r} are reserved")

    def create(
        self,
        principal: Principal,
        product_id: str,
        *,
        name: str,
        kind: str,
        payload: dict[str, Any] | None = None,
        tenant_id: str | None = None,
        interval_seconds: int | None = None,
        cron: str | None = None,
        enabled: bool = True,
        priority: int = 0,
        max_attempts: int = 5,
    ) -> Schedule:
        self.authz.require(principal, "jobs:manage", product_id, tenant_id)
        self._check_kind(kind)
        _validate_timing(interval_seconds, cron)
        payload = check_payload(payload)
        if not name.strip() or len(name) > 200:
            raise ValidationFailed("name must be 1-200 characters")
        if not -100 <= priority <= 100 or not 1 <= max_attempts <= 100:
            raise ValidationFailed("priority must be -100..100 and max_attempts 1..100")
        sid = new_id("sch")
        nxt = next_slot(utcnow(), interval_seconds=interval_seconds, cron=cron)
        with self.db.transaction(job_scope(product_id, tenant_id)) as tx:
            if tenant_id and not tx.one(
                "SELECT 1 FROM axentra_tenants WHERE id = %s AND product_id = %s", (tenant_id, product_id)
            ):
                raise NotFound("tenant not found")
            tx.execute(
                "INSERT INTO axentra_schedules (id, product_id, tenant_id, name, kind, payload, interval_seconds,"
                " cron, enabled, priority, max_attempts, next_run_at, created_by)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    sid,
                    product_id,
                    tenant_id,
                    name.strip(),
                    kind,
                    Jsonb(payload),
                    interval_seconds,
                    cron,
                    enabled,
                    priority,
                    max_attempts,
                    nxt,
                    principal.actor.id,
                ),
            )
            self.audit.record(
                tx,
                principal,
                "events.schedule.create",
                target_type="schedule",
                target_id=sid,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"kind": kind, "interval_seconds": interval_seconds, "cron": cron},
            )
            row = tx.one_or_404("SELECT * FROM axentra_schedules WHERE id = %s", (sid,))
        return _schedule(row)

    def _load(self, principal: Principal, product_id: str, schedule_id: str, perm: str) -> Row:
        self.authz.grant(principal, product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_schedules WHERE id = %s AND product_id = %s",
                (schedule_id, product_id),
                what="schedule",
            )
        try:
            self.authz.require(principal, perm, product_id, row["tenant_id"])
        except NotFound:
            raise NotFound("schedule not found") from None
        return row

    def get(self, principal: Principal, product_id: str, schedule_id: str) -> Schedule:
        return _schedule(self._load(principal, product_id, schedule_id, "jobs:read"))

    def list(
        self,
        principal: Principal,
        product_id: str,
        *,
        tenant_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Schedule]:
        self.authz.require(principal, "jobs:read", product_id, tenant_id)
        n = clamp_limit(limit)
        sql = "SELECT * FROM axentra_schedules WHERE product_id = %s"
        params: list[Any] = [product_id]
        if tenant_id is not None:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        after = decode_cursor(cursor, ("str",))
        if after:
            sql += " AND id > %s"
            params.append(after[0])
        sql += " ORDER BY id LIMIT %s"
        params.append(n + 1)
        with self.db.transaction(job_scope(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [_schedule(r) for r in rows[:n]]
        return Page[Schedule](
            items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > n and items else None
        )

    def update(
        self,
        principal: Principal,
        product_id: str,
        schedule_id: str,
        *,
        changes: dict[str, Any],
        if_match: int | None = None,
    ) -> Schedule:
        row = self._load(principal, product_id, schedule_id, "jobs:manage")
        allowed = {
            "name",
            "kind",
            "payload",
            "interval_seconds",
            "cron",
            "enabled",
            "priority",
            "max_attempts",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValidationFailed(f"unknown fields: {', '.join(sorted(unknown))}")
        merged = {k: row[k] for k in allowed} | changes
        if "kind" in changes:
            self._check_kind(merged["kind"])
        if (
            "interval_seconds" in changes
            and changes["interval_seconds"] is not None
            and "cron" not in changes
        ):
            merged["cron"] = None
        if "cron" in changes and changes["cron"] is not None and "interval_seconds" not in changes:
            merged["interval_seconds"] = None
        _validate_timing(merged["interval_seconds"], merged["cron"])
        merged["payload"] = check_payload(merged["payload"])
        if not str(merged["name"]).strip() or len(merged["name"]) > 200:
            raise ValidationFailed("name must be 1-200 characters")
        if not -100 <= merged["priority"] <= 100 or not 1 <= merged["max_attempts"] <= 100:
            raise ValidationFailed("priority must be -100..100 and max_attempts 1..100")
        timing_changed = (merged["interval_seconds"], merged["cron"], merged["enabled"]) != (
            row["interval_seconds"],
            row["cron"],
            row["enabled"],
        )
        nxt = (
            next_slot(utcnow(), interval_seconds=merged["interval_seconds"], cron=merged["cron"])
            if timing_changed
            else row["next_run_at"]
        )
        with self.db.transaction(job_scope(product_id, row["tenant_id"])) as tx:
            cur = tx.one_or_404(
                "SELECT version FROM axentra_schedules WHERE id = %s AND product_id = %s FOR UPDATE",
                (schedule_id, product_id),
                what="schedule",
            )
            if if_match is not None and cur["version"] != if_match:
                raise PreconditionFailed("the schedule was changed by someone else")
            tx.execute(
                "UPDATE axentra_schedules SET name = %s, kind = %s, payload = %s, interval_seconds = %s, cron = %s,"
                " enabled = %s, priority = %s, max_attempts = %s, next_run_at = %s, version = version + 1,"
                " updated_at = now() WHERE id = %s",
                (
                    str(merged["name"]).strip(),
                    merged["kind"],
                    Jsonb(merged["payload"]),
                    merged["interval_seconds"],
                    merged["cron"],
                    bool(merged["enabled"]),
                    merged["priority"],
                    merged["max_attempts"],
                    nxt,
                    schedule_id,
                ),
            )
            self.audit.record(
                tx,
                principal,
                "events.schedule.update",
                target_type="schedule",
                target_id=schedule_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
                details={"fields": sorted(changes)},
            )
            out = tx.one_or_404("SELECT * FROM axentra_schedules WHERE id = %s", (schedule_id,))
        return _schedule(out)

    def delete(
        self, principal: Principal, product_id: str, schedule_id: str, *, if_match: int | None = None
    ) -> None:
        row = self._load(principal, product_id, schedule_id, "jobs:manage")
        if if_match is not None and row["version"] != if_match:
            raise PreconditionFailed("the schedule was changed by someone else")
        with self.db.transaction(job_scope(product_id, row["tenant_id"])) as tx:
            tx.execute(
                "DELETE FROM axentra_schedules WHERE id = %s AND product_id = %s", (schedule_id, product_id)
            )
            self.audit.record(
                tx,
                principal,
                "events.schedule.delete",
                target_type="schedule",
                target_id=schedule_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
                details={"kind": row["kind"]},
            )

    def firings(self, product_id: str, schedule_id: str) -> builtins.list[tuple[datetime, str | None]]:
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT slot, job_id FROM axentra_schedule_firings WHERE schedule_id = %s AND product_id = %s"
                " ORDER BY slot",
                (schedule_id, product_id),
            )
        return [(r["slot"], r["job_id"]) for r in rows]
