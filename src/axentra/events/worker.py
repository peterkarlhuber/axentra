"""Job workers: claim, run handlers with heartbeats, retry, reap, schedule and purge.

``JobWorker(ax, kinds=..., concurrency=...)`` runs in its own process (``axentra worker``) or in
a background thread of a product backend. Every worker:

- claims due jobs of its kinds (``FOR UPDATE SKIP LOCKED``), at most ``concurrency`` at a time,
  woken by ``LISTEN/NOTIFY`` and polling every ``events.poll_interval_seconds`` as a fallback;
- renews the leases of its running jobs every ``lease/3`` seconds (a separate thread, so a busy
  handler never delays it) and passes cancellation requests to the handlers; a job whose kind
  declares ``max_runtime_seconds`` is no longer renewed once it ran longer (it is retried after
  its lease expires);
- re-queues jobs of crashed workers whose lease expired (any worker, ``SKIP LOCKED``);
- fires due schedules and purges old finished jobs while it holds the scheduler leader lock.

Graceful shutdown (:meth:`JobWorker.stop`, SIGTERM/SIGINT in the CLI) stops claiming and waits for
running handlers up to a timeout while still renewing their leases. Handlers still running after
the timeout lose their lease and are retried elsewhere (at-least-once).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
import concurrent.futures
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import logging
import os
import socket
import threading
import time
from typing import TYPE_CHECKING, Any
import uuid

import psycopg

from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.db_errors import install_db_error_redaction
from axentra.data.database import DbScope, Tx
from axentra.events.jobs import (
    DEFAULT_HANDLER_PERMISSIONS,
    NOTIFY_CHANNEL,
    SKIPPED_PREFIX,
    JobCancelled,
    PermanentJobError,
    RetryJob,
    format_error,
    job_scope,
)
from axentra.events.models import Job
from axentra.events.schedules import LeaderLock

if TYPE_CHECKING:
    from axentra.platform import Axentra

logger = logging.getLogger(__name__)

PURGE_INTERVAL_SECONDS = 3600.0


def worker_name() -> str:
    """A name no other worker has (host, process, random part)."""
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


def job_principal(job: Job, permissions: frozenset[str] | None = None) -> Principal:
    """A system actor confined to the job's product (and tenant) with ``permissions`` (default: all
    product and tenant permissions), never platform permissions. Workers use
    :meth:`~axentra.events.jobs.JobService.principal_for`, which applies the kind's declared
    permissions and the enqueuer's current permissions."""
    return Principal(
        actor=Actor(ActorKind.SYSTEM, f"job:{job.id}", f"job {job.kind}"),
        api_key_product_id=job.product_id,
        api_key_tenant_id=job.tenant_id,
        api_key_permissions=frozenset(DEFAULT_HANDLER_PERMISSIONS if permissions is None else permissions),
    )


@dataclass
class JobContext:
    """What a handler receives: the job, a scoped principal, heartbeat and cancellation."""

    job: Job
    principal: Principal
    _ax: Axentra = field(repr=False)
    _worker: str = field(repr=False)
    _cancel: bool = False
    _lost: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _started: float = field(default_factory=time.monotonic, repr=False)

    @property
    def scope(self) -> DbScope:
        return job_scope(self.job.product_id, self.job.tenant_id)

    @contextmanager
    def transaction(self, *, read_only: bool = False) -> Iterator[Tx]:
        """A database transaction in the job's product/tenant scope (row-level security applies)."""
        with self._ax.db.transaction(self.scope, read_only=read_only) as tx:
            yield tx

    def heartbeat(self) -> bool:
        """Renew the lease now (long handlers may call it between steps); ``False`` when the lease
        was lost and the handler should stop: another worker may already run the job again."""
        owned = self._ax.jobs.queue.heartbeat([self.job.id], self._worker)
        self._update(self.job.id in owned, owned.get(self.job.id, False))
        return not self._lost

    def _update(self, owned: bool, cancel: bool) -> None:
        with self._lock:
            if not owned:
                self._lost = True
            self._cancel = self._cancel or cancel

    def cancel_requested(self) -> bool:
        """Whether someone asked to cancel this job (refreshed by every heartbeat)."""
        return self._cancel

    @property
    def lease_lost(self) -> bool:
        return self._lost


def _jsonable(value: Any) -> Any:
    if value is None:
        return None
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return {"repr": repr(value)[:1000]}


class JobWorker:
    def __init__(
        self,
        ax: Axentra,
        *,
        kinds: list[str] | None = None,
        concurrency: int = 4,
        name: str | None = None,
        scheduler: bool = True,
        housekeeping: bool = True,
        listen: bool | None = None,
        poll_interval: float | None = None,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        # A worker may run in a process of its own: its job failure logs must not carry database values (B-06-1).
        install_db_error_redaction()
        self.ax = ax
        self.kinds = kinds
        self.concurrency = concurrency
        self.name = name or worker_name()
        self.scheduler = scheduler
        self.housekeeping = housekeeping
        ev = ax.settings.events
        self.listen = ev.listen_notify if listen is None else listen
        self.poll_interval = poll_interval or ev.poll_interval_seconds
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._hb_stop = threading.Event()
        self._stop_timeout = 30.0
        self._running: dict[str, tuple[JobContext, concurrent.futures.Future[None]]] = {}
        self._running_lock = threading.Lock()
        self._leader = LeaderLock(ax.db.url)
        self._last_reap = 0.0
        self._last_schedule = 0.0
        self._last_purge = 0.0
        self._thread: threading.Thread | None = None
        self._threads: list[threading.Thread] = []
        self.processed = 0

    @property
    def queue(self) -> Any:
        return self.ax.jobs.queue

    def active_kinds(self) -> list[str]:
        known = self.ax.jobs.handlers
        kinds = self.kinds if self.kinds is not None else sorted(known)
        missing = [k for k in kinds if k not in known]
        if missing:
            raise ValueError(f"no handler registered for job kinds: {', '.join(missing)}")
        return kinds

    # -- executing one job ---------------------------------------------------------------------

    def _skip(self, job: Job, reason: str) -> None:
        logger.info("job %s (%s) skipped: %s", job.id, job.kind, reason)
        callback = self.ax.jobs.skip_callbacks.get(job.kind)
        if callback is not None:
            try:
                callback(job, reason)
            except Exception:
                logger.exception("skip callback of job %s (%s) failed", job.id, job.kind)
        self.queue.fail(job.id, self.name, f"{SKIPPED_PREFIX}{reason}", permanent=True)

    def _execute(self, ctx: JobContext) -> None:
        job = ctx.job
        handler = self.ax.jobs.handlers[job.kind]
        try:
            reason = self.ax.jobs.skip_reason(job)
            if reason is not None:
                self._skip(job, reason)
                return
            result = handler(ctx)
        except JobCancelled as exc:
            self.queue.fail(job.id, self.name, f"cancelled: {exc}", cancelled=True)
        except PermanentJobError as exc:
            self.queue.fail(job.id, self.name, format_error(exc), permanent=True)
        except RetryJob as exc:
            self.queue.fail(job.id, self.name, format_error(exc), delay_seconds=exc.delay_seconds)
        except Exception as exc:
            logger.warning("job %s (%s) attempt %s failed", job.id, job.kind, job.attempts, exc_info=True)
            status = self.queue.fail(job.id, self.name, format_error(exc))
            if status is None:
                logger.warning("job %s lost its lease before failing", job.id)
        else:
            if not self.queue.complete(job.id, self.name, _jsonable(result)):
                logger.warning("job %s finished after its lease was lost; result discarded", job.id)
        finally:
            self.processed += 1

    def _context(self, job: Job) -> JobContext:
        return JobContext(
            job=job,
            principal=self.ax.jobs.principal_for(job),
            _ax=self.ax,
            _worker=self.name,
            _cancel=job.cancel_requested,
        )

    # -- maintenance ---------------------------------------------------------------------------

    def maintenance(self, *, force: bool = False) -> None:
        now = time.monotonic()
        ev = self.ax.settings.events
        try:
            if force or now - self._last_reap >= ev.reap_interval_seconds:
                self._last_reap = now
                self.queue.reap_expired()
            if self.scheduler and (force or now - self._last_schedule >= ev.scheduler_interval_seconds):
                self._last_schedule = now
                if self._leader.acquire():
                    self.ax.schedules.fire_due()
                    if self.housekeeping and (force or now - self._last_purge >= PURGE_INTERVAL_SECONDS):
                        self._last_purge = now
                        purged = self.queue.purge_finished(self.ax.settings.observability.job_retention_days)
                        if any(purged.values()):
                            logger.info("retention purge: %s", purged)
                        self._platform_housekeeping()
                    if self.housekeeping:
                        self._periodic_sweeps()
            if self.housekeeping:
                self._dispatch_notifications()
        except Exception:
            logger.exception("worker maintenance failed")

    def _dispatch_notifications(self) -> None:
        """Deliver queued notifications; safe on every worker (SKIP LOCKED leases)."""
        notify = getattr(self.ax, "notify", None)
        if notify is not None:
            try:
                notify.dispatcher().run_once()
            except Exception:
                logger.exception("notification dispatch failed")

    def _periodic_sweeps(self) -> None:
        """Leader only: release expired usage reservations and roll subscription periods."""
        for name, fn in (
            (
                "usage reservations",
                getattr(getattr(self.ax, "usage", None), "sweep_expired_reservations", None),
            ),
            ("billing periods", getattr(getattr(self.ax, "billing", None), "advance_periods", None)),
        ):
            if fn is None:
                continue
            try:
                fn()
            except Exception:
                logger.exception("%s sweep failed", name)

    def _platform_housekeeping(self) -> None:
        """Leader only, hourly: audit/session/notify retention and storage purge."""
        try:
            from axentra.observability.maintenance import run_maintenance

            run_maintenance(self.ax)
        except Exception:
            logger.exception("maintenance purge failed")
        storage = getattr(self.ax, "storage", None)
        if storage is not None:
            try:
                storage.purge()
            except Exception:
                logger.exception("storage purge failed")

    # -- synchronous processing (tests, `axentra worker --once`) -------------------------------

    def run_once(self, *, max_jobs: int | None = None, maintenance: bool = True) -> int:
        """Run due jobs one by one in this thread until none is due; returns how many ran."""
        if maintenance:
            self.maintenance(force=True)
        kinds = self.active_kinds()
        done = 0
        while max_jobs is None or done < max_jobs:
            job = self.queue.claim(self.name, kinds)
            if job is None:
                break
            self._execute(self._context(job))
            done += 1
        return done

    # -- the loop ------------------------------------------------------------------------------

    def _heartbeats(self) -> None:
        interval = max(0.2, self.ax.settings.events.lease_seconds / 3)
        while not self._hb_stop.wait(interval):
            now = time.monotonic()
            limits = self.ax.jobs.max_runtime
            with self._running_lock:
                ids = []
                for jid, (ctx, _) in self._running.items():
                    limit = limits.get(ctx.job.kind)
                    if limit is not None and now - ctx._started > limit:
                        if not ctx.lease_lost:
                            logger.warning(
                                "job %s (%s) ran longer than %.0f s; its lease is no longer renewed",
                                jid,
                                ctx.job.kind,
                                limit,
                            )
                        ctx._update(False, False)
                        continue
                    ids.append(jid)
            if not ids:
                continue
            try:
                owned = self.queue.heartbeat(ids, self.name)
            except Exception:
                logger.warning("heartbeat failed", exc_info=True)
                continue
            with self._running_lock:
                for jid in ids:
                    entry = self._running.get(jid)
                    if entry:
                        entry[0]._update(jid in owned, owned.get(jid, False))

    def _listener(self) -> None:
        while not self._stop.is_set():
            try:
                with psycopg.connect(self.ax.db.url, autocommit=True, connect_timeout=10) as conn:
                    conn.execute(f"LISTEN {NOTIFY_CHANNEL}")
                    while not self._stop.is_set():
                        for _ in conn.notifies(timeout=1.0, stop_after=1):
                            self._wake.set()
            except psycopg.Error:
                logger.warning("LISTEN connection failed; polling only for now", exc_info=True)
                self._stop.wait(self.poll_interval * 5)

    def _done_callback(self, job_id: str) -> Callable[[concurrent.futures.Future[None]], None]:
        return lambda _f: self._done(job_id)

    def _done(self, job_id: str) -> None:
        with self._running_lock:
            self._running.pop(job_id, None)
        self._wake.set()

    def run(self) -> None:
        """Process jobs until :meth:`stop` is called (blocking)."""
        kinds = self.active_kinds()
        logger.info("worker %s started (kinds=%s, concurrency=%s)", self.name, kinds, self.concurrency)
        pool = concurrent.futures.ThreadPoolExecutor(self.concurrency, thread_name_prefix="axentra-job")
        hb = threading.Thread(target=self._heartbeats, name="axentra-heartbeat", daemon=True)
        hb.start()
        self._threads = [hb]
        if self.listen:
            lt = threading.Thread(target=self._listener, name="axentra-listen", daemon=True)
            lt.start()
            self._threads.append(lt)
        try:
            while not self._stop.is_set():
                self.maintenance()
                self._wake.clear()
                while not self._stop.is_set():
                    with self._running_lock:
                        if len(self._running) >= self.concurrency:
                            break
                    try:
                        job = self.queue.claim(self.name, kinds)
                    except Exception:
                        logger.warning("claim failed", exc_info=True)
                        break
                    if job is None:
                        break
                    ctx = self._context(job)
                    with self._running_lock:
                        fut = pool.submit(self._execute, ctx)
                        self._running[job.id] = (ctx, fut)
                    fut.add_done_callback(self._done_callback(job.id))
                self._wake.wait(self.poll_interval)
        finally:
            self._drain(pool)
            self._hb_stop.set()
            self._leader.release()
            logger.info("worker %s stopped", self.name)

    def _drain(self, pool: concurrent.futures.ThreadPoolExecutor) -> None:
        with self._running_lock:
            futures = [f for _, f in self._running.values()]
        timeout = self._stop_timeout
        _, pending = concurrent.futures.wait(futures, timeout=timeout)
        if pending:
            logger.warning(
                "%d job(s) still running after %.0fs; their leases will expire and they will be retried",
                len(pending),
                timeout,
            )
            with self._running_lock:
                self._running.clear()  # stop renewing their leases
        pool.shutdown(wait=False, cancel_futures=True)

    def start(self) -> threading.Thread:
        """Run the worker in a background thread."""
        self._thread = threading.Thread(target=self.run, name=f"axentra-worker-{self.name}", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self, timeout: float = 30.0) -> None:
        """Graceful shutdown: stop claiming, wait up to ``timeout`` for running handlers."""
        self._stop_timeout = timeout
        self._stop.set()
        self._wake.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout + 5)

    @property
    def running_jobs(self) -> list[str]:
        with self._running_lock:
            return list(self._running)
