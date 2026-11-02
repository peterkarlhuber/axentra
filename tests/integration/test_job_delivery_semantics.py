"""What the job queue guarantees after a lost lease, against a real PostgreSQL (plan gap G-8).

Documented experiment behind the G-8 decision (docs/TODO.md, docs/modules/EVENTS_AND_JOBS.md): Axentra's jobs are
**at least once**. A worker whose lease expires while its handler is still running (a stalled heartbeat, a paused
VM) is fenced out of ``complete``/``fail``, but its handler is not stopped, and the reaper queues the job again, so
a second worker runs the same handler while the first one is still busy: a side effect without an idempotency
guard of its own happens twice. ``max_attempts=1`` turns a lost lease into a ``dead`` job instead of a retry, and
idempotency keys deduplicate enqueues for good (also after the job ended), not only while a job is active. Products
whose handlers must never repeat an external effect (paid model calls, external writes) keep a queue with those
semantics of their own or make every effect idempotent at its target.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import threading

from axentra.core.context import Principal
from axentra.data.database import DbScope
from axentra.events import JobWorker

SYS = Principal.system("test")
FAST = {"events": {"backoff_base_seconds": 0.01, "backoff_max_seconds": 0.05, "listen_notify": False}}


def _product(ax):
    return ax.tenancy.create_product(SYS, slug="ledger", name="Ledger").id


def _expire(ax, job_id):
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_jobs SET lease_until = %s WHERE id = %s",
            (datetime.now(UTC) - timedelta(seconds=1), job_id),
        )


def test_a_live_worker_that_lost_its_lease_runs_the_handler_while_the_retry_runs_it_again(ax_factory):
    ax = ax_factory(**FAST)
    pid = _product(ax)
    effects: list[tuple[str, int]] = []
    entered, release = threading.Event(), threading.Event()

    def post_invoice(ctx):
        effects.append((ctx.job.payload["invoice"], ctx.job.attempts))  # the external write
        if ctx.job.attempts == 1:
            entered.set()
            release.wait(20)  # the first worker stalls after its write; its heartbeat stops
        return "posted"

    ax.jobs.register("ledger.post", post_invoice)
    job = ax.jobs.enqueue(SYS, pid, "ledger.post", {"invoice": "42"}, max_attempts=3)
    first = JobWorker(ax, name="stalled", scheduler=False, housekeeping=False)
    running = threading.Thread(target=first.run_once, kwargs={"max_jobs": 1, "maintenance": False})
    running.start()
    try:
        assert entered.wait(10)
        _expire(ax, job.id)
        second = JobWorker(ax, name="rescuer", scheduler=False, housekeeping=False)
        deadline = datetime.now(UTC) + timedelta(seconds=10)
        while len(effects) < 2 and datetime.now(UTC) < deadline:
            second.run_once()  # reaps the expired lease, then claims the re-queued job
    finally:
        release.set()
        running.join(20)
    # The handler ran twice for one logical job while the first execution was still alive.
    assert effects == [("42", 1), ("42", 2)]
    final = ax.jobs.get(SYS, pid, job.id)
    assert final.status == "succeeded" and final.worker == "rescuer" and final.attempts == 2
    # The stalled worker was fenced out of the result only; its write had already happened.
    assert ax.jobs.queue.complete(job.id, "stalled", "late") is False


def test_one_attempt_makes_a_lost_lease_dead_instead_of_retrying(ax_factory):
    ax = ax_factory(**FAST)
    pid = _product(ax)
    ran: list[int] = []
    ax.jobs.register("ledger.once", lambda ctx: ran.append(ctx.job.attempts))
    job = ax.jobs.enqueue(SYS, pid, "ledger.once", {}, max_attempts=1)
    assert ax.jobs.queue.claim("crashed", ["ledger.once"]) is not None
    _expire(ax, job.id)
    reaped = ax.jobs.queue.reap_expired()
    assert [(j.id, j.status) for j in reaped] == [(job.id, "dead")]
    assert JobWorker(ax, name="other", scheduler=False, housekeeping=False).run_once() == 0
    assert ran == []


def test_idempotency_keys_deduplicate_for_good_not_only_while_a_job_is_active(ax_factory):
    ax = ax_factory(**FAST)
    pid = _product(ax)
    ax.jobs.register("ledger.work", lambda ctx: "ok")
    first = ax.jobs.enqueue(SYS, pid, "ledger.work", {"ref": "doc_1"}, idempotency_key="doc_1")
    assert JobWorker(ax, name="w", scheduler=False, housekeeping=False).run_once() == 1
    # The same piece of work queued again after its job ended gets the ended job back, not a new one.
    again = ax.jobs.enqueue(SYS, pid, "ledger.work", {"ref": "doc_1"}, idempotency_key="doc_1")
    assert again.id == first.id and again.status == "succeeded"
    # Without a key, nothing stops two active jobs for the same piece of work.
    a = ax.jobs.enqueue(SYS, pid, "ledger.work", {"ref": "doc_2"})
    b = ax.jobs.enqueue(SYS, pid, "ledger.work", {"ref": "doc_2"})
    assert a.id != b.id and {a.status, b.status} == {"queued"}
