"""Job queue, worker, schedules and events against a real PostgreSQL (RLS enforced)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
import threading
import time

import psycopg
import pytest

from axentra.core.context import Principal
from axentra.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from axentra.data.database import DbScope
from axentra.events import JobCancelled, JobWorker, PermanentJobError
from axentra.events.schedules import LeaderLock

SYS = Principal.system("test")
FAST = {"events": {"backoff_base_seconds": 0.01, "backoff_max_seconds": 0.05, "listen_notify": False}}


def _setup(ax, slug="crm"):
    p = ax.tenancy.create_product(SYS, slug=slug, name=slug.upper())
    t1 = ax.tenancy.create_tenant(SYS, p.id, slug="acme", name="Acme")
    t2 = ax.tenancy.create_tenant(SYS, p.id, slug="globex", name="Globex")
    return p.id, t1.id, t2.id


@pytest.fixture
def fast_ax(ax_factory):
    return ax_factory(**FAST)


def _set_job(ax, job_id, **cols):
    sets = ", ".join(f"{k} = %s" for k in cols)
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(f"UPDATE axentra_jobs SET {sets} WHERE id = %s", (*cols.values(), job_id))


def test_enqueue_claim_complete_and_result(fast_ax):
    ax = fast_ax
    pid, tid, _ = _setup(ax)
    seen = []

    def handler(ctx):
        seen.append((ctx.job.payload, ctx.scope, ctx.principal.api_key_tenant_id))
        with ctx.transaction() as tx:
            assert tx.scalar("SELECT current_setting('axentra.tenant_id')") == tid
        return {"ok": 1}

    ax.jobs.register("demo.work", handler)
    job = ax.jobs.enqueue(SYS, pid, "demo.work", {"n": 1}, tenant_id=tid)
    assert job.status == "queued" and job.attempts == 0
    assert JobWorker(ax).run_once() == 1
    done = ax.jobs.get(SYS, pid, job.id)
    assert done.status == "succeeded" and done.result == {"ok": 1} and done.attempts == 1
    assert seen == [({"n": 1}, DbScope.tenant(pid, tid), tid)]
    with pytest.raises(ValueError, match="already registered"):
        ax.jobs.register("demo.work", handler)


def test_reserved_kinds_and_validation(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    with pytest.raises(ValidationFailed):
        ax.jobs.enqueue(SYS, pid, "axentra.event.dispatch", {})
    with pytest.raises(ValidationFailed):
        ax.jobs.enqueue(SYS, pid, "Bad Kind", {})
    with pytest.raises(ValidationFailed):
        ax.jobs.enqueue(SYS, pid, "demo.big", {"x": "y" * 70_000})


def test_priority_and_delay(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    order = []
    ax.jobs.register("demo.p", lambda ctx: order.append(ctx.job.payload["n"]))
    ax.jobs.enqueue(SYS, pid, "demo.p", {"n": "low"}, priority=-5)
    ax.jobs.enqueue(SYS, pid, "demo.p", {"n": "high"}, priority=50)
    ax.jobs.enqueue(SYS, pid, "demo.p", {"n": "later"}, priority=100, delay_seconds=3600)
    JobWorker(ax).run_once()
    assert order == ["high", "low"]


def test_retries_backoff_and_dead_letter_then_manual_retry(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    calls = []

    def flaky(ctx):
        calls.append(ctx.job.attempts)
        raise RuntimeError("boom token=Bearer abcdefghijklmnop")

    ax.jobs.register("demo.flaky", flaky)
    job = ax.jobs.enqueue(SYS, pid, "demo.flaky", {}, max_attempts=3)
    w = JobWorker(ax)
    for _ in range(20):
        w.run_once()
        if ax.jobs.get(SYS, pid, job.id).status == "dead":
            break
        time.sleep(0.03)
    dead = ax.jobs.get(SYS, pid, job.id)
    assert dead.status == "dead" and dead.attempts == 3 and calls == [1, 2, 3]
    assert "boom" in dead.last_error and "abcdefghijklmnop" not in dead.last_error
    retried = ax.jobs.retry(SYS, pid, job.id)
    assert retried.status == "queued" and retried.attempts == 0
    with pytest.raises(Conflict):
        ax.jobs.retry(SYS, pid, job.id)


def test_backoff_delays_the_next_attempt(ax_factory):
    ax = ax_factory(events={"backoff_base_seconds": 30, "listen_notify": False})
    pid, _, _ = _setup(ax)
    ax.jobs.register("demo.fail", lambda ctx: 1 / 0)
    job = ax.jobs.enqueue(SYS, pid, "demo.fail", {}, max_attempts=5)
    w = JobWorker(ax)
    assert w.run_once() == 1
    assert w.run_once() == 0  # backing off
    j = ax.jobs.get(SYS, pid, job.id)
    assert j.status == "queued" and j.attempts == 1
    delay = (j.run_after - datetime.now(UTC)).total_seconds()
    assert 10 < delay <= 31


def test_permanent_error_fails_without_retry(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)

    def bad(ctx):
        raise PermanentJobError("invalid input")

    ax.jobs.register("demo.bad", bad)
    job = ax.jobs.enqueue(SYS, pid, "demo.bad", {}, max_attempts=5)
    JobWorker(ax).run_once()
    j = ax.jobs.get(SYS, pid, job.id)
    assert j.status == "failed" and j.attempts == 1


def test_idempotency_keys(fast_ax):
    ax = fast_ax
    pid, t1, t2 = _setup(ax)
    a = ax.jobs.enqueue(SYS, pid, "demo.k", {"v": 1}, tenant_id=t1, idempotency_key="k1")
    b = ax.jobs.enqueue(SYS, pid, "demo.k", {"v": 1}, tenant_id=t1, idempotency_key="k1")
    assert a.id == b.id and b.payload == {"v": 1}
    # A different request with the same key is a conflict (security review 2026-11-01, F8).
    with pytest.raises(Conflict):
        ax.jobs.enqueue(SYS, pid, "demo.k", {"v": 2}, tenant_id=t1, idempotency_key="k1")
    # Other tenant, other kind or product level: separate key spaces.
    c = ax.jobs.enqueue(SYS, pid, "demo.k", {}, tenant_id=t2, idempotency_key="k1")
    d = ax.jobs.enqueue(SYS, pid, "demo.other", {}, tenant_id=t1, idempotency_key="k1")
    e = ax.jobs.enqueue(SYS, pid, "demo.k", {}, idempotency_key="k1")
    assert len({a.id, c.id, d.id, e.id}) == 4
    # Permanent while the row exists: also after the job finished.
    ax.jobs.register("demo.k", lambda ctx: None)
    JobWorker(ax, kinds=["demo.k"]).run_once()
    again = ax.jobs.enqueue(SYS, pid, "demo.k", {"v": 1}, tenant_id=t1, idempotency_key="k1")
    assert again.id == a.id and again.status == "succeeded"


def test_cancellation_queued_and_running(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    q = ax.jobs.enqueue(SYS, pid, "demo.c", {})
    assert ax.jobs.cancel(SYS, pid, q.id).status == "cancelled"
    with pytest.raises(Conflict):
        ax.jobs.cancel(SYS, pid, q.id)

    started = threading.Event()
    observed = []

    def long(ctx):
        started.set()
        for _ in range(200):
            ctx.heartbeat()
            if ctx.cancel_requested():
                observed.append(True)
                raise JobCancelled("stopping")
            time.sleep(0.02)
        return "finished"

    ax.jobs.register("demo.c", long)
    r = ax.jobs.enqueue(SYS, pid, "demo.c", {})
    w = JobWorker(ax)
    t = threading.Thread(target=w.run_once)
    t.start()
    assert started.wait(5)
    j = ax.jobs.cancel(SYS, pid, r.id)
    assert j.status == "running" and j.cancel_requested
    t.join(10)
    assert observed == [True]
    assert ax.jobs.get(SYS, pid, r.id).status == "cancelled"


def test_two_workers_never_get_the_same_job(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    lock = threading.Lock()
    runs: dict[str, list[str]] = {}

    def handler(ctx):
        with lock:
            runs.setdefault(ctx.job.id, []).append(ctx._worker)
        time.sleep(0.002)

    ax.jobs.register("demo.many", handler)
    with ax.db.transaction(DbScope.product(pid)) as tx:
        ids = [ax.jobs.queue.enqueue_in_tx(tx, pid, None, "demo.many", {"i": i})[0].id for i in range(200)]
    workers = [JobWorker(ax, name=f"w{i}", scheduler=False) for i in range(4)]
    threads = [threading.Thread(target=w.run_once, kwargs={"maintenance": False}) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(runs) == sorted(ids)
    assert all(len(v) == 1 for v in runs.values())
    assert len({w for v in runs.values() for w in v}) > 1
    stats = ax.jobs.stats(SYS, pid)
    assert stats.counts["succeeded"] == 200 and stats.counts["queued"] == 0


def test_threaded_worker_with_listen_notify_and_graceful_stop(ax_factory):
    ax = ax_factory(events={"poll_interval_seconds": 5, "listen_notify": True})
    pid, _, _ = _setup(ax)
    done = threading.Event()
    ax.jobs.register("demo.n", lambda ctx: done.set())
    w = JobWorker(ax, concurrency=2)
    w.start()
    time.sleep(0.5)  # listener connected; the next wake-up comes from NOTIFY, not polling
    t0 = time.monotonic()
    ax.jobs.enqueue(SYS, pid, "demo.n", {})
    assert done.wait(4)
    assert time.monotonic() - t0 < 4
    w.stop(timeout=5)
    assert not w.running_jobs


def test_lease_expiry_reaps_and_retries(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    job = ax.jobs.enqueue(SYS, pid, "demo.r", {}, max_attempts=2)
    claimed = ax.jobs.queue.claim("crashed-worker", ["demo.r"])
    assert claimed and claimed.id == job.id
    _set_job(ax, job.id, lease_until=datetime.now(UTC) - timedelta(seconds=1))
    reaped = ax.jobs.queue.reap_expired()
    assert [j.id for j in reaped] == [job.id] and reaped[0].status == "queued"
    # The crashed worker can no longer finish it (fenced by the lease).
    assert ax.jobs.queue.complete(job.id, "crashed-worker", {}) is False
    # Second attempt also lost: no attempts left -> dead.
    _set_job(ax, job.id, run_after=datetime.now(UTC))
    ax.jobs.queue.claim("crashed-again", ["demo.r"])
    _set_job(ax, job.id, lease_until=datetime.now(UTC) - timedelta(seconds=1))
    assert ax.jobs.queue.reap_expired()[0].status == "dead"


WORKER_SCRIPT = textwrap.dedent(
    """
    import sys, time
    from pathlib import Path
    from axentra.config.settings import load_settings
    from axentra.platform import Axentra
    from axentra.events import JobWorker

    marker = Path(sys.argv[1])
    ax = Axentra.from_settings(load_settings())
    ax.start()
    def handler(ctx):
        marker.write_text(ctx.job.id)
        time.sleep(600)
    ax.jobs.register("demo.crash", handler)
    JobWorker(ax, name="doomed", scheduler=False, listen=False).run()
    """
)


def test_worker_killed_mid_job_is_retried_by_another_worker(ax_factory, pg_urls, tmp_path):
    ax = ax_factory(events={"lease_seconds": 2, "backoff_base_seconds": 0.01, "listen_notify": False})
    pid, _, _ = _setup(ax)
    job = ax.jobs.enqueue(SYS, pid, "demo.crash", {})
    script = tmp_path / "worker.py"
    script.write_text(WORKER_SCRIPT)
    marker = tmp_path / "marker"
    env = {
        **os.environ,
        "AXENTRA__ENVIRONMENT": "test",
        "AXENTRA__MODE": "multi",
        "AXENTRA__DATABASE__URL": pg_urls["app"],
        "AXENTRA__DATABASE__POOL_MAX": "2",
        "AXENTRA__SECURITY__MASTER_KEYS": ax.settings.security.master_keys or "",
        "AXENTRA__EVENTS__LEASE_SECONDS": "2",
        "AXENTRA__EVENTS__POLL_INTERVAL_SECONDS": "0.1",
    }
    proc = subprocess.Popen(
        [sys.executable, str(script), str(marker)], env=env, cwd=str(Path(__file__).resolve().parents[2])
    )
    try:
        for _ in range(200):
            if marker.exists():
                break
            time.sleep(0.05)
        assert marker.read_text() == job.id
        running = ax.jobs.get(SYS, pid, job.id)
        assert running.status == "running" and running.worker == "doomed"
        proc.send_signal(signal.SIGKILL)
        proc.wait(10)
    finally:
        if proc.poll() is None:
            proc.kill()
    ok = []
    ax.jobs.register("demo.crash", lambda ctx: ok.append(ctx.job.attempts) or "recovered")
    rescuer = JobWorker(ax, name="rescuer", scheduler=False)
    deadline = time.monotonic() + 15
    while not ok and time.monotonic() < deadline:
        rescuer.run_once()
        time.sleep(0.2)
    assert ok == [2]
    final = ax.jobs.get(SYS, pid, job.id)
    assert final.status == "succeeded" and final.worker == "rescuer"
    assert final.last_error.startswith("lease expired")


def test_schedule_fires_each_slot_once_with_two_schedulers(fast_ax):
    ax = fast_ax
    pid, tid, _ = _setup(ax)
    s = ax.schedules.create(SYS, pid, name="nightly", kind="demo.sched", interval_seconds=60, tenant_id=tid)
    assert s.next_run_at is not None and s.next_run_at.timestamp() % 60 == 0
    # Make it due and fire concurrently from two "schedulers" (no leader lock: the slot key alone).
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute("UPDATE axentra_schedules SET next_run_at = next_run_at - interval '120 seconds'")
    barrier = threading.Barrier(2)
    results: list[list[str]] = []

    def fire():
        barrier.wait()
        results.append(ax.schedules.fire_due())

    threads = [threading.Thread(target=fire) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert sorted(len(r) for r in results) == [0, 1]
    assert ax.schedules.fire_due() == []
    firings = ax.schedules.firings(pid, s.id)
    assert len(firings) == 1
    jobs = ax.jobs.list(SYS, pid, kind="demo.sched").items
    assert len(jobs) == 1 and jobs[0].tenant_id == tid and jobs[0].schedule_id == s.id
    after = ax.schedules.get(SYS, pid, s.id)
    assert after.next_run_at > datetime.now(UTC) and after.last_job_id == jobs[0].id
    # Re-firing the same slot (e.g. a leader that lost its lock mid-way) is refused by the key.
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute("UPDATE axentra_schedules SET next_run_at = %s", (firings[0][0],))
    assert ax.schedules.fire_due() == []


def test_leader_lock_is_exclusive(fast_ax):
    ax = fast_ax
    a, b = LeaderLock(ax.db.url, key=4242), LeaderLock(ax.db.url, key=4242)
    try:
        assert a.acquire() is True
        assert b.acquire() is False
        assert a.acquire() is True
        a.release()
        assert b.acquire() is True
    finally:
        a.release()
        b.release()


def test_cron_schedule_and_validation(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    s = ax.schedules.create(SYS, pid, name="hourly", kind="demo.c", cron="15 * * * *")
    assert s.next_run_at.minute == 15
    with pytest.raises(ValidationFailed):
        ax.schedules.create(SYS, pid, name="x", kind="demo.c", cron="61 * * * *")
    with pytest.raises(ValidationFailed):
        ax.schedules.create(SYS, pid, name="x", kind="demo.c", cron="* * * * *", interval_seconds=60)
    with pytest.raises(ValidationFailed):
        ax.schedules.create(SYS, pid, name="x", kind="axentra.event.dispatch", interval_seconds=60)
    u = ax.schedules.update(SYS, pid, s.id, changes={"interval_seconds": 120}, if_match=1)
    assert u.cron is None and u.interval_seconds == 120 and u.version == 2
    from axentra.core.errors import PreconditionFailed

    with pytest.raises(PreconditionFailed):
        ax.schedules.update(SYS, pid, s.id, changes={"enabled": False}, if_match=1)
    ax.schedules.delete(SYS, pid, s.id)
    with pytest.raises(NotFound):
        ax.schedules.get(SYS, pid, s.id)


def test_events_outbox_subscribers_and_idempotency(fast_ax):
    ax = fast_ax
    pid, tid, t2 = _setup(ax)
    got = []
    ax.events.subscribe(
        "invoice.*", lambda ctx, ev: got.append((ev.type, ev.data, ctx.job.tenant_id)), name="t1"
    )
    ax.events.subscribe("other.*", lambda ctx, ev: got.append("never"), name="t2")

    # Atomic with product writes: a rolled-back transaction leaves no event and no job.
    def rolled_back() -> None:
        with ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
            ax.events.publish_in_tx(tx, pid, tid, "invoice.created", {"n": 0})
            raise RuntimeError("rollback")

    with pytest.raises(RuntimeError):
        rolled_back()
    assert ax.events.list(SYS, pid).items == []
    with ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
        ev = ax.events.publish_in_tx(tx, pid, tid, "invoice.created", {"n": 1}, idempotency_key="inv-1")
    again = ax.events.publish(SYS, pid, tid, "invoice.created", {"n": 1}, idempotency_key="inv-1")
    assert again.id == ev.id and again.data == {"n": 1}
    with pytest.raises(Conflict):
        ax.events.publish(SYS, pid, tid, "invoice.created", {"n": 2}, idempotency_key="inv-1")
    with pytest.raises(ValueError, match="scope"), ax.db.transaction(DbScope.tenant(pid, t2)) as tx:
        ax.events.publish_in_tx(tx, pid, tid, "invoice.created", {})
    with pytest.raises(ValidationFailed):
        ax.events.publish(SYS, pid, tid, "axentra.fake", {})
    w = JobWorker(ax)
    w.run_once()
    w.run_once()
    assert got == [("invoice.created", {"n": 1}, tid)]
    # Re-running the dispatch (at-least-once) does not duplicate subscriber jobs.
    disp = ax.jobs.list(SYS, pid, kind="axentra.event.dispatch").items[0]
    _set_job(ax, disp.id, status="queued", attempts=0)
    w.run_once()
    assert len(ax.jobs.list(SYS, pid, kind="axentra.event.handle").items) == 1


def test_tenant_isolation_and_permissions(world):
    ax = world.ax
    pid, t1, t2 = _setup(ax)
    other_pid, ot, _ = _setup(ax, "erp")
    j1 = ax.jobs.enqueue(SYS, pid, "demo.iso", {"secret_token": "x"}, tenant_id=t1)
    ax.jobs.enqueue(SYS, pid, "demo.iso", {}, tenant_id=t2)
    oj = ax.jobs.enqueue(SYS, other_pid, "demo.iso", {}, tenant_id=ot)
    assert j1.payload == {"secret_token": "[redacted]"}
    # A tenant-bound API key with jobs:read sees only its tenant.
    key = ax.api_keys.create_key(
        SYS, pid, name="t1", permissions=["jobs:read", "events:publish"], tenant_id=t1
    )
    kp = ax.api_keys.authenticate(key.secret)
    assert [j.id for j in ax.jobs.list(kp, pid, tenant_id=t1).items] == [j1.id]
    with pytest.raises(NotFound):
        ax.jobs.list(kp, pid, tenant_id=t2)
    with pytest.raises(Forbidden):
        ax.jobs.list(kp, pid)
    assert ax.jobs.get(kp, pid, j1.id).id == j1.id
    t2job = ax.jobs.list(SYS, pid, tenant_id=t2).items[0]
    with pytest.raises(NotFound):
        ax.jobs.get(kp, pid, t2job.id)
    with pytest.raises(NotFound):
        ax.jobs.get(kp, other_pid, oj.id)
    with pytest.raises(NotFound):
        ax.jobs.get(SYS, pid, oj.id)  # wrong product in the path
    # Tenant-bound key may enqueue (events:publish) a kind opened to it in its tenant but not cancel
    # (jobs:manage); kinds that are not opened need jobs:manage.
    with pytest.raises(Forbidden):
        ax.jobs.enqueue(kp, pid, "demo.iso", {}, tenant_id=t1)
    ax.jobs.declare("demo.iso", enqueue_permission="events:publish", permissions={"records:read"})
    mine = ax.jobs.enqueue(kp, pid, "demo.iso", {}, tenant_id=t1)
    with pytest.raises(Forbidden):
        ax.jobs.cancel(kp, pid, mine.id)
    with pytest.raises(NotFound):
        ax.jobs.enqueue(kp, pid, "demo.iso", {}, tenant_id=t2)
    # RLS: a tenant-scoped transaction cannot see another tenant's jobs even without a filter.
    with ax.db.transaction(DbScope.tenant(pid, t1), read_only=True) as tx:
        tenants = {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM axentra_jobs")}
    assert tenants == {t1}


def test_job_handler_principal_is_confined(fast_ax):
    ax = fast_ax
    pid, t1, t2 = _setup(ax)
    out = {}

    def handler(ctx):
        out["own"] = ax.records.create(ctx.principal, pid, t1, "notes", {"a": 1}).id
        try:
            ax.records.create(ctx.principal, pid, t2, "notes", {"a": 1})
        except NotFound:
            out["other"] = "denied"

    ax.jobs.register("demo.p", handler)
    ax.jobs.enqueue(SYS, pid, "demo.p", {}, tenant_id=t1)
    JobWorker(ax).run_once()
    assert out["own"].startswith("rec_") and out["other"] == "denied"


def test_retention_purge(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    ax.jobs.register("demo.old", lambda ctx: None)
    old = ax.jobs.enqueue(SYS, pid, "demo.old", {})
    keep = ax.jobs.enqueue(SYS, pid, "demo.old", {}, delay_seconds=3600)
    JobWorker(ax).run_once()
    _set_job(ax, old.id, finished_at=datetime.now(UTC) - timedelta(days=40))
    purged = ax.jobs.queue.purge_finished(30)
    assert purged["jobs"] == 1
    assert ax.jobs.queue.get(old.id) is None and ax.jobs.queue.get(keep.id) is not None


def test_job_changes_stream_positions_follow_commit_order(fast_ax):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    from axentra.events.streams import current_position, parse_position

    start = current_position(ax.db, DbScope.product(pid), "axentra_jobs")
    a = ax.jobs.enqueue(SYS, pid, "demo.s", {})
    items = ax.jobs.poll_changes(pid, None, start)
    assert [i.data["id"] for i in items] == [a.id] and items[0].type == "job.queued"
    pos = parse_position(items[-1].position)
    # A transaction that started earlier but commits later still sorts after what was seen.
    conn = psycopg.connect(ax.db.url)
    try:
        conn.execute("SELECT set_config('axentra.scope', 'platform', false)")
        conn.execute(
            "INSERT INTO axentra_jobs (id, product_id, kind) VALUES ('job_late', %s, 'demo.s')", (pid,)
        )
        b = ax.jobs.enqueue(SYS, pid, "demo.s", {})
        mid = ax.jobs.poll_changes(pid, None, pos)
        assert [i.data["id"] for i in mid] == [b.id]
        pos = parse_position(mid[-1].position)
        conn.commit()
    finally:
        conn.close()
    late = ax.jobs.poll_changes(pid, None, pos)
    assert [i.data["id"] for i in late] == ["job_late"]
    ax.jobs.cancel(SYS, pid, a.id)
    changed = ax.jobs.poll_changes(pid, None, parse_position(late[-1].position))
    assert [(i.data["id"], i.type) for i in changed] == [(a.id, "job.cancelled")]


def test_cli_worker_once(fast_ax, pg_urls, monkeypatch, capsys):
    ax = fast_ax
    pid, _, _ = _setup(ax)
    ax.events.publish(SYS, pid, None, "demo.cli", {})
    monkeypatch.setenv("AXENTRA__ENVIRONMENT", "test")
    monkeypatch.setenv("AXENTRA__MODE", "multi")
    monkeypatch.setenv("AXENTRA__DATABASE__URL", pg_urls["app"])
    monkeypatch.setenv("AXENTRA__SECURITY__MASTER_KEYS", ax.settings.security.master_keys or "")
    from axentra.cli import main

    assert main(["worker", "--once"]) == 0
    assert '"processed": 1' in capsys.readouterr().out
    assert ax.jobs.list(SYS, pid, kind="axentra.event.dispatch").items[0].status == "succeeded"
