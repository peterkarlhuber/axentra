"""Audit round 2 (stream ax) regression tests; each failed on master 2767a2e.

AX2-01: a schedule's jobs must not keep the full handler permissions after its creator lost access,
        and nothing runs for a suspended tenant or an archived product (skipped with a reason).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from axentra.core.clock import utcnow
from axentra.data.database import DbScope
from axentra.events.worker import JobWorker
from tests.integration.conftest import World
from tests.integration.test_events_webhooks_api import Receiver, lworld, receiver

__all__ = ["lworld", "receiver"]  # pytest fixtures used below


def _pt(world: World) -> tuple[str, str]:
    a = world.admin
    pid = a.post("/v1/products", json={"slug": "rg", "name": "RG"}).json()["id"]
    tid = a.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    return pid, tid


# -- AX2-01 ------------------------------------------------------------------------------------


def test_ax2_01_schedule_jobs_follow_creator_access(world: World) -> None:
    perms: list[int] = []
    world.ax.jobs.register("demo.rg", lambda ctx: perms.append(len(ctx.principal.api_key_permissions)))
    pid, tid = _pt(world)
    uid = world.user("pa@example.com")
    assert (
        world.admin.post(
            f"/v1/products/{pid}/members", json={"email": "pa@example.com", "role": "product_admin"}
        ).status_code
        == 201
    )
    pa = world.login_as("pa@example.com")
    r = pa.post(
        f"/v1/products/{pid}/schedules",
        json={"name": "s", "kind": "demo.rg", "interval_seconds": 60, "tenant_id": tid},
    )
    assert r.status_code == 201
    # While the creator has access, the job holds the creator's (reduced) permissions.
    world.ax.schedules.fire_due(utcnow() + timedelta(seconds=120))
    JobWorker(world.ax, kinds=["demo.rg"], listen=False).run_once(maintenance=False)
    assert len(perms) == 1 and perms[0] > 0
    assert world.admin.delete(f"/v1/products/{pid}/members/{uid}").status_code == 204
    world.ax.schedules.fire_due(utcnow() + timedelta(seconds=240))
    JobWorker(world.ax, kinds=["demo.rg"], listen=False).run_once(maintenance=False)
    assert perms[1:] == [0], "a schedule job of a removed creator still holds handler permissions"


def test_ax2_01_schedule_of_deleted_schedule_fails_closed(world: World) -> None:
    perms: list[int] = []
    world.ax.jobs.register("demo.rg3", lambda ctx: perms.append(len(ctx.principal.api_key_permissions)))
    pid, tid = _pt(world)
    world.user("pa@example.com")
    assert (
        world.admin.post(
            f"/v1/products/{pid}/members", json={"email": "pa@example.com", "role": "product_admin"}
        ).status_code
        == 201
    )
    pa = world.login_as("pa@example.com")
    sid = pa.post(
        f"/v1/products/{pid}/schedules",
        json={"name": "s", "kind": "demo.rg3", "interval_seconds": 60, "tenant_id": tid},
    ).json()["id"]
    world.ax.schedules.fire_due(utcnow() + timedelta(seconds=120))
    assert pa.delete(f"/v1/products/{pid}/schedules/{sid}").status_code == 204
    JobWorker(world.ax, kinds=["demo.rg3"], listen=False).run_once(maintenance=False)
    assert perms == [0]


def test_ax2_01_suspended_tenant_schedule_does_not_fire(world: World) -> None:
    world.ax.jobs.register("demo.rg2", lambda ctx: None)
    pid, tid = _pt(world)
    r = world.admin.post(
        f"/v1/products/{pid}/schedules",
        json={"name": "s", "kind": "demo.rg2", "interval_seconds": 60, "tenant_id": tid},
    )
    assert r.status_code == 201
    sid = r.json()["id"]
    assert (
        world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"}).status_code
        == 200
    )
    assert world.ax.schedules.fire_due(utcnow() + timedelta(seconds=120)) == []
    assert world.ax.schedules.fire_due(utcnow() + timedelta(seconds=240)) == []
    # The schedule is kept, moved on, and the skip is recorded once per inactive period.
    s = world.admin.get(f"/v1/products/{pid}/schedules/{sid}").json()
    assert s["enabled"] is True and s["last_job_id"] is None
    audit = world.ax.audit.list(DbScope.platform(), product_id=pid, action="events.schedule.skip").items
    assert len(audit) == 1 and audit[0].target_id == sid
    assert audit[0].details["reason"] == "product_or_tenant_inactive"
    # Active again: it fires.
    assert (
        world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"}).status_code == 200
    )
    assert len(world.ax.schedules.fire_due(utcnow() + timedelta(seconds=400))) == 1


def test_ax2_01_archived_product_schedule_does_not_fire(world: World) -> None:
    world.ax.jobs.register("demo.rg4", lambda ctx: None)
    pid, _ = _pt(world)
    r = world.admin.post(
        f"/v1/products/{pid}/schedules", json={"name": "s", "kind": "demo.rg4", "interval_seconds": 60}
    )
    assert r.status_code == 201
    assert world.admin.post(f"/v1/products/{pid}/archive").status_code == 200
    assert world.ax.schedules.fire_due(utcnow() + timedelta(seconds=120)) == []


def test_ax2_01_queued_job_of_suspended_tenant_is_skipped_and_kept(world: World) -> None:
    ran: list[str] = []
    world.ax.jobs.register("demo.rg5", lambda ctx: ran.append(ctx.job.id))
    pid, tid = _pt(world)
    r = world.admin.post(f"/v1/products/{pid}/jobs", json={"kind": "demo.rg5", "tenant_id": tid})
    assert r.status_code == 201, r.text
    jid = r.json()["id"]
    assert (
        world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"}).status_code
        == 200
    )
    assert JobWorker(world.ax, kinds=["demo.rg5"], listen=False).run_once(maintenance=False) == 1
    assert ran == []
    with world.ax.db.transaction(DbScope.platform()) as tx:
        row: Any = tx.one("SELECT status, last_error FROM axentra_jobs WHERE id = %s", (jid,))
    assert row["status"] == "failed" and row["last_error"].startswith("skipped: ")
    # Reactivated: the kept job can be retried and runs.
    assert (
        world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"}).status_code == 200
    )
    assert world.admin.post(f"/v1/products/{pid}/jobs/{jid}/retry").status_code == 200
    JobWorker(world.ax, kinds=["demo.rg5"], listen=False).run_once(maintenance=False)
    assert ran == [jid]


def test_ax2_01_webhook_delivery_of_suspended_tenant_is_skipped(lworld: World, receiver: Receiver) -> None:
    w, ax = lworld, lworld.ax
    pid, tid = _pt(w)
    wid = w.admin.post(
        f"/v1/products/{pid}/webhooks", json={"url": receiver.url, "event_types": ["*"]}
    ).json()["endpoint"]["id"]
    assert (
        w.admin.post(
            f"/v1/products/{pid}/tenants/{tid}/events", json={"type": "order.created", "data": {}}
        ).status_code
        == 201
    )
    worker = JobWorker(ax, scheduler=False, listen=False)
    # Fan out while active, then suspend before the delivery runs.
    worker.run_once(max_jobs=1, maintenance=False)
    assert w.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"}).status_code == 200
    worker.run_once(maintenance=False)
    assert receiver.requests == []
    with ax.db.transaction(DbScope.platform()) as tx:
        rows = tx.all(
            "SELECT status, last_error FROM axentra_webhook_deliveries WHERE endpoint_id = %s", (wid,)
        )
    assert [r["status"] for r in rows] == ["dead"]
    assert rows[0]["last_error"].startswith("skipped: ")
