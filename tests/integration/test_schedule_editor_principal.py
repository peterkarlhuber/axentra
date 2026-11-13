"""A schedule's jobs act as whoever chose what they run (security assessment finding A-02).

An editor with ``jobs:manage`` who changes another principal's schedule (its kind or payload, or
turns it on) becomes the schedule's ``created_by``, so the fired jobs are bounded by the editor's
permissions instead of running the editor's choice with the creator's permissions.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from axentra.core.clock import utcnow
from axentra.data.database import DbScope
from tests.integration.conftest import World


def _ok(r: Any, code: int = 201) -> Any:
    assert r.status_code == code, r.text
    return r.json() if r.content else {}


def _fired_permissions(world: World, schedule_id: str, pid: str, tid: str) -> frozenset[str]:
    world.ax.schedules.fire_due(utcnow() + timedelta(days=2))
    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        row = tx.one(
            "SELECT id FROM axentra_jobs WHERE created_by = %s ORDER BY created_at DESC LIMIT 1",
            (f"schedule:{schedule_id}",),
        )
    assert row, "the schedule did not fire"
    job = world.ax.jobs.queue.get(row["id"])
    assert job is not None
    return world.ax.authz.grant(world.ax.jobs.principal_for(job), pid, tid).permissions


def _setup(world: World) -> tuple[str, str, Any, Any, str, str]:
    world.ax.jobs.register("demo.report", lambda ctx: None)
    world.ax.jobs.register(
        "demo.admin_task", lambda ctx: None
    )  # undeclared: all product and tenant permissions
    a = world.admin
    pid = _ok(a.post("/v1/products", json={"slug": "crm", "name": "CRM"}))["id"]
    tid = _ok(a.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}))["id"]
    po_id = world.user("po@example.com")
    _ok(a.post(f"/v1/products/{pid}/members", json={"email": "po@example.com", "role": "product_owner"}))
    _ok(
        a.post(
            f"/v1/products/{pid}/roles",
            json={
                "key": "jobs_op",
                "name": "Jobs operator",
                "scope": "product",
                "permissions": ["product:read", "jobs:read", "jobs:manage"],
            },
        )
    )
    jo_id = world.user("jo@example.com")
    _ok(a.post(f"/v1/products/{pid}/members", json={"email": "jo@example.com", "role": "jobs_op"}))
    return pid, tid, world.login_as("po@example.com"), world.login_as("jo@example.com"), po_id, jo_id


def test_weaker_editor_changing_what_runs_bounds_the_fired_job(world: World) -> None:
    pid, tid, po, jo, po_id, jo_id = _setup(world)
    body = {"name": "nightly", "kind": "demo.report", "interval_seconds": 3600, "tenant_id": tid}
    sid = _ok(po.post(f"/v1/products/{pid}/schedules", json=body))["id"]
    s = _ok(
        jo.patch(
            f"/v1/products/{pid}/schedules/{sid}", json={"kind": "demo.admin_task", "payload": {"x": 1}}
        ),
        200,
    )
    assert s["created_by"] == jo_id
    editor = world.ax.authz.grant(world.ax.authz.actor_principal(jo_id), pid, tid).permissions  # type: ignore[arg-type]
    perms = _fired_permissions(world, sid, pid, tid)
    assert perms <= editor
    assert "api_keys:manage" not in perms and "members:manage" not in perms
    # A payload change alone hands the schedule over too.
    sid2 = _ok(po.post(f"/v1/products/{pid}/schedules", json=body | {"name": "other"}))["id"]
    assert (
        _ok(jo.patch(f"/v1/products/{pid}/schedules/{sid2}", json={"payload": {"y": 2}}), 200)["created_by"]
        == jo_id
    )
    # So does turning on a schedule its creator had turned off.
    sid3 = _ok(po.post(f"/v1/products/{pid}/schedules", json=body | {"name": "off", "enabled": False}))["id"]
    assert (
        _ok(jo.patch(f"/v1/products/{pid}/schedules/{sid3}", json={"enabled": True}), 200)["created_by"]
        == jo_id
    )
    del po_id


def test_timing_edits_and_the_creators_own_edits_keep_the_creator(world: World) -> None:
    pid, tid, po, jo, po_id, _ = _setup(world)
    body = {"name": "nightly", "kind": "demo.report", "interval_seconds": 3600, "tenant_id": tid}
    sid = _ok(po.post(f"/v1/products/{pid}/schedules", json=body))["id"]
    # Changing only when or how often it runs (or resending the same kind) does not change who it acts as.
    s = _ok(
        jo.patch(
            f"/v1/products/{pid}/schedules/{sid}",
            json={"interval_seconds": 7200, "name": "renamed", "kind": "demo.report", "enabled": True},
        ),
        200,
    )
    assert s["created_by"] == po_id
    # The creator editing its own schedule keeps its permissions for the jobs.
    s = _ok(
        po.patch(
            f"/v1/products/{pid}/schedules/{sid}", json={"kind": "demo.admin_task", "payload": {"x": 1}}
        ),
        200,
    )
    assert s["created_by"] == po_id
    perms = _fired_permissions(world, sid, pid, tid)
    assert {"api_keys:manage", "members:manage", "product_members:manage"} <= perms
