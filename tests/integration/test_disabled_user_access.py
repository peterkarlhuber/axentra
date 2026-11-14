"""A disabled user holds no product or tenant relation, wherever the principal comes from (delta review N-5).

Disabling a user ended their sessions, but the authorizer still read their product membership: API keys they had
created kept working, their webhook endpoints kept delivering and jobs of their schedules kept their rights. The
authorizer now checks the user's status in the same query as the membership. Enabling the user again restores all
of it (the memberships stay).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient

from axentra.core.clock import utcnow
from axentra.data.database import DbScope
from axentra.events.webhooks import CREATOR_LOST_ACCESS
from axentra.events.worker import JobWorker
from tests.integration.conftest import World
from tests.integration.test_events_webhooks_api import Receiver, lworld, receiver
from tests.integration.test_webhook_creator_access import _deliveries, _drain, _hook, _publish, _setup

__all__ = ["lworld", "receiver"]  # pytest fixtures used below

CODE = "api_key_creator_lost_access"


def _ok(r: Any, code: int = 201) -> Any:
    assert r.status_code == code, r.text
    return r.json() if r.content else {}


def _status(w: World, uid: str, status: str) -> None:
    _ok(w.admin.patch(f"/v1/users/{uid}", json={"status": status}), 200)


def test_disabled_product_admins_api_key_has_no_rights_until_enabled(lworld: World) -> None:
    w = lworld
    pid, tid, uid, pa = _setup(w)
    j = _ok(
        pa.post(
            f"/v1/products/{pid}/api-keys",
            json={"name": "k", "permissions": ["webhooks:read", "api_keys:manage"]},
        )
    )
    key = TestClient(w.app, headers={"Authorization": f"Bearer {j['secret']}"})
    _ok(key.get(f"/v1/products/{pid}/webhooks"), 200)

    _status(w, uid, "disabled")
    r = key.get(f"/v1/products/{pid}/webhooks")
    assert r.status_code == 403 and r.json()["code"] == CODE, r.text
    r = key.post(f"/v1/products/{pid}/api-keys", json={"name": "k2", "permissions": ["webhooks:read"]})
    assert r.status_code == 403 and r.json()["code"] == CODE, r.text
    assert w.ax.authz.tenant_grants(w.ax.authz.actor_principal(uid), pid) == {}  # type: ignore[arg-type]
    assert pa.get(f"/v1/products/{pid}/webhooks").status_code == 401  # the session ended (unchanged)

    _status(w, uid, "active")
    _ok(key.get(f"/v1/products/{pid}/webhooks"), 200)
    _ok(key.post(f"/v1/products/{pid}/api-keys", json={"name": "k2", "permissions": ["webhooks:read"]}))
    assert tid in w.ax.authz.tenant_grants(w.ax.authz.actor_principal(uid), pid)  # type: ignore[arg-type]


def test_disabled_creators_webhook_gets_no_deliveries_until_enabled(
    lworld: World, receiver: Receiver
) -> None:
    w = lworld
    pid, tid, uid, pa = _setup(w)
    wid = _hook(pa, pid, receiver.url)
    # Planned while the creator was active, sent after they were disabled: dropped.
    _publish(w, pid, tid)
    JobWorker(w.ax, scheduler=False).run_once(max_jobs=1)  # only the dispatch (fan-out) job
    assert [d["status"] for d in _deliveries(w, pid, wid)] == ["pending"]
    _status(w, uid, "disabled")
    assert _ok(w.admin.get(f"/v1/products/{pid}/webhooks/{wid}"), 200)["creator_has_access"] is False
    _drain(w)
    (d,) = _deliveries(w, pid, wid)
    assert d["status"] == "dead" and d["last_error"] == CREATOR_LOST_ACCESS
    # A new event plans nothing for the endpoint.
    _publish(w, pid, tid)
    _drain(w)
    assert len(_deliveries(w, pid, wid)) == 1 and receiver.requests == []

    _status(w, uid, "active")
    _publish(w, pid, tid)
    _drain(w)
    assert sorted(d["status"] for d in _deliveries(w, pid, wid)) == ["dead", "succeeded"]
    assert len(receiver.requests) == 1


def test_jobs_of_a_disabled_users_schedule_run_without_rights_until_enabled(lworld: World) -> None:
    w = lworld
    w.ax.jobs.register("demo.report", lambda ctx: None)
    pid, tid, uid, pa = _setup(w)
    body = {"name": "nightly", "kind": "demo.report", "interval_seconds": 3600, "tenant_id": tid}
    sid = _ok(pa.post(f"/v1/products/{pid}/schedules", json=body))["id"]

    def fired_permissions(days: int) -> frozenset[str]:
        w.ax.schedules.fire_due(utcnow() + timedelta(days=days))
        with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
            row = tx.one(
                "SELECT id FROM axentra_jobs WHERE created_by = %s ORDER BY created_at DESC LIMIT 1",
                (f"schedule:{sid}",),
            )
        assert row, "the schedule did not fire"
        job = w.ax.jobs.queue.get(row["id"])
        assert job is not None
        return w.ax.authz.grant(w.ax.jobs.principal_for(job), pid, tid).permissions

    _status(w, uid, "disabled")
    assert fired_permissions(2) == frozenset()  # as for a removed creator
    _status(w, uid, "active")
    assert fired_permissions(4)
