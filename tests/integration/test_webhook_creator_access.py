"""Webhook endpoints are bound to their creator (security assessment finding A-03).

Like the creator's API keys, an endpoint stops delivering once its creator no longer holds
``webhooks:manage`` in the product: no new deliveries are planned, and deliveries planned before
are dropped (``dead`` with a reason) instead of being sent. Endpoints created by platform admins or
in process by system code keep working.
"""

from __future__ import annotations

from typing import Any

from axentra.core.context import Principal
from axentra.data.database import DbScope
from axentra.events.webhooks import CREATOR_LOST_ACCESS
from axentra.events.worker import JobWorker
from tests.integration.conftest import World
from tests.integration.test_events_webhooks_api import Receiver, lworld, receiver

__all__ = ["lworld", "receiver"]  # pytest fixtures used below


def _ok(r: Any, code: int = 201) -> Any:
    assert r.status_code == code, r.text
    return r.json() if r.content else {}


def _setup(w: World) -> tuple[str, str, str, Any]:
    pid = _ok(w.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}))["id"]
    tid = _ok(w.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}))["id"]
    uid = w.user("pa@example.com")
    _ok(
        w.admin.post(f"/v1/products/{pid}/members", json={"email": "pa@example.com", "role": "product_admin"})
    )
    return pid, tid, uid, w.login_as("pa@example.com")


def _hook(client: Any, pid: str, url: str) -> str:
    return str(
        _ok(client.post(f"/v1/products/{pid}/webhooks", json={"url": url, "event_types": ["*"]}))["endpoint"][
            "id"
        ]
    )


def _publish(w: World, pid: str, tid: str) -> None:
    body = {"type": "invoice.paid", "data": {"customer": "c1"}}
    _ok(w.admin.post(f"/v1/products/{pid}/tenants/{tid}/events", json=body))


def _drain(w: World) -> None:
    worker = JobWorker(w.ax, scheduler=False)
    for _ in range(10):
        if worker.run_once() == 0:
            return


def _deliveries(w: World, pid: str, wid: str) -> list[dict[str, Any]]:
    return list(_ok(w.admin.get(f"/v1/products/{pid}/webhooks/{wid}/deliveries"), 200)["items"])


def test_removed_creator_gets_no_new_deliveries(lworld: World, receiver: Receiver) -> None:
    w = lworld
    pid, tid, uid, pa = _setup(w)
    wid = _hook(pa, pid, receiver.url)
    admin_wid = _hook(w.admin, pid, receiver.url)
    assert _ok(w.admin.get(f"/v1/products/{pid}/webhooks/{wid}"), 200)["creator_has_access"] is True
    _ok(w.admin.delete(f"/v1/products/{pid}/members/{uid}"), 204)
    listed = {
        e["id"]: e["creator_has_access"]
        for e in _ok(w.admin.get(f"/v1/products/{pid}/webhooks"), 200)["items"]
    }
    assert listed == {wid: False, admin_wid: True}
    assert _ok(w.admin.get(f"/v1/products/{pid}/webhooks/{wid}"), 200)["creator_has_access"] is False
    _publish(w, pid, tid)
    _drain(w)
    assert _deliveries(w, pid, wid) == []
    # The platform admin's endpoint still delivers the same event.
    assert [d["status"] for d in _deliveries(w, pid, admin_wid)] == ["succeeded"]
    assert len(receiver.requests) == 1


def test_demoted_creator_gets_no_new_deliveries(lworld: World, receiver: Receiver) -> None:
    w = lworld
    pid, tid, _, pa = _setup(w)
    wid = _hook(pa, pid, receiver.url)
    # product_viewer may still read webhooks but no longer create them.
    _ok(
        w.admin.post(
            f"/v1/products/{pid}/members", json={"email": "pa@example.com", "role": "product_viewer"}
        )
    )
    _publish(w, pid, tid)
    _drain(w)
    assert _deliveries(w, pid, wid) == []
    assert receiver.requests == []


def test_pending_delivery_is_not_sent_after_the_creator_lost_access(
    lworld: World, receiver: Receiver
) -> None:
    w = lworld
    pid, tid, uid, pa = _setup(w)
    wid = _hook(pa, pid, receiver.url)
    _publish(w, pid, tid)
    JobWorker(w.ax, scheduler=False).run_once(max_jobs=1)  # only the dispatch (fan-out) job
    assert [d["status"] for d in _deliveries(w, pid, wid)] == ["pending"]
    _ok(w.admin.delete(f"/v1/products/{pid}/members/{uid}"), 204)
    _drain(w)
    (d,) = _deliveries(w, pid, wid)
    assert d["status"] == "dead" and d["last_error"] == CREATOR_LOST_ACCESS
    assert receiver.requests == []
    # A redelivery is dropped the same way.
    _ok(w.admin.post(f"/v1/products/{pid}/webhooks/{wid}/deliveries/{d['id']}/redeliver"), 202)
    _drain(w)
    assert _deliveries(w, pid, wid)[0]["status"] == "dead" and receiver.requests == []


def test_active_and_system_creators_keep_delivering(lworld: World, receiver: Receiver) -> None:
    w = lworld
    pid, tid, _, pa = _setup(w)
    wid = _hook(pa, pid, receiver.url)
    system_ep = w.ax.webhooks.create(Principal.system(), pid, url=receiver.url, event_types=["*"]).endpoint
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        assert (
            tx.scalar("SELECT created_by FROM axentra_webhook_endpoints WHERE id = %s", (system_ep.id,))
            == "system"
        )
    _publish(w, pid, tid)
    _drain(w)
    assert [d["status"] for d in _deliveries(w, pid, wid)] == ["succeeded"]
    assert [d["status"] for d in _deliveries(w, pid, system_ep.id)] == ["succeeded"]
    assert _ok(w.admin.get(f"/v1/products/{pid}/webhooks/{system_ep.id}"), 200)["creator_has_access"] is True
    assert len(receiver.requests) == 2
