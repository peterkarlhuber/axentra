"""Webhook fan-out and the connection pool (delta review N-4).

The fan-out checks each endpoint creator's ``webhooks:manage`` (finding A-03) inside the dispatch transaction. These
tests pin that it does so on the dispatch transaction's own connection: one fan-out holds one pooled connection,
whatever the number of creators, so concurrent dispatch jobs cannot exhaust the pool by waiting on themselves.
"""

from __future__ import annotations

from collections.abc import Iterator
import concurrent.futures
from contextlib import contextmanager
import threading
import time
from typing import Any

import pytest

from axentra.api.app import create_app
from axentra.core.context import Principal
from axentra.data.database import DbScope
from axentra.events.jobs import job_scope
from axentra.events.models import Event
from tests.integration.conftest import World, bootstrap_admin
from tests.integration.test_events_webhooks_api import ALLOW_LOCAL


class PoolProbe:
    """Counts checkouts of the pool and the most connections held at once."""

    def __init__(self, pool: Any) -> None:
        self.pool = pool
        self.original = pool.connection
        self.lock = threading.Lock()
        self.checkouts = 0
        self.held = 0
        self.peak = 0
        pool.connection = self.connection

    @contextmanager
    def connection(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        with self.original(*args, **kwargs) as conn:
            with self.lock:
                self.checkouts += 1
                self.held += 1
                self.peak = max(self.peak, self.held)
            try:
                yield conn
            finally:
                with self.lock:
                    self.held -= 1

    def reset(self) -> None:
        with self.lock:
            self.checkouts = 0
            self.peak = self.held

    def close(self) -> None:
        self.pool.connection = self.original


def _setup(w: World, endpoints: int, creators: int) -> tuple[str, str, list[str]]:
    pid = w.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = w.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    uids = []
    for i in range(creators):
        email = f"c{i}@example.com"
        uids.append(w.user(email))
        r = w.admin.post(f"/v1/products/{pid}/members", json={"email": email, "role": "product_admin"})
        assert r.status_code in (200, 201), r.text
    ids = [
        w.ax.webhooks.create(
            Principal.system(), pid, url="http://127.0.0.1:9/hook", event_types=["*"]
        ).endpoint.id
        for _ in range(endpoints)
    ]
    with w.ax.db.transaction(DbScope.product(pid)) as tx:
        for i, wid in enumerate(ids):
            tx.execute(
                "UPDATE axentra_webhook_endpoints SET created_by = %s WHERE id = %s",
                (uids[i % creators], wid),
            )
    return pid, tid, uids


def _event(w: World, pid: str, tid: str) -> Event:
    return w.ax.events.publish(Principal.system(), pid, tid, "invoice.paid", {"n": 1})


def _fan_out(w: World, event: Event) -> None:
    with w.ax.db.transaction(job_scope(event.product_id, event.tenant_id)) as tx:
        w.ax.webhooks._fan_out(tx, event)


def _planned(w: World, event: Event) -> int:
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return int(
            tx.scalar("SELECT count(*) FROM axentra_webhook_deliveries WHERE event_id = %s", (event.id,))
        )


@pytest.fixture
def pworld(ax_factory: Any) -> Iterator[World]:
    ax = ax_factory(**ALLOW_LOCAL, database={"pool_max": 4})
    app = create_app(axentra=ax, start=False)
    yield World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


@pytest.mark.parametrize("creators", [1, 12])
def test_fan_out_holds_one_connection_whatever_the_number_of_creators(pworld: World, creators: int) -> None:
    w = pworld
    pid, tid, uids = _setup(w, 24, creators)
    # One creator without access: the check still runs for it and plans nothing for its endpoints.
    w.admin.delete(f"/v1/products/{pid}/members/{uids[0]}")
    event = _event(w, pid, tid)
    probe = PoolProbe(w.ax.db.pool)
    try:
        _fan_out(w, event)
    finally:
        probe.close()
    assert (probe.checkouts, probe.peak) == (1, 1)
    assert _planned(w, event) == 24 - 24 // creators


def test_concurrent_fan_outs_on_a_small_pool_complete(pworld: World) -> None:
    w = pworld
    pid, tid, _ = _setup(w, 40, 10)
    events = [_event(w, pid, tid) for _ in range(8)]
    w.ax.db.pool.timeout = 5.0
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda e: _fan_out(w, e), events))
    assert time.monotonic() - start < 5.0
    assert [_planned(w, e) for e in events] == [40] * 8


def test_fan_out_on_one_connection_still_skips_removed_user_and_key_creators(pworld: World) -> None:
    from fastapi.testclient import TestClient

    w = pworld
    pid, tid, uids = _setup(w, 2, 2)  # c0 and c1, one endpoint each
    op = w.login_as("c0@example.com")
    r = op.post(f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["webhooks:manage"]})
    assert r.status_code == 201, r.text
    key = TestClient(w.app, headers={"Authorization": f"Bearer {r.json()['secret']}"})
    r = key.post(f"/v1/products/{pid}/webhooks", json={"url": "http://127.0.0.1:9/k", "event_types": ["*"]})
    assert r.status_code == 201, r.text
    # c0 is removed from the product: its own endpoint and the one of its key stop; c1's keeps delivering.
    assert w.admin.delete(f"/v1/products/{pid}/members/{uids[0]}").status_code == 204
    event = _event(w, pid, tid)
    probe = PoolProbe(w.ax.db.pool)
    try:
        _fan_out(w, event)
    finally:
        probe.close()
    assert (probe.checkouts, probe.peak) == (1, 1)
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        planned = tx.all(
            "SELECT e.created_by FROM axentra_webhook_deliveries d"
            " JOIN axentra_webhook_endpoints e ON e.id = d.endpoint_id WHERE d.event_id = %s",
            (event.id,),
        )
    assert [p["created_by"] for p in planned] == [uids[1]]
