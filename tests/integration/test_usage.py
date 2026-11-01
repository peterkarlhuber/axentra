from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from axentra.core.context import Principal
from axentra.core.errors import Conflict, QuotaExceeded

SYSTEM = Principal.system("test")


def _product(world, slug="crm"):
    r = world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _tenant(world, pid, slug="acme"):
    r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug.title()})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _meter(world, pid, key="api_calls", **kw):
    r = world.admin.post(f"/v1/products/{pid}/usage/meters", json={"key": key, "unit": "calls", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def _record(client, pid, tid, key, meter="api_calls", quantity=1, **body):
    return client.post(
        f"/v1/products/{pid}/tenants/{tid}/usage/events",
        json={"meter": meter, "quantity": quantity, **body},
        headers={"Idempotency-Key": key},
    )


def _member(world, pid, tid, email, role="member"):
    world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/members", json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    return world.login_as(email)


def test_meter_crud_and_versioning(world):
    pid = _product(world)
    m = _meter(world, pid, default_limit=100)
    assert m["aggregation"] == "sum" and m["reset_period"] == "month" and m["default_limit"] == 100
    assert world.admin.post(f"/v1/products/{pid}/usage/meters", json={"key": "api_calls"}).status_code == 409
    assert world.admin.post(f"/v1/products/{pid}/usage/meters", json={"key": "Bad Key"}).status_code == 422
    url = f"/v1/products/{pid}/usage/meters/{m['id']}"
    r = world.admin.patch(url, json={"description": "API", "default_limit": None}, headers={"If-Match": "1"})
    assert r.status_code == 200 and r.json()["version"] == 2 and r.json()["default_limit"] is None
    assert world.admin.patch(url, json={"name": "x"}, headers={"If-Match": "1"}).status_code == 412
    assert [x["key"] for x in world.admin.get(f"/v1/products/{pid}/usage/meters").json()] == ["api_calls"]
    tid = _tenant(world, pid)
    assert _record(world.admin, pid, tid, "k1").status_code == 201
    assert world.admin.delete(url).status_code == 409  # has usage: deactivate instead
    assert world.admin.patch(url, json={"active": False}).json()["active"] is False
    assert _record(world.admin, pid, tid, "k2").status_code == 409
    other = _meter(world, pid, "reports")
    assert world.admin.delete(f"/v1/products/{pid}/usage/meters/{other['id']}").status_code == 204


def test_idempotent_recording(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _meter(world, pid)
    r1 = _record(world.admin, pid, tid, "req-1", quantity=3, properties={"endpoint": "/x"})
    assert r1.status_code == 201, r1.text
    body = r1.json()
    assert body["replayed"] is False and body["event"]["quantity"] == 3 and body["quota"]["used"] == 3
    r2 = _record(world.admin, pid, tid, "req-1", quantity=3, properties={"endpoint": "/x"})
    assert r2.status_code == 200 and r2.json()["replayed"] is True
    assert r2.json()["event"]["id"] == body["event"]["id"]
    assert _record(world.admin, pid, tid, "req-1", quantity=4).status_code == 409
    # Missing key is refused; aggregates counted once.
    r = world.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/usage/events", json={"meter": "api_calls", "quantity": 1}
    )
    assert r.status_code == 422
    summary = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/usage/summary").json()
    assert summary[0]["value"] == 3 and summary[0]["event_count"] == 1
    events = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/usage/events").json()
    assert len(events["items"]) == 1 and events["items"][0]["properties"] == {"endpoint": "/x"}
    # Validation
    assert _record(world.admin, pid, tid, "neg", quantity=-1).status_code == 422
    assert _record(world.admin, pid, tid, "nomtr", meter="nope").status_code == 404
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert _record(world.admin, pid, tid, "fut", occurred_at=future).status_code == 422


def test_same_key_is_per_tenant(world):
    pid = _product(world)
    t1, t2 = _tenant(world, pid, "acme"), _tenant(world, pid, "globex")
    _meter(world, pid)
    assert _record(world.admin, pid, t1, "same").status_code == 201
    assert _record(world.admin, pid, t2, "same").status_code == 201


def test_hard_and_soft_quotas_and_enforce_flag(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _meter(world, pid, default_limit=5)
    assert _record(world.admin, pid, tid, "a", quantity=5).status_code == 201
    r = _record(world.admin, pid, tid, "b", quantity=1)
    assert r.status_code == 429 and r.json()["code"] == "quota_exceeded" and r.json()["limit"] == 5
    # Product operators may record usage that already happened.
    r = _record(world.admin, pid, tid, "c", quantity=1, enforce=False)
    assert r.status_code == 201 and r.json()["quota"]["over_limit"] is True
    member = _member(world, pid, tid, "m@example.com")
    assert _record(member, pid, tid, "d", enforce=False).status_code == 403
    # Override: soft limit records but flags.
    q = f"/v1/products/{pid}/tenants/{tid}/usage/quotas/api_calls"
    r = world.admin.put(q, json={"limit": 6, "enforcement": "soft"})
    assert r.status_code == 200 and r.json()["source"] == "quota"
    r = _record(member, pid, tid, "e", quantity=10)
    assert r.status_code == 201 and r.json()["quota"]["over_limit"] is True
    assert member.put(q, json={"limit": 1000}).status_code == 403  # usage:manage is a product permission
    r = world.admin.delete(q)
    assert r.json()["source"] == "meter" and r.json()["limit"] == 5
    limits = member.get(f"/v1/products/{pid}/tenants/{tid}/usage/quotas").json()
    assert limits == [
        {"meter": "api_calls", "limit": 5.0, "enforcement": "hard", "source": "meter", "period": "month"}
    ]


def test_max_and_last_aggregation(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _meter(world, pid, "storage_bytes", aggregation="last", reset_period="none", default_limit=1000)
    _meter(world, pid, "seats", aggregation="max", default_limit=10)
    now = datetime.now(UTC)
    ax.usage.record(SYSTEM, pid, tid, "storage_bytes", 500, "s1", occurred_at=now - timedelta(minutes=2))
    ax.usage.record(SYSTEM, pid, tid, "storage_bytes", 300, "s2", occurred_at=now - timedelta(minutes=3))
    ax.usage.record(SYSTEM, pid, tid, "seats", 4, "x1")
    ax.usage.record(SYSTEM, pid, tid, "seats", 2, "x2")
    by = {m.meter: m for m in ax.usage.summary(SYSTEM, pid, tid)}
    assert by["storage_bytes"].value == 500  # the older event does not overwrite the latest value
    assert by["seats"].value == 4
    with pytest.raises(QuotaExceeded):
        ax.usage.check_and_record(SYSTEM, pid, tid, "storage_bytes", 1001, "s3")
    ax.usage.check_and_record(SYSTEM, pid, tid, "storage_bytes", 900, "s4")
    with pytest.raises(QuotaExceeded):
        ax.usage.check_and_record(SYSTEM, pid, tid, "seats", 11, "x3")


def test_concurrent_check_and_record_never_overshoots(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _meter(world, pid, default_limit=10)

    def attempt(i: int) -> str:
        try:
            ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 1, f"c-{i}")
            return "ok"
        except QuotaExceeded:
            return "refused"

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(attempt, range(30)))
    assert results.count("ok") == 10 and results.count("refused") == 20
    summary = ax.usage.summary(SYSTEM, pid, tid)
    assert summary[0].value == 10 and summary[0].event_count == 10

    # The same idempotency key raced from many threads records exactly once.
    tid2 = _tenant(world, pid, "globex")
    with ThreadPoolExecutor(max_workers=8) as pool:
        out = list(
            pool.map(lambda _: ax.usage.check_and_record(SYSTEM, pid, tid2, "api_calls", 2, "dup"), range(8))
        )
    assert len({r.event.id for r in out}) == 1 and sum(not r.replayed for r in out) == 1
    assert ax.usage.summary(SYSTEM, pid, tid2)[0].value == 2


def test_reservations(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _meter(world, pid, default_limit=10)
    base = f"/v1/products/{pid}/tenants/{tid}/usage/reservations"
    r = world.admin.post(base, json={"meter": "api_calls", "quantity": 6, "ttl_seconds": 60})
    assert r.status_code == 201 and r.json()["status"] == "active"
    rid = r.json()["id"]
    # Reserved quantity counts against the limit.
    assert _record(world.admin, pid, tid, "r1", quantity=5).status_code == 429
    assert world.admin.post(base, json={"meter": "api_calls", "quantity": 5}).status_code == 429
    summary = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/usage/summary").json()[0]
    assert summary["reserved"] == 6 and summary["remaining"] == 4
    # Commit the actual usage (idempotent).
    c1 = world.admin.post(f"{base}/{rid}/commit", json={"quantity": 4})
    assert (
        c1.status_code == 200
        and c1.json()["event"]["quantity"] == 4
        and c1.json()["event"]["reservation_id"] == rid
    )
    c2 = world.admin.post(f"{base}/{rid}/commit", json={})
    assert c2.json()["replayed"] is True and c2.json()["event"]["id"] == c1.json()["event"]["id"]
    assert world.admin.post(f"{base}/{rid}/commit", json={"quantity": 5}).status_code == 409
    assert world.admin.post(f"{base}/{rid}/release").status_code == 409
    assert world.admin.get(f"{base}/{rid}").json()["status"] == "committed"
    # Release gives the quantity back.
    r = world.admin.post(base, json={"meter": "api_calls", "quantity": 6})
    rid2 = r.json()["id"]
    assert world.admin.post(f"{base}/{rid2}/release").json()["status"] == "released"
    assert world.admin.post(f"{base}/{rid2}/release").status_code == 200
    assert world.admin.post(f"{base}/{rid2}/commit").status_code == 409
    assert _record(world.admin, pid, tid, "r2", quantity=5).status_code == 201
    # Idempotent reservation creation.
    k = {"Idempotency-Key": "res-1"}
    a = world.admin.post(base, json={"meter": "api_calls", "quantity": 0.5}, headers=k).json()
    b = world.admin.post(base, json={"meter": "api_calls", "quantity": 0.5}, headers=k).json()
    assert a["id"] == b["id"]
    assert world.admin.post(base, json={"meter": "api_calls", "quantity": 0.25}, headers=k).status_code == 409


def test_reservation_expiry_and_sweep(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _meter(world, pid, default_limit=10)
    res = ax.usage.reserve(SYSTEM, pid, tid, "api_calls", 10, ttl_seconds=30)
    with pytest.raises(QuotaExceeded):
        ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 1, "e1")
    real = ax.usage.clock
    ax.usage.clock = lambda: real() + timedelta(seconds=31)
    try:
        # Expired reservations stop counting even before the sweep runs.
        ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 1, "e2")
        assert ax.usage.get_reservation(SYSTEM, pid, tid, res.id).status == "expired"
        with pytest.raises(Conflict):
            ax.usage.commit_reservation(SYSTEM, pid, tid, res.id)
        assert ax.usage.sweep_expired_reservations() == 1
        assert ax.usage.sweep_expired_reservations() == 0
    finally:
        ax.usage.clock = real


def test_period_rollover_and_timeseries(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _meter(world, pid, default_limit=10)
    _meter(world, pid, "reports", reset_period="day")
    fixed = datetime(2026, 3, 15, 12, 0, tzinfo=UTC)
    ax.usage.clock = lambda: fixed
    feb = datetime(2026, 2, 27, 9, 0, tzinfo=UTC)
    ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 10, "feb", occurred_at=feb)
    with pytest.raises(QuotaExceeded):
        ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 1, "feb2", occurred_at=feb)
    # A new month starts with a fresh counter.
    ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 7, "mar", occurred_at=fixed - timedelta(days=1))
    ax.usage.check_and_record(SYSTEM, pid, tid, "reports", 2, "rep1", occurred_at=fixed - timedelta(days=1))
    ax.usage.check_and_record(SYSTEM, pid, tid, "reports", 3, "rep2")
    by = {m.meter: m for m in ax.usage.summary(SYSTEM, pid, tid)}
    assert by["api_calls"].value == 7 and by["api_calls"].period_start == datetime(2026, 3, 1, tzinfo=UTC)
    assert by["api_calls"].period_end == datetime(2026, 4, 1, tzinfo=UTC)
    assert by["reports"].value == 3  # daily reset
    feb_summary = {m.meter: m for m in ax.usage.summary(SYSTEM, pid, tid, at=feb)}
    assert feb_summary["api_calls"].value == 10 and feb_summary["api_calls"].over_limit is False
    ts = ax.usage.timeseries(SYSTEM, pid, "api_calls", tenant_id=tid, since=feb.date(), until=fixed.date())
    points = {p.day.isoformat(): p.value for p in ts.points}
    assert len(ts.points) == (fixed.date() - feb.date()).days + 1
    assert points["2026-02-27"] == 10 and points["2026-03-14"] == 7 and points["2026-03-01"] == 0
    tid2 = _tenant(world, pid, "globex")
    ax.usage.record(SYSTEM, pid, tid2, "api_calls", 5, "g", occurred_at=fixed - timedelta(days=1))
    total = ax.usage.timeseries(
        SYSTEM, pid, "api_calls", since=fixed.date() - timedelta(days=1), until=fixed.date()
    )
    assert [p.value for p in total.points] == [Decimal(12), Decimal(0)]
    page = ax.usage.product_totals(
        SYSTEM, pid, since=feb.date(), until=fixed.date(), meter="api_calls", limit=1
    )
    assert len(page.items) == 1 and page.next_cursor
    page2 = ax.usage.product_totals(
        SYSTEM, pid, since=feb.date(), until=fixed.date(), meter="api_calls", cursor=page.next_cursor
    )
    totals = {i.tenant_id: i.value for i in page.items + page2.items}
    assert totals == {tid: Decimal(17), tid2: Decimal(5)}


def test_usage_isolation_and_permissions(world):
    pid = _product(world)
    t1, t2 = _tenant(world, pid, "acme"), _tenant(world, pid, "globex")
    _meter(world, pid)
    alice = _member(world, pid, t1, "alice@example.com")
    viewer = _member(world, pid, t1, "viewer@example.com", role="viewer")
    assert _record(alice, pid, t1, "a1").status_code == 201
    assert _record(viewer, pid, t1, "v1").status_code == 403  # viewers cannot record
    assert viewer.get(f"/v1/products/{pid}/tenants/{t1}/usage/summary").status_code == 200
    # Foreign tenant: 404, no existence oracle.
    assert _record(alice, pid, t2, "a2").status_code == 404
    assert alice.get(f"/v1/products/{pid}/tenants/{t2}/usage/events").status_code == 404
    # Product-wide statistics and meter management need product-level rights.
    assert alice.get(f"/v1/products/{pid}/usage/summary").status_code == 403
    assert alice.post(f"/v1/products/{pid}/usage/meters", json={"key": "x"}).status_code == 403
    assert world.admin.get(f"/v1/products/{pid}/usage/summary").status_code == 200
    # Another product cannot see or use this product's meters.
    pid2 = _product(world, "erp")
    t3 = _tenant(world, pid2, "initech")
    assert _record(world.admin, pid2, t3, "x").status_code == 404  # no meter api_calls in erp
    assert _record(world.admin, pid2, t1, "x").status_code == 404  # tenant of another product
    # Tenant-bound API key with usage:record only.
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "ingest", "permissions": ["usage:record"], "tenant_id": t1},
    )
    assert r.status_code == 201, r.text
    from fastapi.testclient import TestClient

    key = TestClient(world.app, headers={"Authorization": f"Bearer {r.json()['secret']}"})
    assert _record(key, pid, t1, "k1").status_code == 201
    assert _record(key, pid, t2, "k2").status_code == 404
    assert key.get(f"/v1/products/{pid}/tenants/{t1}/usage/summary").status_code == 403
    assert _record(key, pid, t1, "k3", enforce=False).status_code == 403
    # Unauthenticated
    anon = world.browser()
    assert _record(anon, pid, t1, "z").status_code == 401


def test_new_tables_force_rls_and_confine_queries(ax, world, pg_urls):
    import psycopg

    from axentra.data.database import DbScope

    with psycopg.connect(pg_urls["admin"]) as conn:
        rows = conn.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relkind = 'r'"
            " AND (relname LIKE 'axentra_usage_%' OR relname LIKE 'axentra_billing_%')"
        ).fetchall()
    assert len(rows) == 9 and all(r[1] and r[2] for r in rows), rows
    pid = _product(world)
    t1, t2 = _tenant(world, pid, "acme"), _tenant(world, pid, "globex")
    _meter(world, pid)
    ax.usage.record(SYSTEM, pid, t1, "api_calls", 1, "a")
    ax.usage.record(SYSTEM, pid, t2, "api_calls", 1, "b")
    with ax.db.transaction(DbScope.tenant(pid, t1), read_only=True) as tx:
        # No tenant filter on purpose: RLS confines the query to tenant t1.
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM axentra_usage_events")} == {t1}
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM axentra_usage_counters")} == {t1}
    pid2 = _product(world, "erp")
    with ax.db.transaction(DbScope.product(pid2), read_only=True) as tx:
        assert tx.all("SELECT * FROM axentra_usage_meters") == []
        assert tx.all("SELECT * FROM axentra_usage_events") == []
