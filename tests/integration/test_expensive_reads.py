"""Bounds on expensive reads (AX2-06): search candidate cap and statement timeout, the heavy-read
rate limit for search and record lists, and the time-sort indexes of records."""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from axentra.api.app import create_app
from axentra.core.errors import ValidationFailed
from axentra.data.database import DbScope
from axentra.search.adapters import QUERY_TOO_EXPENSIVE, PostgresSearchAdapter
from axentra.search.models import SearchQuery
from tests.integration.conftest import World, bootstrap_admin
from tests.integration.test_search import _product, _tenant


def _world(ax_factory: Any, **overrides: Any) -> World:
    ax = ax_factory(**overrides)
    app = create_app(axentra=ax, start=False)
    return World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


def _bulk_index(admin_url: str, pid: str, tid: str, n: int, body: str = "common words here") -> None:
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO axentra_search_documents (id, product_id, tenant_id, kind, ref_id, title, body)"
            " SELECT 'sdoc_bulk' || g, %s, %s, 'note', 'n' || g, 'Note ' || g, %s FROM generate_series(1, %s) g",
            (pid, tid, body, n),
        )


def test_search_ranks_at_most_max_candidates(ax_factory, pg_urls):
    world = _world(ax_factory, search={"max_candidates": 100})
    pid = _product(world)
    tid = _tenant(world, pid)
    _bulk_index(pg_urls["admin"], pid, tid, 250)
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, Any] = {"q": "common", "limit": 100}
        if cursor:
            params["cursor"] = cursor
        r = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/search", params=params)
        assert r.status_code == 200, r.text
        seen += [h["ref_id"] for h in r.json()["items"]]
        cursor = r.json()["next_cursor"]
        if not cursor:
            break
    # 250 documents match, but only 100 candidates are ranked and paged.
    assert len(seen) == 100 and len(set(seen)) == 100
    # Narrow queries are unaffected.
    r = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/search", params={"q": "Note 7"})
    assert "n7" in [h["ref_id"] for h in r.json()["items"]]


def test_slow_search_is_cancelled_with_a_reason(ax_factory, pg_urls):
    world = _world(ax_factory)
    pid = _product(world)
    tid = _tenant(world, pid)
    _bulk_index(pg_urls["admin"], pid, tid, 20_000, body="common " * 200)
    adapter = PostgresSearchAdapter(world.ax.db, max_candidates=1_000_000, statement_timeout_ms=1)
    query = SearchQuery(text="common", kinds=(), limit=20, offset=0, match="words")
    with pytest.raises(ValidationFailed) as info:
        adapter.query(pid, tid, query)
    assert info.value.extra == {"reason": QUERY_TOO_EXPENSIVE}
    # Through the API the same refusal is a 422 with the reason.
    world.ax.search.adapter = adapter
    r = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/search", params={"q": "common"})
    assert r.status_code == 422 and r.json()["reason"] == QUERY_TOO_EXPENSIVE
    # The pooled connection is healthy afterwards and keeps no short timeout.
    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        assert tx.scalar("SELECT current_setting('statement_timeout')") != "1ms"


def test_search_timeout_inside_a_host_transaction_restores_the_setting(ax_factory, pg_urls):
    world = _world(ax_factory)
    pid = _product(world)
    tid = _tenant(world, pid)
    _bulk_index(pg_urls["admin"], pid, tid, 5)
    adapter = PostgresSearchAdapter(world.ax.db, statement_timeout_ms=4_321)
    query = SearchQuery(text="common", kinds=(), limit=20, offset=0, match="words")
    with psycopg.connect(pg_urls["app"]) as conn:
        conn.execute("SET LOCAL statement_timeout = '7s'")
        with world.ax.db.joined(conn):
            hits, _ = adapter.query(pid, tid, query)
        assert len(hits) == 5
        assert conn.execute("SELECT current_setting('statement_timeout')").fetchone()[0] == "7s"
        conn.rollback()


def test_heavy_reads_have_their_own_budget(ax_factory):
    world = _world(ax_factory, security={"heavy_rate_limit_per_minute": 3})
    pid = _product(world)
    tid = _tenant(world, pid)
    search = f"/v1/products/{pid}/tenants/{tid}/search"
    records = f"/v1/products/{pid}/tenants/{tid}/records/notes"
    assert world.admin.get(search, params={"q": "x"}).status_code == 200
    assert world.admin.get(records).status_code == 200
    assert world.admin.get(records, params={"sort": "-created_at"}).status_code == 200
    r = world.admin.get(search, params={"q": "x"})
    assert r.status_code == 429 and r.json()["code"] == "rate_limited" and int(r.headers["Retry-After"]) >= 1
    # Other reads, writes and single documents are not charged to the heavy budget.
    assert world.admin.get(f"/v1/products/{pid}/tenants/{tid}").status_code == 200
    assert world.admin.post(records, json={"data": {"a": 1}}).status_code == 201
    assert world.admin.get(f"{search}/kinds").status_code == 200
    # The budget is per credential: another session is not affected.
    other = world.browser()
    other.login("admin@example.com", "correct horse battery staple")
    assert other.get(search, params={"q": "x"}).status_code == 200


def test_heavy_read_limit_can_be_turned_off(ax_factory):
    world = _world(ax_factory, security={"heavy_rate_limit_per_minute": 0})
    pid = _product(world)
    tid = _tenant(world, pid)
    for _ in range(5):
        r = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/search", params={"q": "x"})
        assert r.status_code == 200


def test_record_time_sort_uses_an_index(ax_factory, pg_urls):
    world = _world(ax_factory)
    pid = _product(world)
    tid = _tenant(world, pid)
    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute(
            "INSERT INTO axentra_records (id, product_id, tenant_id, collection, data)"
            " SELECT 'rec_bulk' || g, %s, %s, 'notes', '{}'::jsonb FROM generate_series(1, 5000) g",
            (pid, tid),
        )
        conn.execute("ANALYZE axentra_records")
        for column in ("created_at", "updated_at"):
            plan = "\n".join(
                row[0]
                for row in conn.execute(
                    "EXPLAIN SELECT * FROM axentra_records WHERE product_id = %s AND tenant_id = %s"
                    f" AND collection = 'notes' ORDER BY {column} DESC, id DESC LIMIT 51",
                    (pid, tid),
                ).fetchall()
            )
            assert f"axentra_records_{column.split('_')[0]}" in plan, plan
            assert "Sort" not in plan.split("Index")[0], plan
