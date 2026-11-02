"""Row-level security is a real second line of defense: queries without any WHERE clause stay in scope."""

from __future__ import annotations

import psycopg
import pytest

from axentra.data.database import DbScope


def _seed(world):
    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    p2 = world.admin.post("/v1/products", json={"slug": "books", "name": "Books"}).json()["id"]
    t1 = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "A"}).json()["id"]
    t2 = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "globex", "name": "G"}).json()["id"]
    t3 = world.admin.post(f"/v1/products/{p2}/tenants", json={"slug": "other", "name": "O"}).json()["id"]
    for p, t in ((pid, t1), (pid, t2), (p2, t3)):
        world.admin.post(f"/v1/products/{p}/tenants/{t}/records/notes", json={"t": t})
    return pid, p2, t1, t2, t3


def test_app_role_is_not_superuser(world):
    from tests.conftest import SPLIT_ROLES

    info = world.ax.db.check_role(allow_superuser=False)
    # With separate roles (AXENTRA_TEST_SPLIT_ROLES=1) the application role owns no table either.
    assert info == {"superuser": False, "bypass_rls": False, "table_owner": not SPLIT_ROLES}


def test_unfiltered_queries_are_confined(world):
    pid, p2, t1, t2, t3 = _seed(world)
    db = world.ax.db
    with db.transaction(DbScope.tenant(pid, t1)) as tx:
        rows = tx.all("SELECT tenant_id FROM axentra_records")
        assert {r["tenant_id"] for r in rows} == {t1}
        assert {r["id"] for r in tx.all("SELECT id FROM axentra_tenants")} == {t1}
    with db.transaction(DbScope.product(pid)) as tx:
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM axentra_records")} == {t1, t2}
        assert {r["id"] for r in tx.all("SELECT id FROM axentra_products")} == {pid}
    with db.transaction(DbScope.platform()) as tx:
        assert len(tx.all("SELECT id FROM axentra_records")) == 3


def test_writes_into_foreign_scope_are_rejected(world):
    pid, p2, t1, t2, t3 = _seed(world)
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        world.ax.db.transaction(DbScope.tenant(pid, t1)) as tx,
    ):
        tx.execute(
            "INSERT INTO axentra_records (id, product_id, tenant_id, collection, data)"
            " VALUES ('rec_x', %s, %s, 'notes', '{}')",
            (pid, t2),
        )
    with world.ax.db.transaction(DbScope.tenant(pid, t1)) as tx:
        assert tx.execute("UPDATE axentra_records SET data = '{}' WHERE tenant_id = %s", (t2,)) == 0
        assert tx.execute("DELETE FROM axentra_records WHERE product_id = %s", (p2,)) == 0


def test_missing_scope_sees_nothing(world, pg_urls):
    _seed(world)
    with psycopg.connect(pg_urls["app"]) as conn:
        assert conn.execute("SELECT count(*) FROM axentra_records").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM axentra_tenants").fetchone()[0] == 0


def test_scope_settings_do_not_leak_between_pooled_transactions(world):
    pid, p2, t1, t2, t3 = _seed(world)
    with world.ax.db.transaction(DbScope.tenant(pid, t1)) as tx:
        tx.all("SELECT 1")
    with world.ax.db.pool.connection() as conn:
        row = conn.execute("SELECT current_setting('axentra.scope', true) AS s").fetchone()
        assert row["s"] in (None, "")
        conn.rollback()
