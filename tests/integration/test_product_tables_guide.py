"""The product-table template of docs/guides/PRODUCT_TABLES.md works as documented."""

from __future__ import annotations

from pathlib import Path

import psycopg
import pytest

from axentra.core.ids import new_id
from axentra.data.database import DbScope
from axentra.data.migrations import load_directory

pytestmark = pytest.mark.postgres

EXAMPLE = Path(__file__).resolve().parents[2] / "docs" / "guides" / "examples" / "crm" / "migrations"


def _tenant(world, pid: str, slug: str) -> str:
    r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _insert(tx, pid: str, tid: str, title: str) -> str:
    deal_id = new_id("deal")
    tx.execute(
        "INSERT INTO crm_deals (id, product_id, tenant_id, title, amount_cents) VALUES (%s, %s, %s, %s, %s)",
        (deal_id, pid, tid, title, 1000),
    )
    return deal_id


def test_example_product_table_is_confined_by_rls(world):
    ax = world.ax
    migrations = load_directory("crm", EXAMPLE)
    assert [m.name for m in migrations] == ["deals"]
    ax.register_migrations(migrations)
    applied = ax.migrate()
    assert applied in (["crm:0001_deals"], [])  # the session database may already have it

    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    p2 = world.admin.post("/v1/products", json={"slug": "books", "name": "Books"}).json()["id"]
    t1, t2, t3 = _tenant(world, pid, "acme"), _tenant(world, pid, "globex"), _tenant(world, p2, "other")
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute("DELETE FROM crm_deals")
    for p, t in ((pid, t1), (pid, t2), (p2, t3)):
        with ax.db.transaction(DbScope.tenant(p, t)) as tx:
            _insert(tx, p, t, f"deal of {t}")

    # An unfiltered query sees only its own tenant / product.
    with ax.db.transaction(DbScope.tenant(pid, t1), read_only=True) as tx:
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM crm_deals")} == {t1}
    with ax.db.transaction(DbScope.product(pid), read_only=True) as tx:
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM crm_deals")} == {t1, t2}

    # Writing into another tenant is refused by the policy's WITH CHECK.
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        ax.db.transaction(DbScope.tenant(pid, t1)) as tx,
    ):
        _insert(tx, pid, t2, "smuggled")

    # Deleting a tenant cascades to its rows.
    assert world.admin.delete(f"/v1/products/{pid}/tenants/{t2}").status_code == 204
    with ax.db.transaction(DbScope.product(pid), read_only=True) as tx:
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM crm_deals")} == {t1}
