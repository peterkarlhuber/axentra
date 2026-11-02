"""Embedding Axentra as a library: joining the host application's own transaction."""

from __future__ import annotations

import psycopg
import pytest

from axentra.core.context import Principal
from axentra.core.errors import ConfigurationError, NotFound
from axentra.data.database import DbScope, join

SYSTEM = Principal.system("embed-test")


def _setup(world):  # type: ignore[no-untyped-def]
    pid = world.admin.post("/v1/products", json={"slug": "host", "name": "Host"}).json()["id"]
    tid = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    r = world.admin.post(f"/v1/products/{pid}/usage/meters", json={"key": "runs", "unit": "runs"})
    assert r.status_code == 201, r.text
    return pid, tid


def _counts(admin_url: str, action: str) -> tuple[int, int]:
    with psycopg.connect(admin_url) as conn:
        audits = conn.execute(
            "SELECT count(*) FROM axentra_audit_events WHERE action = %s", (action,)
        ).fetchone()
        usage = conn.execute("SELECT count(*) FROM axentra_usage_events").fetchone()
    assert audits is not None and usage is not None
    return int(audits[0]), int(usage[0])


def _write(tx, world, pid, tid, key="run-1"):  # type: ignore[no-untyped-def]
    world.ax.audit.record(
        tx, SYSTEM, "host.run.start", target_type="run", target_id=key, product_id=pid, tenant_id=tid
    )
    return world.ax.usage.record_in(tx, SYSTEM, pid, tid, "runs", 1, key)


def test_join_autocommit_connection_with_explicit_begin(world, pg_urls):
    """The host style: autocommit=True, an explicit BEGIN, tuple rows (default row factory)."""
    pid, tid = _setup(world)
    scope = DbScope.tenant(pid, tid)
    with psycopg.connect(pg_urls["app"], autocommit=True) as conn:
        # Outside a transaction block: refused (the writes would commit one by one).
        with pytest.raises(ConfigurationError, match="open transaction"), join(conn, scope):
            pass

        conn.execute("BEGIN")
        conn.execute("SELECT set_config('axentra.scope', 'host-value', true)")
        with join(conn, scope) as tx:
            assert tx.one("SELECT 1 AS one") == {"one": 1}  # dict rows despite the tuple factory
            result = _write(tx, world, pid, tid)
            assert result.replayed is False
            # The host's own query in the same transaction sees Axentra's rows.
            assert conn.execute("SELECT count(*) FROM axentra_usage_events").fetchone() == (1,)
        # The scope the host had set before is restored for the rest of its transaction.
        assert conn.execute("SELECT current_setting('axentra.scope')").fetchone() == ("host-value",)
        conn.execute("ROLLBACK")
        assert _counts(pg_urls["admin"], "host.run.start") == (0, 0)

        conn.execute("BEGIN")
        with join(conn, scope) as tx:
            first = _write(tx, world, pid, tid)
        conn.execute("COMMIT")
        assert _counts(pg_urls["admin"], "host.run.start") == (1, 1)

        # Replaying the idempotency key returns the same event and adds no second one.
        conn.execute("BEGIN")
        with join(conn, scope) as tx:
            again = world.ax.usage.record_in(tx, SYSTEM, pid, tid, "runs", 1, "run-1")
        conn.execute("COMMIT")
        assert again.replayed is True and again.event.id == first.event.id
        assert _counts(pg_urls["admin"], "host.run.start")[1] == 1


def test_join_with_connection_transaction_block(world, pg_urls):
    pid, tid = _setup(world)
    with psycopg.connect(pg_urls["app"]) as conn:
        # A fresh non-autocommit connection has no transaction yet: refused.
        with pytest.raises(ConfigurationError), join(conn, DbScope.tenant(pid, tid)):
            pass

        def failing_host_work() -> None:
            with conn.transaction():
                with join(conn, DbScope.tenant(pid, tid)) as tx:
                    _write(tx, world, pid, tid)
                raise RuntimeError("host failure")

        with pytest.raises(RuntimeError, match="host failure"):
            failing_host_work()
        assert _counts(pg_urls["admin"], "host.run.start") == (0, 0)
        with conn.transaction(), join(conn, DbScope.product(pid)) as tx:
            _write(tx, world, pid, tid, key="run-2")
        assert _counts(pg_urls["admin"], "host.run.start") == (1, 1)
        # A scope that does not cover the tenant is refused before anything is written.
        with (
            conn.transaction(),
            join(conn, DbScope.tenant(pid, "ten_other")) as tx,
            pytest.raises(ConfigurationError, match="scope"),
        ):
            world.ax.usage.record_in(tx, SYSTEM, pid, tid, "runs", 1, "run-3")
    assert _counts(pg_urls["admin"], "host.run.start") == (1, 1)


def test_join_respects_row_level_security(world, pg_urls):
    pid, tid = _setup(world)
    other = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "other", "name": "O"}).json()["id"]
    world.ax.usage.record(SYSTEM, pid, other, "runs", 1, "other-1")
    with (
        psycopg.connect(pg_urls["app"]) as conn,
        conn.transaction(),
        join(conn, DbScope.tenant(pid, tid)) as tx,
    ):
        assert tx.scalar("SELECT count(*) FROM axentra_usage_events") == 0


def test_injected_keyring_in_production(pg_urls, tmp_path):
    from axentra.config.secrets import Keyring, generate_key
    from axentra.config.settings import load_settings
    from axentra.platform import Axentra

    def prod(**security):  # type: ignore[no-untyped-def]
        return load_settings(
            None,
            environ={},
            environment="production",
            mode="multi",
            database={"url": pg_urls["app"], "pool_max": 2},
            security={
                "public_url": "https://api.example",
                "allowed_origins": ["https://studio.example"],
                **security,
            },
            storage={"local_path": str(tmp_path / "s")},
        )

    # Without a ref and without an injected keyring: refused, as before.
    with pytest.raises(ConfigurationError, match="master_keys_ref"):
        Axentra(prod())
    # Inline keys stay refused in production even with an injected keyring.
    with pytest.raises(ConfigurationError, match="inline"):
        Axentra(prod(master_keys=f"k1:{generate_key()}"), keyring=Keyring.parse(f"k1:{generate_key()}"))

    keyring = Keyring.parse(f"host1:{generate_key()}")
    ax = Axentra(prod(), keyring=keyring)
    ax.start()
    try:
        assert ax.keyring is keyring
        token = ax.secrets.encrypt("value", "ctx")
        assert token.startswith("axs1.host1.") and ax.secrets.decrypt(token, "ctx") == "value"
    finally:
        ax.close()


def _count(admin_url: str, sql: str, params: tuple[object, ...] = ()) -> int:
    with psycopg.connect(admin_url) as conn:
        row = conn.execute(sql, params).fetchone()  # type: ignore[arg-type]
    assert row is not None
    return int(row[0])


def test_services_run_inside_the_host_transaction(world, pg_urls):
    """Database.joined(): whole services (tenancy, identity, audit) in the host's transaction."""
    from concurrent.futures import ThreadPoolExecutor

    from axentra.core.errors import Conflict

    ax = world.ax
    with psycopg.connect(pg_urls["owner"], autocommit=True) as owner:  # the host's own migration
        owner.execute("CREATE TABLE IF NOT EXISTS host_items (id text PRIMARY KEY)")
        owner.execute("TRUNCATE host_items")
    with psycopg.connect(pg_urls["app"], autocommit=True) as conn:

        def host_work(slug: str) -> tuple[str, str, str]:
            product = ax.tenancy.create_product(SYSTEM, slug=slug, name=slug.upper())
            tenant = ax.tenancy.create_tenant(SYSTEM, product.id, slug="t1", name="T1")
            with ax.db.transaction(DbScope.platform()) as tx:
                uid = ax.identity.create_user(tx, email=f"{slug}@example.com", name="Host User")
            ax.tenancy.set_member(SYSTEM, product.id, tenant.id, role="member", user_id=uid)
            ax.audit.record_standalone(SYSTEM, "host.import", product_id=product.id, target_id=uid)
            return product.id, tenant.id, uid

        # Host ROLLBACK: none of Axentra's rows remain.
        conn.execute("BEGIN")
        conn.execute("SELECT set_config('axentra.scope', 'host-value', true)")
        with ax.db.joined(conn):
            pid, tid, uid = host_work("hostrb")
            # Another thread uses the pool and does not see the uncommitted product.
            with ThreadPoolExecutor(1) as pool:
                seen = pool.submit(ax.tenancy.get_product, SYSTEM, pid)
                with pytest.raises(NotFound):
                    seen.result()
                assert pool.submit(lambda: ax.db.joined_connection).result() is None
            assert ax.db.joined_connection is conn
        assert ax.db.joined_connection is None
        assert conn.execute("SELECT current_setting('axentra.scope')").fetchone() == ("host-value",)
        conn.execute("ROLLBACK")
        assert _count(pg_urls["admin"], "SELECT count(*) FROM axentra_products WHERE id = %s", (pid,)) == 0
        assert _count(pg_urls["admin"], "SELECT count(*) FROM axentra_users WHERE id = %s", (uid,)) == 0
        assert (
            _count(pg_urls["admin"], "SELECT count(*) FROM axentra_audit_events WHERE target_id = %s", (uid,))
            == 0
        )

        # Host COMMIT: everything is there; an Axentra error inside only rolls back its savepoint.
        conn.execute("BEGIN")
        conn.execute("INSERT INTO host_items VALUES ('before')")
        with ax.db.joined(conn):
            pid, tid, uid = host_work("hostok")
            with pytest.raises(Conflict):
                ax.tenancy.create_tenant(SYSTEM, pid, slug="t1", name="Duplicate")
            conn.execute("INSERT INTO host_items VALUES ('after')")  # the host transaction is usable
            assert ax.tenancy.get_tenant(SYSTEM, pid, tid).slug == "t1"
        conn.execute("COMMIT")
    assert _count(pg_urls["admin"], "SELECT count(*) FROM host_items") == 2
    assert _count(pg_urls["admin"], "SELECT count(*) FROM axentra_tenants WHERE product_id = %s", (pid,)) == 1
    assert (
        _count(
            pg_urls["admin"],
            "SELECT count(*) FROM axentra_memberships WHERE tenant_id = %s AND user_id = %s",
            (tid, uid),
        )
        == 1
    )
    assert (
        _count(pg_urls["admin"], "SELECT count(*) FROM axentra_audit_events WHERE action = 'host.import'")
        == 1
    )
    assert [m.user_id for m in ax.tenancy.list_members(SYSTEM, pid, tid)] == [uid]


def test_joined_requires_an_open_transaction(world, pg_urls):
    with psycopg.connect(pg_urls["app"], autocommit=True) as conn:
        with pytest.raises(ConfigurationError, match="open transaction"), world.ax.db.joined(conn):
            pass
        assert world.ax.db.joined_connection is None
        conn.execute("BEGIN")
        with world.ax.db.joined(conn):
            conn.execute("ROLLBACK")  # the host ended its transaction too early
            with pytest.raises(ConfigurationError, match="IDLE"):
                world.ax.identity.setup_required()


def test_joined_nested_transactions_restore_the_outer_scope(world, pg_urls):
    db = world.ax.db
    with psycopg.connect(pg_urls["app"]) as conn, conn.transaction(), db.joined(conn):
        with db.transaction(DbScope.product("prd_a"), read_only=True) as outer:
            assert outer.scalar("SELECT current_setting('axentra.product_id')") == "prd_a"
            with db.transaction(DbScope.platform()) as inner:
                assert inner.scalar("SELECT current_setting('axentra.scope')") == "platform"
            assert outer.scalar("SELECT current_setting('axentra.scope')") == "product"
            with (
                pytest.raises(psycopg.errors.DivisionByZero),
                db.transaction(DbScope.tenant("prd_a", "ten_b")) as failing,
            ):
                failing.execute("SELECT 1/0")
            assert outer.scalar("SELECT current_setting('axentra.product_id')") == "prd_a"
        assert conn.execute("SELECT current_setting('axentra.scope', true)").fetchone() in ((None,), ("",))


def test_a_service_call_inside_join_inside_joined_keeps_the_join_scope(world, pg_urls):
    """joined() + join(tenant) + a service whose authorization opens its own (savepoint) transaction:
    the tenant scope of join() must be back afterwards, or the next read in that scope sees no rows
    under row-level security (found when Nodestro ran its usage mirror as a non-owner role)."""
    pid, tid = _setup(world)
    with psycopg.connect(pg_urls["app"], autocommit=True) as conn:
        conn.execute("BEGIN")
        with world.ax.db.joined(conn), join(conn, DbScope.tenant(pid, tid)) as tx:
            world.ax.authz.require(SYSTEM, "usage:record", pid, tid)  # a joined platform transaction
            assert conn.execute("SELECT current_setting('axentra.tenant_id')").fetchone() == (tid,)
            # Meter lookup, counter and event in the join's tenant scope: works only with the scope intact.
            assert _write(tx, world, pid, tid, key="nested-1").replayed is False
        conn.execute("COMMIT")
    assert _counts(pg_urls["admin"], "host.run.start") == (1, 1)
