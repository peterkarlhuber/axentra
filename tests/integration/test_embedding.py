"""Embedding Axentra as a library: joining the host application's own transaction."""

from __future__ import annotations

import psycopg
import pytest

from axentra.core.context import Principal
from axentra.core.errors import ConfigurationError
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
