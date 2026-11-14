"""Database roles (owner vs. runtime role) and a pool borrowed from the host application.

The negative tests prove that row-level security is real defense in depth for a runtime role that
was set up with :func:`axentra.data.roles.grant_runtime_role`: it cannot read another tenant's rows
without a scope, cannot switch RLS off, change policies, drop or truncate tables, or become the
owner. They create their own owner and runtime roles in a fresh database, so they run in both test
modes (``AXENTRA_TEST_SPLIT_ROLES``).
"""

from __future__ import annotations

from collections.abc import Iterator
import threading
import uuid

import psycopg
from psycopg import sql
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool
import pytest

from axentra.core.context import Principal
from axentra.core.errors import ConfigurationError
from axentra.data.database import Database, DbScope, join
from axentra.data.migrations import MigrationRunner
from axentra.data.roles import grant_runtime_role, inspect_role
from tests.conftest import ADMIN_URL, _with_db

pytestmark = pytest.mark.postgres

PASSWORD = "role-test-pw"
SYSTEM = Principal.system("roles-test")


@pytest.fixture(scope="module")
def roles_db() -> Iterator[dict[str, str]]:
    """A fresh database owned by a non-superuser owner role (which migrates), and a runtime role."""
    if not ADMIN_URL:
        pytest.skip("AXENTRA_TEST_DATABASE_URL is not set")
    suffix = uuid.uuid4().hex[:8]
    dbname, owner, runtime = f"axentra_roles_{suffix}", f"ax_owner_{suffix}", f"ax_runtime_{suffix}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        for role in (owner, runtime):
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD {}"
                ).format(sql.Identifier(role), sql.Literal(PASSWORD))
            )
        conn.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(dbname), sql.Identifier(owner))
        )
    admin = _with_db(ADMIN_URL, dbname)
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(sql.SQL("ALTER SCHEMA public OWNER TO {}").format(sql.Identifier(owner)))
        conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(dbname)))
    urls = {
        "admin": admin,
        "owner": _with_db(ADMIN_URL, dbname, owner, PASSWORD),
        "runtime": _with_db(ADMIN_URL, dbname, runtime, PASSWORD),
        "owner_role": owner,
        "runtime_role": runtime,
    }
    MigrationRunner(urls["owner"]).migrate()
    yield urls
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(dbname)))
        for role in (runtime, owner):
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


@pytest.fixture(scope="module")
def granted(roles_db: dict[str, str]) -> dict[str, str]:
    report = grant_runtime_role(roles_db["owner"], roles_db["runtime_role"])
    assert report.restricted and report.connect and not report.can_create
    assert report.tables > 10 and report.owner == roles_db["owner_role"]
    return roles_db


@pytest.fixture(scope="module")
def two_tenants(granted: dict[str, str]) -> tuple[str, str, str]:
    """A product with two tenants and one record each, written by the runtime role in their scopes."""
    db = Database(granted["runtime"], max_size=2)
    db.open()
    try:
        pid, ta, tb = "prd_rolestest", "ten_rolesa", "ten_rolesb"
        with db.transaction(DbScope.platform()) as tx:
            tx.execute("INSERT INTO axentra_products (id, slug, name) VALUES (%s, 'roles', 'Roles')", (pid,))
            for tid, slug in ((ta, "tenant-a"), (tb, "tenant-b")):
                tx.execute(
                    "INSERT INTO axentra_tenants (id, product_id, slug, name) VALUES (%s, %s, %s, %s)",
                    (tid, pid, slug, slug),
                )
        for tid in (ta, tb):
            with db.transaction(DbScope.tenant(pid, tid)) as tx:
                tx.execute(
                    "INSERT INTO axentra_records (id, product_id, tenant_id, collection, data)"
                    " VALUES (%s, %s, %s, 'notes', '{}')",
                    (f"rec_{tid}", pid, tid),
                )
    finally:
        db.close()
    return pid, ta, tb


# ---- grant_runtime_role ---------------------------------------------------------------------------


def test_grant_refuses_roles_that_bypass_or_own(roles_db: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError, match="owner"):
        grant_runtime_role(roles_db["owner"], roles_db["owner_role"])
    with pytest.raises(ConfigurationError, match="superuser"):
        grant_runtime_role(roles_db["owner"], "postgres")
    with pytest.raises(ConfigurationError, match="does not exist"):
        grant_runtime_role(roles_db["owner"], "no_such_role_x")


def test_grant_is_idempotent_and_covers_later_tables(granted: dict[str, str]) -> None:
    again = grant_runtime_role(granted["owner"], granted["runtime_role"])
    assert again.restricted and again.connect
    # A table the owner creates later (a product migration) is usable by the runtime role at once.
    with psycopg.connect(granted["owner"], autocommit=True) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS later_things (id text PRIMARY KEY)")
    with psycopg.connect(granted["runtime"], autocommit=True) as conn:
        conn.execute("INSERT INTO later_things VALUES ('x') ON CONFLICT DO NOTHING")
        assert conn.execute("SELECT count(*) FROM later_things").fetchone() == (1,)
    with psycopg.connect(granted["owner"], autocommit=True) as conn:
        report = inspect_role(conn, granted["runtime_role"])
    assert report.owned_tables == [] and report.restricted


# ---- negative tests: what the runtime role cannot do ----------------------------------------------------


def test_runtime_role_sees_no_rows_without_a_scope(granted, two_tenants) -> None:  # type: ignore[no-untyped-def]
    pid, ta, tb = two_tenants
    with psycopg.connect(granted["runtime"]) as conn:
        assert conn.execute("SELECT count(*) FROM axentra_records").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM axentra_tenants").fetchone() == (0,)
        # A tenant scope confines even an unfiltered query to that tenant.
        conn.execute(
            "SELECT set_config('axentra.scope', 'tenant', true), set_config('axentra.product_id', %s, true),"
            " set_config('axentra.tenant_id', %s, true)",
            (pid, ta),
        )
        assert {r[0] for r in conn.execute("SELECT tenant_id FROM axentra_records").fetchall()} == {ta}
        conn.rollback()


def test_runtime_role_cannot_write_into_another_tenant(granted, two_tenants) -> None:  # type: ignore[no-untyped-def]
    pid, ta, tb = two_tenants
    db = Database(granted["runtime"], max_size=1)
    db.open()
    try:
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            db.transaction(DbScope.tenant(pid, ta)) as tx,
        ):
            tx.execute(
                "INSERT INTO axentra_records (id, product_id, tenant_id, collection, data)"
                " VALUES ('rec_forged', %s, %s, 'notes', '{}')",
                (pid, tb),
            )
        with db.transaction(DbScope.tenant(pid, ta)) as tx:
            assert tx.execute("DELETE FROM axentra_records WHERE tenant_id = %s", (tb,)) == 0
            assert (
                tx.execute("UPDATE axentra_records SET data = '{\"x\": 1}' WHERE tenant_id = %s", (tb,)) == 0
            )
    finally:
        db.close()


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE axentra_records NO FORCE ROW LEVEL SECURITY",
        "ALTER TABLE axentra_records DISABLE ROW LEVEL SECURITY",
        "DROP POLICY scope ON axentra_records",
        "CREATE POLICY forged ON axentra_records USING (true)",
        "DROP TABLE axentra_records",
        "TRUNCATE axentra_records",
        "ALTER TABLE axentra_records OWNER TO CURRENT_USER",
        "CREATE TABLE forged (id int)",
        "ALTER ROLE CURRENT_USER BYPASSRLS",
        "SET ROLE {owner}",
        "INSERT INTO axentra_schema_migrations (namespace, version, name, checksum) VALUES ('axentra', 999, 'x', 'x')",
        "DELETE FROM axentra_schema_migrations",
        "CREATE OR REPLACE FUNCTION axentra_scope_allows(p text, t text) RETURNS boolean"
        " LANGUAGE sql AS 'SELECT true'",
    ],
)
def test_runtime_role_cannot_switch_rls_off_or_change_the_schema(granted, statement: str) -> None:  # type: ignore[no-untyped-def]
    with psycopg.connect(granted["runtime"], autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement.format(owner=granted["owner_role"]))
        assert conn.execute("SELECT count(*) > 0 FROM axentra_schema_migrations").fetchone() == (True,)
        flags = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'axentra_records'"
        ).fetchone()
        assert flags == (True, True)


def test_row_security_off_is_an_error_not_a_bypass(granted, two_tenants) -> None:  # type: ignore[no-untyped-def]
    with psycopg.connect(granted["runtime"], autocommit=True) as conn:
        conn.execute("SET row_security = off")
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
            conn.execute("SELECT count(*) FROM axentra_records")


def test_role_info_and_the_table_owner_check(granted) -> None:  # type: ignore[no-untyped-def]
    for url, owner in ((granted["owner"], True), (granted["runtime"], False)):
        db = Database(url, max_size=1)
        db.open()
        try:
            info = db.role_info()
            assert info == {"superuser": False, "bypass_rls": False, "table_owner": owner}
            if owner:
                with pytest.raises(ConfigurationError, match="owns tables"):
                    db.check_role(allow_superuser=False, allow_table_owner=False)
                assert db.check_role(allow_superuser=False)["table_owner"]  # the default allows it
            else:
                db.check_role(allow_superuser=False, allow_table_owner=False)
        finally:
            db.close()


# ---- a pool borrowed from the host --------------------------------------------------------------------


@pytest.fixture
def host_pool(granted) -> Iterator[ConnectionPool]:  # type: ignore[no-untyped-def]
    """The host's pool: autocommit, tuple rows, ONE connection, so every test reuses the same backend."""
    pool = ConnectionPool(granted["runtime"], min_size=1, max_size=1, kwargs={"autocommit": True}, open=True)
    try:
        yield pool
    finally:
        pool.close()


def _backend(conn: psycopg.Connection) -> int:  # type: ignore[type-arg]
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute("SELECT pg_backend_pid()")
        row = cur.fetchone()
    assert row is not None
    return int(row[0])


def _scope(conn: psycopg.Connection) -> tuple[str, str, str]:  # type: ignore[type-arg]
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute(
            "SELECT coalesce(current_setting('axentra.scope', true), ''),"
            " coalesce(current_setting('axentra.product_id', true), ''),"
            " coalesce(current_setting('axentra.tenant_id', true), '')"
        )
        row = cur.fetchone()
    assert row is not None
    return row


def test_borrowed_pool_is_not_opened_or_closed(host_pool) -> None:  # type: ignore[no-untyped-def]
    db = Database.on_pool(host_pool)
    assert db.owns_pool is False and db.url == host_pool.conninfo
    db.open()
    db.close()
    assert not host_pool.closed
    assert db.ping()
    assert db.role_info()["table_owner"] is False


def test_no_scope_leaks_between_tenants_on_the_same_connection(host_pool, two_tenants) -> None:  # type: ignore[no-untyped-def]
    pid, ta, tb = two_tenants
    db = Database.on_pool(host_pool)
    backends = set()
    for tid in (ta, tb, ta):
        with db.transaction(DbScope.tenant(pid, tid)) as tx:
            backends.add(_backend(tx.conn))
            assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM axentra_records")} == {tid}
        # Back in the host's hands: the same physical connection, no Axentra scope, no rows visible.
        with host_pool.connection() as conn:
            backends.add(_backend(conn))
            assert _scope(conn) == ("", "", "")
            assert conn.execute("SELECT count(*) FROM axentra_records").fetchone() == (0,)
            assert conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    assert len(backends) == 1  # really one connection, reused for every step


def test_failed_transaction_leaves_no_scope_behind(host_pool, two_tenants) -> None:  # type: ignore[no-untyped-def]
    pid, ta, _tb = two_tenants
    db = Database.on_pool(host_pool)

    def fail() -> None:
        with db.transaction(DbScope.tenant(pid, ta)) as tx:
            tx.all("SELECT 1")
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        fail()
    with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction(DbScope.tenant(pid, ta)) as tx:
        tx.execute(
            "INSERT INTO axentra_records (id, product_id, tenant_id, collection, data)"
            " VALUES ('rec_x', %s, 'ten_other', 'n', '{}')",
            (pid,),
        )
    with host_pool.connection() as conn:
        assert _scope(conn) == ("", "", "")
        assert conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    with db.transaction(DbScope.platform(), read_only=True) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_records WHERE id = 'rec_x'") == 0


def test_joined_nesting_on_a_borrowed_connection(host_pool, two_tenants) -> None:  # type: ignore[no-untyped-def]
    """Host transaction -> joined Axentra transactions (nested, different scopes) -> back to the host scope."""
    pid, ta, tb = two_tenants
    db = Database.on_pool(host_pool)
    with host_pool.connection() as conn:
        conn.execute("BEGIN")
        with db.joined(conn):
            with db.transaction(DbScope.tenant(pid, ta)) as outer:
                assert outer.conn is conn
                assert _scope(conn) == ("tenant", pid, ta)
                with db.transaction(DbScope.tenant(pid, tb)) as inner:
                    assert {r["tenant_id"] for r in inner.all("SELECT tenant_id FROM axentra_records")} == {
                        tb
                    }
                assert _scope(conn) == ("tenant", pid, ta)  # the outer scope again
                with join(conn, DbScope.platform()) as tx:
                    assert tx.scalar("SELECT count(*) FROM axentra_records") == 2
                assert _scope(conn) == ("tenant", pid, ta)
            assert _scope(conn) == ("", "", "")
        conn.execute("ROLLBACK")
        assert _scope(conn) == ("", "", "")


def test_threads_share_one_budget_without_mixing_scopes(granted, two_tenants) -> None:  # type: ignore[no-untyped-def]
    """Several threads on a borrowed pool of two connections: each transaction sees only its own tenant."""
    pid, ta, tb = two_tenants
    pool = ConnectionPool(granted["runtime"], min_size=2, max_size=2, kwargs={"autocommit": True}, open=True)
    db = Database.on_pool(pool)
    errors: list[BaseException] = []

    def work(tid: str) -> None:
        try:
            for _ in range(25):
                with db.transaction(DbScope.tenant(pid, tid), read_only=True) as tx:
                    seen = {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM axentra_records")}
                    assert seen == {tid}, seen
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(tid,)) for tid in (ta, tb, ta, tb, ta, tb)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        assert pool.get_stats()["pool_max"] == 2
    finally:
        pool.close()


def test_db_commands(granted, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    import json

    from axentra.cli import main

    cfg = tmp_path / "ax.toml"
    cfg.write_text(
        f'environment = "test"\n[database]\nurl = "{granted["runtime"]}"\nmigration_url = "{granted["owner"]}"\n',
        encoding="utf-8",
    )
    capsys.readouterr()
    assert main(["--config", str(cfg), "db", "grant-runtime-role", granted["runtime_role"]]) == 0
    assert json.loads(capsys.readouterr().out)["restricted"] is True
    assert main(["--config", str(cfg), "db", "inspect-role"]) == 0  # the role of database.url
    assert json.loads(capsys.readouterr().out)["role"] == granted["runtime_role"]
    assert main(["--config", str(cfg), "db", "inspect-role", granted["owner_role"]]) == 3
    assert json.loads(capsys.readouterr().out)["owned_tables"]
    assert main(["--config", str(cfg), "migrate", "--grant-runtime-role", granted["runtime_role"]]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] == [] and out["runtime_role"]["restricted"] is True


# ---- stricter role check through Tabrion (TABRION MIG-AXE-6, contract I-20) ---------------------------------------


def test_roles_that_can_become_an_unsafe_role_are_refused(roles_db: dict[str, str]) -> None:
    """A role is as privileged as every role it can become (role membership, also NOINHERIT): a member of a
    ``BYPASSRLS`` or superuser role, and a member of the schema's owner, are refused by ``grant_runtime_role``;
    an application role that is a member of a ``BYPASSRLS`` role fails ``check_role`` (Peter's decision for
    MIG-NOD-5 and MIG-AXE-6: adopt Tabrion's stricter check)."""
    suffix = uuid.uuid4().hex[:6]
    names = {k: f"ax6_{k}_{suffix}" for k in ("byp", "byp_m", "su", "su_m", "s_own", "s_own_m")}
    schema = f"ax6_schema_{suffix}"
    ident = {k: sql.Identifier(v) for k, v in names.items()}
    with psycopg.connect(roles_db["admin"], autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN BYPASSRLS").format(ident["byp"]))
        admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN SUPERUSER").format(ident["su"]))
        admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(ident["s_own"]))
        for member, parent in (("byp_m", "byp"), ("su_m", "su"), ("s_own_m", "s_own")):
            admin.execute(
                sql.SQL("CREATE ROLE {} LOGIN NOINHERIT PASSWORD {}").format(
                    ident[member], sql.Literal(PASSWORD)
                )
            )
            admin.execute(sql.SQL("GRANT {} TO {}").format(ident[parent], ident[member]))
        admin.execute(
            sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(schema), ident["s_own"])
        )
        admin.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(str(admin.info.dbname)), ident["byp_m"]
            )
        )
    try:
        with pytest.raises(ConfigurationError) as err:
            grant_runtime_role(roles_db["owner"], names["byp_m"])
        assert str(err.value) == (
            f"the runtime role {names['byp_m']!r} can become a role with BYPASSRLS (role membership):"
            " row-level security would not apply to it"
        )
        with pytest.raises(ConfigurationError) as err:
            grant_runtime_role(roles_db["owner"], names["su_m"])
        assert f"the runtime role {names['su_m']!r} can become a superuser (role membership)" in str(
            err.value
        )
        with pytest.raises(ConfigurationError) as err:
            grant_runtime_role(roles_db["owner"], names["s_own_m"], schema=schema)
        assert str(err.value) == (
            f"the runtime role {names['s_own_m']!r} can become the owner role or the owner of the schema"
            " (role membership): row-level security would not apply to it"
        )
        with psycopg.connect(roles_db["owner"], autocommit=True) as conn:
            report = inspect_role(conn, names["byp_m"])
        assert report.bypass_rls and not report.superuser and not report.restricted
        db = Database(_with_db(ADMIN_URL, str(conninfo_dbname(roles_db["admin"])), names["byp_m"], PASSWORD))
        db.open()
        try:
            assert db.role_info() == {"superuser": False, "bypass_rls": True, "table_owner": False}
            with pytest.raises(ConfigurationError, match="bypasses row-level security"):
                db.check_role(allow_superuser=False, allow_table_owner=False)
        finally:
            db.close()
        # Nothing was granted to the refused roles.
        with psycopg.connect(roles_db["admin"], autocommit=True) as admin:
            granted_to = admin.execute(
                "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = ANY(%s)",
                ([names["byp_m"], names["su_m"], names["s_own_m"]],),
            ).fetchone()
            assert granted_to == (0,)
    finally:
        with psycopg.connect(roles_db["admin"], autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA IF EXISTS {}").format(sql.Identifier(schema)))
            admin.execute(
                sql.SQL("REVOKE ALL ON DATABASE {} FROM {}").format(
                    sql.Identifier(str(admin.info.dbname)), ident["byp_m"]
                )
            )
            for key in ("byp_m", "su_m", "s_own_m", "byp", "su", "s_own"):
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(ident[key]))


def conninfo_dbname(url: str) -> str:
    from psycopg.conninfo import conninfo_to_dict

    return str(conninfo_to_dict(url)["dbname"])
