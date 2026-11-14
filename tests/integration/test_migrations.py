from __future__ import annotations

import time

import pytest

from axentra.core.errors import ConfigurationError
from axentra.data.migrations import Migration, MigrationRunner, split_statements


def test_split_statements():
    sql = """-- head; comment
CREATE TABLE a (v text DEFAULT 'x;y');
/* block; comment */ CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $body$ SELECT 1; $body$;
SELECT "odd;name" FROM a;
"""
    parts = split_statements(sql)
    assert len(parts) == 3
    assert parts[0].endswith("DEFAULT 'x;y')") and "$body$ SELECT 1; $body$" in parts[1]
    assert split_statements("-- only a comment\n") == []


def test_migrations_are_idempotent_and_checksummed(pg_urls):
    runner = MigrationRunner(pg_urls["owner"])
    assert runner.migrate() == []
    status = runner.status()
    assert all(s["applied"] and s["checksum_ok"] for s in status)


def test_product_namespace_migrations(pg_urls):
    runner = MigrationRunner(pg_urls["owner"])
    runner.register([Migration("demo_ns", 1, "init", "CREATE TABLE demo_ns_items (id text PRIMARY KEY);")])
    assert runner.migrate() == ["demo_ns:0001_init"]
    assert runner.migrate() == []
    tampered = MigrationRunner(pg_urls["owner"])
    tampered.register([Migration("demo_ns", 1, "init", "CREATE TABLE something_else (id text);")])
    with pytest.raises(RuntimeError, match="changed after it was applied"):
        tampered.migrate()


def _delete_namespace(pg_urls, namespace):
    import psycopg

    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute("DELETE FROM axentra_schema_migrations WHERE namespace = %s", (namespace,))


def test_check_reports_pending_unknown_and_foreign_namespaces(pg_urls):
    import psycopg

    runner = MigrationRunner(pg_urls["owner"])
    runner.register(
        [
            Migration("chk_ns", 1, "one", "CREATE TABLE chk_ns_one (id text);"),
            Migration("chk_ns", 2, "two", "CREATE TABLE chk_ns_two (id text);"),
        ]
    )
    try:
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute(
                "INSERT INTO axentra_schema_migrations (namespace, version, name, checksum) VALUES"
                " ('chk_ns', 1, 'one', %s), ('chk_ns', 7, 'future', 'x'), ('chk_foreign', 1, 'other', 'y')",
                (runner.migrations[-2].checksum,),
            )
        result = runner.check()
        ns = result.namespaces["chk_ns"]
        assert ns.registered and ns.applied == [1] and [m.version for m in ns.pending] == [2]
        assert ns.unknown == [7] and not ns.current
        assert result.namespaces["axentra"].current
        foreign = result.namespaces["chk_foreign"]
        assert not foreign.registered and foreign.unknown == [1]
        assert not result.current
        assert result.as_dict()["namespaces"][0]["namespace"] == "axentra"

        # Only the axentra namespace: current; a foreign namespace never blocks unless named.
        assert runner.check(["axentra"]).current
        assert not runner.check(["chk_foreign"]).current

        from axentra.data.migrations import SchemaNotCurrent

        with pytest.raises(SchemaNotCurrent, match="newer than the code"):
            runner.require_current()
        runner.require_current(["axentra"])

        # The schema is newer than the code: migrate refuses and applies nothing.
        hook_calls = []
        with pytest.raises(ConfigurationError, match="newer than this code"):
            runner.migrate(before_apply=hook_calls.append)
        assert hook_calls == []
        assert [m.version for m in runner.check(["chk_ns"]).namespaces["chk_ns"].pending] == [2]
        # Explicitly allowed: the pending migration is applied.
        assert runner.migrate(allow_newer=True) == ["chk_ns:0002_two"]
    finally:
        _delete_namespace(pg_urls, "chk_ns")
        _delete_namespace(pg_urls, "chk_foreign")
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS chk_ns_one, chk_ns_two")


def test_newer_axentra_schema_is_refused(pg_urls):
    import psycopg

    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute(
            "INSERT INTO axentra_schema_migrations (namespace, version, name, checksum)"
            " VALUES ('axentra', 9999, 'from_the_future', 'x')"
        )
    try:
        runner = MigrationRunner(pg_urls["owner"])
        assert runner.check().namespaces["axentra"].unknown == [9999]
        with pytest.raises(ConfigurationError, match=r"axentra \[9999\]"):
            runner.migrate()
        assert runner.migrate(allow_newer=True) == []
    finally:
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute(
                "DELETE FROM axentra_schema_migrations WHERE namespace = 'axentra' AND version = 9999"
            )


def test_before_apply_hook(pg_urls):
    import psycopg

    migs = [Migration("hook_ns", 1, "init", "CREATE TABLE hook_ns_items (id text PRIMARY KEY);")]
    try:
        failing = MigrationRunner(pg_urls["owner"])
        failing.register(migs)

        def broken_backup(pending):
            raise RuntimeError("backup failed")

        with pytest.raises(RuntimeError, match="backup failed"):
            failing.migrate(before_apply=broken_backup)
        assert [m.label for m in failing.check(["hook_ns"]).pending] == ["hook_ns:0001_init"]

        calls = []
        runner = MigrationRunner(pg_urls["owner"])
        runner.register(migs)

        def backup(pending):
            # Runs under the migration lock: another runner cannot start now.
            with psycopg.connect(pg_urls["owner"], autocommit=True) as other:
                from axentra.data.migrations import MIGRATION_LOCK

                got = other.execute("SELECT pg_try_advisory_lock(%s)", (MIGRATION_LOCK,)).fetchone()
                assert got == (False,)
            calls.append([m.label for m in pending])

        assert runner.migrate(before_apply=backup) == ["hook_ns:0001_init"]
        assert runner.migrate(before_apply=backup) == []  # nothing pending: not called
        assert calls == [["hook_ns:0001_init"]]
        assert runner.check(["hook_ns"]).current
    finally:
        _delete_namespace(pg_urls, "hook_ns")
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS hook_ns_items")


def test_no_transaction_migration(pg_urls):
    import psycopg

    sql = """-- Build an index without blocking writes.
-- axentra:no-transaction
CREATE TABLE IF NOT EXISTS ntx_items (id text PRIMARY KEY, label text);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ntx_items_label ON ntx_items (label);
CREATE OR REPLACE FUNCTION ntx_noop() RETURNS text LANGUAGE sql AS $$ SELECT 'a;b' $$;
"""
    mig = Migration("ntx_ns", 1, "concurrent_index", sql)
    assert not mig.transactional
    assert Migration("x", 1, "y", "CREATE TABLE t (id int);\n-- axentra:no-transaction\n").transactional
    runner = MigrationRunner(pg_urls["owner"])
    runner.register([mig])
    try:
        assert runner.migrate() == ["ntx_ns:0001_concurrent_index"]
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            assert conn.execute("SELECT to_regclass('ntx_items_label') IS NOT NULL").fetchone() == (True,)
            assert conn.execute("SELECT ntx_noop()").fetchone() == ("a;b",)
    finally:
        _delete_namespace(pg_urls, "ntx_ns")
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS ntx_items")
            conn.execute("DROP FUNCTION IF EXISTS ntx_noop()")


def test_start_gate_and_readiness(pg_urls, tmp_path):
    from fastapi.testclient import TestClient

    from axentra.api.app import create_app
    from axentra.data.migrations import SchemaNotCurrent
    from axentra.platform import Axentra
    from tests.conftest import make_settings

    settings = make_settings(
        pg_urls, database={"require_current_schema": True}, _storage_path=str(tmp_path / "s")
    )
    pending = Axentra.from_settings(settings)
    pending.register_migrations([Migration("gate_ns", 1, "init", "CREATE TABLE gate_ns_t (id text);")])
    with pytest.raises(SchemaNotCurrent, match="gate_ns"):
        pending.start()
    assert pending.migration_runner().check().pending[0].label == "gate_ns:0001_init"
    pending.close()

    current = Axentra.from_settings(settings)
    current.start()
    try:
        assert current.schema_ready()
        client = TestClient(create_app(axentra=current, start=False))
        body = client.get("/v1/health/ready").json()
        assert body["checks"]["schema"] is True
    finally:
        current.close()


def test_cli_migrate_check(pg_urls, tmp_path, capsys):
    import json

    from axentra.cli import main

    cfg = tmp_path / "ax.toml"
    cfg.write_text(
        'environment = "test"\nmode = "multi"\n[database]\n'
        f"url = {json.dumps(pg_urls['app'])}\nmigration_entry_points = false\n"
        f'[security]\nmaster_keys = "t1:{"A" * 43}="\n',
        encoding="utf-8",
    )
    capsys.readouterr()
    assert main(["--config", str(cfg), "migrate", "--check", "--namespace", "axentra"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["current"] is True and out["namespaces"][0]["namespace"] == "axentra"
    assert main(["--config", str(cfg), "migrate", "--check", "--namespace", "never_applied"]) == 0
    capsys.readouterr()


def test_cli_setup_token_closes_the_pool(pg_urls, tmp_path, capsys, monkeypatch):
    """`axentra admin setup-token` closes its Axentra instance (and pool) on success and on refusal;
    before, the pool threads delayed the exit by about 20 seconds (audit round 3)."""
    import json

    from axentra.cli import main
    from axentra.platform import Axentra

    closed: list[int] = []
    real_close = Axentra.close

    def close(self: Axentra) -> None:
        closed.append(1)
        real_close(self)

    monkeypatch.setattr(Axentra, "close", close)
    cfg = tmp_path / "ax.toml"
    cfg.write_text(
        'environment = "test"\nmode = "multi"\n[database]\n'
        f"url = {json.dumps(pg_urls['app'])}\nmigration_entry_points = false\n"
        f'[security]\nmaster_keys = "t1:{"A" * 43}="\n',
        encoding="utf-8",
    )
    capsys.readouterr()
    # --force: other tests of this session may already have created a platform admin.
    assert main(["--config", str(cfg), "admin", "setup-token", "--force"]) == 0
    assert capsys.readouterr().out.strip().startswith("axsetup_")
    assert closed == [1]


def test_parallel_runners_on_a_fresh_database_apply_each_migration_once(pg_urls):
    """Several processes running ``axentra migrate`` at the same time (for example replicas that
    migrate on start) serialize on the advisory lock: on an empty database every migration is
    applied exactly once, the others wait and find nothing pending, and nobody fails."""
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import uuid

    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    fresh = f"{pg_urls['dbname']}_par_{uuid.uuid4().hex[:6]}"
    with psycopg.connect(pg_urls["server_admin"], autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(fresh), sql.Identifier(pg_urls["owner_role"])
            )
        )
    try:
        url = make_conninfo(**{**conninfo_to_dict(pg_urls["owner"]), "dbname": fresh})
        extra = [
            Migration("par_ns", 1, "init", "CREATE TABLE par_ns_items (id int PRIMARY KEY);"),
            Migration("par_ns", 2, "seed", "INSERT INTO par_ns_items VALUES (1);"),
        ]
        runners = 5
        start = threading.Barrier(runners)

        def run(_: int) -> list[str]:
            runner = MigrationRunner(url)
            runner.register(extra)
            start.wait()
            return runner.migrate()

        with ThreadPoolExecutor(runners) as ex:
            results = list(ex.map(run, range(runners)))
        expected = [m.label for m in MigrationRunner(url).migrations] + [m.label for m in extra]
        applied = [label for r in results for label in r]
        # Exactly one runner did the work, in order; the others found nothing pending.
        assert sorted(applied) == sorted(expected)
        assert sorted(len(r) for r in results) == [0] * (runners - 1) + [len(expected)]
        with psycopg.connect(url) as conn:
            assert conn.execute("SELECT count(*) FROM par_ns_items").fetchone() == (1,)
            rows = conn.execute(
                "SELECT count(*), count(DISTINCT (namespace, version)) FROM axentra_schema_migrations"
            ).fetchone()
            assert rows == (len(expected), len(expected))
        checker = MigrationRunner(url)
        checker.register(extra)
        assert all(s["applied"] and s["checksum_ok"] for s in checker.status())
    finally:
        with psycopg.connect(pg_urls["server_admin"], autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(fresh)))


def test_a_waiting_runner_does_not_block_create_index_concurrently(pg_urls):
    """TABRION MIG-AXE-5: runner A holds the migration lock and applies a ``-- axentra:no-transaction`` migration with
    ``CREATE INDEX CONCURRENTLY`` while runner B waits for the lock. B waits with ``wait_advisory_lock`` (polling,
    no open statement or snapshot between attempts), so the index build does not wait for B and both finish: A
    applies the migration, B finds nothing pending. A blocking ``pg_advisory_lock`` in B would hold a snapshot and
    the index build would wait for it forever."""
    import threading

    import psycopg

    from axentra.data.migrations import MIGRATION_LOCK

    migs = [
        Migration(
            "cicwait_ns",
            1,
            "concurrent_index",
            "-- axentra:no-transaction\n"
            "CREATE TABLE IF NOT EXISTS cicwait_ns_items (id int PRIMARY KEY, label text);\n"
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS cicwait_ns_items_label ON cicwait_ns_items (label);\n",
        )
    ]
    results: dict[str, list[str]] = {}
    errors: list[BaseException] = []
    b_started = threading.Event()

    def run(name: str, **kwargs) -> None:
        runner = MigrationRunner(pg_urls["owner"])
        runner.register(migs)
        try:
            results[name] = runner.migrate(**kwargs)
        except BaseException as exc:  # reported by the main thread
            errors.append(exc)

    def start_b_while_a_holds_the_lock(pending) -> None:
        # Called under A's migration lock, before A applies anything: B starts and waits for the lock.
        b.start()
        b_started.set()
        with psycopg.connect(pg_urls["admin"], autocommit=True) as admin:
            for _ in range(100):
                waiting = admin.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                    " AND query LIKE %s AND pid <> pg_backend_pid()",
                    ("%pg_try_advisory_lock%",),
                ).fetchone()[0]
                if waiting:
                    break
                time.sleep(0.05)
            assert waiting, "runner B never tried the migration lock"
            # A still holds the lock (advisory locks are per database).
            assert admin.execute("SELECT pg_try_advisory_lock(%s)", (MIGRATION_LOCK,)).fetchone() == (False,)

    b = threading.Thread(target=run, args=("b",), daemon=True)
    a = threading.Thread(
        target=run, args=("a",), kwargs={"before_apply": start_b_while_a_holds_the_lock}, daemon=True
    )
    try:
        a.start()
        a.join(timeout=60)
        assert not a.is_alive(), "runner A did not finish: CREATE INDEX CONCURRENTLY waited for runner B"
        assert errors == []
        assert b_started.is_set()
        b.join(timeout=60)
        assert not b.is_alive(), "runner B did not finish after A released the lock"
        assert errors == []
        assert results == {"a": ["cicwait_ns:0001_concurrent_index"], "b": []}
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            valid = conn.execute(
                "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass('cicwait_ns_items_label')"
            ).fetchone()
            assert valid == (True,)
    finally:
        _delete_namespace(pg_urls, "cicwait_ns")
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS cicwait_ns_items")
