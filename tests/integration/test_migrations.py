from __future__ import annotations

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
    runner = MigrationRunner(pg_urls["app"])
    assert runner.migrate() == []
    status = runner.status()
    assert all(s["applied"] and s["checksum_ok"] for s in status)


def test_product_namespace_migrations(pg_urls):
    runner = MigrationRunner(pg_urls["app"])
    runner.register([Migration("demo_ns", 1, "init", "CREATE TABLE demo_ns_items (id text PRIMARY KEY);")])
    assert runner.migrate() == ["demo_ns:0001_init"]
    assert runner.migrate() == []
    tampered = MigrationRunner(pg_urls["app"])
    tampered.register([Migration("demo_ns", 1, "init", "CREATE TABLE something_else (id text);")])
    with pytest.raises(RuntimeError, match="changed after it was applied"):
        tampered.migrate()


def _delete_namespace(pg_urls, namespace):
    import psycopg

    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute("DELETE FROM axentra_schema_migrations WHERE namespace = %s", (namespace,))


def test_check_reports_pending_unknown_and_foreign_namespaces(pg_urls):
    import psycopg

    runner = MigrationRunner(pg_urls["app"])
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
        runner = MigrationRunner(pg_urls["app"])
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
        failing = MigrationRunner(pg_urls["app"])
        failing.register(migs)

        def broken_backup(pending):
            raise RuntimeError("backup failed")

        with pytest.raises(RuntimeError, match="backup failed"):
            failing.migrate(before_apply=broken_backup)
        assert [m.label for m in failing.check(["hook_ns"]).pending] == ["hook_ns:0001_init"]

        calls = []
        runner = MigrationRunner(pg_urls["app"])
        runner.register(migs)

        def backup(pending):
            # Runs under the migration lock: another runner cannot start now.
            with psycopg.connect(pg_urls["app"], autocommit=True) as other:
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
    runner = MigrationRunner(pg_urls["app"])
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
