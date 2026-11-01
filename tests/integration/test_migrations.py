from __future__ import annotations

from axentra.data.migrations import Migration, MigrationRunner


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
    import pytest

    with pytest.raises(RuntimeError, match="changed after it was applied"):
        tampered.migrate()
