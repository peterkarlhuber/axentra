"""Migration runner follow-ups: per-migration timeouts and the dry-run SQL output."""

from __future__ import annotations

import json
import threading

import psycopg
import pytest

from axentra.data.migrations import Migration, MigrationRunner, render_plan

#: Pending for the dry-run CLI test (loaded through ``database.extra_migrations``).
DRY_RUN_MIGRATIONS = [
    Migration(
        "dry_ns", 1, "init", "-- axentra:lock-timeout=3s\nCREATE TABLE dry_ns_items (id text PRIMARY KEY);\n"
    ),
    Migration(
        "dry_ns",
        2,
        "index",
        "-- axentra:no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS dry_ns_i ON dry_ns_items (id);\n",
    ),
]


def _applied(pg_urls, namespace):  # type: ignore[no-untyped-def]
    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        return [
            r[0]
            for r in conn.execute(
                "SELECT version FROM axentra_schema_migrations WHERE namespace = %s ORDER BY version",
                (namespace,),
            ).fetchall()
        ]


def test_timeout_directives_are_parsed_and_validated():
    mig = Migration(
        "t_ns",
        1,
        "x",
        "-- intro\n-- axentra:lock-timeout = 250ms\n-- AXENTRA:statement-timeout=2min\nSELECT 1;",
    )
    assert mig.timeouts == {"lock_timeout": "250ms", "statement_timeout": "2min"}
    # Directives after the first statement are ordinary comments.
    assert Migration("t_ns", 1, "x", "SELECT 1;\n-- axentra:lock-timeout=1s\n").timeouts == {}
    bad = Migration("t_ns", 1, "x", "-- axentra:lock-timeout=1s; DROP TABLE x\nSELECT 1;")
    with pytest.raises(ValueError, match="invalid lock-timeout"):
        bad.timeouts  # noqa: B018
    with pytest.raises(ValueError, match="invalid statement-timeout"):
        MigrationRunner("postgresql://unused").register(
            [Migration("t_ns", 1, "x", "-- axentra:statement-timeout='5s'\nSELECT 1;")]
        )


def test_lock_timeout_fails_fast_and_a_rerun_applies(pg_urls):
    runner = MigrationRunner(pg_urls["owner"])
    runner.register([Migration("lock_ns", 1, "init", "CREATE TABLE lock_ns_items (id text PRIMARY KEY);")])
    runner.migrate()
    waiting = MigrationRunner(pg_urls["owner"])
    waiting.register(
        [
            *runner.migrations[-1:],
            Migration(
                "lock_ns",
                2,
                "col",
                "-- axentra:lock-timeout=200ms\nALTER TABLE lock_ns_items ADD COLUMN note text;",
            ),
        ]
    )
    holder = psycopg.connect(pg_urls["admin"])
    try:
        holder.execute("LOCK TABLE lock_ns_items IN ACCESS SHARE MODE")  # a long-running reader
        with pytest.raises(psycopg.errors.LockNotAvailable):
            waiting.migrate()
        assert _applied(pg_urls, "lock_ns") == [1]
    finally:
        holder.rollback()
        holder.close()
    assert waiting.migrate() == ["lock_ns:0002_col"]


def test_runner_defaults_apply_and_are_reset_after_a_no_transaction_step(pg_urls):
    runner = MigrationRunner(pg_urls["owner"], lock_timeout_ms=1500, statement_timeout_ms=60_000)
    assert runner.timeouts == {"lock_timeout": "1500ms", "statement_timeout": "60000ms"}
    check = (
        "DO $$ BEGIN IF current_setting('lock_timeout') <> '{lock}' OR current_setting('statement_timeout') <> '{stmt}'"
        " THEN RAISE EXCEPTION 'unexpected % %', current_setting('lock_timeout'), current_setting('statement_timeout');"
        " END IF; END $$;"
    )
    runner.register(
        [
            Migration("def_ns", 1, "uses_defaults", check.format(lock="1500ms", stmt="1min")),
            Migration(
                "def_ns",
                2,
                "own",
                "-- axentra:no-transaction\n-- axentra:lock-timeout=5s\n"
                + check.format(lock="5s", stmt="1min"),
            ),
            Migration("def_ns", 3, "defaults_again", check.format(lock="1500ms", stmt="1min")),
        ]
    )
    assert runner.migrate() == ["def_ns:0001_uses_defaults", "def_ns:0002_own", "def_ns:0003_defaults_again"]


def test_plan_and_render_plan(pg_urls):
    runner = MigrationRunner(pg_urls["owner"], lock_timeout_ms=1000)
    runner.register(DRY_RUN_MIGRATIONS)
    pending = runner.plan()
    assert [m.label for m in pending] == ["dry_ns:0001_init", "dry_ns:0002_index"]
    sql = render_plan(pending, runner.timeouts)
    assert (
        "BEGIN;\nSET LOCAL lock_timeout = '3s';\n-- axentra:lock-timeout=3s\nCREATE TABLE dry_ns_items" in sql
    )
    assert "-- runs outside a transaction" in sql
    assert (
        "SET lock_timeout = '1000ms';\n-- axentra:no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS"
        in sql
    )
    assert sql.rstrip().endswith("RESET lock_timeout;")
    assert _applied(pg_urls, "dry_ns") == []  # planning applies nothing
    assert render_plan([]) == "-- No pending migrations.\n"
    # plan() refuses what migrate() refuses.
    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute(
            "INSERT INTO axentra_schema_migrations (namespace, version, name, checksum)"
            " VALUES ('dry_ns', 9, 'future', 'x')"
        )
    try:
        with pytest.raises(Exception, match="newer than this code"):
            runner.plan()
        assert [m.label for m in runner.plan(allow_newer=True)] == ["dry_ns:0001_init", "dry_ns:0002_index"]
    finally:
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute("DELETE FROM axentra_schema_migrations WHERE namespace = 'dry_ns'")


def test_cli_migrate_dry_run(pg_urls, tmp_path, capsys):
    from axentra.cli import main

    cfg = tmp_path / "ax.toml"
    cfg.write_text(
        'environment = "test"\nmode = "multi"\n[database]\n'
        f"url = {json.dumps(pg_urls['app'])}\nmigration_entry_points = false\n"
        'extra_migrations = ["tests.integration.test_migration_runner_options:DRY_RUN_MIGRATIONS"]\n'
        "migration_statement_timeout_ms = 30000\n"
        f'[security]\nmaster_keys = "t1:{"A" * 43}="\n',
        encoding="utf-8",
    )
    capsys.readouterr()
    assert main(["--config", str(cfg), "migrate", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("-- 2 pending migration(s)")
    assert "-- ==== dry_ns:0001_init" in out and "SET LOCAL statement_timeout = '30000ms';" in out
    assert _applied(pg_urls, "dry_ns") == []


def test_parallel_runners_with_a_concurrent_index_do_not_deadlock(pg_urls):
    """Two runners, one building an index CONCURRENTLY under the lock while the other waits for it."""
    base = [Migration("cic_ns", 1, "init", "CREATE TABLE cic_ns_items (id text PRIMARY KEY);")]
    first = MigrationRunner(pg_urls["owner"])
    first.register(base)
    first.migrate()
    mig = Migration(
        "cic_ns",
        2,
        "idx",
        "-- axentra:no-transaction\nSELECT pg_sleep(0.5);\nCREATE INDEX CONCURRENTLY IF NOT EXISTS cic_ns_i ON cic_ns_items (id);",
    )
    results: list[object] = []

    def run() -> None:
        runner = MigrationRunner(pg_urls["owner"], lock_timeout_ms=20_000)
        runner.register([*base, mig])
        try:
            results.append(runner.migrate())
        except Exception as exc:  # recorded for the assertion below
            results.append(exc)

    threads = [threading.Thread(target=run) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(map(str, results)) == sorted(["['cic_ns:0002_idx']", "[]", "[]"]), results
