"""Security evidence for the Tabrion adoption (TABRION QA-25): MIG-T-AXE-1..9 against the old code.

Document 07 of the Tabrion plan (section 8) names eight invariants AX-I-1..8 that every TABRION MIG-AXE step must
keep, each with a test, and a benchmark bound (section 8.2). These tests are written against the code before any
step, so they are the "before" evidence, and they stay: each MIG-AXE pull request runs them unchanged before and
after its change (document 09: "QA-25 green before and after each step").

======================  =====================================================================================
Test                    What it proves
======================  =====================================================================================
MIG-T-AXE-1 (AX-I-1)    after every ``transaction()`` path (commit, read-only, exception, database error with
                        error classification, ping, advisory locks, role check, leader lock) the same pooled
                        connection carries no scope (``current_setting('axentra.tenant_id', true) = ''``)
MIG-T-AXE-2 (AX-I-2)    the statements Axentra's helpers run set the scope only with ``set_config(..., true)``;
                        session-wide settings only ``statement_timeout`` when a connection is set up (grep rule:
                        ``tests/unit/test_adoption_scope_rules.py``)
MIG-T-AXE-3 (AX-I-3)    an error in the middle of a transaction (exception, database error, swallowed error, statement
                        timeout, classified and re-raised error, read-only violation, killed backend) never returns
                        a connection with a scope or an open transaction to the pool
MIG-T-AXE-4 (AX-I-4)    ``join``/``on_pool`` (M10): nested joins and savepoints in a host transaction restore the
                        previous scope; Axentra borrows no connection of the shared pool and opens none
MIG-T-AXE-5 (AX-I-5)    the role decision table of eight variants equals the snapshot of the old code
MIG-T-AXE-6 (AX-I-6)    ``relforcerowsecurity`` of every table equals the snapshot of the old code (34 tables)
MIG-T-AXE-7 (AX-I-7)    canary values of database errors reach no HTTP answer, log record or audit event (one
                        path through a table without RLS, whose DETAIL carries the canary, checked as a positive
                        control); the problem details snapshot equals the old code's; the 500 path, logs, jobs
                        and notifications: ``tests/integration/test_db_error_logging.py``
MIG-T-AXE-8 (AX-I-8)    a write whose connection is lost after it was sent runs exactly once (no retry)
MIG-T-AXE-9             the benchmark of 1,000 scoped transactions runs; the +5 % bound is an interleaved A/B
                        comparison per step with a noise-aware verdict (``tests/evidence/bench_transactions.py``
                        ``ab``); no MIG-AXE pull request states a performance result without it
======================  =====================================================================================

Tests and evidence only: nothing here changes RLS, ``DbScope``, ``join``/``on_pool`` or the pool.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
import contextlib
import logging
import os
from pathlib import Path
import re
import threading
from typing import Any
import uuid

from fastapi.testclient import TestClient
import psycopg
from psycopg import pq, sql
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool
import pytest

from axentra.core.db_errors import safe_message
from axentra.core.errors import Conflict, problem_details
from axentra.data.database import Database, DbScope, join
from axentra.events.schedules import LeaderLock
from tests.conftest import ADMIN_URL, APP_ROLE
from tests.evidence import bench_transactions, snapshots
from tests.evidence.faults import CutProxy
from tests.integration.conftest import World

pytestmark = pytest.mark.postgres

PREFIX = os.environ.get("AXENTRA_TEST_EVIDENCE_PREFIX", "axentra_ev_")
PRODUCT = "00000000-0000-4000-8000-0000000000a1"
TENANT = "00000000-0000-4000-8000-0000000000b1"
SCOPE = DbScope.tenant(PRODUCT, TENANT)
EMPTY = ("", "", "")


def scope_of(conn: psycopg.Connection[Any]) -> tuple[str, str, str]:
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute(
            "SELECT current_setting('axentra.scope', true), current_setting('axentra.product_id', true),"
            " current_setting('axentra.tenant_id', true)"
        )
        row = cur.fetchone()
    assert row is not None
    return (row[0] or "", row[1] or "", row[2] or "")


def next_borrow(db: Database) -> tuple[int, tuple[str, str, str], pq.TransactionStatus]:
    """Backend pid, scope and transaction status of the connection the pool hands out next."""
    with db.pool.connection() as conn:
        status = conn.info.transaction_status  # before this function's own statement
        pid = conn.info.backend_pid
        found = scope_of(conn)
        if not conn.autocommit:
            conn.rollback()
    return pid, found, status


@pytest.fixture(params=["owned_pool", "on_pool"])
def db(request: pytest.FixtureRequest, pg_urls: dict[str, str]) -> Iterator[Database]:
    """A database with ONE connection, so the next borrow is the very same connection: Axentra's own pool, or a
    host's autocommit pool lent with ``on_pool`` (as Nodestro's server profile lends its pool)."""
    url = pg_urls["app"]
    if request.param == "owned_pool":
        owned = Database(url, min_size=1, max_size=1)
        owned.open()
        yield owned
        owned.close()
        return
    host = ConnectionPool(url, min_size=1, max_size=1, kwargs={"autocommit": True}, open=False, name="host")
    host.open(wait=True)
    yield Database.on_pool(host, url=url)
    host.close()


def _unique_violation(conn: psycopg.Connection[Any]) -> None:
    """A real unique violation whose DETAIL carries a canary value (temporary table: nothing shared)."""
    conn.execute("CREATE TEMPORARY TABLE IF NOT EXISTS qa25_unique (v text UNIQUE) ON COMMIT DROP")
    conn.execute("INSERT INTO qa25_unique VALUES ('canary-qa25@example.com')")
    conn.execute("INSERT INTO qa25_unique VALUES ('canary-qa25@example.com')")


# -- MIG-T-AXE-1 ----------------------------------------------------------------------------------------------------


def _commit(db: Database) -> None:
    with db.transaction(SCOPE) as tx:
        assert scope_of(tx.conn) == ("tenant", PRODUCT, TENANT)
        tx.scalar("SELECT 1")


def _read_only(db: Database) -> None:
    with db.transaction(SCOPE, read_only=True) as tx:
        assert tx.scalar("SHOW transaction_read_only") == "on"


def _exception(db: Database) -> None:
    with pytest.raises(RuntimeError), db.transaction(SCOPE):
        raise RuntimeError("boom")


def _db_error_classified(db: Database) -> None:
    with pytest.raises(psycopg.errors.UniqueViolation) as info, db.transaction(SCOPE) as tx:
        _unique_violation(tx.conn)
    # The error classification path (TABRION MIG-AXE-3 moves it to tabrion.errors): text and problem details.
    assert "canary" not in safe_message(info.value)
    assert problem_details(info.value).status == 500


def _ping(db: Database) -> None:
    _commit(db)
    assert db.ping()


def _xact_lock(db: Database) -> None:
    with db.transaction(SCOPE) as tx:
        tx.scalar("SELECT pg_advisory_xact_lock(hashtext('qa25.lock'))")
        pid = tx.conn.info.backend_pid
    with db.pool.connection() as conn:
        with conn.cursor(row_factory=tuple_row) as cur:
            cur.execute("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = %s", (pid,))
            held = cur.fetchone()
        if not conn.autocommit:
            conn.rollback()
    assert held is not None and held[0] == 0


def _role_check(db: Database) -> None:
    _commit(db)
    assert db.check_role(allow_superuser=True)["bypass_rls"] is False


def _leader_lock(db: Database) -> None:
    _commit(db)
    lock = LeaderLock(db.url, key=int(uuid.uuid4().int % (2**62)))
    assert lock.acquire()
    try:
        assert lock._conn is not None and scope_of(lock._conn) == EMPTY
    finally:
        lock.release()


def _scopes_in_a_row(db: Database) -> None:
    for scope in (SCOPE, DbScope.product(PRODUCT), DbScope.platform()):
        with db.transaction(scope) as tx:
            assert scope_of(tx.conn) == (scope.kind, scope.product_id or "", scope.tenant_id or "")


PATHS: dict[str, Callable[[Database], None]] = {
    "commit": _commit,
    "read_only": _read_only,
    "exception": _exception,
    "db_error_classified": _db_error_classified,
    "ping": _ping,
    "xact_lock": _xact_lock,
    "role_check": _role_check,
    "leader_lock": _leader_lock,
    "scopes_in_a_row": _scopes_in_a_row,
}


@pytest.mark.parametrize("path", sorted(PATHS))
def test_mig_t_axe_1_no_scope_on_the_same_connection_after_a_transaction(db: Database, path: str) -> None:
    pid, before, _ = next_borrow(db)
    assert before == EMPTY
    PATHS[path](db)
    after_pid, after, status = next_borrow(db)
    assert after_pid == pid, "the pool of one connection handed out another connection"
    assert after == EMPTY
    assert status == pq.TransactionStatus.IDLE


# -- MIG-T-AXE-2 (part 2: the statements Axentra's helpers run) ------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.phase = ""
        self.lock = threading.Lock()
        self.statements: list[tuple[str, str, Any]] = []


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    """Records every statement run through a cursor of every psycopg connection opened during the test."""
    found = _Recorder()

    class RecordingCursor(psycopg.Cursor[Any]):
        def _record(self, query: Any, params: Any) -> None:
            text = query if isinstance(query, str | bytes) else query.as_string(self)
            text = text.decode() if isinstance(text, bytes) else text
            with found.lock:
                found.statements.append((found.phase, text, params))

        def execute(self, query: Any, params: Any = None, **kwargs: Any) -> Any:
            self._record(query, params)
            return super().execute(query, params, **kwargs)

        def executemany(self, query: Any, params_seq: Any, **kwargs: Any) -> Any:
            params_seq = list(params_seq)
            for params in params_seq or [None]:
                self._record(query, params)
            return super().executemany(query, params_seq, **kwargs)

    original = psycopg.Connection.connect.__func__  # type: ignore[attr-defined]

    def connect(cls: Any, *args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("cursor_factory", RecordingCursor)
        return original(cls, *args, **kwargs)

    monkeypatch.setattr(psycopg.Connection, "connect", classmethod(connect))
    monkeypatch.setattr(psycopg, "connect", psycopg.Connection.connect)
    return found


def test_mig_t_axe_2_helpers_set_the_scope_only_transaction_locally(
    recorder: _Recorder, pg_urls: dict[str, str]
) -> None:
    from axentra.data.migrations import MigrationRunner

    url = pg_urls["app"]
    recorder.phase = "owned_pool.open"
    owned = Database(url, min_size=1, max_size=1)
    owned.open()
    try:
        recorder.phase = "owned_pool.use"
        _commit(owned)
        _read_only(owned)
        _db_error_classified(owned)
        owned.ping()
        owned.check_role(allow_superuser=True)
    finally:
        owned.close()
    recorder.phase = "on_pool.use"
    host = ConnectionPool(url, min_size=1, max_size=1, kwargs={"autocommit": True}, open=False)
    host.open(wait=True)
    try:
        lent = Database.on_pool(host, url=url)
        _commit(lent)
        lent.ping()
        lent.role_info()
    finally:
        host.close()
    recorder.phase = "joined.use"
    with psycopg.connect(url) as conn:
        conn.execute("SELECT 1")
        with lent.joined(conn), lent.transaction(SCOPE), join(conn, DbScope.product(PRODUCT)):
            pass
        conn.rollback()
    recorder.phase = "leader_lock.use"
    lock = LeaderLock(url, key=int(uuid.uuid4().int % (2**62)))
    assert lock.acquire()
    lock.release()
    recorder.phase = "migration_runner.use"
    MigrationRunner(pg_urls["owner"]).migrate()  # nothing to apply: the lock and the checks only

    session_wide: list[tuple[str, str]] = []
    for phase, text, params in recorder.statements:
        squashed = " ".join(text.split())
        for part in (p.strip() for p in squashed.split(";")):  # every statement of a multi-statement string
            assert not part.upper().startswith(("SET SESSION", "SET AXENTRA", "RESET AXENTRA")), squashed
            if part.upper().startswith("SET ") and not part.upper().startswith(
                ("SET LOCAL", "SET TRANSACTION")
            ):
                session_wide.append((phase, part))
        for name, local in _set_config_calls(squashed, params):
            if name.startswith("axentra."):
                assert local == "true", (phase, squashed)
            elif local != "true":
                session_wide.append((phase, name))
    # The only session-wide setting: the statement timeout of Axentra's own pool, once per new connection.
    assert session_wide == [("owned_pool.open", "statement_timeout")]
    assert {phase for phase, *_ in recorder.statements} >= {
        "owned_pool.open",
        "owned_pool.use",
        "on_pool.use",
        "joined.use",
        "leader_lock.use",
        "migration_runner.use",
    }


_PARAM = re.compile(r"%s|%\((\w+)\)s")


def _set_config_calls(text: str, params: Any) -> list[tuple[str, str]]:
    """``(name, is_local)`` of each ``set_config`` call of a statement. Placeholders (``%s``, ``%(name)s``) are
    resolved from the statement's params; ``is_local`` is ``true``/``false`` or ``unknown`` when it is neither a
    literal nor a resolvable parameter (then it is not proven transaction-local)."""
    positional = list(params) if isinstance(params, list | tuple) else []
    named = params if isinstance(params, dict) else {}

    def resolve(arg: str, start: int) -> Any:
        m = _PARAM.fullmatch(arg)
        if m is None:
            return arg.strip("'")
        if m[1] is not None:
            return named.get(m[1], _UNKNOWN)
        index = len(re.findall(r"%s", text[:start]))
        return positional[index] if index < len(positional) else _UNKNOWN

    calls = []
    for m in re.finditer(r"set_config\(\s*([^,]+?)\s*,\s*([^,]+?)\s*,\s*(%\(\w+\)s|[^,()]+?)\s*\)", text):
        name = resolve(m[1], m.start(1))
        local = resolve(m[3], m.start(3))
        if isinstance(local, bool):
            local = "true" if local else "false"
        elif isinstance(local, str) and local.lower() in ("true", "false"):
            local = local.lower()
        else:
            local = "unknown"
        calls.append((str(name), local))
    return calls


_UNKNOWN = object()


@pytest.mark.parametrize(
    ("text", "params", "expected"),
    [
        ("SELECT set_config('axentra.scope', %s, true)", ("tenant",), [("axentra.scope", "true")]),
        ("SELECT set_config('axentra.scope', %s, %s)", ("tenant", False), [("axentra.scope", "false")]),
        ("SELECT set_config('axentra.scope', %s, %s)", ("tenant", True), [("axentra.scope", "true")]),
        (
            "SELECT set_config(%s, %s, %s)",
            ("axentra.tenant_id", "t", False),
            [("axentra.tenant_id", "false")],
        ),
        (
            "SELECT set_config(%(n)s, %(v)s, %(local)s)",
            {"n": "axentra.scope", "v": "x", "local": False},
            [("axentra.scope", "false")],
        ),
        ("SELECT set_config('axentra.scope', %s, %s)", ("tenant",), [("axentra.scope", "unknown")]),
        (
            "SELECT 1, %s; SELECT set_config('statement_timeout', %s, false)",
            (1, "5s"),
            [("statement_timeout", "false")],
        ),
    ],
)
def test_mig_t_axe_2_the_recorder_resolves_a_parameterised_local_flag(
    text: str, params: Any, expected: list[tuple[str, str]]
) -> None:
    """Mutation probe (M-4 of the QA-13/25 review): a flag passed as a parameter is checked, not skipped."""
    assert _set_config_calls(text, params) == expected


# -- MIG-T-AXE-3 ----------------------------------------------------------------------------------------------------


def _swallowed_db_error(db: Database) -> None:
    """The error is caught inside the block: the transaction is aborted when the block ends."""
    try:
        with db.transaction(SCOPE) as tx, contextlib.suppress(psycopg.errors.UniqueViolation):
            _unique_violation(tx.conn)
    except psycopg.Error:
        pass  # psycopg may report the aborted transaction at COMMIT; either way the next borrow must be clean


def _statement_timeout(db: Database) -> None:
    with pytest.raises(psycopg.errors.QueryCanceled), db.transaction(SCOPE) as tx:  # noqa: PT012 - the whole transaction is the subject
        tx.execute("SET LOCAL statement_timeout = '50ms'")
        tx.execute("SELECT pg_sleep(2)")


def _classified_and_raised(db: Database) -> None:
    """Axentra's modules turn a database error into a typed error inside the transaction (``raise Conflict``)."""
    with pytest.raises(Conflict), db.transaction(SCOPE) as tx:  # noqa: PT012 - the whole transaction is the subject
        try:
            _unique_violation(tx.conn)
        except psycopg.errors.UniqueViolation as exc:
            raise Conflict(safe_message(exc)) from None


def _read_only_violation(db: Database) -> None:
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), db.transaction(SCOPE, read_only=True) as tx:
        tx.execute("CREATE TEMPORARY TABLE qa25_ro (v int)")


ERROR_PATHS: dict[str, Callable[[Database], None]] = {
    "exception": _exception,
    "db_error": _db_error_classified,
    "swallowed_db_error": _swallowed_db_error,
    "statement_timeout": _statement_timeout,
    "classified_and_raised": _classified_and_raised,
    "read_only_violation": _read_only_violation,
}


@pytest.mark.parametrize("path", sorted(ERROR_PATHS))
def test_mig_t_axe_3_an_error_mid_transaction_returns_a_clean_idle_connection(
    db: Database, path: str
) -> None:
    pid, _, _ = next_borrow(db)
    ERROR_PATHS[path](db)
    after_pid, after, status = next_borrow(db)
    assert after_pid == pid
    assert after == EMPTY
    assert status == pq.TransactionStatus.IDLE


def test_mig_t_axe_3_a_killed_backend_is_replaced_by_a_clean_connection(db: Database) -> None:
    assert ADMIN_URL
    pid, _, _ = next_borrow(db)
    with pytest.raises(psycopg.OperationalError), db.transaction(SCOPE) as tx:  # noqa: PT012 - the whole transaction is the subject
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            admin.execute("SELECT pg_terminate_backend(%s)", (tx.conn.info.backend_pid,))
        tx.execute("SELECT 1")
    for _ in range(3):  # the pool may hand out the broken connection once more before it notices
        try:
            after_pid, after, status = next_borrow(db)
            break
        except psycopg.OperationalError:
            continue
    else:
        pytest.fail("the pool handed out a broken connection three times in a row")
    assert after_pid != pid and after == EMPTY and status == pq.TransactionStatus.IDLE


# -- MIG-T-AXE-4 ----------------------------------------------------------------------------------------------------


def _backends(admin_url: str, dbname: str) -> int:
    with psycopg.connect(admin_url, autocommit=True) as admin:
        row = admin.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = %s AND datname = %s", (APP_ROLE, dbname)
        ).fetchone()
    return int(row[0]) if row else 0


def test_mig_t_axe_4_nested_joins_on_a_shared_pool_restore_the_scope(pg_urls: dict[str, str]) -> None:
    url = pg_urls["app"]
    host = ConnectionPool(url, min_size=2, max_size=2, kwargs={"autocommit": True}, open=False, name="shared")
    host.open(wait=True)
    try:
        db = Database.on_pool(host, url=url)
        backends = _backends(pg_urls["admin"], pg_urls["dbname"])
        opened = host.get_stats().get("connections_num", 0)
        host_scope = DbScope.tenant(PRODUCT, "00000000-0000-4000-8000-0000000000c1")
        with host.connection() as conn, conn.transaction():
            plain_timeout = conn.execute("SHOW statement_timeout").fetchone()
            with join(conn, host_scope):
                expected_host = ("tenant", PRODUCT, host_scope.tenant_id)
                assert scope_of(conn) == expected_host
                requests = host.get_stats().get("requests_num", 0)
                with db.joined(conn):
                    with db.transaction(SCOPE) as outer:
                        assert outer.conn is conn and scope_of(conn) == ("tenant", PRODUCT, TENANT)
                        with db.transaction(DbScope.product(PRODUCT)):
                            assert scope_of(conn) == ("product", PRODUCT, "")
                            with join(conn, DbScope.platform()):
                                assert scope_of(conn) == ("platform", "", "")
                            assert scope_of(conn) == ("product", PRODUCT, "")
                        assert scope_of(conn) == ("tenant", PRODUCT, TENANT)
                        with pytest.raises(RuntimeError), db.transaction(DbScope.platform()):
                            raise RuntimeError("rolled back to its savepoint")
                        assert scope_of(conn) == ("tenant", PRODUCT, TENANT)
                    assert scope_of(conn) == expected_host
                    with join(conn, SCOPE), db.transaction(DbScope.product(PRODUCT)):
                        assert scope_of(conn) == ("product", PRODUCT, "")
                    assert scope_of(conn) == expected_host
                # Axentra borrowed no connection of the shared pool inside the joined host transaction.
                assert host.get_stats().get("requests_num", 0) == requests
                assert scope_of(conn) == expected_host
            assert scope_of(conn) == EMPTY
            # Axentra configured nothing on the host's connection (the pool's owner configures its connections).
            assert conn.execute("SHOW statement_timeout").fetchone() == plain_timeout
        with host.connection() as conn:
            assert scope_of(conn) == EMPTY and conn.info.transaction_status == pq.TransactionStatus.IDLE
        _commit(db)  # outside joined(): one borrow of the shared pool, no connection of its own
        assert host.get_stats().get("connections_num", 0) == opened
        assert _backends(pg_urls["admin"], pg_urls["dbname"]) == backends
    finally:
        host.close()


# -- MIG-T-AXE-5 and MIG-T-AXE-6 ------------------------------------------------------------------------------------


def test_mig_t_axe_5_the_role_decision_table_equals_the_old_code() -> None:
    assert ADMIN_URL
    current = snapshots.collect(ADMIN_URL, PREFIX, ("roles",))["roles"]
    assert not snapshots.diff("roles", snapshots.golden("roles"), current)
    table = current["table"]
    strict = "allow_superuser=False,allow_table_owner=False"
    assert "ok" in table["restricted"]["check_role"][strict]
    assert "ok" in table["restricted"]["grant_runtime_role"]
    for variant in ("superuser", "bypass_rls", "superuser_bypass_rls", "table_owner", "owner_member",
                    "connecting_owner"):  # fmt: skip
        assert table[variant]["check_role"][strict]["code"] == "configuration_error", variant
        assert table[variant]["grant_runtime_role"]["code"] == "configuration_error", variant
    assert table["missing"]["grant_runtime_role"]["code"] == "configuration_error"


def test_mig_t_axe_6_forced_row_level_security_equals_the_old_code(pg_urls: dict[str, str]) -> None:
    from pathlib import Path
    import re

    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        current = dict(
            conn.execute(
                "SELECT c.relname::text, c.relforcerowsecurity FROM pg_class c"
                " JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname LIKE 'axentra\\_%%'"
            ).fetchall()
        )
    golden = {t["table"]: t["force_row_security"] for t in snapshots.golden("catalog")["tables"]}
    assert current == golden
    sources = Path(__file__).resolve().parents[2] / "src"
    statements = sum(
        len(re.findall(r"FORCE ROW LEVEL SECURITY", p.read_text("utf-8"))) for p in sources.rglob("*.sql")
    )
    assert (
        statements
        == sum(golden.values())
        == snapshots.golden("catalog")["summary"]["force_row_security"]
        == 34
    )


# -- MIG-T-AXE-7 ----------------------------------------------------------------------------------------------------


def _audit_rows(admin_url: str) -> list[str]:
    with psycopg.connect(admin_url, autocommit=True) as conn:
        return [
            str(r[0]) for r in conn.execute("SELECT to_jsonb(a)::text FROM axentra_audit_events a").fetchall()
        ]


@pytest.fixture
def server_errors(monkeypatch: pytest.MonkeyPatch) -> list[psycopg.Error]:
    """Every database error a cursor of this process receives (the positive control of MIG-T-AXE-7)."""
    seen: list[psycopg.Error] = []
    original = psycopg.Cursor.execute

    def execute(self: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return original(self, *args, **kwargs)
        except psycopg.Error as exc:
            seen.append(exc)
            raise

    monkeypatch.setattr(psycopg.Cursor, "execute", execute)
    return seen


@contextlib.contextmanager
def _unique_user_names(admin_url: str) -> Iterator[None]:
    """A unique index on ``axentra_users.name`` (a table WITHOUT row-level security, so the server's
    ``DETAIL: Key (name)=(...)`` carries the value), dropped afterwards."""
    index = sql.Identifier(f"qa25_unique_name_{uuid.uuid4().hex[:8]}")
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE UNIQUE INDEX {} ON axentra_users (name)").format(index))
    try:
        yield
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP INDEX IF EXISTS {}").format(index))


#: The canary paths of MIG-T-AXE-7, and whether the server's error DETAIL carries the canary. PostgreSQL leaves the
#: key values out of a unique violation's DETAIL when row-level security applies to the table (``axentra_products``,
#: ``axentra_tenants``), so only the ``axentra_users`` path (no RLS) puts the canary on the wire to Axentra: that case
#: is what proves AX-I-7 here; the RLS cases pin that their DETAIL stays empty (review ``qa-13-25-review.md``, M-3).
CANARY_PATHS = {"product_slug": False, "tenant_slug": False, "user_name": True}


@pytest.mark.parametrize("what", sorted(CANARY_PATHS))
def test_mig_t_axe_7_canary_of_a_unique_violation_reaches_no_answer_log_or_audit_event(
    world: World,
    pg_urls: dict[str, str],
    caplog: pytest.LogCaptureFixture,
    server_errors: list[psycopg.Error],
    what: str,
) -> None:
    canary = f"canary-{uuid.uuid4().hex[:12]}"
    with contextlib.ExitStack() as stack:
        if what == "product_slug":
            method, path, body = "post", "/v1/products", {"slug": canary, "name": "Canary"}
            assert world.admin.post(path, json=body).status_code == 201
        elif what == "tenant_slug":
            pid = world.admin.post("/v1/products", json={"slug": "host", "name": "Host"}).json()["id"]
            method, path, body = "post", f"/v1/products/{pid}/tenants", {"slug": canary, "name": "Canary"}
            assert world.admin.post(path, json=body).status_code == 201
        else:
            stack.enter_context(_unique_user_names(pg_urls["admin"]))
            world.user(f"{canary}@example.com", name=canary)  # another user already has the name
            method, path, body = "patch", "/v1/me", {"name": canary}
            # The unclassified violation goes through the generic 500 handler: answer it, do not re-raise it here.
            client = world.admin.client
            stack.callback(setattr, world.admin, "client", client)
            world.admin.client = TestClient(
                world.app,
                base_url="http://testserver",
                headers=dict(client.headers),
                cookies=client.cookies,
                raise_server_exceptions=False,
            )
        audit_before = _audit_rows(pg_urls["admin"])
        caplog.clear()
        server_errors.clear()
        with caplog.at_level(logging.DEBUG):
            answer = getattr(world.admin, method)(path, json=body)  # a unique violation in the database
    # Positive control: the server's error really was a unique violation, with (or, under RLS, without) the canary.
    violations = [e for e in server_errors if isinstance(e, psycopg.errors.UniqueViolation)]
    assert violations, (
        f"no unique violation reached Axentra: the test does not exercise the path ({answer.text})"
    )
    carried = any(canary in (e.diag.message_detail or "") for e in violations)
    assert carried is CANARY_PATHS[what], [e.diag.message_detail for e in violations]
    if what == "user_name":
        assert answer.status_code in (409, 500), answer.text
    else:
        assert answer.status_code == 409 and answer.json()["code"] == "conflict"
    assert canary not in answer.text and "DETAIL" not in answer.text and "Key (" not in answer.text
    logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
    assert canary not in logged and "Key (" not in logged
    # The failed request wrote no audit event (its transaction rolled back) and none carries the server text.
    audit_after = _audit_rows(pg_urls["admin"])
    assert audit_after == audit_before
    assert not any("Key (" in row or "DETAIL" in row for row in audit_after)


def test_mig_t_axe_7_the_problem_details_snapshot_equals_the_old_code() -> None:
    assert ADMIN_URL
    current = snapshots.collect(ADMIN_URL, PREFIX, ("problems",))["problems"]
    assert not snapshots.diff("problems", snapshots.golden("problems"), current)
    assert all("canary" not in str(v) for v in current["other_exceptions"].values())


# -- MIG-T-AXE-8 ----------------------------------------------------------------------------------------------------


@pytest.fixture
def probe(pg_urls: dict[str, str]) -> Iterator[str]:
    """A write probe: a table the runtime role writes, and a sequence whose ``nextval`` counts every execution of the
    write on the server (a sequence is not transactional: a rolled back or lost write still counts)."""
    name = f"qa25_probe_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SEQUENCE {}").format(sql.Identifier(f"{name}_seq")))
        conn.execute(sql.SQL("CREATE TABLE {} (n bigint, marker text)").format(sql.Identifier(name)))
        for obj in ("TABLE", "SEQUENCE"):
            target = name if obj == "TABLE" else f"{name}_seq"
            conn.execute(sql.SQL("GRANT ALL ON {} {} TO PUBLIC").format(sql.SQL(obj), sql.Identifier(target)))
    yield name
    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(name)))
        conn.execute(sql.SQL("DROP SEQUENCE IF EXISTS {}").format(sql.Identifier(f"{name}_seq")))


def _executions(admin_url: str, probe: str) -> tuple[int, int]:
    """(server-side executions, committed rows) of the probe write."""
    with psycopg.connect(admin_url, autocommit=True) as conn:
        seq = conn.execute(
            sql.SQL("SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM {}").format(
                sql.Identifier(f"{probe}_seq")
            )
        ).fetchone()
        rows = conn.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(probe))).fetchone()
    assert seq is not None and rows is not None
    return int(seq[0]), int(rows[0])


@pytest.mark.parametrize("cut", ["after_the_write", "after_the_commit"])
def test_mig_t_axe_8_a_lost_write_is_not_repeated(pg_urls: dict[str, str], probe: str, cut: str) -> None:
    proxy = CutProxy.for_url(pg_urls["app"])
    db = Database(proxy.url(pg_urls["app"]), min_size=1, max_size=2)
    db.open()
    try:
        marker = f'INSERT INTO "{probe}"'.encode()  # the identifier as psycopg quotes it
        proxy.arm(marker, then=b"COMMIT" if cut == "after_the_commit" else None)
        insert = sql.SQL("INSERT INTO {} (n, marker) VALUES (nextval({}), %s)").format(
            sql.Identifier(probe), sql.Literal(f"{probe}_seq")
        )
        with pytest.raises(psycopg.OperationalError), db.transaction(SCOPE) as tx:
            tx.execute(insert.as_string(tx.conn), ("lost",))
        assert proxy.cuts == 1
        executions, rows = _executions(pg_urls["admin"], probe)
        assert executions == 1, "the write ran more than once (or not at all)"
        assert rows == (1 if cut == "after_the_commit" else 0)
        # The database keeps working (a new connection), and nothing replays the lost write.
        _commit(db)
        assert _executions(pg_urls["admin"], probe) == (executions, rows)
    finally:
        db.close()
        proxy.close()


def test_the_fault_proxy_refuses_a_remote_server_and_closes_live_connections(pg_urls: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="only a local server"):
        CutProxy.for_url("postgresql://u@db.example.com:5432/x")
    proxy = CutProxy.for_url(pg_urls["app"])
    conn = psycopg.connect(proxy.url(pg_urls["app"]), autocommit=True)
    try:
        conn.execute("SELECT 1")
        proxy.close()
        with pytest.raises(psycopg.OperationalError):
            conn.execute("SELECT 1")
    finally:
        conn.close()


def test_mig_t_axe_8_a_service_write_whose_answer_is_lost_runs_once(
    ax_factory: Any, pg_urls: dict[str, str], probe: str
) -> None:
    """A service of Axentra (identity: create a user) through the proxy; a trigger counts the INSERT executions."""
    trigger = sql.Identifier(f"{probe}_count")
    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute(
            sql.SQL(
                "CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS"
                " $$BEGIN PERFORM nextval({}); RETURN NEW; END$$"
            ).format(trigger, sql.Literal(f"{probe}_seq"))
        )
        conn.execute(
            sql.SQL(
                "CREATE TRIGGER {} BEFORE INSERT ON axentra_users FOR EACH ROW EXECUTE FUNCTION {}()"
            ).format(trigger, trigger)
        )
    proxy = CutProxy.for_url(pg_urls["app"])
    try:
        ax = ax_factory(database={"url": proxy.url(pg_urls["app"])})
        proxy.arm(b"INSERT INTO axentra_users")
        with pytest.raises(psycopg.OperationalError), ax.db.transaction(DbScope.platform()) as tx:
            ax.identity.create_user(tx, email="lost-write@example.com", name="Lost", password=None)
        assert proxy.cuts == 1
        assert _executions(pg_urls["admin"], probe) == (1, 0)
        with ax.db.transaction(DbScope.platform()) as tx:
            assert tx.scalar("SELECT count(*) FROM axentra_users WHERE email = 'lost-write@example.com'") == 0
    finally:
        proxy.close()
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute(sql.SQL("DROP TRIGGER IF EXISTS {} ON axentra_users").format(trigger))
            conn.execute(sql.SQL("DROP FUNCTION IF EXISTS {}()").format(trigger))


# -- MIG-T-AXE-9 ----------------------------------------------------------------------------------------------------


def test_mig_t_axe_9_the_transaction_benchmark_runs(pg_urls: dict[str, str]) -> None:
    result = bench_transactions.measure(pg_urls["app"], calls=200, rounds=3, warmup=20)
    assert result["calls"] == 200 and len(result["round_ms"]) == 3 and result["median_ms"] > 0


def test_mig_t_axe_9_the_ab_comparison_interleaves_both_checkouts(pg_urls: dict[str, str]) -> None:
    """Smoke test of ``ab`` (this checkout against itself): fresh processes, alternating order, one ratio a pair."""
    root = Path(__file__).resolve().parents[2]
    result = bench_transactions.ab(pg_urls["app"], root, root, pairs=2, calls=50, rounds=1, warmup=5)
    assert [p["order"] for p in result["pairs"]] == [["old", "new"], ["new", "old"]]
    assert all(p["ratio"] > 0 for p in result["pairs"])
    assert result["verdict"] in bench_transactions.EXIT


@pytest.mark.parametrize(
    ("ratios", "expected"),
    [
        ([1.0, 1.01, 0.99, 1.02, 1.0, 1.03, 0.98, 1.01, 1.0, 1.02], "ok"),
        ([1.05] * 10, "ok"),  # exactly +5 % passes
        ([1.08, 1.09, 1.1, 1.07, 1.08, 1.09, 1.08, 1.1, 1.07, 1.09], "too_slow"),
        ([1.03, 1.04, 1.06, 1.07, 1.05, 1.04, 1.06, 1.07, 1.03, 1.06], "inconclusive"),
        (
            [0.7, 1.3, 0.8, 1.2, 1.0, 0.9, 1.1, 1.4, 0.6, 1.0],
            "too_noisy",
        ),  # the review's spread of identical code
    ],
)
def test_mig_t_axe_9_the_verdict_is_noise_aware(ratios: list[float], expected: str) -> None:
    assert bench_transactions.verdict(ratios) == expected
