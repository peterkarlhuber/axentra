"""Session settings of Axentra's pool through ``tabrion.postgres.configure`` (TABRION MIG-AXE-4).

- G-AX-4: with the default settings a connection of Axentra's own pool has the same ``SHOW ALL`` as one set up by the
  code before the step (``set_config('statement_timeout', '30000', false)`` and a commit);
- the new options (``database.idle_in_transaction_timeout_ms``, ``database.application_name``) are off by default and
  change exactly their own setting when given;
- G-AX-5 (T-NOTX, NOD-M10): a pool borrowed from the host (:meth:`Database.on_pool`) is never configured, and its
  connection's ``SHOW ALL`` is the same before and after Axentra used it.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool
import pytest

from axentra.config.settings import DatabaseSettings
from axentra.data import database as database_module
from axentra.data.database import Database, DbScope

pytestmark = pytest.mark.postgres


def show_all(conn: psycopg.Connection[Any]) -> dict[str, str]:
    with psycopg.Cursor(conn, row_factory=tuple_row) as cur:
        rows = cur.execute("SHOW ALL").fetchall()
    if not conn.autocommit:
        conn.rollback()
    return {name: value for name, value, *_ in rows}


def pooled_show_all(db: Database) -> dict[str, str]:
    db.open()
    try:
        with db.pool.connection() as conn:
            return show_all(conn)
    finally:
        db.close()


def reference_show_all(url: str) -> dict[str, str]:
    """``SHOW ALL`` of a connection set up as Axentra's ``_configure`` did before TABRION MIG-AXE-4."""
    with psycopg.connect(url, autocommit=False) as conn:
        conn.execute("SELECT set_config('statement_timeout', %s, false)", ("30000",))
        conn.commit()
        return show_all(conn)


def test_new_options_are_off_by_default() -> None:
    settings = DatabaseSettings()
    assert settings.idle_in_transaction_timeout_ms == 0
    assert settings.application_name == ""


@pytest.mark.parametrize("value", ["x" * 64, "café", "tab\there"])
def test_application_name_is_printable_ascii_of_at_most_63_characters(value: str) -> None:
    with pytest.raises(ValueError):
        DatabaseSettings(application_name=value)


def test_show_all_of_a_pool_connection_is_unchanged_with_the_defaults(pg_urls: dict[str, str]) -> None:
    settings = DatabaseSettings()
    db = Database(
        pg_urls["app"],
        min_size=1,
        max_size=1,
        statement_timeout_ms=settings.statement_timeout_ms,
        idle_in_transaction_timeout_ms=settings.idle_in_transaction_timeout_ms,
        application_name=settings.application_name,
    )
    assert pooled_show_all(db) == reference_show_all(pg_urls["app"])


def test_new_options_change_only_their_own_setting(pg_urls: dict[str, str]) -> None:
    db = Database(
        pg_urls["app"],
        min_size=1,
        max_size=1,
        idle_in_transaction_timeout_ms=60_000,
        application_name="axentra-test",
    )
    got = pooled_show_all(db)
    want = reference_show_all(pg_urls["app"])
    changed = {name for name in want if got.get(name) != want[name]}
    assert changed == {"idle_in_transaction_session_timeout", "application_name"}
    assert got["idle_in_transaction_session_timeout"] == "1min"
    assert got["application_name"] == "axentra-test"


def test_a_borrowed_pool_is_never_configured(
    pg_urls: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(database_module, "configure", lambda *args, **kwargs: calls.append(args))
    url = pg_urls["app"]
    for autocommit in (True, False):
        host = ConnectionPool(url, min_size=1, max_size=1, kwargs={"autocommit": autocommit}, open=False)
        host.open(wait=True)
        try:
            with host.connection() as conn:
                before = show_all(conn)
                pid = conn.info.backend_pid
            lent = Database.on_pool(host, url=url)
            lent.open()
            with lent.transaction(DbScope.platform()) as tx:
                tx.one("SELECT 1 AS one")
            with lent.transaction(DbScope.platform(), read_only=True) as tx:
                tx.one("SELECT 1 AS one")
            lent.ping()
            lent.close()
            with host.connection() as conn:
                assert conn.info.backend_pid == pid
                assert show_all(conn) == before
        finally:
            host.close()
    assert calls == []
