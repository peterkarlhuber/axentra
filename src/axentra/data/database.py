"""Connection pool and scoped transactions.

Every transaction declares its :class:`DbScope`. The scope is written into transaction-local
PostgreSQL settings (``SET LOCAL`` via ``set_config(..., true)``):

- ``axentra.scope``: ``platform`` | ``product`` | ``tenant``
- ``axentra.product_id`` and ``axentra.tenant_id``

Row-level security policies on product and tenant tables (migration ``0001``) compare rows with
these settings, so a query that forgets its ``WHERE product_id = ...`` still cannot read or write
rows of another product or tenant. Settings are transaction-local and therefore never leak to the
next user of a pooled connection. RLS is defense in depth: services still filter explicitly, and
the policies only help when the application role is not a superuser and has no ``BYPASSRLS``
(checked by :meth:`Database.check_role`).

An application that embeds Axentra and has its own psycopg connection to the same database can
run Axentra writes inside its own transaction with :func:`join` (see
docs/architecture/EMBEDDING.md).
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import logging
import threading
from typing import Any, Literal

import psycopg
from psycopg import pq
from psycopg.rows import dict_row, tuple_row
from psycopg_pool import ConnectionPool
from tabrion.postgres import role_info as _tabrion_role_info

from axentra.core.errors import ConfigurationError, NotFound

logger = logging.getLogger(__name__)

ScopeKind = Literal["platform", "product", "tenant"]


@dataclass(frozen=True, slots=True)
class DbScope:
    kind: ScopeKind
    product_id: str | None = None
    tenant_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind == "platform" and (self.product_id or self.tenant_id):
            raise ValueError("platform scope takes no product or tenant")
        if self.kind == "product" and (not self.product_id or self.tenant_id):
            raise ValueError("product scope needs exactly a product id")
        if self.kind == "tenant" and not (self.product_id and self.tenant_id):
            raise ValueError("tenant scope needs product and tenant ids")

    @classmethod
    def platform(cls) -> DbScope:
        return cls("platform")

    @classmethod
    def product(cls, product_id: str) -> DbScope:
        return cls("product", product_id)

    @classmethod
    def tenant(cls, product_id: str, tenant_id: str) -> DbScope:
        return cls("tenant", product_id, tenant_id)


Row = dict[str, Any]


Params = Sequence[Any] | dict[str, Any] | None
_SET_SCOPE_SQL = (
    "SELECT set_config('axentra.scope', %s, true), set_config('axentra.product_id', %s, true),"
    " set_config('axentra.tenant_id', %s, true)"
)


class Tx:
    """A transaction bound to one scope; thin helpers over a psycopg connection.

    Rows are always returned as dicts (each query uses a ``dict_row`` cursor), whatever row
    factory the connection itself has, so a :class:`Tx` also works on a connection of the host
    application (:func:`join`)."""

    def __init__(self, conn: psycopg.Connection[Any], scope: DbScope) -> None:
        self.conn = conn
        self.scope = scope

    def execute(self, sql: str, params: Params = None) -> int:
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.rowcount

    def one(self, sql: str, params: Params = None) -> Row | None:
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def one_or_404(
        self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None, what: str = "resource"
    ) -> Row:
        row = self.one(sql, params)
        if row is None:
            raise NotFound(f"{what} not found")
        return row

    def all(self, sql: str, params: Params = None) -> list[Row]:
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    def scalar(self, sql: str, params: Params = None) -> Any:
        row = self.one(sql, params)
        return None if row is None else next(iter(row.values()))

    def require_scope(self, product_id: str, tenant_id: str | None = None) -> None:
        """Refuse a transaction whose scope cannot reach the given product (and tenant)."""
        sc = self.scope
        if sc.kind == "platform":
            return
        if sc.product_id != product_id or (sc.kind == "tenant" and sc.tenant_id != tenant_id):
            raise ConfigurationError(
                f"the transaction scope ({sc.kind}) does not cover product {product_id}"
                + (f" and tenant {tenant_id}" if tenant_id else "")
            )


_ScopeValues = tuple[str, str, str]


def _values(scope: DbScope) -> _ScopeValues:
    return (scope.kind, scope.product_id or "", scope.tenant_id or "")


def _require_open_transaction(conn: psycopg.Connection[Any]) -> None:
    status = conn.info.transaction_status
    if status != pq.TransactionStatus.INTRANS:
        raise ConfigurationError(
            "Axentra can only join an open transaction (begin one first; the connection's"
            f" transaction status is {status.name})"
        )


def _read_scope(conn: psycopg.Connection[Any]) -> _ScopeValues:
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute(
            "SELECT current_setting('axentra.scope', true), current_setting('axentra.product_id', true),"
            " current_setting('axentra.tenant_id', true)"
        )
        row = cur.fetchone()
    return (row[0] or "", row[1] or "", row[2] or "") if row else ("", "", "")


def _set_scope(conn: psycopg.Connection[Any], values: _ScopeValues) -> None:
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute(_SET_SCOPE_SQL, values)


@contextmanager
def join(conn: psycopg.Connection[Any], scope: DbScope) -> Iterator[Tx]:
    """Run Axentra writes inside a transaction the host application already opened.

    ``conn`` is the host's own psycopg connection to the Axentra database; it must be inside a
    transaction block (``conn.info.transaction_status`` is ``INTRANS``): either ``with
    conn.transaction():`` on a non-autocommit or autocommit connection, an explicit ``BEGIN`` on
    an autocommit connection, or an implicit transaction of a non-autocommit connection that has
    already executed a statement. Anything else (idle, failed, or no connection) is refused with
    :class:`~axentra.core.errors.ConfigurationError`, because Axentra's writes would otherwise
    commit on their own.

    The scope is written with ``set_config(..., true)`` (transaction-local); the values that were
    set before are restored when the block ends normally, so the rest of the host transaction
    (and a nested :func:`join`) keeps its own scope. Axentra never commits or rolls back the
    joined transaction: the host does, and everything written through the yielded :class:`Tx`
    (audit events, usage events, ...) commits or rolls back with the host's own changes.

    To call whole Axentra services (which open their own transactions) inside the host
    transaction, use :meth:`Database.joined` instead.
    """
    _require_open_transaction(conn)
    prev = _read_scope(conn)
    _set_scope(conn, _values(scope))
    yield Tx(conn, scope)
    if conn.info.transaction_status == pq.TransactionStatus.INTRANS:
        _set_scope(conn, prev)


class _Joined(threading.local):
    """Per-thread state of :meth:`Database.joined`."""

    def __init__(self) -> None:
        self.conn: psycopg.Connection[Any] | None = None
        #: The host's own scope values when it joined, restored when the block ends.
        self.host: _ScopeValues = ("", "", "")


class Database:
    """The connection pool of Axentra's services and their scoped transactions.

    By default Axentra owns a pool built from ``url``. A host application that already has a
    ``psycopg_pool.ConnectionPool`` to the same database can hand it in instead
    (:meth:`on_pool`), so the process keeps **one** connection budget: Axentra then borrows
    connections from it, never opens, resizes or closes it, and works with whatever the host's
    connections are configured with (autocommit or not, any row factory; see :meth:`on_pool`).
    """

    def __init__(
        self,
        url: str = "",
        *,
        min_size: int = 1,
        max_size: int = 10,
        statement_timeout_ms: int = 30_000,
        pool: Any = None,
    ) -> None:
        self._timeout = statement_timeout_ms
        self._joined = _Joined()
        if pool is not None:
            #: A borrowed pool (:meth:`on_pool`): the host opens and closes it.
            self.owns_pool = False
            self.pool = pool
            self.url = url or str(getattr(pool, "conninfo", "") or "")
            return
        self.owns_pool = True
        self.url = url
        self.pool = ConnectionPool(
            url,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": dict_row, "autocommit": False},
            configure=self._configure,
            check=ConnectionPool.check_connection,
            open=False,
            name="axentra",
        )

    @classmethod
    def on_pool(cls, pool: Any, *, url: str = "") -> Database:
        """Axentra's database on a pool the host application owns (one pool per process).

        ``pool`` is a ``psycopg_pool.ConnectionPool`` or any object with the same
        ``connection(timeout=None)`` context manager (and optionally ``get_stats()`` for the pool
        metrics). The host keeps every decision about its connections:

        - connections may be ``autocommit=True`` or not, with any row factory: every Axentra
          transaction is an explicit transaction block (``conn.transaction()``) and every query
          reads dict rows from its own cursor;
        - the host configures the session (``statement_timeout``, ``search_path``) of each new
          connection; Axentra sets nothing at session level, only transaction-local scope
          settings (``set_config(..., true)``), which end with the transaction, so a connection
          handed back to the host carries no Axentra scope;
        - :meth:`open` and :meth:`close` do nothing; the host opens the pool before
          ``Axentra.start()`` and closes it after ``Axentra.close()``;
        - ``url`` (default: the pool's ``conninfo``) is used only by components that need a
          dedicated connection of their own (``LISTEN``, the job worker's advisory lock).

        Size the pool for both: each request or job holds at most one connection at a time on a
        joined host transaction (:meth:`joined`); an Axentra service call made outside one takes
        its own.
        """
        return cls(url, pool=pool)

    def _configure(self, conn: psycopg.Connection[Row]) -> None:
        conn.execute("SELECT set_config('statement_timeout', %s, false)", (str(self._timeout),))
        conn.commit()

    def open(self, wait: bool = True, timeout: float = 30.0) -> None:
        if self.owns_pool:
            self.pool.open(wait=wait, timeout=timeout)

    def close(self) -> None:
        if self.owns_pool:
            self.pool.close()

    @contextmanager
    def joined(self, conn: psycopg.Connection[Any]) -> Iterator[None]:
        """Route this thread's Axentra transactions into the host application's transaction.

        While the block is active, every :meth:`transaction` opened **on the calling thread**
        (so every service call made from it) runs on ``conn`` inside a savepoint instead of on a
        pooled connection; other threads keep using the pool. ``conn`` must be inside a
        transaction block (see :func:`join`). Each Axentra transaction:

        - sets its scope with ``set_config(..., true)``; when it ends, the scope that was active
          before it is set again (the enclosing Axentra transaction's, a :func:`join` scope the
          host opened inside this block, or the host's own values);
        - returns dict rows whatever the connection's row factory;
        - ignores ``read_only`` (``SET TRANSACTION READ ONLY`` cannot be issued mid-transaction);
        - on an exception, rolls back to its savepoint and re-raises: the host transaction and
          the host's earlier writes stay intact and usable;
        - never commits or rolls back the host transaction: the host's COMMIT or ROLLBACK decides
          for Axentra's writes as well.

        Reads by services see the host's uncommitted changes. Work Axentra hands to other
        threads or processes (job workers, webhooks) only sees the rows after the host commits.
        """
        state = self._joined
        if state.conn is not None:
            if state.conn is not conn:
                raise ConfigurationError("this thread already joined another connection")
            yield
            return
        _require_open_transaction(conn)
        state.conn = conn
        state.host = _read_scope(conn)
        try:
            yield
        finally:
            host = state.host
            state.conn = None
            state.host = ("", "", "")
            if conn.info.transaction_status == pq.TransactionStatus.INTRANS:
                _set_scope(conn, host)

    @property
    def joined_connection(self) -> psycopg.Connection[Any] | None:
        """The host connection joined on this thread (:meth:`joined`), if any."""
        return self._joined.conn

    @contextmanager
    def transaction(self, scope: DbScope, *, read_only: bool = False) -> Iterator[Tx]:
        state = self._joined
        if state.conn is not None:
            conn = state.conn
            _require_open_transaction(conn)
            # The scope in effect right now, read from the connection (not remembered): the host
            # may have set one with join() inside joined(), or the enclosing Axentra transaction's.
            outer = _read_scope(conn)
            try:
                with conn.transaction():  # a savepoint inside the host transaction
                    _set_scope(conn, _values(scope))
                    yield Tx(conn, scope)
            finally:
                if conn.info.transaction_status == pq.TransactionStatus.INTRANS:
                    _set_scope(conn, outer)
            return
        with self.pool.connection() as conn, conn.transaction():
            # conn.transaction() is a BEGIN/COMMIT block on autocommit connections (a borrowed
            # pool) and on the implicit transaction otherwise: the scope is transaction-local in
            # both cases.
            with conn.cursor(row_factory=tuple_row) as cur:
                if read_only:
                    cur.execute("SET TRANSACTION READ ONLY")
                cur.execute(_SET_SCOPE_SQL, _values(scope))
            yield Tx(conn, scope)

    def ping(self) -> bool:
        try:
            with self.pool.connection(timeout=5) as conn:
                conn.execute("SELECT 1")
                if not conn.autocommit:
                    conn.rollback()
            return True
        except Exception:
            logger.warning("database ping failed", exc_info=True)
            return False

    def role_info(self) -> dict[str, bool]:
        """How row-level security applies to the role of this pool's connections.

        - ``superuser`` / ``bypass_rls``: the role ignores every policy;
        - ``table_owner``: the role owns (or may act as the owner of) a table with row-level
          security in its ``search_path``. FORCE ROW LEVEL SECURITY still applies to it, but an
          owner can switch it off (``ALTER TABLE ... NO FORCE / DISABLE ROW LEVEL SECURITY``) or
          drop the table, so a runtime role should not own the tables (run migrations with a
          separate owner role, ``database.migration_url_ref``).

        Each flag also holds when the role can become such a role through role membership (``tabrion.postgres.role_info``
        with ``owner_scope="rls"``, contract I-20; TABRION MIG-AXE-6). Read-only: on a connection without
        autocommit the implicit transaction is rolled back, on a borrowed pool too.
        """
        with self.pool.connection() as conn:
            info = _tabrion_role_info(conn, owner_scope="rls")
        return {"superuser": info.superuser, "bypass_rls": info.bypass_rls, "table_owner": info.table_owner}

    def check_role(self, *, allow_superuser: bool, allow_table_owner: bool = True) -> dict[str, bool]:
        """Verify that row-level security applies to the application role (see :meth:`role_info`).

        Refuses a superuser or ``BYPASSRLS`` role unless ``allow_superuser``, and a role that owns
        protected tables unless ``allow_table_owner`` (the default of this method; ``Axentra.start()``
        passes ``Settings.table_owner_allowed``, which is ``False`` in production unless
        ``database.allow_table_owner = true``)."""
        info = self.role_info()
        if (info["superuser"] or info["bypass_rls"]) and not allow_superuser:
            raise ConfigurationError(
                "the database role bypasses row-level security (superuser or BYPASSRLS); use a dedicated "
                "application role or set database.allow_superuser = true for local development only"
            )
        if info["table_owner"] and not (allow_table_owner or allow_superuser):
            raise ConfigurationError(
                "the database role owns tables protected by row-level security and could switch it off; run "
                "migrations with a separate owner role (database.migration_url_ref) and use a role without "
                "ownership at runtime, or set database.allow_table_owner = true"
            )
        return info
