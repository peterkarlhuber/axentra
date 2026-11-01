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
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import logging
from typing import Any, Literal

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

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


class Tx:
    """A transaction bound to one scope; thin helpers over a psycopg connection."""

    def __init__(self, conn: psycopg.Connection[Row], scope: DbScope) -> None:
        self.conn = conn
        self.scope = scope

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> int:
        cur = self.conn.execute(sql, params)
        return cur.rowcount

    def one(self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> Row | None:
        cur = self.conn.execute(sql, params)
        return cur.fetchone()

    def one_or_404(
        self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None, what: str = "resource"
    ) -> Row:
        row = self.one(sql, params)
        if row is None:
            raise NotFound(f"{what} not found")
        return row

    def all(self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> list[Row]:
        cur = self.conn.execute(sql, params)
        return cur.fetchall()

    def scalar(self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> Any:
        row = self.one(sql, params)
        return None if row is None else next(iter(row.values()))


class Database:
    def __init__(
        self, url: str, *, min_size: int = 1, max_size: int = 10, statement_timeout_ms: int = 30_000
    ) -> None:
        self.url = url
        self._timeout = statement_timeout_ms
        self.pool: ConnectionPool[psycopg.Connection[Row]] = ConnectionPool(
            url,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": dict_row, "autocommit": False},
            configure=self._configure,
            check=ConnectionPool.check_connection,
            open=False,
            name="axentra",
        )

    def _configure(self, conn: psycopg.Connection[Row]) -> None:
        conn.execute("SELECT set_config('statement_timeout', %s, false)", (str(self._timeout),))
        conn.commit()

    def open(self, wait: bool = True, timeout: float = 30.0) -> None:
        self.pool.open(wait=wait, timeout=timeout)

    def close(self) -> None:
        self.pool.close()

    @contextmanager
    def transaction(self, scope: DbScope, *, read_only: bool = False) -> Iterator[Tx]:
        with self.pool.connection() as conn, conn.transaction():
            if read_only:
                conn.execute("SET TRANSACTION READ ONLY")
            conn.execute(
                "SELECT set_config('axentra.scope', %s, true), set_config('axentra.product_id', %s, true),"
                " set_config('axentra.tenant_id', %s, true)",
                (scope.kind, scope.product_id or "", scope.tenant_id or ""),
            )
            yield Tx(conn, scope)

    def ping(self) -> bool:
        try:
            with self.pool.connection(timeout=5) as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            logger.warning("database ping failed", exc_info=True)
            return False

    def check_role(self, *, allow_superuser: bool) -> dict[str, bool]:
        """Verify that row-level security applies to the application role."""
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            ).fetchone()
            conn.rollback()
        info = {"superuser": bool(row and row["rolsuper"]), "bypass_rls": bool(row and row["rolbypassrls"])}
        if (info["superuser"] or info["bypass_rls"]) and not allow_superuser:
            raise ConfigurationError(
                "the database role bypasses row-level security (superuser or BYPASSRLS); use a dedicated "
                "application role or set database.allow_superuser = true for local development only"
            )
        return info
