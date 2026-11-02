"""Database roles: grant a restricted runtime role access to the schema the owner role migrates.

Row-level security is defense in depth only when the role the application runs as

- is not a superuser and has no ``BYPASSRLS`` (both ignore every policy), and
- does not own the protected tables: an owner is subject to ``FORCE ROW LEVEL SECURITY``, but may
  switch it off (``ALTER TABLE ... NO FORCE ROW LEVEL SECURITY``), drop the table or change its
  policies.

So a deployment uses two roles: an **owner** role that owns the schema and runs ``axentra
migrate`` (``database.migration_url_ref``), and a **runtime** role with data privileges only
(``database.url_ref``). :func:`grant_runtime_role` gives the runtime role exactly those privileges
on everything the owner has created and will create in the schema (default privileges), so new
migrations need no new grants. It is idempotent and runs as the owner role
(``axentra db grant-runtime-role ROLE``); ``deploy/compose/initdb/01-roles.sql`` does the same for a
new database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import tuple_row

from axentra.core.errors import ConfigurationError

#: Privileges of the runtime role: data, never DDL.
TABLE_PRIVILEGES = "SELECT, INSERT, UPDATE, DELETE"
SEQUENCE_PRIVILEGES = "USAGE, SELECT"


@dataclass(frozen=True, slots=True)
class RoleReport:
    """What :func:`grant_runtime_role` did and how row-level security applies to the role."""

    role: str
    schema: str
    owner: str
    tables: int
    #: Whether the role may connect to the database (granted here when the owner may grant it).
    connect: bool
    superuser: bool = False
    bypass_rls: bool = False
    #: Tables of the schema the role owns (or may act as the owner of).
    owned_tables: list[str] = field(default_factory=list)
    #: The role may create objects in the schema (not needed at runtime; revoke it if you can).
    can_create: bool = False

    @property
    def restricted(self) -> bool:
        """True when row-level security fully applies to the role."""
        return not (self.superuser or self.bypass_rls or self.owned_tables)

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "schema": self.schema,
            "owner": self.owner,
            "tables": self.tables,
            "connect": self.connect,
            "superuser": self.superuser,
            "bypass_rls": self.bypass_rls,
            "owned_tables": self.owned_tables,
            "can_create": self.can_create,
            "restricted": self.restricted,
        }


def inspect_role(conn: psycopg.Connection[Any], role: str, schema: str | None = None) -> RoleReport:
    """How row-level security applies to ``role`` in ``schema`` (default: the current schema). Read-only."""
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute("SELECT current_user, coalesce(%s, current_schema())", (schema,))
        owner, schema_name = cur.fetchone() or ("", "")
        cur.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = %s", (role,))
        attrs = cur.fetchone()
        if attrs is None:
            raise ConfigurationError(f"the database role {role!r} does not exist")
        cur.execute(
            "SELECT c.relname, pg_has_role(%s, c.relowner, 'MEMBER') FROM pg_class c"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = %s AND c.relkind IN ('r', 'p') ORDER BY c.relname",
            (role, schema_name),
        )
        tables = cur.fetchall()
        cur.execute(
            "SELECT has_database_privilege(%s, current_database(), 'CONNECT'),"
            " has_schema_privilege(%s, %s, 'CREATE')",
            (role, role, schema_name),
        )
        connect, create = cur.fetchone() or (False, False)
    return RoleReport(
        role=role,
        schema=str(schema_name),
        owner=str(owner),
        tables=len(tables),
        connect=bool(connect),
        superuser=bool(attrs[0]),
        bypass_rls=bool(attrs[1]),
        owned_tables=[str(name) for name, owned in tables if owned],
        can_create=bool(create),
    )


def grant_runtime_role(
    url_or_conn: str | psycopg.Connection[Any], role: str, *, schema: str | None = None
) -> RoleReport:
    """Grant ``role`` data access (no DDL) to the schema, now and for what the connecting role creates later.

    Run it as the **owner** role (the role that runs migrations): it grants ``USAGE`` on the schema,
    ``SELECT, INSERT, UPDATE, DELETE`` on every table, ``USAGE, SELECT`` on every sequence and
    ``EXECUTE`` on every function of the schema, sets the same as default privileges of the owner
    role in the schema, and ``CONNECT`` on the database when the owner may grant it. The migration
    bookkeeping (``axentra_schema_migrations``) stays read-only for the runtime role: run this again
    after the first ``axentra migrate``. Idempotent.

    Refused (:class:`~axentra.core.errors.ConfigurationError`, nothing granted) when ``role`` is the
    connecting role itself, a superuser, has ``BYPASSRLS``, or owns tables of the schema: row-level
    security would not protect anything for it.
    """
    own = isinstance(url_or_conn, str)
    conn = psycopg.connect(url_or_conn, autocommit=True) if isinstance(url_or_conn, str) else url_or_conn
    try:
        before = inspect_role(conn, role, schema)
        if role == before.owner:
            raise ConfigurationError(
                f"{role!r} is the connecting (owner) role; name the separate runtime role"
            )
        if not before.restricted:
            reasons = [
                reason
                for reason, flag in (
                    ("is a superuser", before.superuser),
                    ("has BYPASSRLS", before.bypass_rls),
                    (f"owns tables ({', '.join(before.owned_tables[:5])})", bool(before.owned_tables)),
                )
                if flag
            ]
            raise ConfigurationError(
                f"the runtime role {role!r} {' and '.join(reasons)}: row-level security would not apply to it"
            )
        target = sql.Identifier(role)
        nsp = sql.Identifier(before.schema)
        with conn.transaction():
            for statement in (
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}"),
                sql.SQL("GRANT " + TABLE_PRIVILEGES + " ON ALL TABLES IN SCHEMA {} TO {}"),
                sql.SQL("GRANT " + SEQUENCE_PRIVILEGES + " ON ALL SEQUENCES IN SCHEMA {} TO {}"),
                sql.SQL("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {} TO {}"),
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT " + TABLE_PRIVILEGES + " ON TABLES TO {}"
                ),
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT "
                    + SEQUENCE_PRIVILEGES
                    + " ON SEQUENCES TO {}"
                ),
                sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT EXECUTE ON FUNCTIONS TO {}"),
            ):
                conn.execute(statement.format(nsp, target))
            # The migration bookkeeping is the owner's: the runtime role may read it (schema gate), never fake it.
            row = conn.execute(
                "SELECT to_regclass(format('%%I.%%I', %s::text, 'axentra_schema_migrations')) IS NOT NULL",
                (before.schema,),
            ).fetchone()
            if row and row[0]:
                conn.execute(
                    sql.SQL(
                        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON {}.axentra_schema_migrations FROM {}"
                    ).format(nsp, target)
                )
        if not before.connect:
            try:
                with conn.transaction():
                    conn.execute(
                        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                            sql.Identifier(str(conn.info.dbname)), target
                        )
                    )
            except psycopg.errors.InsufficientPrivilege:
                pass  # reported: connect=False; the database owner grants it
        return inspect_role(conn, role, before.schema)
    finally:
        if own:
            conn.close()


__all__ = ["RoleReport", "grant_runtime_role", "inspect_role"]
