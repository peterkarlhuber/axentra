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

Since TABRION MIG-AXE-6 this module is a shim over ``tabrion.postgres`` (``inspect_role``, ``grant_runtime_role``):
the grants and the refusals are Tabrion's, the report (:class:`RoleReport`, ``as_dict()``) and the error texts stay
Axentra's. Tabrion's check is stricter than the one it replaces (contract I-20): a role is as privileged as every
role it can become through role membership, so a member of a superuser or ``BYPASSRLS`` role, and a role that can become
the owner role or the schema's owner, is refused too.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg.rows import tuple_row
from tabrion.errors import RoleMissing, RoleUnsafe, UsageError
from tabrion.postgres import grant_runtime_role as _tabrion_grant_runtime_role
from tabrion.postgres import inspect_role as _tabrion_inspect_role

from axentra.core.errors import ConfigurationError

#: Privileges of the runtime role: data, never DDL (granted by ``tabrion.postgres.grant_runtime_role``).
TABLE_PRIVILEGES = "SELECT, INSERT, UPDATE, DELETE"
SEQUENCE_PRIVILEGES = "USAGE, SELECT"
#: The migration bookkeeping stays read-only for the runtime role.
PROTECTED_TABLES = ("axentra_schema_migrations",)


@dataclass(frozen=True, slots=True)
class RoleReport:
    """What :func:`grant_runtime_role` did and how row-level security applies to the role."""

    role: str
    schema: str
    owner: str
    tables: int
    #: Whether the role may connect to the database (granted here when the owner may grant it).
    connect: bool
    #: The role is a superuser or can become one (role membership).
    superuser: bool = False
    #: The role has ``BYPASSRLS`` or can become a role that has it (role membership).
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


def _report(found: Any) -> RoleReport:
    """Axentra's report from ``tabrion.postgres.RoleReport`` (the same fields, without ``database``)."""
    return RoleReport(
        role=found.role,
        schema=found.schema,
        owner=found.owner,
        tables=found.tables,
        connect=found.connect,
        superuser=found.superuser,
        bypass_rls=found.bypass_rls,
        owned_tables=list(found.owned_tables),
        can_create=found.can_create,
    )


def _missing(role: str) -> ConfigurationError:
    return ConfigurationError(f"the database role {role!r} does not exist")


def inspect_role(conn: psycopg.Connection[Any], role: str, schema: str | None = None) -> RoleReport:
    """How row-level security applies to ``role`` in ``schema`` (default: the current schema). Read-only.

    ``superuser`` and ``bypass_rls`` also hold when the role can become such a role (role membership)."""
    try:
        return _report(_tabrion_inspect_role(conn, role, schema=schema))
    except RoleMissing:
        raise _missing(role) from None


def _refusal(
    conn: psycopg.Connection[Any], role: str, schema: str | None, reasons: list[str]
) -> ConfigurationError:
    """The error text of a refused grant: Axentra's texts, and new ones for what only Tabrion refuses."""
    before = inspect_role(conn, role, schema)
    if role == before.owner:
        return ConfigurationError(f"{role!r} is the connecting (owner) role; name the separate runtime role")
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute("SELECT rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = %s", (role,))
        direct = cur.fetchone() or (False, False)
    if not conn.autocommit:
        conn.rollback()
    texts: list[str] = []
    if "superuser" in reasons:
        texts.append("is a superuser" if direct[0] else "can become a superuser (role membership)")
    if "bypass_rls" in reasons and not (direct[0] and not direct[1]):
        # A superuser is a member of every role, also of the BYPASSRLS ones: "is a superuser" says it all.
        texts.append("has BYPASSRLS" if direct[1] else "can become a role with BYPASSRLS (role membership)")
    if "table_owner" in reasons:
        if before.owned_tables:
            texts.append(f"owns tables ({', '.join(before.owned_tables[:5])})")
        else:
            texts.append("can become the owner role or the owner of the schema (role membership)")
    return ConfigurationError(
        f"the runtime role {role!r} {' and '.join(texts)}: row-level security would not apply to it"
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
    after the first ``axentra migrate``. Idempotent. The grants are ``tabrion.postgres.grant_runtime_role``'s;
    a connection handed in must not be inside a transaction.

    Refused (:class:`~axentra.core.errors.ConfigurationError`, nothing granted) when ``role`` is the
    connecting role itself, a superuser, has ``BYPASSRLS``, or owns tables of the schema, or can become such a role
    (role membership) or the owner of the schema: row-level security would not protect anything for it.
    """
    own = isinstance(url_or_conn, str)
    conn = psycopg.connect(url_or_conn, autocommit=True) if isinstance(url_or_conn, str) else url_or_conn
    try:
        try:
            return _report(
                _tabrion_grant_runtime_role(conn, role, schema=schema, protected_tables=PROTECTED_TABLES)
            )
        except RoleMissing:
            raise _missing(role) from None
        except RoleUnsafe as exc:
            reasons = str((exc.details or {}).get("reasons", "")).split(",")
            raise _refusal(conn, role, schema, reasons) from None
        except UsageError as exc:
            if exc.code == "postgres.schema_missing":
                raise ConfigurationError(f"the schema {schema!r} does not exist") from None
            raise
    finally:
        if own:
            conn.close()


__all__ = ["RoleReport", "grant_runtime_role", "inspect_role"]
