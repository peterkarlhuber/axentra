"""Snapshot tools for rollback evidence (TABRION QA-13): what a migration step of the Tabrion adoption must keep.

Each TABRION MIG-AXE step (document 06 of the Tabrion plan) replaces a generic piece of Axentra with Tabrion's and must
leave the security guarantees unchanged (document 07, section 8; document 11, section 3.1). These tools write the
"before" picture from the old code, so a step (and its revert) can show that nothing changed:

``catalog``
    Row-level security per table (``relrowsecurity``, ``relforcerowsecurity``), every policy, the runtime role's
    privileges after ``grant_runtime_role`` (tables, sequences, functions, schema, database, default privileges),
    every access control entry of the schema's objects (``aclexplode`` of ``relacl``, ``attacl``, ``proacl``,
    ``nspacl``, ``datacl``: grantor, grantee including ``PUBLIC`` and other roles, privilege, ``is_grantable``) and
    the role memberships of the owner and runtime roles.
``roles``
    The role decision table: eight role variants through ``inspect_role``, ``grant_runtime_role``,
    ``Database.role_info`` and ``Database.check_role`` (decision, error class, code and message).
``problems``
    The problem details of every ``AxentraError`` class and of other exceptions (``problem_details``), the HTTP
    answers of the API's error handlers for a fixed set of requests, and the OpenAPI ``Problem`` schemas.
``settings``
    The ``SHOW`` extract: the session settings each kind of connection runs with (owned pool, read-only transaction,
    borrowed pool ``on_pool``, ``joined``, ``join``, the scheduler's leader lock, after ``ping``), as the difference to
    a plain connection of the same role, plus the scope settings inside and after each transaction.
``schema``
    A schema dump from the catalog (columns, constraints, indexes, triggers, functions, applied migrations), with
    no server version or dump-format details, so it compares across PostgreSQL 15 to 17.

Every run creates its own database and roles (names start with ``--prefix``, ``[a-z][a-z0-9_]{0,19}``; the login
roles get a random password per run, never a fixed one), migrates it as a separate owner role,
grants a runtime role as a production deployment does (``axentra db grant-runtime-role``), collects the snapshots and
drops the database and roles again. Names of these objects are written as placeholders (``<owner>``, ``<app>``,
``<role:superuser>``, ``<database>``), and ids as ``<uuid>`` or ``<prd_id>`` (request ids ``<req_id>``), so two runs write
identical files (``tests/integration/test_rollback_snapshots.py`` checks both that and the golden files).

The golden files in ``tests/evidence/golden/`` are the snapshots of the old code (the commit is named in
``tests/evidence/golden/SOURCE.md``). Usage, from the repository root with the dev dependencies installed and a
superuser URL::

    python -m tests.evidence.snapshots --url postgresql://postgres:pg@127.0.0.1:5432/postgres check
    python -m tests.evidence.snapshots --url ... write            # rewrite the golden files
    python -m tests.evidence.snapshots --url ... write --dir out  # write elsewhere (e.g. the old SHA's checkout)

``check`` prints a unified diff per snapshot that differs and exits with 1. A run that was killed (SIGKILL, CI
timeout) cannot drop its objects; ``check`` and ``write`` report such leftovers of the same prefix first, and::

    python -m tests.evidence.snapshots --url ... cleanup          # drop leftovers of crashed runs (own prefix only)

drops them. ``cleanup`` matches only the exact names a run creates (``<prefix><8 hex>``, ``..._owner``, ``..._app``,
``..._v_<variant>``), so it never touches another object; do not run it while another run with the same prefix
is still going. A step that changes a snapshot on
purpose rewrites the golden file in the same pull request, so the diff is reviewed; a new migration does the same
(it adds tables and policies).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
import difflib
import json
from pathlib import Path
import re
import secrets
import sys
import tempfile
from typing import Any
import uuid

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import tuple_row

GOLDEN = Path(__file__).resolve().parent / "golden"
NAMES = ("catalog", "roles", "problems", "settings", "schema")
DEFAULT_PREFIX = "axentra_ev_"
#: Allowed prefixes: short enough that no generated name exceeds PostgreSQL's 63 bytes (L-2 of the QA-13 review).
_PREFIX = re.compile(r"[a-z][a-z0-9_]{0,19}")
#: The platform admin's password of the HTTP snapshot (the password policy refuses simple ones).
PASS_PHRASE = "correct horse battery staple"
#: The scope every transaction of the settings snapshot runs with (any ids: no row is read).
PRODUCT_ID = "00000000-0000-4000-8000-000000000001"
TENANT_ID = "00000000-0000-4000-8000-000000000002"
#: The scope settings Axentra writes with ``set_config(..., true)``.
SCOPE_SETTINGS = ("axentra.scope", "axentra.product_id", "axentra.tenant_id")
#: The role variants of the decision table (document 07, AX-I-5: eight variants).
ROLE_VARIANTS = (
    "restricted",
    "superuser",
    "bypass_rls",
    "superuser_bypass_rls",
    "table_owner",
    "owner_member",
    "connecting_owner",
    "missing",
)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
#: Axentra's prefixed ids (``prd_01m6...``) and request ids.
_PREFIXED_ID = re.compile(r"\b([a-z]{2,6})_[0-9a-z]{26}\b")


def validate_prefix(prefix: str) -> str:
    """``prefix`` when it is a valid run prefix, else :class:`ValueError`."""
    if not _PREFIX.fullmatch(prefix):
        raise ValueError(f"invalid prefix {prefix!r}: expected [a-z][a-z0-9_]{{0,19}}")
    return prefix


def _run_names(prefix: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """The exact database and role names a run with ``prefix`` creates."""
    base = re.escape(prefix) + r"[0-9a-f]{8}"
    variants = "|".join(re.escape(v) for v in ROLE_VARIANTS)
    return re.compile(base), re.compile(base + rf"_(?:owner|app|v_(?:{variants}))")


def leftovers(admin_url: str, prefix: str = DEFAULT_PREFIX, bases: list[str] | None = None) -> list[str]:
    """Databases and roles of runs with ``prefix`` that still exist (only those of ``bases`` when given)."""
    database_name, role_name = _run_names(validate_prefix(prefix))
    with psycopg.connect(admin_url, autocommit=True) as conn:
        found = [
            f"database {r[0]}"
            for r in _rows(conn, "SELECT datname::text FROM pg_database")
            if database_name.fullmatch(r[0])
        ]
        found += [
            f"role {r[0]}"
            for r in _rows(conn, "SELECT rolname::text FROM pg_roles")
            if role_name.fullmatch(r[0])
        ]
    if bases is not None:
        found = [item for item in found if any(item.split(" ", 1)[1].startswith(b) for b in bases)]
    return sorted(found)


def cleanup(admin_url: str, prefix: str = DEFAULT_PREFIX) -> list[str]:
    """Drop the leftovers of crashed runs with ``prefix`` (databases first, then roles); what was dropped."""
    left = leftovers(admin_url, prefix)
    with psycopg.connect(admin_url, autocommit=True) as conn:
        for item in left:
            kind, name = item.split(" ", 1)
            if kind == "database":
                conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))
        for item in left:
            kind, name = item.split(" ", 1)
            if kind == "role":
                conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))
    return left


def with_db(url: str, dbname: str, user: str | None = None, password: str | None = None) -> str:
    """``url`` with another database (and user)."""
    params = conninfo_to_dict(url)
    params["dbname"] = dbname
    if user:
        params["user"] = user
        params["password"] = password
    return make_conninfo(**params)


@dataclass
class EvidenceDatabase:
    """A migrated database of its own, with a separate owner role and a granted runtime role."""

    admin_url: str
    base: str
    #: The password of every login role of this run: random per run, never stored (M-2 of the QA-13 review).
    password: str = field(default_factory=lambda: secrets.token_urlsafe(24), repr=False)
    #: Placeholder for every name of this run, longest first (see :meth:`normalize`).
    names: dict[str, str] = field(default_factory=dict)

    @property
    def dbname(self) -> str:
        return self.base

    @property
    def owner(self) -> str:
        return f"{self.base}_owner"

    @property
    def app(self) -> str:
        return f"{self.base}_app"

    def variant(self, name: str) -> str:
        return f"{self.base}_v_{name}"

    def url(self, role: str | None = None) -> str:
        """The URL of this database as ``role`` (default: the admin's user)."""
        return with_db(self.admin_url, self.dbname, role, self.password if role else None)

    def normalize(self, value: Any) -> Any:
        """``value`` with this run's names, ids and request ids replaced by placeholders."""
        if isinstance(value, str):
            for name, placeholder in sorted(self.names.items(), key=lambda item: -len(item[0])):
                value = value.replace(name, placeholder)
            return _PREFIXED_ID.sub(lambda m: f"<{m.group(1)}_id>", _UUID.sub("<uuid>", value))
        if isinstance(value, dict):
            return {self.normalize(k): self.normalize(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self.normalize(v) for v in value]
        return value


@contextmanager
def evidence_database(
    admin_url: str, prefix: str = DEFAULT_PREFIX, bases: list[str] | None = None
) -> Iterator[EvidenceDatabase]:
    """Create, migrate and grant a database of its own; drop it and its roles afterwards.

    The run's base name is appended to ``bases`` when given (the tests check that nothing of it is left).
    """
    from axentra.data.migrations import MigrationRunner
    from axentra.data.roles import grant_runtime_role

    ev = EvidenceDatabase(admin_url, f"{validate_prefix(prefix)}{uuid.uuid4().hex[:8]}")
    if bases is not None:
        bases.append(ev.base)
    ev.names = {ev.owner: "<owner>", ev.app: "<app>", ev.dbname: "<database>"}
    ev.names.update({ev.variant(v): f"<role:{v}>" for v in ROLE_VARIANTS})
    ev.names[f"{ev.base}_owned"] = "<owned_table>"
    ev.names.update({PRODUCT_ID: "<product_id>", TENANT_ID: "<tenant_id>"})
    roles = [ev.owner, ev.app]
    try:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            for role in roles:
                conn.execute(
                    sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(ev.password)
                    )
                )
            conn.execute(
                sql.SQL("CREATE DATABASE {} OWNER {}").format(
                    sql.Identifier(ev.dbname), sql.Identifier(ev.owner)
                )
            )
        with psycopg.connect(ev.url(), autocommit=True) as conn:
            conn.execute(sql.SQL("ALTER SCHEMA public OWNER TO {}").format(sql.Identifier(ev.owner)))
            conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        MigrationRunner(ev.url(ev.owner)).migrate()
        report = grant_runtime_role(ev.url(ev.owner), ev.app)
        if not report.restricted:
            raise RuntimeError(f"the runtime role is not restricted: {report}")
        yield ev
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(ev.dbname)))
            for role in [*roles, *(ev.variant(v) for v in ROLE_VARIANTS)]:
                conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def _rows(conn: psycopg.Connection[Any], query: str, params: Any = None) -> list[tuple[Any, ...]]:
    return list(conn.execute(query, params).fetchall())


# -- catalog ------------------------------------------------------------------------------------------------------


def catalog_snapshot(ev: EvidenceDatabase) -> dict[str, Any]:
    """Row-level security, policies and the runtime role's privileges (read as the admin)."""
    app = ev.app
    with psycopg.connect(ev.url(), autocommit=True) as conn:
        tables = []
        for name, kind, rls, force, owner, oid in _rows(
            conn,
            "SELECT c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner), c.oid"
            " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') ORDER BY c.relname",
        ):
            privileges = [
                p
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
                if _rows(conn, "SELECT has_table_privilege(%s, %s::oid, %s)", (app, oid, p))[0][0]
            ]
            tables.append(
                {
                    "table": name,
                    "kind": kind,
                    "row_security": rls,
                    "force_row_security": force,
                    "owner": owner,
                    "app_privileges": privileges,
                }
            )
        sequences = [
            {
                "sequence": name,
                "app_privileges": [
                    p
                    for p in ("USAGE", "SELECT", "UPDATE")
                    if _rows(conn, "SELECT has_sequence_privilege(%s, %s::oid, %s)", (app, oid, p))[0][0]
                ],
            }
            for name, oid in _rows(
                conn,
                "SELECT c.relname, c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname = 'public' AND c.relkind = 'S' ORDER BY c.relname",
            )
        ]
        policies = [
            {
                "table": table,
                "policy": policy,
                "permissive": permissive,
                "roles": sorted(roles),
                "command": cmd,
                "using": qual,
                "with_check": check,
            }
            for table, policy, permissive, roles, cmd, qual, check in _rows(
                conn,
                "SELECT tablename::text, policyname::text, permissive, roles::text[], cmd, qual, with_check"
                " FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, policyname",
            )
        ]
        functions = [
            {
                "function": f"{name}({args})",
                "owner": owner,
                "security_definer": secdef,
                "config": sorted(config or []),
                "app_execute": execute,
            }
            for name, args, owner, secdef, config, execute in _rows(
                conn,
                "SELECT p.proname, pg_get_function_identity_arguments(p.oid), pg_get_userbyid(p.proowner),"
                " p.prosecdef, p.proconfig, has_function_privilege(%s, p.oid, 'EXECUTE')"
                " FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'"
                " AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass"
                "   AND d.objid = p.oid AND d.deptype = 'e')"
                " ORDER BY 1, 2",
                (app,),
            )
        ]
        default_privileges = sorted(
            [
                list(row)
                for row in _rows(
                    conn,
                    "SELECT pg_get_userbyid(d.defaclrole), coalesce(n.nspname, ''), d.defaclobjtype::text,"
                    " CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, a.privilege_type,"
                    " a.is_grantable"
                    " FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace,"
                    " LATERAL aclexplode(d.defaclacl) a",
                )
            ]
        )
        schema = {
            p.lower(): _rows(conn, "SELECT has_schema_privilege(%s, 'public', %s)", (app, p))[0][0]
            for p in ("USAGE", "CREATE")
        }
        database = {
            p.lower(): _rows(conn, "SELECT has_database_privilege(%s, current_database(), %s)", (app, p))[0][
                0
            ]
            for p in ("CONNECT", "CREATE", "TEMPORARY")
        }
        attributes = _rows(
            conn,
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolinherit FROM pg_roles WHERE rolname = %s",
            (app,),
        )[0]
        acl = _acl_entries(conn)
        memberships = sorted(
            list(row)
            for row in _rows(
                conn,
                "SELECT pg_get_userbyid(m.roleid), pg_get_userbyid(m.member), m.admin_option"
                " FROM pg_auth_members m"
                " WHERE pg_get_userbyid(m.member) = ANY(%s) OR pg_get_userbyid(m.roleid) = ANY(%s)",
                ([app, ev.owner], [app, ev.owner]),
            )
        )
    return ev.normalize(
        {
            "summary": {
                "tables": len(tables),
                "row_security": sum(1 for t in tables if t["row_security"]),
                "force_row_security": sum(1 for t in tables if t["force_row_security"]),
                "policies": len(policies),
            },
            "tables": tables,
            "sequences": sequences,
            "policies": policies,
            "functions": functions,
            "default_privileges": default_privileges,
            "app_role": {
                "schema_public": schema,
                "database": database,
                "attributes": dict(
                    zip(
                        ("superuser", "bypass_rls", "create_role", "create_db", "inherit"),
                        attributes,
                        strict=True,
                    )
                ),
                "memberships": memberships,
            },
            "acl": acl,
        }
    )


#: Every access control entry of the schema's objects. ``NULL`` ACLs are read as their default (``acldefault``),
#: so the implicit ``PUBLIC`` rights (``EXECUTE`` on functions, ``CONNECT``/``TEMPORARY`` on the database) show.
#: An owner's entries for its own object (grantor = grantee = owner) are left out: they are implicit, and
#: PostgreSQL 17 adds ``MAINTAIN`` to them, so they would differ across versions. Everything else is kept,
#: including ``MAINTAIN`` granted to another role.
_ACL_SQL = """
SELECT kind, object, grantor, grantee, privilege, grantable FROM (
  SELECT CASE WHEN c.relkind = 'S' THEN 'sequence' ELSE 'relation' END AS kind, c.relname::text AS object,
         c.relowner AS owner, a.grantor, a.grantee, a.privilege_type AS privilege, a.is_grantable AS grantable
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,
         LATERAL aclexplode(coalesce(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char",
                                                          c.relowner))) a
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
     AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
                     AND d.deptype = 'e')
  UNION ALL
  SELECT 'column', c.relname || '.' || at.attname, c.relowner, a.grantor, a.grantee, a.privilege_type,
         a.is_grantable
    FROM pg_attribute at JOIN pg_class c ON c.oid = at.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace,
         LATERAL aclexplode(at.attacl) a
   WHERE n.nspname = 'public' AND at.attacl IS NOT NULL AND at.attnum > 0 AND NOT at.attisdropped
  UNION ALL
  SELECT 'function', p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', p.proowner,
         a.grantor, a.grantee, a.privilege_type, a.is_grantable
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace,
         LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
   WHERE n.nspname = 'public'
     AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                     AND d.deptype = 'e')
  UNION ALL
  SELECT 'schema', n.nspname::text, n.nspowner, a.grantor, a.grantee, a.privilege_type, a.is_grantable
    FROM pg_namespace n, LATERAL aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
   WHERE n.nspname = 'public'
  UNION ALL
  SELECT 'database', '<database>', d.datdba, a.grantor, a.grantee, a.privilege_type, a.is_grantable
    FROM pg_database d, LATERAL aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
   WHERE d.datname = current_database()
) e
WHERE NOT (e.grantee = e.owner AND e.grantor = e.owner)
"""


def _acl_entries(conn: psycopg.Connection[Any]) -> list[list[Any]]:
    """``[kind, object, grantor, grantee, privilege, grantable]`` of every entry; ``PUBLIC`` and ``<admin>`` named."""
    admin = str(_rows(conn, "SELECT current_user")[0][0])

    def role(oid: int) -> str:
        if oid == 0:
            return "PUBLIC"
        name = str(_rows(conn, "SELECT pg_get_userbyid(%s)", (oid,))[0][0])
        return "<admin>" if name == admin else name

    return sorted(
        [kind, obj, role(grantor), role(grantee), privilege, grantable]
        for kind, obj, grantor, grantee, privilege, grantable in _rows(conn, _ACL_SQL)
    )


# -- role decision table -------------------------------------------------------------------------------------------


def _outcome(call: Callable[[], Any]) -> Any:
    """``{"ok": result}`` or the refusal: error class, code and message."""
    try:
        result = call()
    except Exception as exc:
        return {"refused": type(exc).__name__, "code": getattr(exc, "code", None), "message": str(exc)}
    if hasattr(result, "as_dict"):
        result = result.as_dict()
    return {"ok": result}


def _create_variant(ev: EvidenceDatabase, name: str) -> str:
    """Create the role of a variant (nothing for ``missing``; the owner for ``connecting_owner``)."""
    if name == "connecting_owner":
        return ev.owner
    role = ev.variant(name)
    if name == "missing":
        return role
    attributes = {
        "restricted": "NOSUPERUSER NOBYPASSRLS",
        "superuser": "SUPERUSER NOBYPASSRLS",
        "bypass_rls": "NOSUPERUSER BYPASSRLS",
        "superuser_bypass_rls": "SUPERUSER BYPASSRLS",
        "table_owner": "NOSUPERUSER NOBYPASSRLS",
        "owner_member": "NOSUPERUSER NOBYPASSRLS",
    }[name]
    with psycopg.connect(ev.admin_url, autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN " + attributes + " PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(ev.password)
            )
        )
        if name == "owner_member":
            conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(ev.owner), sql.Identifier(role)))
    if name == "table_owner":
        table = sql.Identifier(f"{ev.base}_owned")
        with psycopg.connect(ev.url(), autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE TABLE public.{} (id integer)").format(table))
            conn.execute(sql.SQL("ALTER TABLE public.{} ENABLE ROW LEVEL SECURITY").format(table))
            conn.execute(sql.SQL("ALTER TABLE public.{} OWNER TO {}").format(table, sql.Identifier(role)))
    return role


def roles_snapshot(ev: EvidenceDatabase) -> dict[str, Any]:
    """The decision table of the eight role variants (changes the database: run it after the other snapshots)."""
    from axentra.data.database import Database
    from axentra.data.roles import grant_runtime_role, inspect_role

    table: dict[str, Any] = {}
    for name in ROLE_VARIANTS:
        role = _create_variant(ev, name)
        row: dict[str, Any] = {}
        with psycopg.connect(ev.url(ev.owner), autocommit=True) as owner:
            row["inspect_role"] = _outcome(lambda: inspect_role(owner, role))  # noqa: B023 - called at once
        row["grant_runtime_role"] = _outcome(lambda: grant_runtime_role(ev.url(ev.owner), role))  # noqa: B023
        if name != "missing":
            db = Database(ev.url(role), min_size=1, max_size=1)
            db.open()
            try:
                row["role_info"] = _outcome(db.role_info)
                row["check_role"] = {
                    f"allow_superuser={su},allow_table_owner={to}": _outcome(
                        lambda: db.check_role(allow_superuser=su, allow_table_owner=to)  # noqa: B023
                    )
                    for su in (False, True)
                    for to in (False, True)
                }
            finally:
                db.close()
        table[name] = row
    return ev.normalize({"variants": list(ROLE_VARIANTS), "table": table})


# -- problem details ------------------------------------------------------------------------------------------------


def _error_classes() -> list[type[Any]]:
    import axentra.api.app  # noqa: F401 - imports every module, so every error class is defined
    from axentra.core.errors import AxentraError

    found: dict[str, type[Any]] = {}
    pending: list[type[Any]] = [AxentraError]
    while pending:
        cls = pending.pop()
        if cls.__module__.startswith("axentra."):
            found[f"{cls.__module__}.{cls.__qualname__}"] = cls
        pending.extend(cls.__subclasses__())
    return [found[k] for k in sorted(found)]


def _http_problems(ev: EvidenceDatabase) -> dict[str, Any]:
    """The API's answers to a fixed list of failing requests (status, headers that matter, body)."""
    from fastapi.testclient import TestClient

    from axentra.api.app import create_app
    from axentra.platform import Axentra
    from tests.conftest import make_settings

    answers: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as storage:
        urls = {"app": ev.url(ev.app), "owner": ev.url(ev.owner)}
        ax = Axentra.from_settings(make_settings(urls, _storage_path=storage))
        ax.start()
        try:
            app = create_app(axentra=ax, start=False)
            origin = {"Origin": "http://studio.test"}
            client = TestClient(app, base_url="http://testserver", headers=origin)

            def record(label: str, response: Any) -> None:
                body = response.json() if response.headers.get("content-type", "").endswith("json") else None
                answers[label] = {
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "retry_after": response.headers.get("retry-after"),
                    "body": body,
                }

            record("unknown_route", client.get("/v1/no-such-route"))
            record("method_not_allowed", client.delete("/v1/meta"))
            record("unauthenticated", client.get("/v1/me"))
            record("validation_failed", client.post("/v1/auth/login/password", json={}))
            record(
                "wrong_password",
                client.post(
                    "/v1/auth/login/password", json={"email": "nobody@example.com", "password": "x" * 12}
                ),
            )
            record(
                "invalid_setup_token",
                client.post(
                    "/v1/auth/setup",
                    json={
                        "setup_token": "wrong",
                        "email": "admin@example.com",
                        "name": "A",
                        "password": PASS_PHRASE,
                    },
                ),
            )
            token = ax.identity.create_setup_token()
            setup = client.post(
                "/v1/auth/setup",
                json={
                    "setup_token": token,
                    "email": "admin@example.com",
                    "name": "Admin",
                    "password": PASS_PHRASE,
                },
            )
            if setup.status_code != 200:
                raise RuntimeError(f"setup failed: {setup.status_code} {setup.text}")
            csrf = {"X-Axentra-CSRF": setup.json()["csrf_token"]}
            record(
                "setup_again",
                client.post(
                    "/v1/auth/setup",
                    json={
                        "setup_token": token,
                        "email": "b@example.com",
                        "name": "B",
                        "password": PASS_PHRASE,
                    },
                ),
            )
            record("csrf_missing", client.post("/v1/products", json={"slug": "crm", "name": "CRM"}))
            created = client.post("/v1/products", json={"slug": "crm", "name": "CRM"}, headers=csrf)
            if created.status_code != 201:
                raise RuntimeError(f"product failed: {created.status_code} {created.text}")
            # A unique violation of the database, turned into a typed conflict (tenancy service).
            record(
                "product_slug_taken",
                client.post("/v1/products", json={"slug": "crm", "name": "C"}, headers=csrf),
            )
            pid = created.json()["id"]
            tenant = {"slug": "acme", "name": "Acme"}
            client.post(f"/v1/products/{pid}/tenants", json=tenant, headers=csrf)
            record("tenant_slug_taken", client.post(f"/v1/products/{pid}/tenants", json=tenant, headers=csrf))
            record("product_not_found", client.get(f"/v1/products/{PRODUCT_ID}"))
            record(
                "invalid_cursor",
                client.get("/v1/audit", params={"product_id": pid, "cursor": "not-a-cursor"}),
            )
        finally:
            ax.close()
    return ev.normalize(answers)


def problems_snapshot(ev: EvidenceDatabase) -> dict[str, Any]:
    from axentra.core.errors import problem_details

    classes: dict[str, Any] = {}
    for cls in _error_classes():
        info = problem_details(cls())
        classes[f"{cls.__module__}.{cls.__qualname__}"] = {
            "class": {"code": cls.code, "status": cls.status, "title": cls.title},
            "problem": info.body(request_id=None),
            "headers": info.headers,
            "internal": info.internal,
        }
    canary = "canary-qa13@example.com"
    others: dict[str, Any] = {}
    for label, exc in (
        (
            "unique_violation",
            psycopg.errors.UniqueViolation(f"duplicate key\nDETAIL:  Key (email)=({canary}) exists."),
        ),
        ("operational_error", psycopg.OperationalError("connection lost")),
        ("value_error", ValueError(canary)),
    ):
        info = problem_details(exc)
        others[label] = {
            "problem": info.body(request_id=None),
            "headers": info.headers,
            "internal": info.internal,
        }
    openapi = json.loads(
        (Path(__file__).resolve().parents[2] / "openapi" / "axentra-v1.json").read_text("utf-8")
    )
    schemas = openapi["components"]["schemas"]
    return {
        "classes": classes,
        "other_exceptions": others,
        "http": _http_problems(ev),
        "openapi_schemas": {name: schemas[name] for name in sorted(schemas) if name.startswith("Problem")},
    }


# -- session settings (SHOW extract) ---------------------------------------------------------------------------------


def _show_all(conn: psycopg.Connection[Any]) -> dict[str, str]:
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute("SELECT name, setting FROM pg_settings")
        return {str(row[0]): str(row[1]) for row in cur.fetchall()}


def _scope(conn: psycopg.Connection[Any]) -> dict[str, str]:
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute(
            "SELECT " + ", ".join("coalesce(current_setting(%s, true), '')" for _ in SCOPE_SETTINGS),
            SCOPE_SETTINGS,
        )
        row = cur.fetchone()
    return dict(zip(SCOPE_SETTINGS, (str(v) for v in row or ()), strict=True))


def _state(conn: psycopg.Connection[Any], plain: dict[str, str]) -> dict[str, Any]:
    """The settings that differ from a plain connection, the scope settings and the transaction status."""
    status = conn.info.transaction_status.name  # before this function's own reads
    current = _show_all(conn)
    return {
        "differs_from_plain": {k: current[k] for k in sorted(current) if plain.get(k) != current[k]},
        "scope": _scope(conn),
        "transaction_status": status,
    }


def settings_snapshot(ev: EvidenceDatabase) -> dict[str, Any]:
    """The ``SHOW`` extract of each kind of Axentra connection (as the runtime role)."""
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    from axentra.data.database import Database, DbScope, join
    from axentra.events.schedules import LeaderLock

    url = ev.url(ev.app)
    scope = DbScope.tenant(PRODUCT_ID, TENANT_ID)
    with psycopg.connect(url, autocommit=True) as conn:
        plain = _show_all(conn)
    kinds: dict[str, Any] = {}

    def through(db: Database, label: str, *, read_only: bool = False) -> None:
        with db.transaction(scope, read_only=read_only) as tx:
            inside = _state(tx.conn, plain)
        with db.pool.connection() as conn:  # the pool holds one connection: the same one
            after = _state(conn, plain)
            if not conn.autocommit:
                conn.rollback()
        kinds[label] = {"inside": inside, "after": after}

    owned = Database(url, min_size=1, max_size=1)
    owned.open()
    try:
        through(owned, "owned_pool")
        through(owned, "owned_pool_read_only", read_only=True)
        owned.ping()
        with owned.pool.connection() as conn:
            kinds["owned_pool_after_ping"] = {"after": _state(conn, plain)}
            conn.rollback()
    finally:
        owned.close()

    host = ConnectionPool(url, min_size=1, max_size=1, kwargs={"autocommit": True}, open=False, name="host")
    host.open(wait=True)
    try:
        through(Database.on_pool(host, url=url), "on_pool")
    finally:
        host.close()

    with psycopg.connect(url, autocommit=False, row_factory=dict_row) as conn:
        conn.execute("SELECT 1")  # the host's implicit transaction
        joined_db = Database.on_pool(_NoPool(), url=url)
        with joined_db.joined(conn):
            with joined_db.transaction(scope) as tx:
                inside = _state(tx.conn, plain)
            between = _state(conn, plain)
        after = _state(conn, plain)
        kinds["joined"] = {"inside": inside, "after_transaction": between, "after_joined": after}
        with join(conn, scope) as tx:
            inside = _state(tx.conn, plain)
        kinds["join"] = {"inside": inside, "after": _state(conn, plain)}
        conn.rollback()
        kinds["join"]["after_rollback"] = _state(conn, plain)

    lock = LeaderLock(url, key=0x5145_3133)  # any key: the database is this run's own
    if not lock.acquire():
        raise RuntimeError("the leader lock was not acquired")
    try:
        assert lock._conn is not None
        kinds["leader_lock"] = {"held": _state(lock._conn, plain)}
    finally:
        lock.release()
    return ev.normalize(
        {"scope": dict(zip(SCOPE_SETTINGS, ("tenant", PRODUCT_ID, TENANT_ID), strict=True)), "kinds": kinds}
    )


class _NoPool:
    """A pool that must not be used: inside :meth:`Database.joined` every transaction runs on the host's connection."""

    conninfo = ""

    def connection(self, timeout: float | None = None) -> Any:
        raise AssertionError("joined() borrowed a pool connection")


# -- schema dump ------------------------------------------------------------------------------------------------------


def schema_snapshot(ev: EvidenceDatabase) -> dict[str, Any]:
    """The schema of the migrated database from the catalog (read as the admin)."""
    not_extension = (
        " AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = {cls}::regclass AND d.objid = {oid}"
        " AND d.deptype = 'e')"
    )
    with psycopg.connect(ev.url(), autocommit=True) as conn:
        relations: dict[str, Any] = {}
        for name, kind in _rows(
            conn,
            "SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')"
            + not_extension.format(cls="'pg_class'", oid="c.oid")
            + " ORDER BY c.relname",
        ):
            relations[name] = {"kind": kind}
        for table, column, typ, notnull, default, identity, generated in _rows(
            conn,
            "SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,"
            " pg_get_expr(ad.adbin, ad.adrelid), a.attidentity::text, a.attgenerated::text"
            " FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace"
            " LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum"
            " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0"
            " AND NOT a.attisdropped ORDER BY c.relname, a.attnum",
        ):
            if table in relations:
                relations[table].setdefault("columns", []).append(
                    {
                        "name": column,
                        "type": typ,
                        "not_null": notnull,
                        "default": default,
                        "identity": identity,
                        "generated": generated,
                    }
                )
        for table, name, kind, definition in _rows(
            conn,
            "SELECT c.relname, k.conname, k.contype::text, pg_get_constraintdef(k.oid)"
            " FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace"
            # NOT NULL constraints are catalogued from PostgreSQL 18 on (contype 'n'); ``columns`` holds them already.
            " WHERE n.nspname = 'public' AND k.contype <> 'n' ORDER BY c.relname, k.conname",
        ):
            if table in relations:
                relations[table].setdefault("constraints", []).append(
                    {"name": name, "type": kind, "definition": definition}
                )
        for table, name, definition in _rows(
            conn,
            "SELECT tablename::text, indexname::text, indexdef FROM pg_indexes WHERE schemaname = 'public'"
            " ORDER BY tablename, indexname",
        ):
            if table in relations:
                relations[table].setdefault("indexes", []).append({"name": name, "definition": definition})
        for table, definition in _rows(
            conn,
            "SELECT c.relname, pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
            " JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND NOT t.tgisinternal"
            " ORDER BY c.relname, t.tgname",
        ):
            if table in relations:
                relations[table].setdefault("triggers", []).append(definition)
        functions = [
            {
                "function": f"{name}({args})",
                "returns": returns,
                "language": language,
                "volatility": volatility,
                "body_md5": body,
            }
            for name, args, returns, language, volatility, body in _rows(
                conn,
                "SELECT p.proname, pg_get_function_identity_arguments(p.oid), pg_get_function_result(p.oid),"
                " l.lanname, p.provolatile::text, md5(p.prosrc)"
                " FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang"
                " WHERE n.nspname = 'public'"
                + not_extension.format(cls="'pg_proc'", oid="p.oid")
                + " ORDER BY 1, 2",
            )
        ]
        extensions = sorted(str(r[0]) for r in _rows(conn, "SELECT extname FROM pg_extension"))
        migrations = [
            {"namespace": ns, "version": version, "name": name, "checksum": checksum}
            for ns, version, name, checksum in _rows(
                conn,
                "SELECT namespace, version, name, checksum FROM axentra_schema_migrations ORDER BY namespace, version",
            )
        ]
    return ev.normalize(
        {"relations": relations, "functions": functions, "extensions": extensions, "migrations": migrations}
    )


# -- running -----------------------------------------------------------------------------------------------------------

#: The order matters: the role decision table adds roles and a table, so it runs last.
COLLECTORS: dict[str, Callable[[EvidenceDatabase], dict[str, Any]]] = {
    "catalog": catalog_snapshot,
    "schema": schema_snapshot,
    "settings": settings_snapshot,
    "problems": problems_snapshot,
    "roles": roles_snapshot,
}


def collect(
    admin_url: str,
    prefix: str = DEFAULT_PREFIX,
    names: tuple[str, ...] = NAMES,
    bases: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """All snapshots of one run (its own database, dropped afterwards)."""
    with evidence_database(admin_url, prefix, bases) as ev:
        found = {name: COLLECTORS[name](ev) for name in COLLECTORS if name in names}
    return {name: found[name] for name in names}


def dumps(snapshot: dict[str, Any]) -> str:
    """The canonical file text of a snapshot."""
    return json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n"


def golden(name: str, directory: Path = GOLDEN) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((directory / f"{name}.json").read_text("utf-8"))
    return loaded


def diff(name: str, expected: dict[str, Any], actual: dict[str, Any]) -> str:
    """A unified diff of two snapshots (empty when equal)."""
    return "".join(
        difflib.unified_diff(
            dumps(expected).splitlines(keepends=True),
            dumps(actual).splitlines(keepends=True),
            f"golden/{name}.json",
            f"current/{name}.json",
        )
    )


def _prefix_argument(value: str) -> str:
    try:
        return validate_prefix(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tests.evidence.snapshots", description=__doc__.split("\n")[0]
    )
    parser.add_argument("--url", required=True, help="a superuser URL of the PostgreSQL server")
    parser.add_argument(
        "--prefix",
        default=DEFAULT_PREFIX,
        type=_prefix_argument,
        help="prefix of the database and role names of the run ([a-z][a-z0-9_]{0,19})",
    )
    parser.add_argument("--dir", type=Path, default=GOLDEN, help="directory of the snapshot files")
    parser.add_argument("--only", action="append", choices=NAMES, help="only this snapshot (repeatable)")
    parser.add_argument("action", choices=("write", "check", "cleanup"))
    args = parser.parse_args(argv)
    if args.action == "cleanup":
        dropped = cleanup(args.url, args.prefix)
        for item in dropped:
            print(f"dropped {item}")
        print(f"cleanup: {len(dropped)} leftover(s) of prefix {args.prefix} dropped")
        return 0
    left = leftovers(args.url, args.prefix)
    if left:
        print(f"leftovers of earlier runs with prefix {args.prefix} (a killed run?): {', '.join(left)}")
        print(
            f"  drop them with: python -m tests.evidence.snapshots --url ... --prefix {args.prefix} cleanup"
        )
    names = tuple(args.only or NAMES)
    snapshots = collect(args.url, args.prefix, names)
    if args.action == "write":
        args.dir.mkdir(parents=True, exist_ok=True)
        for name, snapshot in snapshots.items():
            (args.dir / f"{name}.json").write_text(dumps(snapshot), "utf-8")
            print(f"wrote {args.dir / f'{name}.json'}")
        return 0
    failed = False
    for name, snapshot in snapshots.items():
        with suppress(FileNotFoundError):
            text = diff(name, golden(name, args.dir), snapshot)
            if text:
                failed = True
                sys.stdout.write(text)
            continue
        failed = True
        print(f"missing: {args.dir / f'{name}.json'}")
    print("snapshots differ" if failed else "snapshots identical")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
