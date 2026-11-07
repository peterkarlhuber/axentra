"""Versioned SQL migrations with an advisory lock.

Migrations are plain SQL files ``NNNN_name.sql`` in a package directory, grouped by namespace:
Axentra's own schema uses the ``axentra`` namespace; product backends register their own
namespace (e.g. ``crm``) for their relational tables and run them with the same runner, so one
``axentra migrate`` brings the whole database up to date.

Applied migrations are recorded in ``axentra_schema_migrations`` with a SHA-256 checksum; a
changed file that was already applied is refused (never edit applied migrations — add a new one).
Each migration runs in its own transaction; concurrent runners serialize on an advisory lock.
Migrations only move forward; rollback is restore from backup (see docs/operations/BACKUP_RESTORE.md).

Discovery of product namespaces (so ``axentra migrate`` applies them without custom code):

- ``database.extra_migrations = ["crm.schema:migrations"]``: each entry is ``module:attribute``;
  the attribute is a list of :class:`Migration` or a callable returning one (for example
  ``lambda: package_migrations("crm", "crm.sql")``).
- Installed distributions may declare the entry point group ``axentra.migrations`` with the same
  kind of target (disable with ``database.migration_entry_points = false``).

Compatibility checks (:meth:`MigrationRunner.check`): for every namespace the code knows, the
database may hold *pending* versions (code newer than schema) or *unknown* applied versions
(schema newer than code, e.g. after a rollback of the application). :meth:`MigrationRunner.migrate`
refuses to run while a known namespace has unknown versions (``allow_newer=True`` overrides), and
:meth:`MigrationRunner.require_current` is a serving gate that refuses both (enabled for
``Axentra.start()`` with ``database.require_current_schema``). Namespaces that are recorded in the
database but not registered in this process (another product's schema in a shared database) are
reported, never refused, unless they are named explicitly.

A migration whose file starts with the header comment ``-- axentra:no-transaction`` runs outside
a transaction (for ``CREATE INDEX CONCURRENTLY`` and similar): its statements are executed one by
one in autocommit mode and the migration is recorded after the last one. Such a migration cannot
be rolled back halfway, so write every statement so that it can run again (``IF NOT EXISTS``).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
import hashlib
import importlib
from importlib import metadata, resources
import logging
from pathlib import Path
import re
import time
from typing import Any

import psycopg
from psycopg.rows import tuple_row

from axentra.core.errors import ConfigurationError

logger = logging.getLogger(__name__)

#: Advisory lock key for migrations ("axentra" folded into 63 bits).
MIGRATION_LOCK = 0x617865_6E747261
_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
NO_TRANSACTION_MARKER = "-- axentra:no-transaction"
_DOLLAR_TAG = re.compile(r"\$[A-Za-z_]*\$")


@dataclass(frozen=True, slots=True)
class Migration:
    namespace: str
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode()).hexdigest()

    @property
    def label(self) -> str:
        return f"{self.namespace}:{self.version:04d}_{self.name}"

    @property
    def transactional(self) -> bool:
        """False when the file's leading comment lines contain ``-- axentra:no-transaction``."""
        for line in self.sql.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("--"):
                return True
            if stripped.lower() == NO_TRANSACTION_MARKER:
                return False
        return True


def split_statements(sql: str) -> list[str]:
    """Split SQL into statements at top-level semicolons.

    Understands quoted strings and identifiers, dollar-quoted bodies and comments; used only for
    ``-- axentra:no-transaction`` migrations, whose statements must be sent one at a time."""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "-" and sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end < 0 else end
            buf.append(sql[i:end])
            i = end
        elif c == "/" and sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            end = n if end < 0 else end + 2
            buf.append(sql[i:end])
            i = end
        elif c in ("'", '"'):
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:  # doubled quote
                        j += 2
                        continue
                    break
                j += 1
            buf.append(sql[i : j + 1])
            i = j + 1
        elif c == "$" and (m := _DOLLAR_TAG.match(sql, i)):
            tag = m.group(0)
            end = sql.find(tag, i + len(tag))
            end = n if end < 0 else end + len(tag)
            buf.append(sql[i:end])
            i = end
        elif c == ";":
            out.append("".join(buf))
            buf = []
            i += 1
        else:
            buf.append(c)
            i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if _has_code(s)]


def _has_code(statement: str) -> bool:
    for line in statement.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("--"):
            return True
    return False


class SchemaNotCurrent(ConfigurationError):
    """The database schema does not match the code (pending or unknown migrations)."""

    code = "schema_not_current"
    status = 503
    title = "Database schema not current"


@dataclass(frozen=True, slots=True)
class NamespaceStatus:
    """The migration state of one namespace (see :meth:`MigrationRunner.check`)."""

    namespace: str
    #: Whether the code (this runner) has migrations for the namespace.
    registered: bool
    #: Versions known to the code and applied in the database.
    applied: list[int] = field(default_factory=list)
    #: Migrations known to the code and not yet applied (code newer than the schema).
    pending: list[Migration] = field(default_factory=list)
    #: Versions applied in the database that the code does not know (schema newer than the code).
    unknown: list[int] = field(default_factory=list)
    #: Applied versions whose file changed after it was applied.
    changed: list[int] = field(default_factory=list)

    @property
    def current(self) -> bool:
        return not (self.pending or self.unknown or self.changed)

    def as_dict(self) -> dict[str, object]:
        return {
            "namespace": self.namespace,
            "registered": self.registered,
            "current": self.current,
            "applied": self.applied,
            "pending": [m.label for m in self.pending],
            "unknown": self.unknown,
            "changed": self.changed,
        }


@dataclass(frozen=True, slots=True)
class SchemaCheck:
    """Result of :meth:`MigrationRunner.check`, one entry per namespace."""

    namespaces: dict[str, NamespaceStatus]

    @property
    def current(self) -> bool:
        """True when every checked namespace that the code registers is current."""
        return all(ns.current for ns in self.namespaces.values() if ns.registered)

    @property
    def pending(self) -> list[Migration]:
        return [m for ns in self.namespaces.values() for m in ns.pending]

    def as_dict(self) -> dict[str, object]:
        return {
            "current": self.current,
            "namespaces": [ns.as_dict() for ns in self.namespaces.values()],
        }


def load_directory(namespace: str, directory: Path) -> list[Migration]:
    out = []
    for path in sorted(directory.iterdir()):
        m = _NAME.match(path.name)
        if m:
            out.append(Migration(namespace, int(m.group(1)), m.group(2), path.read_text(encoding="utf-8")))
    return out


def package_migrations(namespace: str, package: str) -> list[Migration]:
    """The ``NNNN_name.sql`` files of an importable package (works from wheels and zip files)."""
    out = []
    root = resources.files(package)
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        m = _NAME.match(entry.name)
        if m:
            out.append(Migration(namespace, int(m.group(1)), m.group(2), entry.read_text(encoding="utf-8")))
    return out


def builtin_migrations() -> list[Migration]:
    return package_migrations("axentra", "axentra.data.sql")


ENTRY_POINT_GROUP = "axentra.migrations"


def _coerce(obj: Any, origin: str) -> list[Migration]:
    if callable(obj) and not isinstance(obj, Migration):
        obj = obj()
    if not isinstance(obj, Iterable):
        raise TypeError(f"migration source {origin} is not a list of Migration")
    items = list(obj)
    if not all(isinstance(m, Migration) for m in items):
        raise TypeError(f"migration source {origin} must yield Migration objects")
    return items


def load_migration_source(ref: str) -> list[Migration]:
    """Resolve ``module:attribute`` (attribute: list of migrations or a callable returning one)."""
    module, sep, attr = ref.partition(":")
    if not sep or not module or not attr:
        raise ValueError(f"migration source {ref!r} must look like 'package.module:attribute'")
    obj: Any = importlib.import_module(module)
    for part in attr.split("."):
        obj = getattr(obj, part)
    return _coerce(obj, ref)


def discover_migrations(
    sources: Iterable[str] = (),
    *,
    entry_points: bool = True,
    loader: Callable[[], Iterable[metadata.EntryPoint]] | None = None,
) -> list[Migration]:
    """Configured sources first (in order), then entry points of ``axentra.migrations`` (by name)."""
    out: list[Migration] = []
    for ref in sources:
        out.extend(load_migration_source(ref))
    if entry_points:
        eps = loader() if loader else metadata.entry_points(group=ENTRY_POINT_GROUP)
        for ep in sorted(eps, key=lambda e: e.name):
            out.extend(_coerce(ep.load(), f"entry point {ep.name} ({ep.value})"))
    return out


def _wait_for_lock(conn: psycopg.Connection[Any], poll_seconds: float = 0.2) -> None:
    """Take the migration lock, polling instead of blocking in ``pg_advisory_lock``.

    A blocking ``pg_advisory_lock`` keeps a statement (and its snapshot) open while it waits, and
    ``CREATE INDEX CONCURRENTLY`` in a ``-- axentra:no-transaction`` migration of the runner that
    holds the lock waits for every open snapshot: the two runners would deadlock. Between tries no
    statement is open here."""
    while not conn.execute("SELECT pg_try_advisory_lock(%s)", (MIGRATION_LOCK,)).fetchone()[0]:  # type: ignore[index]
        time.sleep(poll_seconds)


class MigrationRunner:
    def __init__(self, url: str) -> None:
        self.url = url
        self.migrations: list[Migration] = builtin_migrations()

    def register(self, migrations: list[Migration]) -> None:
        """Add product migrations; registering the identical migration twice is a no-op."""
        known = {(m.namespace, m.version): m for m in self.migrations}
        for mig in migrations:
            if mig.namespace == "axentra":
                raise ValueError("the 'axentra' namespace is reserved")
            prev = known.get((mig.namespace, mig.version))
            if prev is not None:
                if prev.checksum != mig.checksum or prev.name != mig.name:
                    raise ValueError(
                        f"two different migrations claim {mig.namespace}:{mig.version:04d}"
                        f" ({prev.name}, {mig.name})"
                    )
                continue
            known[(mig.namespace, mig.version)] = mig
            self.migrations.append(mig)

    def _ensure_table(self, conn: psycopg.Connection[tuple[object, ...]]) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS axentra_schema_migrations (
                namespace text NOT NULL,
                version integer NOT NULL,
                name text NOT NULL,
                checksum text NOT NULL,
                applied_at timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY (namespace, version)
            )
            """
        )

    def _applied(self, conn: psycopg.Connection[Any]) -> dict[tuple[str, int], str]:
        with conn.cursor(row_factory=tuple_row) as cur:
            cur.execute("SELECT to_regclass('axentra_schema_migrations') IS NOT NULL")
            row = cur.fetchone()
            if not row or not row[0]:
                return {}
            cur.execute("SELECT namespace, version, checksum FROM axentra_schema_migrations")
            return {(r[0], r[1]): r[2] for r in cur.fetchall()}

    def status(self) -> list[dict[str, object]]:
        """One row per migration known to the code (see :meth:`check` for unknown versions)."""
        with psycopg.connect(self.url, autocommit=True) as conn:
            applied = self._applied(conn)
        return [
            {
                "namespace": m.namespace,
                "version": m.version,
                "name": m.name,
                "applied": (m.namespace, m.version) in applied,
                "checksum_ok": applied.get((m.namespace, m.version), m.checksum) == m.checksum,
            }
            for m in self._ordered()
        ]

    def _ordered(self) -> list[Migration]:
        # Axentra's own schema first, then product namespaces in registration order.
        ns_order = ["axentra"] + [
            n for n in dict.fromkeys(m.namespace for m in self.migrations) if n != "axentra"
        ]
        return sorted(self.migrations, key=lambda m: (ns_order.index(m.namespace), m.version))

    def _evaluate(self, applied: dict[tuple[str, int], str], namespaces: Sequence[str] | None) -> SchemaCheck:
        code = self._ordered()
        known_ns = list(dict.fromkeys(m.namespace for m in code))
        db_ns = sorted({ns for ns, _ in applied} - set(known_ns))
        selected = list(namespaces) if namespaces is not None else known_ns + db_ns
        out: dict[str, NamespaceStatus] = {}
        for ns in selected:
            mine = [m for m in code if m.namespace == ns]
            versions = {m.version for m in mine}
            done = [m.version for m in mine if (ns, m.version) in applied]
            out[ns] = NamespaceStatus(
                namespace=ns,
                registered=bool(mine) or namespaces is not None,
                applied=done,
                pending=[m for m in mine if (ns, m.version) not in applied],
                unknown=sorted(v for n, v in applied if n == ns and v not in versions),
                changed=[m.version for m in mine if applied.get((ns, m.version), m.checksum) != m.checksum],
            )
        return SchemaCheck(out)

    def check(
        self, namespaces: Sequence[str] | None = None, *, conn: psycopg.Connection[Any] | None = None
    ) -> SchemaCheck:
        """Compare the database with the code, per namespace: applied, pending and unknown versions.

        Without ``namespaces``, every namespace the code registers is checked, and namespaces that
        only the database knows are listed with ``registered=False`` (they never make the result
        not current). Named namespaces are always checked strictly. Read-only: never creates the
        bookkeeping table. ``conn`` reads through an existing connection instead of ``self.url``.
        """
        if conn is not None:
            return self._evaluate(self._applied(conn), namespaces)
        with psycopg.connect(self.url, autocommit=True) as own:
            return self._evaluate(self._applied(own), namespaces)

    def require_current(
        self, namespaces: Sequence[str] | None = None, *, conn: psycopg.Connection[Any] | None = None
    ) -> SchemaCheck:
        """Serving gate: raise :class:`SchemaNotCurrent` when a checked namespace has pending,
        unknown or changed migrations."""
        result = self.check(namespaces, conn=conn)
        problems = [
            f"{ns.namespace}: "
            + ", ".join(
                part
                for part in (
                    f"pending {[m.label for m in ns.pending]}" if ns.pending else "",
                    f"unknown applied versions {ns.unknown} (the schema is newer than the code)"
                    if ns.unknown
                    else "",
                    f"changed after apply {ns.changed}" if ns.changed else "",
                )
                if part
            )
            for ns in result.namespaces.values()
            if ns.registered and not ns.current
        ]
        if problems:
            raise SchemaNotCurrent("the database schema does not match the code: " + "; ".join(problems))
        return result

    def migrate(
        self,
        *,
        allow_newer: bool = False,
        before_apply: Callable[[list[Migration]], None] | None = None,
    ) -> list[str]:
        """Apply pending migrations; returns the applied ``namespace:version_name`` list.

        Refused (:class:`~axentra.core.errors.ConfigurationError`) when a namespace registered by
        the code has applied versions the code does not know (the schema is newer than the code),
        unless ``allow_newer=True``. ``before_apply`` (for example a backup) is called once with
        the pending migrations, under the migration lock and only when something is pending; if it
        raises, nothing is applied."""
        done: list[str] = []
        with psycopg.connect(self.url, autocommit=True) as conn:
            _wait_for_lock(conn)
            try:
                self._ensure_table(conn)
                applied = self._applied(conn)
                result = self._evaluate(applied, None)
                for ns in result.namespaces.values():
                    for version in ns.changed:
                        mig = next(
                            m for m in self.migrations if (m.namespace, m.version) == (ns.namespace, version)
                        )
                        raise RuntimeError(f"migration {mig.label} changed after it was applied")
                newer = {
                    ns.namespace: ns.unknown
                    for ns in result.namespaces.values()
                    if ns.registered and ns.unknown
                }
                if newer and not allow_newer:
                    raise ConfigurationError(
                        "the database schema is newer than this code: applied migrations unknown to the code: "
                        + "; ".join(f"{ns} {versions}" for ns, versions in newer.items())
                        + " (deploy the newer code, or pass allow_newer=True if this is intended)"
                    )
                pending = result.pending
                if pending and before_apply is not None:
                    before_apply(list(pending))
                for mig in pending:
                    self._apply(conn, mig)
                    logger.info("applied migration %s", mig.label)
                    done.append(mig.label)
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK,))
        return done

    @staticmethod
    def _record(conn: psycopg.Connection[Any], mig: Migration) -> None:
        conn.execute(
            "INSERT INTO axentra_schema_migrations (namespace, version, name, checksum)"
            " VALUES (%s, %s, %s, %s)",
            (mig.namespace, mig.version, mig.name, mig.checksum),
        )

    def _apply(self, conn: psycopg.Connection[Any], mig: Migration) -> None:
        if mig.transactional:
            with conn.transaction():
                conn.execute(mig.sql.encode())
                self._record(conn, mig)
            return
        # Autocommit, one statement at a time (a multi-statement string would be one implicit
        # transaction block, where e.g. CREATE INDEX CONCURRENTLY is not allowed).
        for statement in split_statements(mig.sql):
            conn.execute(statement.encode())
        self._record(conn, mig)
