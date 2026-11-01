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
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import importlib
from importlib import metadata, resources
import logging
from pathlib import Path
import re
from typing import Any

import psycopg

logger = logging.getLogger(__name__)

#: Advisory lock key for migrations ("axentra" folded into 63 bits).
MIGRATION_LOCK = 0x617865_6E747261
_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


@dataclass(frozen=True, slots=True)
class Migration:
    namespace: str
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode()).hexdigest()


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

    def status(self) -> list[dict[str, object]]:
        with psycopg.connect(self.url, autocommit=True) as conn:
            self._ensure_table(conn)
            applied = {
                (r[0], r[1]): r[2]
                for r in conn.execute(
                    "SELECT namespace, version, checksum FROM axentra_schema_migrations"
                ).fetchall()
            }
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

    def migrate(self) -> list[str]:
        """Apply pending migrations; returns the applied ``namespace:version_name`` list."""
        done: list[str] = []
        with psycopg.connect(self.url, autocommit=True) as conn:
            conn.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK,))
            try:
                self._ensure_table(conn)
                applied = {
                    (r[0], r[1]): r[2]
                    for r in conn.execute(
                        "SELECT namespace, version, checksum FROM axentra_schema_migrations"
                    ).fetchall()
                }
                for mig in self._ordered():
                    key = (mig.namespace, mig.version)
                    if key in applied:
                        if applied[key] != mig.checksum:
                            raise RuntimeError(
                                f"migration {mig.namespace}:{mig.version:04d}_{mig.name} changed after it was applied"
                            )
                        continue
                    with conn.transaction():
                        conn.execute(mig.sql.encode())
                        conn.execute(
                            "INSERT INTO axentra_schema_migrations (namespace, version, name, checksum)"
                            " VALUES (%s, %s, %s, %s)",
                            (mig.namespace, mig.version, mig.name, mig.checksum),
                        )
                    label = f"{mig.namespace}:{mig.version:04d}_{mig.name}"
                    logger.info("applied migration %s", label)
                    done.append(label)
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK,))
        return done
