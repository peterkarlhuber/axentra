"""Versioned SQL migrations with an advisory lock.

Migrations are plain SQL files ``NNNN_name.sql`` in a package directory, grouped by namespace:
Axentra's own schema uses the ``axentra`` namespace; product backends register their own
namespace (e.g. ``crm``) for their relational tables and run them with the same runner, so one
``axentra migrate`` brings the whole database up to date.

Applied migrations are recorded in ``axentra_schema_migrations`` with a SHA-256 checksum; a
changed file that was already applied is refused (never edit applied migrations — add a new one).
Each migration runs in its own transaction; concurrent runners serialize on an advisory lock.
Migrations only move forward; rollback is restore from backup (see docs/operations/BACKUP_RESTORE.md).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources
import logging
from pathlib import Path
import re

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


def builtin_migrations() -> list[Migration]:
    out = []
    root = resources.files("axentra.data.sql")
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        m = _NAME.match(entry.name)
        if m:
            out.append(Migration("axentra", int(m.group(1)), m.group(2), entry.read_text(encoding="utf-8")))
    return out


class MigrationRunner:
    def __init__(self, url: str) -> None:
        self.url = url
        self.migrations: list[Migration] = builtin_migrations()

    def register(self, migrations: list[Migration]) -> None:
        for mig in migrations:
            if mig.namespace == "axentra":
                raise ValueError("the 'axentra' namespace is reserved")
        self.migrations.extend(migrations)

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
