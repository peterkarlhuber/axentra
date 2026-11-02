"""Bulk re-encryption of stored :class:`~axentra.config.secrets.SecretBox` ciphertexts.

Key rotation (see ADR 0011): put a new key in front of the keyring (it becomes the active key),
restart every process, run ``axentra secrets reencrypt``, check that the dry run reports no value
under the old key id, then remove the old key.

Every column that holds ciphertexts is described by an :class:`EncryptedColumn`. Axentra's own
columns are listed in :func:`builtin_encrypted_columns`; product backends register theirs with
``ax.register_encrypted_column(...)`` so the same command rotates their values too.

Guarantees:

- Batches: each batch of ``batch_size`` rows is one transaction (platform scope, so row-level
  security does not hide rows); a crash loses at most the current batch, and the next run
  continues where it stopped.
- Idempotent: only values whose key id differs from the active key id are touched; a second run
  finds nothing to do.
- Concurrency-safe: each row is updated with a compare-and-swap (``WHERE column = <old value>``),
  so a value the application rewrote in the meantime is left alone (it is already under the
  active key) and counted as ``changed``.
- A value that cannot be decrypted (unknown key id, tampered row, wrong context) is counted as
  ``failed`` and left unchanged; the run continues. The CLI exits non-zero when anything failed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import logging
import re
from typing import Any

from psycopg import sql

from axentra.config.secrets import PREFIX, SecretBox
from axentra.data.database import Database, DbScope

logger = logging.getLogger(__name__)

_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


@dataclass(frozen=True, slots=True)
class EncryptedColumn:
    """A text column holding SecretBox ciphertexts.

    ``context`` builds the associated-data context string from the row (``key_column`` and every
    name in ``context_columns`` are selected); it must match what the owning module passes to
    ``SecretBox.encrypt``/``decrypt``. ``key_column`` must be unique (normally the primary key);
    rows are walked in the order of its text form.
    """

    table: str
    column: str
    key_column: str
    context: Callable[[dict[str, Any]], str]
    context_columns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (self.table, self.column, self.key_column, *self.context_columns):
            if not _IDENT.match(name):
                raise ValueError(f"invalid SQL identifier {name!r}")

    @property
    def label(self) -> str:
        return f"{self.table}.{self.column}"


def builtin_encrypted_columns() -> list[EncryptedColumn]:
    """Every Axentra column that stores ciphertexts (contexts mirror the owning modules).

    The list must name every column an Axentra module writes with ``SecretBox.encrypt``: OIDC login
    states (``identity/oidc.py``), webhook secrets (``events/webhooks.py``), notification messages
    including the in-app inbox (``notify/service.py``) and the local mailbox (``notify/providers.py``).
    A column missing here would keep values under the old key after ``secrets reencrypt`` reported
    ``pending: 0``, and removing that key would make them unreadable (security review SR-05);
    ``tests/integration/test_hardening.py`` scans every Axentra table after a rotation to catch that.
    """

    def login(field_name: str) -> Callable[[dict[str, Any]], str]:
        return lambda r: f"axentra_login_states:{r['state_hash']}:{field_name}"

    def webhook(r: dict[str, Any]) -> str:
        return f"axentra_webhook_endpoints:{r['id']}:secret"

    def notify(table: str, part: str) -> Callable[[dict[str, Any]], str]:
        return lambda r: f"{table}|{r['id']}|{part}"

    cols = [
        EncryptedColumn("axentra_login_states", "nonce", "state_hash", login("nonce")),
        EncryptedColumn("axentra_login_states", "code_verifier", "state_hash", login("code_verifier")),
        EncryptedColumn("axentra_login_states", "invitation_token", "state_hash", login("invitation")),
        EncryptedColumn("axentra_login_states", "host_context", "state_hash", login("host_context")),
        EncryptedColumn("axentra_webhook_endpoints", "secret_enc", "id", webhook),
        EncryptedColumn("axentra_webhook_endpoints", "previous_secret_enc", "id", webhook),
    ]
    for table in ("axentra_notify_messages", "axentra_notify_mailbox"):
        for column, part in (
            ("subject_enc", "subject"),
            ("body_text_enc", "text"),
            ("body_html_enc", "html"),
        ):
            cols.append(EncryptedColumn(table, column, "id", notify(table, part)))
    return cols


@dataclass
class ColumnReport:
    total: int = 0
    """Non-null values (dry run and real run: counted before the run)."""
    pending: int = 0
    """Values not under the active key before the run."""
    by_kid: dict[str, int] = field(default_factory=dict)
    """Values per key id before the run (``?`` for values that are not Axentra ciphertexts)."""
    reencrypted: int = 0
    changed: int = 0
    """Skipped because the application rewrote the value during the run."""
    failed: int = 0


@dataclass
class ReencryptReport:
    active_kid: str
    dry_run: bool
    columns: dict[str, ColumnReport] = field(default_factory=dict)

    @property
    def failed(self) -> int:
        return sum(c.failed for c in self.columns.values())

    @property
    def pending(self) -> int:
        return sum(c.pending for c in self.columns.values())

    @property
    def by_kid(self) -> dict[str, int]:
        """Stored values per key id over every column (``?``: not an Axentra ciphertext), counted before
        the run. A key id that is not listed holds no value of a registered column and may be removed
        from the keyring; a host's startup check can refuse a keyring that lacks a listed key id."""
        out: dict[str, int] = {}
        for c in self.columns.values():
            for kid, n in c.by_kid.items():
                out[kid] = out.get(kid, 0) + n
        return dict(sorted(out.items()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "active_kid": self.active_kid,
            "dry_run": self.dry_run,
            "pending": self.pending,
            "failed": self.failed,
            "reencrypted": sum(c.reencrypted for c in self.columns.values()),
            "by_kid": self.by_kid,
            "columns": {k: vars(v) for k, v in self.columns.items()},
        }


def _count(db: Database, col: EncryptedColumn, active_prefix: str) -> ColumnReport:
    rep = ColumnReport()
    query = sql.SQL(
        "SELECT CASE WHEN {c} LIKE %s THEN split_part({c}, '.', 2) ELSE '?' END AS kid, count(*) AS n"
        " FROM {t} WHERE {c} IS NOT NULL GROUP BY 1"
    ).format(c=sql.Identifier(col.column), t=sql.Identifier(col.table))
    with db.transaction(DbScope.platform(), read_only=True) as tx:
        rows = tx.all(query.as_string(tx.conn), (f"{PREFIX}.%",))
    for r in rows:
        rep.by_kid[r["kid"]] = int(r["n"])
        rep.total += int(r["n"])
    rep.pending = rep.total - sum(n for kid, n in rep.by_kid.items() if f"{PREFIX}.{kid}." == active_prefix)
    return rep


def _table_exists(db: Database, table: str) -> bool:
    with db.transaction(DbScope.platform(), read_only=True) as tx:
        return bool(tx.scalar("SELECT to_regclass(%s) IS NOT NULL", (table,)))


def reencrypt(
    db: Database,
    box: SecretBox,
    columns: list[EncryptedColumn],
    *,
    dry_run: bool = False,
    batch_size: int = 500,
) -> ReencryptReport:
    """Re-encrypt every value of ``columns`` that is not under the active key id."""
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    active = box.keyring.active_kid
    active_prefix = f"{PREFIX}.{active}."
    report = ReencryptReport(active_kid=active, dry_run=dry_run)
    for col in columns:
        if not _table_exists(db, col.table):  # e.g. a product table whose migration is not applied
            logger.warning("re-encryption: table %s does not exist, skipped", col.table)
            continue
        rep = report.columns[col.label] = _count(db, col, active_prefix)
        if dry_run or rep.pending == 0:
            continue
        key = sql.Identifier(col.key_column)
        c = sql.Identifier(col.column)
        extra = [sql.Identifier(n) for n in col.context_columns if n not in (col.key_column, col.column)]
        select = sql.SQL(
            "SELECT {fields} FROM {t} WHERE {c} IS NOT NULL AND {c} NOT LIKE %s AND {key}::text > %s"
            " ORDER BY {key}::text LIMIT %s"
        ).format(fields=sql.SQL(", ").join([key, c, *extra]), t=sql.Identifier(col.table), c=c, key=key)
        update = sql.SQL("UPDATE {t} SET {c} = %s WHERE {key} = %s AND {c} = %s").format(
            t=sql.Identifier(col.table), c=c, key=key
        )
        last = ""
        while True:
            with db.transaction(DbScope.platform()) as tx:
                rows = tx.all(select.as_string(tx.conn), (active_prefix + "%", last, batch_size))
                if not rows:
                    break
                for row in rows:
                    row_key = row[col.key_column]
                    last = str(row_key)
                    old = row[col.column]
                    ctx = col.context(row)
                    try:
                        new = box.encrypt(box.decrypt(old, ctx), ctx)
                    except Exception as exc:  # unknown kid, tampered value, wrong context
                        rep.failed += 1
                        logger.warning(
                            "re-encryption failed for %s %s=%s: %s",
                            col.label,
                            col.key_column,
                            last,
                            type(exc).__name__,
                        )
                        continue
                    if tx.execute(update.as_string(tx.conn), (new, row_key, old)) == 1:
                        rep.reencrypted += 1
                    else:
                        rep.changed += 1
            if len(rows) < batch_size:
                break
    return report
