"""Stream positions for events and job changes (SSE ``Last-Event-ID``).

Streamed rows are written without a position. :func:`assign_positions` gives committed rows the
next numbers of ``axentra_stream_seq``; only one assigner runs at a time (transaction-level
advisory lock), and the next one can only start after the previous one committed. Positions
therefore grow in the order in which they become visible: a reader that has seen position ``N``
never later finds a committed row with a position ``<= N``, so resuming with ``Last-Event-ID``
loses nothing. (A position taken from a sequence at insert time would not have this property:
transactions commit in a different order than they draw numbers.)

Readers call :func:`assign_positions` before every poll, so positions appear within one poll
interval of the commit. Rows locked by a running transaction are skipped and positioned later.
"""

from __future__ import annotations

from axentra.core.errors import ValidationFailed
from axentra.data.database import Database, DbScope

#: Advisory lock key of the position assigner ("axstrm").
ASSIGN_LOCK = 0x61787374726D
BATCH = 1000


def parse_position(value: str) -> int:
    v = value.strip()
    if not v.isdigit() or len(v) > 18:
        raise ValidationFailed("invalid stream position (Last-Event-ID)")
    return int(v)


def assign_positions(db: Database) -> int:
    """Position committed rows that have none yet; returns how many (0 if another assigner runs)."""
    with db.transaction(DbScope.platform()) as tx:
        if not tx.scalar("SELECT pg_try_advisory_xact_lock(%s)", (ASSIGN_LOCK,)):
            return 0
        # Positions follow the row order within a batch (inner ORDER BY, nextval evaluated per row).
        n = tx.execute(
            "WITH c AS (SELECT id FROM axentra_events WHERE pos IS NULL ORDER BY id LIMIT %s FOR UPDATE SKIP LOCKED),"
            " p AS (SELECT id, nextval('axentra_stream_seq') AS pos FROM (SELECT id FROM c ORDER BY id) o)"
            " UPDATE axentra_events e SET pos = p.pos FROM p WHERE e.id = p.id",
            (BATCH,),
        )
        n += tx.execute(
            "WITH c AS (SELECT id, updated_at FROM axentra_jobs WHERE change_pos IS NULL ORDER BY updated_at, id"
            " LIMIT %s FOR UPDATE SKIP LOCKED),"
            " p AS (SELECT id, nextval('axentra_stream_seq') AS pos FROM (SELECT id FROM c ORDER BY updated_at, id) o)"
            " UPDATE axentra_jobs j SET change_pos = p.pos FROM p WHERE j.id = p.id",
            (BATCH,),
        )
    return n


def current_position(db: Database, scope: DbScope, table: str) -> int:
    """A position after every row visible now (rows that become visible later get larger ones)."""
    column = {"axentra_events": "pos", "axentra_jobs": "change_pos"}[table]
    assign_positions(db)
    with db.transaction(scope, read_only=True) as tx:
        return int(tx.scalar(f"SELECT coalesce(max({column}), 0) FROM {table}"))


__all__ = ["assign_positions", "current_position", "parse_position"]
