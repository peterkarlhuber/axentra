"""The append-only audit trail.

Audit events are written in the same transaction as the change they describe, so a change
without its audit event (or the reverse) cannot be committed. Details are redacted
(:func:`axentra.core.redaction.redact`) before they are stored.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from psycopg.types.json import Jsonb
from pydantic import BaseModel

from axentra.core.context import Principal
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.core.redaction import redact
from axentra.data.database import Database, DbScope, Tx

Outcome = Literal["success", "denied", "failure"]


class AuditEvent(BaseModel):
    id: str
    occurred_at: datetime
    product_id: str | None
    tenant_id: str | None
    actor_kind: str
    actor_id: str
    actor_display: str
    action: str
    target_type: str
    target_id: str
    outcome: Outcome
    request_id: str | None
    ip: str | None
    details: dict[str, Any]


class AuditLog:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        tx: Tx,
        principal: Principal | None,
        action: str,
        *,
        target_type: str = "",
        target_id: str = "",
        product_id: str | None = None,
        tenant_id: str | None = None,
        outcome: Outcome = "success",
        details: dict[str, Any] | None = None,
        actor_override: tuple[str, str, str] | None = None,
    ) -> str:
        if actor_override:
            kind, actor_id, display = actor_override
        elif principal is not None:
            kind, actor_id, display = principal.actor.kind.value, principal.actor.id, principal.actor.display
        else:
            kind, actor_id, display = "anonymous", "", ""
        event_id = new_id("aud")
        tx.execute(
            "INSERT INTO axentra_audit_events (id, product_id, tenant_id, actor_kind, actor_id, actor_display, action,"
            " target_type, target_id, outcome, request_id, ip, details)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                event_id,
                product_id,
                tenant_id,
                kind,
                actor_id,
                display[:200],
                action,
                target_type,
                target_id,
                outcome,
                principal.request_id if principal else None,
                principal.ip if principal else None,
                Jsonb(redact(details or {})),
            ),
        )
        return event_id

    def record_standalone(self, principal: Principal | None, action: str, **kwargs: Any) -> str:
        """Record an event in its own transaction (e.g. a denied login that changes nothing)."""
        product_id = kwargs.get("product_id")
        scope = DbScope.product(product_id) if product_id else DbScope.platform()
        with self.db.transaction(scope) as tx:
            return self.record(tx, principal, action, **kwargs)

    def list(
        self,
        scope: DbScope,
        *,
        product_id: str | None = None,
        tenant_id: str | None = None,
        action: str | None = None,
        actor_id: str | None = None,
        outcome: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        q: str | None = None,
        platform_only: bool = False,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[AuditEvent]:
        limit = clamp_limit(limit)
        where: list[str] = []
        params: list[Any] = []
        if platform_only:
            where.append("product_id IS NULL")
        if product_id:
            where.append("product_id = %s")
            params.append(product_id)
        if tenant_id:
            where.append("tenant_id = %s")
            params.append(tenant_id)
        if action:
            if action.endswith("*"):
                where.append("action LIKE %s")
                params.append(action[:-1].replace("%", r"\%").replace("_", r"\_") + "%")
            else:
                where.append("action = %s")
                params.append(action)
        if actor_id:
            where.append("actor_id = %s")
            params.append(actor_id)
        if outcome:
            where.append("outcome = %s")
            params.append(outcome)
        if since:
            where.append("occurred_at >= %s")
            params.append(since)
        if until:
            where.append("occurred_at < %s")
            params.append(until)
        if q:
            where.append(
                "(action ILIKE %s OR target_id ILIKE %s OR actor_display ILIKE %s OR actor_id ILIKE %s)"
            )
            like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
            params += [like, like, like, like]
        after = decode_cursor(cursor, ("timestamp", "str"))
        if after:
            where.append("(occurred_at, id) < (%s::timestamptz, %s)")
            params += [after[0], after[1]]
        sql = "SELECT * FROM axentra_audit_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY occurred_at DESC, id DESC LIMIT %s"
        params.append(limit + 1)
        with self.db.transaction(scope, read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [AuditEvent.model_validate(r) for r in rows[:limit]]
        nxt = encode_cursor([items[-1].occurred_at.isoformat(), items[-1].id]) if len(rows) > limit else None
        return Page[AuditEvent](items=items, next_cursor=nxt)

    def get(self, scope: DbScope, event_id: str) -> AuditEvent:
        with self.db.transaction(scope, read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_audit_events WHERE id = %s", (event_id,), what="audit event"
            )
        return AuditEvent.model_validate(row)

    def purge(self, retention_days: int) -> int:
        with self.db.transaction(DbScope.platform()) as tx:
            return tx.execute(
                "DELETE FROM axentra_audit_events WHERE occurred_at < now() - make_interval(days => %s)",
                (retention_days,),
            )
