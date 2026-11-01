"""Tenant-owned JSON records: a generic store for product data that does not need its own table.

Records live in collections (``^[a-z][a-z0-9_]{0,62}$``) inside one tenant. Every operation runs in
a tenant-scoped transaction, so row-level security confines it to that tenant even if a filter
were wrong. Updates use optimistic concurrency (``version``).

For relational product data, products define their own tables with ``product_id``/``tenant_id``
columns and the same RLS policy (see docs/guides/PRODUCT_TABLES.md) and use
:meth:`axentra.data.database.Database.transaction` with a tenant scope.
"""

from __future__ import annotations

import builtins
from datetime import datetime
import json
import re
from typing import Any

from psycopg.types.json import Jsonb
from pydantic import BaseModel

from axentra.core.errors import NotFound, PayloadTooLarge, PreconditionFailed, ValidationFailed
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope

_COLLECTION = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
MAX_RECORD_BYTES = 256 * 1024


class Record(BaseModel):
    id: str
    product_id: str
    tenant_id: str
    collection: str
    data: dict[str, Any]
    version: int
    created_by: str | None
    updated_by: str | None
    created_at: datetime
    updated_at: datetime


class CollectionStats(BaseModel):
    collection: str
    records: int
    tenants: int
    last_updated_at: datetime | None


def _check_collection(name: str) -> str:
    if not _COLLECTION.match(name):
        raise ValidationFailed("collection must match ^[a-z][a-z0-9_]{0,62}$")
    return name


def _check_data(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationFailed("record data must be a JSON object")
    if len(json.dumps(data)) > MAX_RECORD_BYTES:
        raise PayloadTooLarge(f"a record may hold at most {MAX_RECORD_BYTES} bytes")
    return data


class RecordStore:
    """Data access without authorization; callers (services, the API) authorize first."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self, product_id: str, tenant_id: str, collection: str, data: dict[str, Any], *, actor: str
    ) -> Record:
        rid = new_id("rec")
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            row = tx.one_or_404(
                "INSERT INTO axentra_records (id, product_id, tenant_id, collection, data, created_by, updated_by)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
                (
                    rid,
                    product_id,
                    tenant_id,
                    _check_collection(collection),
                    Jsonb(_check_data(data)),
                    actor,
                    actor,
                ),
            )
        return Record.model_validate(row)

    def get(self, product_id: str, tenant_id: str, collection: str, record_id: str) -> Record:
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            row = tx.one(
                "SELECT * FROM axentra_records WHERE id = %s AND collection = %s AND tenant_id = %s"
                " AND product_id = %s",
                (record_id, collection, tenant_id, product_id),
            )
        if row is None:
            raise NotFound("record not found")
        return Record.model_validate(row)

    def list(
        self,
        product_id: str,
        tenant_id: str,
        collection: str,
        *,
        where: dict[str, Any] | None = None,
        sort: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Record]:
        limit = clamp_limit(limit)
        _check_collection(collection)
        clauses = ["product_id = %s", "tenant_id = %s", "collection = %s"]
        params: list[Any] = [product_id, tenant_id, collection]
        if where:
            for field in where:
                if not _FIELD.match(field):
                    raise ValidationFailed(f"invalid filter field {field!r}")
            clauses.append("data @> %s")
            params.append(Jsonb(where))
        desc = bool(sort and sort.startswith("-"))
        sort_field = (sort or "id").lstrip("-")
        if sort_field not in ("id", "created_at", "updated_at"):
            raise ValidationFailed("sort must be id, created_at or updated_at (prefix - for descending)")
        after = decode_cursor(cursor)
        op = "<" if desc else ">"
        if after:
            if sort_field == "id":
                clauses.append(f"id {op} %s")
                params.append(after[1])
            else:
                clauses.append(f"({sort_field}, id) {op} (%s::timestamptz, %s)")
                params += [after[0], after[1]]
        direction = "DESC" if desc else "ASC"
        order = f"id {direction}" if sort_field == "id" else f"{sort_field} {direction}, id {direction}"
        params.append(limit + 1)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(
                f"SELECT * FROM axentra_records WHERE {' AND '.join(clauses)} ORDER BY {order} LIMIT %s",
                params,
            )
        items = [Record.model_validate(r) for r in rows[:limit]]
        nxt = None
        if len(rows) > limit:
            last = items[-1]
            key = last.id if sort_field == "id" else getattr(last, sort_field).isoformat()
            nxt = encode_cursor([key, last.id])
        return Page[Record](items=items, next_cursor=nxt)

    def replace(
        self,
        product_id: str,
        tenant_id: str,
        collection: str,
        record_id: str,
        data: dict[str, Any],
        *,
        actor: str,
        if_match: int | None = None,
    ) -> Record:
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            cur = tx.one(
                "SELECT version FROM axentra_records WHERE id = %s AND collection = %s AND tenant_id = %s"
                " AND product_id = %s FOR UPDATE",
                (record_id, collection, tenant_id, product_id),
            )
            if cur is None:
                raise NotFound("record not found")
            if if_match is not None and cur["version"] != if_match:
                raise PreconditionFailed("the record was changed by someone else")
            row = tx.one_or_404(
                "UPDATE axentra_records SET data = %s, version = version + 1, updated_by = %s,"
                " updated_at = now() WHERE id = %s RETURNING *",
                (Jsonb(_check_data(data)), actor, record_id),
            )
        return Record.model_validate(row)

    def delete(
        self, product_id: str, tenant_id: str, collection: str, record_id: str, *, if_match: int | None = None
    ) -> None:
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            cur = tx.one(
                "SELECT version FROM axentra_records WHERE id = %s AND collection = %s AND tenant_id = %s"
                " AND product_id = %s FOR UPDATE",
                (record_id, collection, tenant_id, product_id),
            )
            if cur is None:
                raise NotFound("record not found")
            if if_match is not None and cur["version"] != if_match:
                raise PreconditionFailed("the record was changed by someone else")
            tx.execute("DELETE FROM axentra_records WHERE id = %s", (record_id,))

    def collections(self, product_id: str) -> builtins.list[CollectionStats]:
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT collection, count(*) AS records, count(DISTINCT tenant_id) AS tenants,"
                " max(updated_at) AS last_updated_at FROM axentra_records WHERE product_id = %s"
                " GROUP BY collection ORDER BY collection",
                (product_id,),
            )
        return [CollectionStats.model_validate(r) for r in rows]
