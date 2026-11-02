"""Authorized access to the tenant search index (permission checks on top of a :class:`SearchAdapter`)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.config.settings import Settings
from axentra.core.context import Principal
from axentra.core.errors import InvalidCursor, ValidationFailed
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, Tx
from axentra.search.adapters import PostgresSearchAdapter, SearchAdapter, WriteHook
from axentra.search.models import (
    MAX_KINDS,
    MAX_QUERY_CHARS,
    IndexDocument,
    IndexResult,
    SearchDocument,
    SearchHit,
    SearchQuery,
    check_kind,
    check_ref_id,
)

DEFAULT_LIMIT = 20


class SearchService:
    """Products index their objects (``upsert``/``delete`` by kind + ref_id) and users query them.

    Permissions: ``search:query`` for :meth:`query` and :meth:`get`, ``search:index`` for
    :meth:`upsert` and :meth:`delete`. Index writes are audited (``search.document.upsert`` /
    ``search.document.delete``, without title, body or metadata) unless
    ``search.audit_index_writes`` is off.
    """

    def __init__(
        self,
        db: Database,
        settings: Settings,
        authz: Authorizer,
        audit: AuditLog,
        adapter: SearchAdapter | None = None,
    ) -> None:
        self.db = db
        self.settings = settings.search
        self.authz = authz
        self.audit = audit
        self.adapter: SearchAdapter = adapter or PostgresSearchAdapter(db, language=self.settings.language)

    def set_adapter(self, adapter: SearchAdapter) -> None:
        """Replace the default PostgreSQL adapter (e.g. with an external search engine)."""
        self.adapter = adapter

    # -- writes ---------------------------------------------------------------------------------

    def upsert(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        kind: str,
        ref_id: str,
        *,
        title: str = "",
        body: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> IndexResult:
        self.authz.require(principal, "search:index", product_id, tenant_id)
        doc = IndexDocument(product_id, tenant_id, kind, ref_id, title, body, metadata or {}).validate(
            max_body_chars=self.settings.max_body_chars
        )
        return self.adapter.upsert(
            doc, actor=principal.actor.id, hook=self._audit(principal, "search.document.upsert")
        )

    def delete(self, principal: Principal, product_id: str, tenant_id: str, kind: str, ref_id: str) -> None:
        self.authz.require(principal, "search:index", product_id, tenant_id)
        check_kind(kind)
        check_ref_id(ref_id)
        self.adapter.delete(
            product_id, tenant_id, kind, ref_id, hook=self._audit(principal, "search.document.delete")
        )

    def _audit(self, principal: Principal, action: str) -> WriteHook | None:
        if not self.settings.audit_index_writes:
            return None

        def hook(tx: Tx, doc: SearchDocument) -> None:
            self.audit.record(
                tx,
                principal,
                action,
                target_type="search_document",
                target_id=doc.id,
                product_id=doc.product_id,
                tenant_id=doc.tenant_id,
                details={"kind": doc.kind, "ref_id": doc.ref_id, "version": doc.version},
            )

        return hook

    # -- reads ----------------------------------------------------------------------------------

    def get(
        self, principal: Principal, product_id: str, tenant_id: str, kind: str, ref_id: str
    ) -> SearchDocument:
        self.authz.require(principal, "search:query", product_id, tenant_id)
        check_kind(kind)
        check_ref_id(ref_id)
        return self.adapter.get(product_id, tenant_id, kind, ref_id)

    def query(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        q: str,
        *,
        kinds: Sequence[str] | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[SearchHit]:
        """Ranked hits (``ts_rank`` desc, then newest first). The cursor encodes the result
        position; results can shift between pages when the index changes in between."""
        self.authz.require(principal, "search:query", product_id, tenant_id)
        text = (q or "").strip()
        if not text:
            raise ValidationFailed("q must not be empty")
        if len(text) > MAX_QUERY_CHARS or "\x00" in text:
            raise ValidationFailed(f"q may have at most {MAX_QUERY_CHARS} characters")
        unique_kinds = tuple(dict.fromkeys(kinds or ()))
        if len(unique_kinds) > MAX_KINDS:
            raise ValidationFailed(f"at most {MAX_KINDS} kinds per query")
        for k in unique_kinds:
            check_kind(k)
        size = clamp_limit(limit if limit is not None else DEFAULT_LIMIT)
        offset = _offset(decode_cursor(cursor))
        if offset > self.settings.max_offset:
            raise ValidationFailed(f"results beyond position {self.settings.max_offset} are not available")
        hits, more = self.adapter.query(
            product_id, tenant_id, SearchQuery(text=text, kinds=unique_kinds, limit=size, offset=offset)
        )
        nxt = offset + size
        next_cursor = encode_cursor(["o", nxt]) if more and nxt <= self.settings.max_offset else None
        return Page(items=hits, next_cursor=next_cursor)


def _offset(values: list[Any] | None) -> int:
    if values is None:
        return 0
    if len(values) != 2 or values[0] != "o" or not isinstance(values[1], int) or isinstance(values[1], bool):
        raise InvalidCursor()
    if values[1] < 0:
        raise InvalidCursor()
    return values[1]
