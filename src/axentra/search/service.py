"""Authorized access to the tenant search index (permission checks on top of a :class:`SearchAdapter`)."""

from __future__ import annotations

from collections.abc import Sequence
import json
from typing import Any

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.config.settings import Settings
from axentra.core.context import Principal
from axentra.core.errors import Conflict, InvalidCursor, ValidationFailed
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, Tx
from axentra.search.adapters import BulkHook, PostgresSearchAdapter, SearchAdapter, WriteHook
from axentra.search.models import (
    MATCH_MODES,
    MAX_BATCH_DOCUMENTS,
    MAX_KINDS,
    MAX_LISTED_KINDS,
    MAX_METADATA_FILTER_BYTES,
    MAX_QUERY_CHARS,
    IndexDocument,
    IndexResult,
    KindCount,
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
        self.adapter: SearchAdapter = adapter or PostgresSearchAdapter(
            db,
            language=self.settings.language,
            max_candidates=self.settings.max_candidates,
            statement_timeout_ms=self.settings.statement_timeout_ms,
        )

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

    def upsert_many(
        self, principal: Principal, product_id: str, tenant_id: str, documents: Sequence[dict[str, Any]]
    ) -> list[IndexResult]:
        """Index up to :data:`MAX_BATCH_DOCUMENTS` documents of one tenant in one transaction (all or
        nothing; ``search:index``). Each item has ``kind``, ``ref_id`` and optional ``title``,
        ``body``, ``metadata``; a ``(kind, ref_id)`` may appear once. Audited per document like
        :meth:`upsert`."""
        self.authz.require(principal, "search:index", product_id, tenant_id)
        if not documents:
            raise ValidationFailed("documents must not be empty")
        if len(documents) > MAX_BATCH_DOCUMENTS:
            raise ValidationFailed(f"at most {MAX_BATCH_DOCUMENTS} documents per batch")
        docs: list[IndexDocument] = []
        seen: set[tuple[str, str]] = set()
        for i, item in enumerate(documents):
            try:
                doc = IndexDocument(
                    product_id,
                    tenant_id,
                    item.get("kind", ""),
                    item.get("ref_id", ""),
                    item.get("title", ""),
                    item.get("body", ""),
                    item.get("metadata") or {},
                ).validate(max_body_chars=self.settings.max_body_chars)
            except ValidationFailed as exc:
                raise ValidationFailed(f"documents[{i}]: {exc.detail}") from None
            if (doc.kind, doc.ref_id) in seen:
                raise ValidationFailed(f"documents[{i}]: {doc.kind}/{doc.ref_id} appears more than once")
            seen.add((doc.kind, doc.ref_id))
            docs.append(doc)
        upsert_many = getattr(self.adapter, "upsert_many", None)
        if upsert_many is None:
            raise Conflict(f"the search adapter {self.adapter.name!r} cannot index batches")
        results: list[IndexResult] = upsert_many(
            docs, actor=principal.actor.id, hook=self._audit(principal, "search.document.upsert")
        )
        return results

    def delete_kind(self, principal: Principal, product_id: str, tenant_id: str, kind: str) -> int:
        """Remove every document of ``kind`` from the tenant's index (``search:index``); returns the
        count. One audit event ``search.documents.delete_kind`` with the kind and the count."""
        self.authz.require(principal, "search:index", product_id, tenant_id)
        check_kind(kind)
        delete_kind = getattr(self.adapter, "delete_kind", None)
        if delete_kind is None:
            raise Conflict(f"the search adapter {self.adapter.name!r} cannot delete by kind")
        hook: BulkHook | None = None
        if self.settings.audit_index_writes:

            def hook(tx: Tx, count: int) -> None:
                self.audit.record(
                    tx,
                    principal,
                    "search.documents.delete_kind",
                    target_type="search_kind",
                    target_id=kind,
                    product_id=product_id,
                    tenant_id=tenant_id,
                    details={"kind": kind, "count": count},
                )

        removed: int = delete_kind(product_id, tenant_id, kind, hook=hook)
        return removed

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

    def kinds(self, principal: Principal, product_id: str, tenant_id: str) -> list[KindCount]:
        """The kinds indexed in the tenant with their document counts (kind order, at most
        :data:`MAX_LISTED_KINDS`), so clients can offer a kind picker. ``search:query``."""
        self.authz.require(principal, "search:query", product_id, tenant_id)
        list_kinds = getattr(self.adapter, "kinds", None)
        if list_kinds is None:
            raise Conflict(f"the search adapter {self.adapter.name!r} cannot list kinds")
        result: list[KindCount] = list_kinds(product_id, tenant_id, MAX_LISTED_KINDS)
        return result

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
        match: str = "words",
        metadata: dict[str, Any] | None = None,
    ) -> Page[SearchHit]:
        """Ranked hits (``ts_rank`` desc, then newest first). The cursor encodes the result
        position; results can shift between pages when the index changes in between."""
        self.authz.require(principal, "search:query", product_id, tenant_id)
        text = (q or "").strip()
        if not text:
            raise ValidationFailed("q must not be empty")
        if len(text) > MAX_QUERY_CHARS or "\x00" in text:
            raise ValidationFailed(f"q may have at most {MAX_QUERY_CHARS} characters")
        if match not in MATCH_MODES:
            raise ValidationFailed(f"match must be one of: {', '.join(MATCH_MODES)}")
        unique_kinds = tuple(dict.fromkeys(kinds or ()))
        if len(unique_kinds) > MAX_KINDS:
            raise ValidationFailed(f"at most {MAX_KINDS} kinds per query")
        for k in unique_kinds:
            check_kind(k)
        if metadata is not None:
            if not isinstance(metadata, dict):
                raise ValidationFailed("metadata must be a JSON object")
            if len(json.dumps(metadata, ensure_ascii=False).encode()) > MAX_METADATA_FILTER_BYTES:
                raise ValidationFailed(
                    f"the metadata filter may have at most {MAX_METADATA_FILTER_BYTES} bytes"
                )
        size = clamp_limit(limit if limit is not None else DEFAULT_LIMIT)
        offset = _offset(decode_cursor(cursor))
        if offset > self.settings.max_offset:
            raise ValidationFailed(f"results beyond position {self.settings.max_offset} are not available")
        hits, more = self.adapter.query(
            product_id,
            tenant_id,
            SearchQuery(
                text=text,
                kinds=unique_kinds,
                limit=size,
                offset=offset,
                match=match,
                metadata=metadata or None,
            ),
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
