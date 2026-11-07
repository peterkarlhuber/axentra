"""Search adapters: where the index lives and how it is queried.

:class:`SearchAdapter` is the pluggable interface. :class:`PostgresSearchAdapter` (the default)
keeps the index in ``axentra_search_documents`` (migration ``0006``) and queries it with PostgreSQL
full-text search. Adapters do no authorization; :class:`axentra.search.service.SearchService`
authorizes first.

An adapter for an external engine implements the same methods. Its writes cannot share a
transaction with Axentra's database, so it must call ``hook`` in a ``db.transaction`` of the tenant
scope after the external write succeeded (the audit event then follows the write instead of being
atomic with it), and it must enforce the tenant filter in every query itself.
"""

from __future__ import annotations

from collections.abc import Callable
import html
import threading
from typing import Any, Protocol, runtime_checkable

import psycopg
from psycopg.types.json import Jsonb

from axentra.core.errors import ConfigurationError, NotFound, ValidationFailed
from axentra.core.ids import new_id
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.search.models import (
    MARK_START,
    MARK_STOP,
    MAX_PREFIX_TERMS,
    IndexDocument,
    IndexResult,
    KindCount,
    SearchDocument,
    SearchHit,
    SearchQuery,
)

#: Called inside the write transaction (PostgreSQL) or right after the external write (other
#: adapters) with the stored document, e.g. to write the audit event.
WriteHook = Callable[[Tx, SearchDocument], None]
#: ``reason`` of the ``422`` for a search cancelled by ``search.statement_timeout_ms``.
QUERY_TOO_EXPENSIVE = "query_too_expensive"


@runtime_checkable
class SearchAdapter(Protocol):
    name: str

    def upsert(self, doc: IndexDocument, *, actor: str | None, hook: WriteHook | None = None) -> IndexResult:
        """Insert or replace the document identified by (product, tenant, kind, ref_id)."""
        ...

    def get(self, product_id: str, tenant_id: str, kind: str, ref_id: str) -> SearchDocument:
        """The stored document; ``NotFound`` if there is none."""
        ...

    def delete(
        self, product_id: str, tenant_id: str, kind: str, ref_id: str, *, hook: WriteHook | None = None
    ) -> SearchDocument:
        """Remove the document and return what was removed; ``NotFound`` if there is none."""
        ...

    def query(self, product_id: str, tenant_id: str, query: SearchQuery) -> tuple[list[SearchHit], bool]:
        """Ranked hits of one tenant at ``query.offset`` and whether more follow."""
        ...

    # Optional: ``kinds(product_id, tenant_id, limit) -> list[KindCount]`` (the tenant's indexed
    # kinds in kind order with their counts). Adapters without it answer ``GET .../search/kinds``
    # with ``409 conflict``; the PostgreSQL adapter has it.


_COLUMNS = (
    "id, product_id, tenant_id, kind, ref_id, title, body, metadata, language::text AS language,"
    " version, created_by, updated_by, created_at, updated_at"
)
_TITLE_OPTS = f"HighlightAll=true, StartSel={MARK_START}, StopSel={MARK_STOP}"
_BODY_OPTS = (
    f"MaxFragments=2, MaxWords=24, MinWords=8, StartSel={MARK_START}, StopSel={MARK_STOP},"
    ' FragmentDelimiter=" ... "'
)


def render_highlight(text: str) -> str:
    """HTML-escape ``ts_headline`` output and turn the private-use delimiters into ``<mark>``."""
    return html.escape(text, quote=True).replace(MARK_START, "<mark>").replace(MARK_STOP, "</mark>")


class PostgresSearchAdapter:
    """PostgreSQL full-text search: generated ``tsvector`` (title weight A, body weight B), GIN
    index, ``websearch_to_tsquery``, ``ts_rank`` and ``ts_headline``. Every statement runs in a
    tenant-scoped transaction, so row-level security confines it to that tenant."""

    name = "postgres"

    def __init__(
        self,
        db: Database,
        *,
        language: str = "simple",
        max_candidates: int = 10_000,
        statement_timeout_ms: int = 5_000,
    ) -> None:
        self.db = db
        self.language = language
        self.max_candidates = max_candidates
        self.statement_timeout_ms = statement_timeout_ms
        self._checked = False
        self._lock = threading.Lock()

    def _lang(self) -> str:
        if not self._checked:
            with self._lock:
                if not self._checked:
                    try:
                        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
                            tx.one("SELECT %s::regconfig AS cfg", (self.language,))
                    except psycopg.Error:
                        raise ConfigurationError(
                            f"search.language {self.language!r} is not a PostgreSQL text search configuration"
                        ) from None
                    self._checked = True
        return self.language

    @staticmethod
    def _doc(row: Row) -> SearchDocument:
        return SearchDocument(**{k: v for k, v in row.items() if k != "inserted"})

    def upsert(self, doc: IndexDocument, *, actor: str | None, hook: WriteHook | None = None) -> IndexResult:
        lang = self._lang()
        with self.db.transaction(DbScope.tenant(doc.product_id, doc.tenant_id)) as tx:
            row = tx.one(
                "INSERT INTO axentra_search_documents AS d"
                " (id, product_id, tenant_id, kind, ref_id, title, body, metadata, language,"
                "  created_by, updated_by)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::regconfig, %s, %s)"
                " ON CONFLICT (product_id, tenant_id, kind, ref_id) DO UPDATE SET"
                "  title = EXCLUDED.title, body = EXCLUDED.body, metadata = EXCLUDED.metadata,"
                "  language = EXCLUDED.language, updated_by = EXCLUDED.updated_by,"
                "  version = d.version + 1, updated_at = now()"
                f" RETURNING {_COLUMNS}, (xmax = 0) AS inserted",
                (
                    new_id("sdoc"),
                    doc.product_id,
                    doc.tenant_id,
                    doc.kind,
                    doc.ref_id,
                    doc.title,
                    doc.body,
                    Jsonb(doc.metadata),
                    lang,
                    actor,
                    actor,
                ),
            )
            assert row is not None
            stored = self._doc(row)
            if hook is not None:
                hook(tx, stored)
        return IndexResult(document=stored, created=bool(row["inserted"]))

    def get(self, product_id: str, tenant_id: str, kind: str, ref_id: str) -> SearchDocument:
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            row = tx.one_or_404(
                f"SELECT {_COLUMNS} FROM axentra_search_documents"
                " WHERE product_id = %s AND tenant_id = %s AND kind = %s AND ref_id = %s",
                (product_id, tenant_id, kind, ref_id),
                what="search document",
            )
        return self._doc(row)

    def delete(
        self, product_id: str, tenant_id: str, kind: str, ref_id: str, *, hook: WriteHook | None = None
    ) -> SearchDocument:
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            row = tx.one(
                "DELETE FROM axentra_search_documents"
                " WHERE product_id = %s AND tenant_id = %s AND kind = %s AND ref_id = %s"
                f" RETURNING {_COLUMNS}",
                (product_id, tenant_id, kind, ref_id),
            )
            if row is None:
                raise NotFound("search document not found")
            removed = self._doc(row)
            if hook is not None:
                hook(tx, removed)
        return removed

    def kinds(self, product_id: str, tenant_id: str, limit: int) -> list[KindCount]:
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT kind, count(*) AS n FROM axentra_search_documents"
                " WHERE product_id = %s AND tenant_id = %s GROUP BY kind ORDER BY kind LIMIT %s",
                (product_id, tenant_id, limit),
            )
        return [KindCount(kind=r["kind"], count=int(r["n"])) for r in rows]

    def query(self, product_id: str, tenant_id: str, query: SearchQuery) -> tuple[list[SearchHit], bool]:
        lang = self._lang()
        params: dict[str, Any] = {
            "lang": lang,
            "q": query.text,
            "p": product_id,
            "t": tenant_id,
            "kinds": list(query.kinds),
            "offset": query.offset,
            "limit": query.limit + 1,
            "title_opts": _TITLE_OPTS,
            "body_opts": _BODY_OPTS,
            "max_candidates": self.max_candidates,
        }
        kind_filter = " AND d.kind = ANY(%(kinds)s)" if query.kinds else ""
        if query.match == "prefix":
            # Terms are only letters and digits (split on everything else), so quoting them in the
            # tsquery syntax is safe; the configuration still normalizes each one (case, stemming).
            params["max_terms"] = MAX_PREFIX_TERMS
            tsquery = (
                "(SELECT to_tsquery(%(lang)s::regconfig, coalesce(string_agg("
                " chr(39) || term || chr(39) || CASE WHEN char_length(term) >= 2 THEN ':*' ELSE '' END,"
                " ' & ' ORDER BY n), ''))"
                " FROM (SELECT term, n FROM regexp_split_to_table(%(q)s, '[^[:alnum:]]+')"
                " WITH ORDINALITY AS t(term, n) WHERE term <> '' ORDER BY n LIMIT %(max_terms)s) terms)"
            )
        else:
            tsquery = "websearch_to_tsquery(%(lang)s::regconfig, %(q)s)"
        # Bound the work first: at most max_candidates matches (the GIN index finds them without
        # reading every match) are ranked; then rank and page; ts_headline (expensive on long
        # bodies) runs only for the page.
        sql = (
            f"WITH q AS (SELECT {tsquery} AS query),"
            " candidates AS ("
            "  SELECT d.id, d.kind, d.ref_id, d.title, d.body, d.metadata, d.updated_at, d.language,"
            "         d.search_vector"
            "  FROM axentra_search_documents d, q"
            "  WHERE d.product_id = %(p)s AND d.tenant_id = %(t)s AND numnode(q.query) > 0"
            "    AND d.search_vector @@ q.query" + kind_filter + "  LIMIT %(max_candidates)s),"
            " page AS ("
            "  SELECT c.id, c.kind, c.ref_id, c.title, c.body, c.metadata, c.updated_at, c.language,"
            "         ts_rank(c.search_vector, q.query) AS rank"
            "  FROM candidates c, q"
            "  ORDER BY rank DESC, c.updated_at DESC, c.id"
            "  OFFSET %(offset)s LIMIT %(limit)s)"
            " SELECT page.id, page.kind, page.ref_id, page.title, page.metadata, page.updated_at,"
            "        page.rank::float8 AS rank,"
            "        ts_headline(page.language, page.title, q.query, %(title_opts)s) AS title_highlight,"
            "        ts_headline(page.language, page.body, q.query, %(body_opts)s) AS body_highlight"
            " FROM page, q ORDER BY page.rank DESC, page.updated_at DESC, page.id"
        )
        try:
            with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
                # Transaction-local; inside a host transaction (Database.joined) the savepoint is
                # released afterwards, so the previous value is put back explicitly.
                previous = tx.scalar("SELECT current_setting('statement_timeout')")
                tx.execute(
                    "SELECT set_config('statement_timeout', %s, true)", (f"{self.statement_timeout_ms}ms",)
                )
                rows = tx.all(sql, params)
                tx.execute("SELECT set_config('statement_timeout', %s, true)", (str(previous),))
        except psycopg.errors.QueryCanceled:
            raise ValidationFailed(
                "the search took too long; use more specific terms or a kind filter",
                extra={"reason": QUERY_TOO_EXPENSIVE},
            ) from None
        more = len(rows) > query.limit
        hits = [
            SearchHit(
                id=r["id"],
                kind=r["kind"],
                ref_id=r["ref_id"],
                title=r["title"],
                metadata=r["metadata"],
                rank=r["rank"],
                title_highlight=render_highlight(r["title_highlight"]),
                body_highlight=render_highlight(r["body_highlight"]),
                updated_at=r["updated_at"],
            )
            for r in rows[: query.limit]
        ]
        return hits, more
