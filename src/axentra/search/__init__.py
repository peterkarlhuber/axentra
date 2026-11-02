"""Search module: a tenant-scoped full-text index with pluggable adapters (PostgreSQL by default).

See docs/modules/SEARCH.md.
"""

from __future__ import annotations

from axentra.search.adapters import PostgresSearchAdapter, SearchAdapter, WriteHook
from axentra.search.models import IndexDocument, IndexResult, SearchDocument, SearchHit, SearchQuery
from axentra.search.service import SearchService

__all__ = [
    "IndexDocument",
    "IndexResult",
    "PostgresSearchAdapter",
    "SearchAdapter",
    "SearchDocument",
    "SearchHit",
    "SearchQuery",
    "SearchService",
    "WriteHook",
]
