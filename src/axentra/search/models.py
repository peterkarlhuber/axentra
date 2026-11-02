"""Data types of the search module (no I/O)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
import re
from typing import Any

from pydantic import BaseModel

from axentra.core.errors import PayloadTooLarge, ValidationFailed

KIND_PATTERN = r"^[a-z][a-z0-9_.-]{0,62}$"
REF_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,199}$"
_KIND = re.compile(KIND_PATTERN)
_REF_ID = re.compile(REF_ID_PATTERN)
MAX_TITLE_CHARS = 1000
MAX_METADATA_BYTES = 16 * 1024
MAX_QUERY_CHARS = 500
MAX_KINDS = 20

#: Private-use characters that delimit highlighted words between PostgreSQL and Python. They are
#: removed from indexed text, so only the highlighter produces them.
MARK_START = ""
MARK_STOP = ""
_STRIP = {ord("\x00"): None, ord(MARK_START): None, ord(MARK_STOP): None}


class SearchDocument(BaseModel):
    """One indexed document. ``kind`` + ``ref_id`` identify the source object in the product."""

    id: str
    product_id: str
    tenant_id: str
    kind: str
    ref_id: str
    title: str
    body: str
    metadata: dict[str, Any]
    language: str
    version: int
    created_by: str | None
    updated_by: str | None
    created_at: datetime
    updated_at: datetime


class SearchHit(BaseModel):
    """A query result. Highlights are HTML-escaped text in which matches are wrapped in ``<mark>``."""

    id: str
    kind: str
    ref_id: str
    title: str
    metadata: dict[str, Any]
    rank: float
    title_highlight: str
    body_highlight: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class IndexDocument:
    """What a product hands to the index (validated by :meth:`validate`)."""

    product_id: str
    tenant_id: str
    kind: str
    ref_id: str
    title: str = ""
    body: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self, *, max_body_chars: int) -> IndexDocument:
        check_kind(self.kind)
        check_ref_id(self.ref_id)
        if not isinstance(self.title, str) or not isinstance(self.body, str):
            raise ValidationFailed("title and body must be strings")
        title = self.title.translate(_STRIP)
        body = self.body.translate(_STRIP)
        if len(title) > MAX_TITLE_CHARS:
            raise ValidationFailed(f"title may have at most {MAX_TITLE_CHARS} characters")
        if len(body) > max_body_chars:
            raise PayloadTooLarge(f"body may have at most {max_body_chars} characters")
        if not title.strip() and not body.strip():
            raise ValidationFailed("a document needs a title or a body")
        if not isinstance(self.metadata, dict):
            raise ValidationFailed("metadata must be a JSON object")
        try:
            size = len(json.dumps(self.metadata, ensure_ascii=False).encode())
        except (TypeError, ValueError):
            raise ValidationFailed("metadata must be JSON serializable") from None
        if size > MAX_METADATA_BYTES or "\\u0000" in json.dumps(self.metadata):
            raise ValidationFailed(
                f"metadata must be at most {MAX_METADATA_BYTES} bytes without NUL characters"
            )
        return IndexDocument(
            self.product_id, self.tenant_id, self.kind, self.ref_id, title, body, dict(self.metadata)
        )


@dataclass(frozen=True, slots=True)
class SearchQuery:
    """A full-text query in web search syntax: words, ``"quoted phrases"``, ``or``, ``-excluded``."""

    text: str
    kinds: tuple[str, ...] = ()
    limit: int = 20
    offset: int = 0


@dataclass(frozen=True, slots=True)
class IndexResult:
    document: SearchDocument
    created: bool


def check_kind(kind: str) -> str:
    if not isinstance(kind, str) or not _KIND.match(kind):
        raise ValidationFailed(f"kind must match {KIND_PATTERN}")
    return kind


def check_ref_id(ref_id: str) -> str:
    if not isinstance(ref_id, str) or not _REF_ID.match(ref_id):
        raise ValidationFailed(f"ref_id must match {REF_ID_PATTERN}")
    return ref_id
