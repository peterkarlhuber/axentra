"""HTTP API of the search module (tenant-scoped full-text query and index writes)."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Query, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, Limit
from axentra.core.errors import ModuleDisabled, ValidationFailed
from axentra.core.pagination import Page
from axentra.platform import Axentra
from axentra.search.models import (
    KIND_PATTERN,
    MAX_BATCH_DOCUMENTS,
    MAX_KINDS,
    MAX_QUERY_CHARS,
    MAX_TITLE_CHARS,
    REF_ID_PATTERN,
    KindCount,
    SearchDocument,
    SearchHit,
)
from axentra.search.service import SearchService

router = APIRouter(prefix="/v1/products/{product_id}/tenants/{tenant_id}/search", tags=["search"])
D = "/documents/{kind}/{ref_id}"

Kind = Annotated[str, Path(pattern=KIND_PATTERN, description="Document kind, e.g. `invoice`")]
RefId = Annotated[str, Path(pattern=REF_ID_PATTERN, description="Id of the source object in the product")]


def _svc(ax: Axentra) -> SearchService:
    if ax.search is None:
        raise ModuleDisabled("the search module is not enabled")
    return ax.search


class DocumentUpsert(BaseModel):
    title: str = Field(default="", max_length=MAX_TITLE_CHARS)
    body: str = Field(default="", description="Plain text; the limit is search.max_body_chars")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Returned with hits (at most 16 KB); not searched"
    )


class BatchDocument(DocumentUpsert):
    kind: str = Field(pattern=KIND_PATTERN)
    ref_id: str = Field(pattern=REF_ID_PATTERN)


class BatchUpsert(BaseModel):
    documents: list[BatchDocument] = Field(min_length=1, max_length=MAX_BATCH_DOCUMENTS)


class BatchResult(BaseModel):
    created: int
    updated: int
    documents: list[SearchDocument]


class DeleteKindResult(BaseModel):
    deleted: int


@router.get(
    "",
    response_model=Page[SearchHit],
    summary="Full-text search in the tenant's index (ranked, highlighted)",
)
def search(
    product_id: str,
    tenant_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    q: str = Query(
        ...,
        min_length=1,
        max_length=MAX_QUERY_CHARS,
        description='Web search syntax: words (all must match), "quoted phrase", or, -excluded',
    ),
    kind: list[str] | None = Query(
        None, max_length=MAX_KINDS, description="Only these kinds (repeat the parameter for several)"
    ),
    match: Literal["words", "prefix"] = Query(
        "words",
        description=(
            "`words`: web search syntax. `prefix` (search as you type): every term must match, and"
            " terms of two or more characters also match words that start with them"
        ),
    ),
    metadata: str | None = Query(
        None,
        max_length=2000,
        description='JSON object; only documents whose metadata contains it, e.g. {"status":"open"}',
    ),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[SearchHit]:
    filt: dict[str, Any] | None = None
    if metadata:
        try:
            filt = json.loads(metadata)
        except json.JSONDecodeError:
            raise ValidationFailed("metadata must be a JSON object") from None
        if not isinstance(filt, dict):
            raise ValidationFailed("metadata must be a JSON object")
    return _svc(ax).query(
        principal,
        product_id,
        tenant_id,
        q,
        kinds=kind,
        limit=limit,
        cursor=cursor,
        match=match,
        metadata=filt,
    )


@router.post(
    "/documents/batch",
    response_model=BatchResult,
    summary=f"Index up to {MAX_BATCH_DOCUMENTS} documents in one transaction (all or nothing)",
)
def upsert_batch(
    product_id: str, tenant_id: str, body: BatchUpsert, principal: CurrentPrincipal, ax: Ax
) -> BatchResult:
    """Each document is created or replaced by kind and ref_id, as with `PUT .../documents/{kind}/{ref_id}`;
    a (kind, ref_id) may appear once. `search:index` in the tenant."""
    results = _svc(ax).upsert_many(principal, product_id, tenant_id, [d.model_dump() for d in body.documents])
    created = sum(1 for r in results if r.created)
    return BatchResult(
        created=created, updated=len(results) - created, documents=[r.document for r in results]
    )


@router.delete(
    "/documents/{kind}",
    response_model=DeleteKindResult,
    summary="Remove every document of a kind from the tenant's index",
)
def delete_kind(
    product_id: str, tenant_id: str, kind: Kind, principal: CurrentPrincipal, ax: Ax
) -> DeleteKindResult:
    """`search:index` in the tenant; one audit event `search.documents.delete_kind` with the count."""
    return DeleteKindResult(deleted=_svc(ax).delete_kind(principal, product_id, tenant_id, kind))


@router.get(
    "/kinds",
    response_model=list[KindCount],
    summary="The document kinds indexed in the tenant, with counts (kind order, at most 500)",
)
def list_kinds(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> list[KindCount]:
    """Lets clients offer a kind picker for the `kind` filter. `search:query` in the tenant."""
    return _svc(ax).kinds(principal, product_id, tenant_id)


@router.get(D, response_model=SearchDocument, summary="An indexed document")
def get_document(
    product_id: str, tenant_id: str, kind: Kind, ref_id: RefId, principal: CurrentPrincipal, ax: Ax
) -> SearchDocument:
    return _svc(ax).get(principal, product_id, tenant_id, kind, ref_id)


@router.put(
    D,
    response_model=SearchDocument,
    summary="Index a document (create or replace by kind and ref_id)",
    responses={201: {"model": SearchDocument, "description": "Created"}},
)
def upsert_document(
    product_id: str,
    tenant_id: str,
    kind: Kind,
    ref_id: RefId,
    body: DocumentUpsert,
    principal: CurrentPrincipal,
    ax: Ax,
    response: Response,
) -> SearchDocument:
    result = _svc(ax).upsert(
        principal,
        product_id,
        tenant_id,
        kind,
        ref_id,
        title=body.title,
        body=body.body,
        metadata=body.metadata,
    )
    response.status_code = 201 if result.created else 200
    return result.document


@router.delete(D, status_code=204, summary="Remove a document from the index")
def delete_document(
    product_id: str, tenant_id: str, kind: Kind, ref_id: RefId, principal: CurrentPrincipal, ax: Ax
) -> Response:
    _svc(ax).delete(principal, product_id, tenant_id, kind, ref_id)
    return Response(status_code=204)
