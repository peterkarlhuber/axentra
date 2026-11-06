"""HTTP API of the search module (tenant-scoped full-text query and index writes)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, Limit
from axentra.core.errors import ModuleDisabled
from axentra.core.pagination import Page
from axentra.platform import Axentra
from axentra.search.models import (
    KIND_PATTERN,
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
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[SearchHit]:
    return _svc(ax).query(principal, product_id, tenant_id, q, kinds=kind, limit=limit, cursor=cursor)


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
