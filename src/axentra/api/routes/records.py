from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Body, Query, Response

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, IfMatch, Limit, parse_if_match
from axentra.core.errors import ValidationFailed
from axentra.core.pagination import Page
from axentra.data.records import CollectionStats, Record

router = APIRouter(prefix="/v1/products/{product_id}", tags=["records"])
C = "/tenants/{tenant_id}/records/{collection}"


@router.get("/collections", response_model=list[CollectionStats], summary="Record collections of the product")
def collections(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[CollectionStats]:
    return ax.records.collections(principal, product_id)


@router.get(C, response_model=Page[Record])
def list_records(
    product_id: str,
    tenant_id: str,
    collection: str,
    principal: CurrentPrincipal,
    ax: Ax,
    where: str | None = Query(
        None, max_length=2000, description='JSON object; records containing it match, e.g. {"status":"open"}'
    ),
    sort: Literal["id", "-id", "created_at", "-created_at", "updated_at", "-updated_at"] | None = None,
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Record]:
    filt: dict[str, Any] | None = None
    if where:
        try:
            filt = json.loads(where)
        except json.JSONDecodeError:
            raise ValidationFailed("where must be a JSON object") from None
        if not isinstance(filt, dict):
            raise ValidationFailed("where must be a JSON object")
    return ax.records.list(
        principal, product_id, tenant_id, collection, where=filt, sort=sort, limit=limit, cursor=cursor
    )


@router.post(C, response_model=Record, status_code=201)
def create_record(
    product_id: str,
    tenant_id: str,
    collection: str,
    principal: CurrentPrincipal,
    ax: Ax,
    data: dict[str, Any] = Body(...),
) -> Record:
    return ax.records.create(principal, product_id, tenant_id, collection, data)


@router.get(C + "/{record_id}", response_model=Record)
def get_record(
    product_id: str,
    tenant_id: str,
    collection: str,
    record_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    response: Response,
) -> Record:
    rec = ax.records.get(principal, product_id, tenant_id, collection, record_id)
    response.headers["ETag"] = f'"{rec.version}"'
    return rec


@router.put(C + "/{record_id}", response_model=Record)
def replace_record(
    product_id: str,
    tenant_id: str,
    collection: str,
    record_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    data: dict[str, Any] = Body(...),
    if_match: IfMatch = None,
) -> Record:
    return ax.records.replace(
        principal, product_id, tenant_id, collection, record_id, data, if_match=parse_if_match(if_match)
    )


@router.delete(C + "/{record_id}", status_code=204)
def delete_record(
    product_id: str,
    tenant_id: str,
    collection: str,
    record_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Response:
    ax.records.delete(
        principal, product_id, tenant_id, collection, record_id, if_match=parse_if_match(if_match)
    )
    return Response(status_code=204)
