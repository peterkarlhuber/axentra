"""HTTP API of the storage module (files, download URLs, usage and quotas)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
import json
from typing import Any, Literal

from fastapi import APIRouter, Body, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.limits import own_body_limit
from axentra.api.multipart import parse_upload
from axentra.api.routes.common import Cursor, IfMatch, Limit, parse_if_match
from axentra.core.errors import ModuleDisabled, ValidationFailed
from axentra.core.pagination import Page
from axentra.platform import Axentra
from axentra.storage import safety
from axentra.storage.models import (
    DownloadUrl,
    FileInfo,
    ProductStorageUsage,
    StoragePolicy,
    TenantStorageUsage,
)
from axentra.storage.service import StorageService

router = APIRouter(prefix="/v1", tags=["files"])
F = "/products/{product_id}/tenants/{tenant_id}/files"

_UPLOAD_BODY: dict[str, Any] = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file": {"type": "string", "format": "binary"},
                        "name": {"type": "string", "description": "Display name (defaults to the file name)"},
                        "metadata": {
                            "type": "string",
                            "description": "JSON object of user labels (max 8 KiB)",
                        },
                        "expires_at": {"type": "string", "format": "date-time"},
                    },
                }
            }
        },
    }
}
_BINARY: dict[int | str, dict[str, Any]] = {
    200: {"content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}
}


class FileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=1000)
    metadata: dict[str, Any] | None = None


class DownloadUrlRequest(BaseModel):
    ttl_seconds: int | None = Field(default=None, ge=1, le=86_400)


class QuotaSet(BaseModel):
    quota_bytes: int | None = Field(default=None, ge=0, description="null: inherit the product default")
    quota_files: int | None = Field(default=None, ge=0, description="null: inherit the product default")


class StoragePolicySet(BaseModel):
    blocked_types: Literal["refuse", "store_inert"] | None = Field(
        default=None, description="null: inherit the installation setting (storage.store_blocked_as_inert)"
    )
    blocked_extensions: list[str] = Field(default_factory=list, max_length=100)
    blocked_content_types: list[str] = Field(default_factory=list, max_length=100)
    inert_extensions: list[str] = Field(default_factory=list, max_length=100)


def _svc(ax: Axentra) -> StorageService:
    if ax.storage is None:
        raise ModuleDisabled("the storage module is not enabled")
    return ax.storage


def _json_object(value: str | None, what: str) -> dict[str, Any] | None:
    if value is None or value == "":
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        raise ValidationFailed(f"{what} must be a JSON object") from None
    if not isinstance(parsed, dict):
        raise ValidationFailed(f"{what} must be a JSON object")
    if not _storable(parsed):
        # Form fields and query strings bypass the JSON-body NUL guard, and a JSON escape can still
        # produce U+0000 or a lone surrogate, which PostgreSQL refuses with a 500.
        raise ValidationFailed(f"{what} must not contain NUL characters or lone surrogates")
    return parsed


def _storable(value: Any) -> bool:
    if isinstance(value, str):
        if "\x00" in value:
            return False
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, list):
        return all(_storable(v) for v in value)
    if isinstance(value, dict):
        return all(_storable(k) and _storable(v) for k, v in value.items())
    return True


def _file_response(info: FileInfo, stream: Iterator[bytes]) -> StreamingResponse:
    headers = {
        "Content-Disposition": safety.content_disposition(info.name),
        "Content-Length": str(info.size),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store",
        "Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
    }
    if info.sha256:
        headers["ETag"] = f'"{info.sha256}"'
    return StreamingResponse(
        stream, media_type=safety.served_content_type(info.content_type), headers=headers
    )


@router.post(F, response_model=FileInfo, status_code=201, summary="Upload a file", openapi_extra=_UPLOAD_BODY)
@own_body_limit  # storage.max_file_bytes, enforced while streaming (axentra.api.multipart)
async def upload_file(
    product_id: str, tenant_id: str, request: Request, principal: CurrentPrincipal, ax: Ax
) -> FileInfo:
    svc = _svc(ax)
    # Authorize before reading the body, so unauthorized callers cannot make the server spool data.
    await run_in_threadpool(ax.authz.require, principal, "files:write", product_id, tenant_id)
    form = await parse_upload(request, max_file_bytes=svc.max_file_bytes)
    try:
        metadata = _json_object(form.fields.get("metadata"), "metadata")
        expires_at = None
        if form.fields.get("expires_at"):
            try:
                expires_at = datetime.fromisoformat(form.fields["expires_at"].strip())
            except ValueError:
                raise ValidationFailed("expires_at must be an RFC 3339 timestamp") from None
        return await run_in_threadpool(
            svc.upload,
            principal,
            product_id,
            tenant_id,
            form.file,  # type: ignore[arg-type]
            name=form.fields.get("name") or form.filename,
            content_type=form.content_type,
            metadata=metadata,
            expires_at=expires_at,
        )
    finally:
        form.close()


@router.get(F, response_model=Page[FileInfo], summary="List files")
def list_files(
    product_id: str,
    tenant_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    q: str | None = Query(None, max_length=200, description="Substring of the name (case-insensitive)"),
    content_type: str | None = Query(None, max_length=255, description="Exact type or type/*"),
    metadata: str | None = Query(
        None,
        max_length=2000,
        description='JSON object; files whose metadata contains it, e.g. {"kind":"invoice"}',
    ),
    created_by: str | None = Query(None, max_length=100),
    sort: Literal["created_at", "-created_at", "name", "-name", "size", "-size"] | None = Query(
        None, description="Default -created_at"
    ),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[FileInfo]:
    return _svc(ax).list(
        principal,
        product_id,
        tenant_id,
        q=q,
        content_type=content_type,
        metadata=_json_object(metadata, "metadata"),
        created_by=created_by,
        sort=sort,
        limit=limit,
        cursor=cursor,
    )


@router.get(F + "/{file_id}", response_model=FileInfo, summary="File metadata")
def get_file(
    product_id: str, tenant_id: str, file_id: str, principal: CurrentPrincipal, ax: Ax, response: Response
) -> FileInfo:
    info = _svc(ax).get(principal, product_id, tenant_id, file_id)
    response.headers["ETag"] = f'"{info.version}"'
    return info


@router.get(
    F + "/{file_id}/content",
    response_class=StreamingResponse,
    responses=_BINARY,
    summary="Download the file content (always as attachment)",
)
def download_file(
    product_id: str, tenant_id: str, file_id: str, principal: CurrentPrincipal, ax: Ax
) -> StreamingResponse:
    info, stream = _svc(ax).open(principal, product_id, tenant_id, file_id)
    return _file_response(info, stream)


@router.patch(F + "/{file_id}", response_model=FileInfo, summary="Rename a file or replace its metadata")
def update_file(
    product_id: str,
    tenant_id: str,
    file_id: str,
    body: FileUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> FileInfo:
    return _svc(ax).update(
        principal,
        product_id,
        tenant_id,
        file_id,
        name=body.name,
        metadata=body.metadata,
        if_match=parse_if_match(if_match),
    )


@router.delete(F + "/{file_id}", status_code=204, summary="Delete a file and its stored object")
def delete_file(
    product_id: str,
    tenant_id: str,
    file_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Response:
    _svc(ax).delete(principal, product_id, tenant_id, file_id, if_match=parse_if_match(if_match))
    return Response(status_code=204)


@router.post(
    F + "/{file_id}/download-url", response_model=DownloadUrl, summary="Create a short-lived download URL"
)
def create_download_url(
    product_id: str,
    tenant_id: str,
    file_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    body: DownloadUrlRequest | None = Body(None),
) -> DownloadUrl:
    return _svc(ax).create_download_url(
        principal, product_id, tenant_id, file_id, ttl_seconds=body.ttl_seconds if body else None
    )


@router.get(
    "/files/download/{token}",
    response_class=StreamingResponse,
    responses=_BINARY,
    summary="Download through a signed URL (public; the token is the credential)",
)
def download_signed(token: str, ax: Ax) -> StreamingResponse:
    info, stream = _svc(ax).open_signed(token)
    return _file_response(info, stream)


@router.get(
    "/products/{product_id}/storage/usage",
    response_model=ProductStorageUsage,
    tags=["storage"],
    summary="Storage usage and quotas of all tenants",
)
def product_usage(
    product_id: str, principal: CurrentPrincipal, ax: Ax, limit: Limit = None, cursor: Cursor = None
) -> ProductStorageUsage:
    return _svc(ax).product_usage(principal, product_id, limit=limit, cursor=cursor)


@router.get(
    "/products/{product_id}/storage/policy",
    response_model=StoragePolicy,
    tags=["storage"],
    summary="The product's effective content-type policy for blocked file types",
)
def get_policy(product_id: str, principal: CurrentPrincipal, ax: Ax) -> StoragePolicy:
    return _svc(ax).get_policy(principal, product_id)


@router.put(
    "/products/{product_id}/storage/policy",
    response_model=StoragePolicy,
    tags=["storage"],
    summary="Set the product's content-type policy (stored in the product's settings.storage)",
)
def set_policy(
    product_id: str, body: StoragePolicySet, principal: CurrentPrincipal, ax: Ax, if_match: IfMatch = None
) -> StoragePolicy:
    return _svc(ax).set_policy(
        principal,
        product_id,
        blocked_types=body.blocked_types,
        blocked_extensions=body.blocked_extensions,
        blocked_content_types=body.blocked_content_types,
        inert_extensions=body.inert_extensions,
        if_match=parse_if_match(if_match),
    )


@router.get(
    "/products/{product_id}/tenants/{tenant_id}/storage/usage",
    response_model=TenantStorageUsage,
    tags=["storage"],
    summary="Storage usage and quota of one tenant",
)
def tenant_usage(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> TenantStorageUsage:
    return _svc(ax).tenant_usage(principal, product_id, tenant_id)


@router.put(
    "/products/{product_id}/tenants/{tenant_id}/storage/quota",
    response_model=TenantStorageUsage,
    tags=["storage"],
    summary="Set the tenant's storage quota (null inherits the product default)",
)
def set_quota(
    product_id: str,
    tenant_id: str,
    body: QuotaSet,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> TenantStorageUsage:
    return _svc(ax).set_quota(
        principal,
        product_id,
        tenant_id,
        quota_bytes=body.quota_bytes,
        quota_files=body.quota_files,
        if_match=parse_if_match(if_match),
    )
