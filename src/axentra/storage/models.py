from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class FileInfo(BaseModel):
    """File metadata as returned by the API (the storage key stays internal)."""

    id: str
    product_id: str
    tenant_id: str
    name: str
    content_type: str
    size: int
    sha256: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: Literal["pending", "active", "deleted"]
    version: int
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None


class DownloadUrl(BaseModel):
    url: str
    """Absolute URL (``security.public_url`` + path) or a presigned S3 URL."""
    path: str | None
    """``/v1/files/download/{token}`` for Axentra-signed URLs; None for presigned S3 URLs."""
    expires_at: datetime
    kind: Literal["signed", "presigned"]


class TenantStorageUsage(BaseModel):
    product_id: str
    tenant_id: str
    bytes_used: int
    files_used: int
    quota_bytes: int | None
    """Effective byte quota (None: unlimited)."""
    quota_files: int | None
    quota_bytes_override: int | None
    """The tenant's own override (None: inherited from product settings or the installation default)."""
    quota_files_override: int | None
    quota_version: int
    """Version of the tenant's quota row (0 when none exists yet), for ``If-Match``."""


class ProductStorageUsage(BaseModel):
    product_id: str
    bytes_used: int
    files_used: int
    default_quota_bytes: int | None
    default_quota_files: int | None
    tenants: list[TenantStorageUsage]
    next_cursor: str | None = None


class PurgeReport(BaseModel):
    expired: int = 0
    abandoned_pending: int = 0
    objects_deleted: int = 0
    orphans_deleted: int = 0
    temp_files_removed: int = 0
    rows_removed: int = 0
    errors: int = 0
