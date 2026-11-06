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
    """The stored type; ``application/octet-stream`` for files stored inert."""
    stored_inert: bool = False
    """A blocked type (executable/HTML/SVG/script) kept as an opaque attachment by the product's
    content-type policy; it is never served with its real type."""
    original_content_type: str | None = None
    """For inert files: the declared type (else the sniffed one); informational, never served."""
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


class VerifyReport(BaseModel):
    """Result of :meth:`axentra.storage.StorageService.verify` (ids, never names or contents)."""

    files_checked: int = 0
    missing: list[str] = []
    """Active files whose object is missing from the backend."""
    corrupt: list[str] = []
    """Active files whose object differs from the stored SHA-256 (only with ``checksums``)."""
    retained_objects: int = 0
    """Objects of deleted files kept for ``storage.deleted_object_retention_hours``."""
    orphans: int = 0
    """Objects without a file row (removed by the next purge with orphans)."""
    truncated: bool = False
    """True when the ``limit`` stopped the check before every file was checked."""

    @property
    def ok(self) -> bool:
        return not self.missing and not self.corrupt


class StoragePolicy(BaseModel):
    """The effective content-type policy of a product (``settings.storage`` of the product)."""

    product_id: str
    blocked_types: Literal["refuse", "store_inert"]
    """What happens to blocked uploads: ``refuse`` (415) or ``store_inert`` (opaque attachment)."""
    blocked_types_source: Literal["product", "installation"]
    """``installation``: the product inherits ``storage.store_blocked_as_inert``."""
    installation_blocked_types: Literal["refuse", "store_inert"]
    blocked_extensions: list[str]
    """Extensions the product blocks in addition to the built-in list."""
    blocked_content_types: list[str]
    """Content types the product blocks in addition to the built-in list."""
    inert_extensions: list[str]
    """Blocked extensions the product accepts as inert attachments even under ``refuse``."""
    builtin_blocked_extensions: list[str]
    builtin_blocked_content_types: list[str]
    allowed_content_types: list[str]
    """The installation's allow-list (``storage.allowed_content_types``; empty: all)."""
    product_version: int
    """The product's version, for ``If-Match`` on ``PUT .../storage/policy``."""
