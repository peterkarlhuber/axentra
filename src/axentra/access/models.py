from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class PermissionInfo(BaseModel):
    name: str
    scope: Literal["platform", "product", "tenant"]
    description: str
    source: Literal["builtin", "product"] = "builtin"
    """``builtin``: Axentra's catalog; ``product``: declared by the product."""
    read_like: bool = False
    """Only reads data; viewer and support roles hold read-like product permissions."""
    default_roles: list[str] = Field(default_factory=list)
    """Product permissions: built-in roles that hold it beyond the automatic grants."""
    declared_by: Literal["code", "api"] | None = None
    """Product permissions: registered by the embedding product's code or declared over the API."""
    retired_at: datetime | None = None
    """Product permissions: when it was retired (it grants nothing while retired)."""


class Role(BaseModel):
    id: str | None
    """``None`` for built-in roles."""
    key: str
    name: str
    description: str
    scope: Literal["product", "tenant"]
    permissions: list[str]
    builtin: bool
    version: int = 1


class ApiKey(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    name: str
    prefix: str
    permissions: list[str]
    created_by: str | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    replaces: str | None
    status: Literal["active", "revoked", "expired"]


class NewApiKey(BaseModel):
    key: ApiKey
    secret: str
    """The complete key ``axk_<id>_<secret>``; shown exactly once and never stored."""
