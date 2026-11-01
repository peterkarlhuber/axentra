from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class PermissionInfo(BaseModel):
    name: str
    scope: Literal["platform", "product", "tenant"]
    description: str


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
