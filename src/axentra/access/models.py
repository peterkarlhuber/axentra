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
    name_key: str | None = Field(
        default=None,
        description="Built-in roles: a stable translation key for `name` (`axentra.role.<key>.name`);"
        " `null` for custom roles, whose name and description are the product's own text",
    )
    description_key: str | None = Field(
        default=None,
        description="Built-in roles: a stable translation key for `description`"
        " (`axentra.role.<key>.description`); `null` for custom roles",
    )


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
    grace_until: datetime | None = Field(
        default=None,
        description="Set while a rotated key still works (the grace period of `rotate`): the time it"
        " stops working (`revoked_at`, in the future). `null` otherwise",
    )
    creator_has_access: bool | None = Field(
        default=None,
        description="For active keys: `true` while the key's creator holds every permission of the"
        " key in its scope, `false` when the creator lost some (requests needing them are refused"
        " with `api_key_creator_lost_access`, see `withheld_permissions`). `null` for revoked or"
        " expired keys and for keys created in process by a system caller (not bounded)",
    )
    withheld_permissions: list[str] = Field(
        default_factory=list,
        description="The key's permissions its creator no longer holds (empty when `creator_has_access`"
        " is not `false`)",
    )


class NewApiKey(BaseModel):
    key: ApiKey
    secret: str
    """The complete key ``axk_<id>_<secret>``; shown exactly once and never stored."""
