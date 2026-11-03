from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class Product(BaseModel):
    id: str
    slug: str
    name: str
    description: str
    status: Literal["active", "archived"]
    settings: dict[str, Any] = Field(default_factory=dict)
    version: int
    created_at: datetime
    updated_at: datetime


class ProductOverview(BaseModel):
    """Counts for the product dashboard.

    ``scope`` tells what the counts cover. ``product``: callers that hold ``tenants:read`` on the
    product (product operators, platform roles, product-wide API keys with that permission) get
    product-wide counts. ``tenant``: every other caller (plain tenant members, product-wide keys
    without ``tenants:read``) gets counts of its own tenants only: ``tenants`` counts the tenants in
    which it holds ``tenant:read``, ``users`` the distinct members of those in which it holds
    ``members:read``, ``records`` the records of those in which it holds ``records:read``; the
    product-level counters ``api_keys``, ``audit_events_24h`` and ``denied_events_24h`` are
    ``null``."""

    product: Product
    scope: Literal["product", "tenant"] = Field(
        description="product: product-wide counts; tenant: counts of the caller's own tenants only"
    )
    tenants: int
    users: int
    api_keys: int | None = Field(description="null when scope is tenant")
    records: int
    audit_events_24h: int | None = Field(description="null when scope is tenant")
    denied_events_24h: int | None = Field(description="null when scope is tenant")


class Tenant(BaseModel):
    id: str
    product_id: str
    slug: str
    name: str
    status: Literal["active", "suspended"]
    settings: dict[str, Any] = Field(default_factory=dict)
    version: int
    created_at: datetime
    updated_at: datetime
    member_count: int | None = None


class ProductMember(BaseModel):
    product_id: str
    user_id: str
    email: str | None
    name: str
    role: str
    created_at: datetime


class Membership(BaseModel):
    id: str
    product_id: str
    tenant_id: str
    user_id: str
    email: str | None
    name: str
    role: str
    created_at: datetime


class Invitation(BaseModel):
    id: str
    product_id: str
    tenant_id: str
    email: str
    role: str
    invited_by: str | None
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    status: Literal["pending", "accepted", "revoked", "expired"]


class NewInvitation(BaseModel):
    invitation: Invitation
    token: str
    """Shown once; deliver it to the invitee (Axentra sends it when notifications are enabled)."""
    accept_url: str | None = None
