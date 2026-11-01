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
    product: Product
    tenants: int
    users: int
    api_keys: int
    records: int
    audit_events_24h: int
    denied_events_24h: int


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
    email: str
    name: str
    role: str
    created_at: datetime


class Membership(BaseModel):
    id: str
    product_id: str
    tenant_id: str
    user_id: str
    email: str
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
