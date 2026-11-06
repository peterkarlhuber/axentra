from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, IfMatch, Limit, parse_if_match
from axentra.core.pagination import Page
from axentra.tenancy.models import Invitation, Membership, NewInvitation, Tenant

router = APIRouter(prefix="/v1", tags=["tenants"])


class TenantCreate(BaseModel):
    slug: str = Field(min_length=2, max_length=63)
    name: str = Field(min_length=1, max_length=200)
    settings: dict[str, Any] = Field(default_factory=dict)
    owner_user_id: str | None = None


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    status: Literal["active", "suspended"] | None = None
    settings: dict[str, Any] | None = None


class MemberSet(BaseModel):
    role: str = Field(max_length=64)
    user_id: str | None = None
    email: str | None = Field(default=None, max_length=320)


class MemberRole(BaseModel):
    role: str = Field(max_length=64)


class InvitationCreate(BaseModel):
    email: str = Field(max_length=320)
    role: str = Field(default="member", max_length=64)


class InvitationAccept(BaseModel):
    token: str = Field(max_length=200)


T = "/products/{product_id}/tenants"


@router.get(T, response_model=Page[Tenant], tags=["tenants"])
def list_tenants(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    q: str | None = Query(None, max_length=200),
    status: Literal["active", "suspended"] | None = None,
    limit: Limit = None,
    cursor: Cursor = None,
    sort: Literal["id", "name"] = Query(
        "id", description="`id` (default, oldest first) or `name` (case-insensitive, then id)"
    ),
) -> Page[Tenant]:
    return ax.tenancy.list_tenants(
        principal, product_id, q=q, status=status, limit=limit, cursor=cursor, sort=sort
    )


@router.post(T, response_model=Tenant, status_code=201)
def create_tenant(product_id: str, body: TenantCreate, principal: CurrentPrincipal, ax: Ax) -> Tenant:
    return ax.tenancy.create_tenant(
        principal,
        product_id,
        slug=body.slug,
        name=body.name,
        settings=body.settings,
        owner_user_id=body.owner_user_id,
    )


@router.get(T + "/{tenant_id}", response_model=Tenant)
def get_tenant(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> Tenant:
    return ax.tenancy.get_tenant(principal, product_id, tenant_id)


@router.patch(T + "/{tenant_id}", response_model=Tenant)
def update_tenant(
    product_id: str,
    tenant_id: str,
    body: TenantUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Tenant:
    return ax.tenancy.update_tenant(
        principal,
        product_id,
        tenant_id,
        name=body.name,
        status=body.status,
        settings=body.settings,
        if_match=parse_if_match(if_match),
    )


@router.delete(T + "/{tenant_id}", status_code=204, summary="Delete a tenant and all its data")
def delete_tenant(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> Response:
    ax.tenancy.delete_tenant(principal, product_id, tenant_id)
    return Response(status_code=204)


@router.get(T + "/{tenant_id}/members", response_model=list[Membership])
def list_members(product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax) -> list[Membership]:
    return ax.tenancy.list_members(principal, product_id, tenant_id)


@router.post(T + "/{tenant_id}/members", response_model=Membership, status_code=201)
def add_member(
    product_id: str, tenant_id: str, body: MemberSet, principal: CurrentPrincipal, ax: Ax
) -> Membership:
    return ax.tenancy.set_member(
        principal, product_id, tenant_id, role=body.role, user_id=body.user_id, email=body.email
    )


@router.patch(T + "/{tenant_id}/members/{user_id}", response_model=Membership)
def change_member(
    product_id: str, tenant_id: str, user_id: str, body: MemberRole, principal: CurrentPrincipal, ax: Ax
) -> Membership:
    return ax.tenancy.set_member(principal, product_id, tenant_id, role=body.role, user_id=user_id)


@router.delete(T + "/{tenant_id}/members/{user_id}", status_code=204)
def remove_member(
    product_id: str, tenant_id: str, user_id: str, principal: CurrentPrincipal, ax: Ax
) -> Response:
    ax.tenancy.remove_member(principal, product_id, tenant_id, user_id)
    return Response(status_code=204)


@router.get(T + "/{tenant_id}/invitations", response_model=list[Invitation])
def list_invitations(
    product_id: str, tenant_id: str, principal: CurrentPrincipal, ax: Ax
) -> list[Invitation]:
    return ax.tenancy.list_invitations(principal, product_id, tenant_id)


@router.post(
    T + "/{tenant_id}/invitations",
    response_model=NewInvitation,
    status_code=201,
    summary="Invite by email; the token is returned once",
)
def invite(
    product_id: str, tenant_id: str, body: InvitationCreate, principal: CurrentPrincipal, ax: Ax
) -> NewInvitation:
    result = ax.tenancy.invite(principal, product_id, tenant_id, email=body.email, role=body.role)
    hook = getattr(ax, "on_invitation", None)
    if hook is not None:
        hook(result)
    return result


@router.delete(T + "/{tenant_id}/invitations/{invitation_id}", status_code=204)
def revoke_invitation(
    product_id: str, tenant_id: str, invitation_id: str, principal: CurrentPrincipal, ax: Ax
) -> Response:
    ax.tenancy.revoke_invitation(principal, product_id, tenant_id, invitation_id)
    return Response(status_code=204)


@router.post(
    "/invitations/accept", response_model=Membership, summary="Accept an invitation as the logged-in user"
)
def accept_invitation(body: InvitationAccept, principal: CurrentPrincipal, ax: Ax) -> Membership:
    """A refusal answers ``403 forbidden`` with a ``reason`` member: ``email_mismatch`` (the
    invitation was sent to another email address), ``scope_inactive`` (the tenant or product is
    not active; the invitation stays open) or ``inviter_lost_access`` (its sender can no longer
    grant the role). An unknown, used, revoked or expired token answers ``404``."""
    return ax.tenancy.accept_invitation(principal, body.token)
