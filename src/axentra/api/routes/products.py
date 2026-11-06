from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import IfMatch, parse_if_match
from axentra.tenancy.models import (
    NewProductInvitation,
    Product,
    ProductInvitation,
    ProductMember,
    ProductOverview,
)

router = APIRouter(prefix="/v1/products", tags=["products"])


class ProductCreate(BaseModel):
    slug: str = Field(min_length=2, max_length=63)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    settings: dict[str, Any] = Field(default_factory=dict)
    owner_user_id: str | None = None


class ProductUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    settings: dict[str, Any] | None = None


class MemberSet(BaseModel):
    role: str = Field(max_length=64)
    user_id: str | None = None
    email: str | None = Field(default=None, max_length=320)


class MemberRole(BaseModel):
    role: str = Field(max_length=64)


@router.get("", response_model=list[Product], summary="Products visible to the caller")
def list_products(principal: CurrentPrincipal, ax: Ax) -> list[Product]:
    return ax.tenancy.list_products(principal)


@router.post("", response_model=Product, status_code=201, summary="Create a product (multi-product mode)")
def create_product(body: ProductCreate, principal: CurrentPrincipal, ax: Ax) -> Product:
    return ax.tenancy.create_product(
        principal,
        slug=body.slug,
        name=body.name,
        description=body.description,
        settings=body.settings,
        owner_user_id=body.owner_user_id,
    )


@router.get("/{product_id}", response_model=Product)
def get_product(product_id: str, principal: CurrentPrincipal, ax: Ax) -> Product:
    return ax.tenancy.get_product(principal, product_id)


@router.patch("/{product_id}", response_model=Product)
def update_product(
    product_id: str, body: ProductUpdate, principal: CurrentPrincipal, ax: Ax, if_match: IfMatch = None
) -> Product:
    return ax.tenancy.update_product(
        principal,
        product_id,
        name=body.name,
        description=body.description,
        settings=body.settings,
        if_match=parse_if_match(if_match),
    )


@router.post("/{product_id}/archive", response_model=Product)
def archive_product(product_id: str, principal: CurrentPrincipal, ax: Ax) -> Product:
    return ax.tenancy.set_product_status(principal, product_id, "archived")


@router.post("/{product_id}/restore", response_model=Product)
def restore_product(product_id: str, principal: CurrentPrincipal, ax: Ax) -> Product:
    return ax.tenancy.set_product_status(principal, product_id, "active")


@router.get(
    "/{product_id}/overview", response_model=ProductOverview, summary="Counts for the product dashboard"
)
def overview(product_id: str, principal: CurrentPrincipal, ax: Ax) -> ProductOverview:
    return ax.tenancy.overview(principal, product_id)


@router.get("/{product_id}/members", response_model=list[ProductMember], summary="Product operators")
def list_members(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[ProductMember]:
    return ax.tenancy.list_product_members(principal, product_id)


@router.post("/{product_id}/members", response_model=ProductMember, status_code=201)
def add_member(product_id: str, body: MemberSet, principal: CurrentPrincipal, ax: Ax) -> ProductMember:
    return ax.tenancy.set_product_member(
        principal, product_id, role=body.role, user_id=body.user_id, email=body.email
    )


@router.patch("/{product_id}/members/{user_id}", response_model=ProductMember)
def change_member(
    product_id: str, user_id: str, body: MemberRole, principal: CurrentPrincipal, ax: Ax
) -> ProductMember:
    return ax.tenancy.set_product_member(principal, product_id, role=body.role, user_id=user_id)


@router.delete("/{product_id}/members/{user_id}", status_code=204)
def remove_member(product_id: str, user_id: str, principal: CurrentPrincipal, ax: Ax) -> Response:
    ax.tenancy.remove_product_member(principal, product_id, user_id)
    return Response(status_code=204)


# -- product team invitations (operators) ---------------------------------------------------------


class ProductInvitationCreate(BaseModel):
    email: str = Field(max_length=320)
    role: str = Field(default="product_viewer", max_length=64, description="A product role")


class ProductInvitationAccept(BaseModel):
    token: str = Field(max_length=200, description="The `axpinv_...` token of the invitation")


@router.get(
    "/{product_id}/invitations",
    response_model=list[ProductInvitation],
    summary="Invitations to the product team (newest first, at most 500)",
)
def list_invitations(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[ProductInvitation]:
    return ax.tenancy.list_product_invitations(principal, product_id)


@router.post(
    "/{product_id}/invitations",
    response_model=NewProductInvitation,
    status_code=201,
    summary="Invite an operator by email; the token is returned once",
)
def invite(
    product_id: str, body: ProductInvitationCreate, principal: CurrentPrincipal, ax: Ax
) -> NewProductInvitation:
    """For operators without an account, or with one the caller cannot see (`POST .../members`
    resolves only visible users). `product_members:manage` and the role ceiling. With the notify
    module the invitee gets the `product_invitation` email (link: the invitation accept URL with
    the token); the invitee signs in and accepts with `POST /v1/product-invitations/accept`."""
    result = ax.tenancy.invite_to_product(principal, product_id, email=body.email, role=body.role)
    hook = getattr(ax, "on_product_invitation", None)
    if hook is not None:
        hook(result)
    return result


@router.delete("/{product_id}/invitations/{invitation_id}", status_code=204)
def revoke_invitation(product_id: str, invitation_id: str, principal: CurrentPrincipal, ax: Ax) -> Response:
    ax.tenancy.revoke_product_invitation(principal, product_id, invitation_id)
    return Response(status_code=204)


accept_router = APIRouter(prefix="/v1", tags=["products"])


@accept_router.post(
    "/product-invitations/accept",
    response_model=ProductMember,
    summary="Accept an invitation to a product team as the logged-in user",
)
def accept_invitation(body: ProductInvitationAccept, principal: CurrentPrincipal, ax: Ax) -> ProductMember:
    """A refusal answers `403 forbidden` with `reason`: `email_mismatch`, `scope_inactive` (the
    product is archived; the invitation stays open) or `inviter_lost_access`. An unknown, used,
    revoked or expired token (or a tenant invitation's token) answers `404`. A product role the
    user already has is kept."""
    return ax.tenancy.accept_product_invitation(principal, body.token)
