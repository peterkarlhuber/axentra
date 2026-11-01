from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import IfMatch, parse_if_match
from axentra.tenancy.models import Product, ProductMember, ProductOverview

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
