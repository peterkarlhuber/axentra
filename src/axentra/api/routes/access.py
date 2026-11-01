from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field

from axentra.access.models import ApiKey, NewApiKey, PermissionInfo, Role
from axentra.access.roles import permission_catalog
from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import IfMatch, parse_if_match

router = APIRouter(prefix="/v1", tags=["access"])


class RoleCreate(BaseModel):
    key: str = Field(min_length=2, max_length=41)
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    scope: Literal["product", "tenant"]
    permissions: list[str] = Field(max_length=100)


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = Field(default=None, max_length=100)


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    permissions: list[str] = Field(min_length=1, max_length=100)
    tenant_id: str | None = None
    expires_at: datetime | None = None


class ApiKeyRotate(BaseModel):
    grace_seconds: int = Field(default=0, ge=0, le=604800)


@router.get("/permissions", response_model=list[PermissionInfo], summary="The permission catalog")
def permissions(principal: CurrentPrincipal) -> list[PermissionInfo]:
    return permission_catalog()


R = "/products/{product_id}/roles"


@router.get(R, response_model=list[Role])
def list_roles(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[Role]:
    return ax.roles.list_roles(principal, product_id)


@router.post(R, response_model=Role, status_code=201)
def create_role(product_id: str, body: RoleCreate, principal: CurrentPrincipal, ax: Ax) -> Role:
    return ax.roles.create_role(
        principal,
        product_id,
        key=body.key,
        name=body.name,
        scope=body.scope,
        permissions=body.permissions,
        description=body.description,
    )


@router.patch(R + "/{role_id}", response_model=Role)
def update_role(
    product_id: str,
    role_id: str,
    body: RoleUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Role:
    return ax.roles.update_role(
        principal,
        product_id,
        role_id,
        name=body.name,
        description=body.description,
        permissions=body.permissions,
        if_match=parse_if_match(if_match),
    )


@router.delete(R + "/{role_id}", status_code=204)
def delete_role(product_id: str, role_id: str, principal: CurrentPrincipal, ax: Ax) -> Response:
    ax.roles.delete_role(principal, product_id, role_id)
    return Response(status_code=204)


K = "/products/{product_id}/api-keys"


@router.get(K, response_model=list[ApiKey], summary="API keys of the product (never their secrets)")
def list_keys(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[ApiKey]:
    return ax.api_keys.list_keys(principal, product_id)


@router.post(
    K, response_model=NewApiKey, status_code=201, summary="Create a key; the secret is returned once"
)
def create_key(product_id: str, body: ApiKeyCreate, principal: CurrentPrincipal, ax: Ax) -> NewApiKey:
    return ax.api_keys.create_key(
        principal,
        product_id,
        name=body.name,
        permissions=body.permissions,
        tenant_id=body.tenant_id,
        expires_at=body.expires_at,
    )


@router.get(K + "/{key_id}", response_model=ApiKey)
def get_key(product_id: str, key_id: str, principal: CurrentPrincipal, ax: Ax) -> ApiKey:
    return ax.api_keys.get_key(principal, product_id, key_id)


@router.post(
    K + "/{key_id}/rotate",
    response_model=NewApiKey,
    summary="Replace a key; the old one ends after the grace period",
)
def rotate_key(
    product_id: str, key_id: str, body: ApiKeyRotate, principal: CurrentPrincipal, ax: Ax
) -> NewApiKey:
    return ax.api_keys.rotate_key(principal, product_id, key_id, grace_seconds=body.grace_seconds)


@router.post(K + "/{key_id}/revoke", response_model=ApiKey)
def revoke_key(product_id: str, key_id: str, principal: CurrentPrincipal, ax: Ax) -> ApiKey:
    return ax.api_keys.revoke_key(principal, product_id, key_id)
