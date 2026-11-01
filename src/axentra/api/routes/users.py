from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, Limit
from axentra.core.errors import Forbidden, NotFound
from axentra.core.pagination import Page
from axentra.identity.models import Session, User
from axentra.tenancy.models import Product, Tenant

router = APIRouter(prefix="/v1", tags=["users"])


class TenantAccess(BaseModel):
    tenant: Tenant
    role: str | None
    permissions: list[str]


class ProductAccess(BaseModel):
    product: Product
    role: str | None
    permissions: list[str]
    tenants: list[TenantAccess]


class Me(BaseModel):
    user: User | None
    actor_kind: str
    platform_role: str | None
    platform_permissions: list[str]
    products: list[ProductAccess]


class MeUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    locale: str | None = Field(default=None, max_length=10)
    preferences: dict[str, Any] | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(default="", max_length=1024)
    new_password: str = Field(max_length=1024)


class UserUpdate(BaseModel):
    status: Literal["active", "disabled"] | None = None
    platform_role: Literal["platform_admin", "platform_viewer", "none"] | None = None


class RevokeResult(BaseModel):
    revoked: int


@router.get("/me", response_model=Me, summary="Who I am and what I may do, per product and tenant")
def get_me(principal: CurrentPrincipal, ax: Ax) -> Me:
    from axentra.core.context import Principal

    user = ax.identity.get_user(principal.user_id) if principal.user_id else None
    products = []
    for product in ax.tenancy.list_products(principal):
        try:
            grant = ax.authz.grant(principal, product.id)
        except (NotFound, Forbidden):
            continue
        tenants = []
        page = ax.tenancy.list_tenants(Principal.system("me"), product.id, limit=200)
        for tenant in page.items:
            try:
                tg = ax.authz.grant(principal, product.id, tenant.id)
            except (NotFound, Forbidden):
                continue
            if tg.permissions & {"tenant:read", "tenants:read"}:
                tenants.append(
                    TenantAccess(tenant=tenant, role=tg.tenant_role, permissions=sorted(tg.permissions))
                )
        products.append(
            ProductAccess(
                product=product,
                role=grant.product_role,
                permissions=sorted(grant.permissions),
                tenants=tenants,
            )
        )
    platform = ax.authz.grant(principal)
    return Me(
        user=user,
        actor_kind=principal.actor.kind.value,
        platform_role=principal.platform_role.value if principal.platform_role else None,
        platform_permissions=sorted(platform.permissions),
        products=products,
    )


@router.patch("/me", response_model=User, summary="Update my profile and preferences")
def update_me(body: MeUpdate, principal: CurrentPrincipal, ax: Ax) -> User:
    return ax.identity.update_profile(
        principal, name=body.name, locale=body.locale, preferences=body.preferences
    )


@router.post("/me/password", status_code=204, summary="Change my password (revokes my other sessions)")
def change_password(body: PasswordChange, principal: CurrentPrincipal, ax: Ax) -> Response:
    ax.identity.change_password(principal, body.current_password, body.new_password)
    return Response(status_code=204)


def _can_see_user(ax: Ax, principal: CurrentPrincipal, user_id: str) -> None:
    if ax.authz.has(principal, "users:read"):
        return
    for product in ax.tenancy.list_products(principal):
        if ax.authz.has(principal, "product_users:read", product.id):
            page = ax.identity.list_users(product_id=product.id, q=None, limit=200)
            if any(u.id == user_id for u in page.items):
                return
    raise NotFound("user not found")


@router.get("/users", response_model=Page[User], summary="List users (all, or of one product)")
def list_users(
    principal: CurrentPrincipal,
    ax: Ax,
    product_id: str | None = None,
    q: str | None = Query(None, max_length=200),
    status: Literal["active", "disabled"] | None = None,
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[User]:
    if product_id:
        ax.authz.require(principal, "product_users:read", product_id)
    else:
        ax.authz.require(principal, "users:read")
    return ax.identity.list_users(product_id=product_id, q=q, status=status, limit=limit, cursor=cursor)


@router.get("/users/{user_id}", response_model=User, summary="One user")
def get_user(user_id: str, principal: CurrentPrincipal, ax: Ax) -> User:
    _can_see_user(ax, principal, user_id)
    return ax.identity.get_user(user_id)


@router.patch(
    "/users/{user_id}", response_model=User, summary="Enable/disable a user or set the platform role"
)
def update_user(user_id: str, body: UserUpdate, principal: CurrentPrincipal, ax: Ax) -> User:
    ax.authz.require(principal, "users:manage")
    user = ax.identity.get_user(user_id)
    if body.status is not None:
        user = ax.identity.set_user_status(principal, user_id, body.status)
    if body.platform_role is not None:
        if not principal.is_platform_admin:
            raise Forbidden("only platform admins can change platform roles")
        user = ax.identity.set_platform_role(
            principal, user_id, None if body.platform_role == "none" else body.platform_role
        )
    return user


@router.get("/users/{user_id}/sessions", response_model=list[Session], summary="Active sessions of a user")
def user_sessions(user_id: str, principal: CurrentPrincipal, ax: Ax) -> list[Session]:
    ax.authz.require(principal, "users:manage")
    return ax.identity.list_sessions(user_id)


@router.post(
    "/users/{user_id}/sessions/revoke", response_model=RevokeResult, summary="Revoke all sessions of a user"
)
def revoke_user_sessions(user_id: str, principal: CurrentPrincipal, ax: Ax) -> RevokeResult:
    ax.authz.require(principal, "users:manage")
    return RevokeResult(revoked=ax.identity.revoke_all_sessions(principal, user_id))
