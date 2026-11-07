from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal, request_id
from axentra.api.routes.common import Cursor, Limit
from axentra.core.errors import Forbidden, NotFound
from axentra.core.pagination import Page
from axentra.identity.models import ExternalIdentity, Session, User
from axentra.tenancy.models import Product, Tenant, UserMemberships

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


class ExternalUserCreate(BaseModel):
    provider: str = Field(min_length=1, max_length=500, description="The issuer (`oidc[].issuer`)")
    subject: str = Field(min_length=1, max_length=500, description="The provider's `sub` claim")
    email: str | None = Field(default=None, max_length=320)
    email_verified: bool = Field(
        default=False,
        description="The email becomes the user's address only when true; otherwise the user has none",
    )
    name: str = Field(default="", max_length=200)


class IdentityLink(BaseModel):
    provider: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=500)


@router.get("/me", response_model=Me, summary="Who I am and what I may do, per product and tenant")
def get_me(principal: CurrentPrincipal, ax: Ax) -> Me:
    # Every tenant the caller may read is listed (all of them, ordered by id), including all
    # tenants of a product for product operators and platform roles. Authorization is computed per
    # product in one pass (Authorizer.tenant_grants), not per tenant. (A comment, not a docstring:
    # FastAPI would put a docstring into the OpenAPI contract.)
    user = ax.identity.get_user(principal.user_id) if principal.user_id else None
    products = []
    for product in ax.tenancy.list_products(principal):
        try:
            grant = ax.authz.grant(principal, product.id)
            grants = ax.authz.tenant_grants(principal, product.id)
        except (NotFound, Forbidden):
            continue
        readable = {tid: g for tid, g in grants.items() if g.permissions & {"tenant:read", "tenants:read"}}
        tenants = [
            TenantAccess(
                tenant=tenant,
                role=readable[tenant.id].tenant_role,
                permissions=sorted(readable[tenant.id].permissions),
            )
            for tenant in ax.tenancy.tenants_by_id(product.id, readable)
        ]
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


class VerificationRequest(BaseModel):
    product_id: str | None = Field(
        default=None,
        max_length=64,
        description="The product whose notification settings send the email, when the user belongs to it.",
    )


@router.post(
    "/me/email-verification",
    status_code=202,
    summary="Send me a link that confirms my email address",
    description="`409` when the address is already verified, `429` within a minute of the last link.",
)
def request_email_verification(
    body: VerificationRequest, request: Request, principal: CurrentPrincipal, ax: Ax
) -> Response:
    from axentra.api.routes.auth import send_account_email

    mail = ax.identity.request_email_verification(
        principal, product_hint=body.product_id, request_id=request_id(request)
    )
    send_account_email(ax, mail)
    return Response(status_code=202)


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


@router.get(
    "/users/{user_id}/memberships",
    response_model=UserMemberships,
    summary="The products and tenants a user is a member of (as far as the caller may read them)",
)
def user_memberships(user_id: str, principal: CurrentPrincipal, ax: Ax) -> UserMemberships:
    """Platform `users:read`: every membership. Product operators: the product roles where they
    hold `product_members:read` and the tenant memberships where they hold `members:read`. `404`
    for users the caller cannot see (as `GET /v1/users/{user_id}`)."""
    _can_see_user(ax, principal, user_id)
    ax.identity.get_user(user_id)  # 404 for an unknown id
    return ax.tenancy.user_memberships(principal, user_id)


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


@router.post(
    "/users/external",
    response_model=User,
    status_code=201,
    summary="Create a user with an external identity, with or without an email address (platform admins)",
)
def create_external_user(body: ExternalUserCreate, principal: CurrentPrincipal, ax: Ax) -> User:
    """For migrations and imports: the user signs in through the identity provider. `409` when the
    identity is already linked or a verified email belongs to another user."""
    return ax.identity.create_external_user(
        principal,
        provider=body.provider,
        subject=body.subject,
        email=body.email,
        email_verified=body.email_verified,
        name=body.name,
    )


@router.get(
    "/users/{user_id}/identities",
    response_model=list[ExternalIdentity],
    summary="External identities linked to a user (users:manage)",
)
def list_identities(user_id: str, principal: CurrentPrincipal, ax: Ax) -> list[ExternalIdentity]:
    ax.authz.require(principal, "users:manage")
    ax.identity.get_user(user_id)  # 404 for an unknown id
    return [ExternalIdentity.model_validate(r) for r in ax.identity.list_identities(user_id)]


@router.post(
    "/users/{user_id}/identities",
    response_model=ExternalIdentity,
    status_code=201,
    summary="Link an external identity to a user (platform admins)",
)
def link_identity(user_id: str, body: IdentityLink, principal: CurrentPrincipal, ax: Ax) -> ExternalIdentity:
    """`409` when the identity is already linked (to this or another user)."""
    ax.identity.link_identity(principal, user_id, provider=body.provider, subject=body.subject)
    for row in ax.identity.list_identities(user_id):
        if row["provider"] == body.provider and row["subject"] == body.subject:
            return ExternalIdentity.model_validate(row)
    raise NotFound("external identity not found")  # pragma: no cover - removed concurrently


@router.delete(
    "/users/{user_id}/identities",
    response_model=RevokeResult,
    summary="Unlink an external identity from a user and revoke the user's sessions (platform admins)",
)
def unlink_identity(
    user_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    provider: str = Query(min_length=1, max_length=500),
    subject: str = Query(min_length=1, max_length=500),
) -> RevokeResult:
    """`409` (`reason` `last_sign_in_method`) when it is the user's only way to sign in: disable
    the user instead. `revoked` counts the user's sessions that were ended."""
    return RevokeResult(
        revoked=ax.identity.unlink_identity(principal, user_id, provider=provider, subject=subject)
    )
