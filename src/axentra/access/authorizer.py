"""Authorization: one place that decides whether a principal may do something in a scope.

Authentication (who is calling) happens in :mod:`axentra.identity` and :mod:`axentra.access.api_keys`
and yields a :class:`~axentra.core.context.Principal`. This module only answers "may this principal
use permission X in product P / tenant T?".

Rules:

- Default deny. A permission is granted only by a platform role, a product role (product members),
  a tenant role (memberships), or the explicit permission list of an API key.
- No existence oracle: a principal without any relation to a product or tenant gets ``NotFound``,
  a related principal without the permission gets ``Forbidden``.
- Archived products and suspended tenants are reachable only by platform admins.
- API keys are confined to their product (and tenant, if bound) and never hold platform permissions.
"""

from __future__ import annotations

from dataclasses import dataclass

from axentra.access.permissions import BUILTIN_ROLES, PLATFORM, PLATFORM_ROLE_PERMISSIONS, TENANT
from axentra.core.context import ActorKind, Principal
from axentra.core.errors import Forbidden, NotFound
from axentra.data.database import Database, DbScope


@dataclass(frozen=True, slots=True)
class Grant:
    """The effective permissions of a principal in one scope and how they were obtained."""

    permissions: frozenset[str]
    related: bool
    product_role: str | None = None
    tenant_role: str | None = None


class Authorizer:
    def __init__(self, db: Database) -> None:
        self.db = db

    def _role_permissions(
        self, product_id: str, role_key: str | None, custom: dict[str, frozenset[str]]
    ) -> frozenset[str]:
        if role_key is None:
            return frozenset()
        if role_key in BUILTIN_ROLES:
            return BUILTIN_ROLES[role_key].permissions
        return custom.get(role_key, frozenset())

    def grant(
        self, principal: Principal, product_id: str | None = None, tenant_id: str | None = None
    ) -> Grant:
        platform_perms = (
            PLATFORM_ROLE_PERMISSIONS.get(principal.platform_role.value, frozenset())
            if principal.platform_role is not None
            else frozenset()
        )
        if product_id is None:
            return Grant(permissions=platform_perms, related=bool(platform_perms))

        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            product = tx.one("SELECT status FROM axentra_products WHERE id = %s", (product_id,))
            if product is None:
                raise NotFound("product not found")
            tenant = None
            if tenant_id is not None:
                tenant = tx.one(
                    "SELECT status FROM axentra_tenants WHERE id = %s AND product_id = %s",
                    (tenant_id, product_id),
                )
                if tenant is None:
                    raise NotFound("tenant not found")

            # API keys, and system principals scoped like a key (job handlers, see axentra.events.worker).
            if principal.actor.kind is ActorKind.API_KEY or (
                principal.actor.kind is ActorKind.SYSTEM and principal.api_key_product_id is not None
            ):
                if principal.api_key_product_id != product_id:
                    raise NotFound("product not found")
                if principal.api_key_tenant_id is not None:
                    if tenant_id is None:
                        # A tenant-bound key may only use tenant-scoped permissions of its own tenant.
                        return Grant(permissions=frozenset(), related=True)
                    if tenant_id != principal.api_key_tenant_id:
                        raise NotFound("tenant not found")
                if product["status"] != "active" or (tenant is not None and tenant["status"] != "active"):
                    raise Forbidden("the product or tenant is not active")
                key_perms = principal.api_key_permissions - PLATFORM
                return Grant(permissions=key_perms, related=True)

            if principal.is_platform_admin:
                return Grant(permissions=platform_perms, related=True)
            user_id = principal.user_id
            custom: dict[str, frozenset[str]] = {
                r["key"]: frozenset(r["permissions"])
                for r in tx.all(
                    "SELECT key, permissions FROM axentra_roles WHERE product_id = %s", (product_id,)
                )
            }
            prow = tx.one(
                "SELECT role FROM axentra_product_members WHERE product_id = %s AND user_id = %s",
                (product_id, user_id),
            )
            product_role = prow["role"] if prow else None
            tenant_role = None
            if tenant_id is not None:
                trow = tx.one(
                    "SELECT role FROM axentra_memberships WHERE product_id = %s AND tenant_id = %s AND user_id = %s",
                    (product_id, tenant_id, user_id),
                )
                tenant_role = trow["role"] if trow else None
            else:
                has_tenant = tx.one(
                    "SELECT 1 FROM axentra_memberships WHERE product_id = %s AND user_id = %s LIMIT 1",
                    (product_id, user_id),
                )
                if has_tenant and not product_role and not platform_perms:
                    # A plain tenant member may see the product itself (to pick a tenant), nothing else.
                    return Grant(permissions=frozenset({"product:read"}), related=True)

        related = bool(product_role or tenant_role or platform_perms)
        if not related:
            raise NotFound("tenant not found" if tenant_id else "product not found")
        if product["status"] != "active" or (tenant is not None and tenant["status"] != "active"):
            # Read-only for platform viewers; nothing for others.
            if not platform_perms:
                raise Forbidden("the product or tenant is not active")
            return Grant(permissions=platform_perms, related=True)
        perms: set[str] = set(platform_perms)
        perms |= self._role_permissions(product_id, product_role, custom)
        if tenant_id is not None:
            perms |= self._role_permissions(product_id, tenant_role, custom) & TENANT
        # Without a tenant, tenant permissions from product roles apply to all tenants of the product.
        return Grant(
            permissions=frozenset(perms), related=True, product_role=product_role, tenant_role=tenant_role
        )

    def require(
        self,
        principal: Principal,
        permission: str,
        product_id: str | None = None,
        tenant_id: str | None = None,
    ) -> Grant:
        g = self.grant(principal, product_id, tenant_id)
        if permission not in g.permissions:
            raise Forbidden(f"missing permission {permission}")
        return g

    def has(
        self,
        principal: Principal,
        permission: str,
        product_id: str | None = None,
        tenant_id: str | None = None,
    ) -> bool:
        try:
            self.require(principal, permission, product_id, tenant_id)
        except (Forbidden, NotFound):
            return False
        return True
