"""Authorization: one place that decides whether a principal may do something in a scope.

Authentication (who is calling) happens in :mod:`axentra.identity` and :mod:`axentra.access.api_keys`
and yields a :class:`~axentra.core.context.Principal`. This module only answers "may this principal
use permission X in product P / tenant T?".

Rules:

- Default deny. A permission is granted only by a platform role, a product role (product members),
  a tenant role (memberships), or the explicit permission list of an API key.
- No existence oracle: a principal without any relation to a product or tenant gets ``NotFound``,
  a related principal without the permission gets ``Forbidden``.
- Archived products and suspended tenants are reachable only by platform admins (the tenant
  record itself is readable with product-wide ``tenants:read``, see ``TenancyService.get_tenant``).
- API keys are confined to their product (and tenant, if bound) and never hold platform permissions.
- An API key never does more than its creator could do *now*: its permissions are intersected, on
  every request, with what the creator (``created_by``) currently holds in the same scope. A user
  who was removed, lost a role or was disabled takes the rights of their keys with them; a key made
  by a key follows its parent the same way. Nothing is revoked or deleted: re-adding the creator
  restores the key. Keys created in process by system callers are not bounded. A request refused
  only because of this bound answers ``403 api_key_creator_lost_access`` (:meth:`Authorizer.require`).
- Product-defined permissions (:mod:`axentra.access.product_permissions`) count only while they are
  active in the product: retired or unknown names stored in roles or keys grant nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import threading
import time
from typing import NoReturn

from axentra.access.permissions import BUILTIN_ROLES, PLATFORM, PLATFORM_ROLE_PERMISSIONS
from axentra.access.product_permissions import ProductCatalog, load_catalog
from axentra.core.context import Actor, ActorKind, PlatformRole, Principal
from axentra.core.errors import ApiKeyCreatorLostAccess, Forbidden, NotFound
from axentra.data.database import Database, DbScope, Tx


@dataclass(frozen=True, slots=True)
class Grant:
    """The effective permissions of a principal in one scope and how they were obtained."""

    permissions: frozenset[str]
    related: bool
    product_role: str | None = None
    tenant_role: str | None = None
    #: API keys only: permissions of the key that its creator no longer holds in this scope (they
    #: are not in ``permissions``), and the creator's actor id.
    withheld: frozenset[str] = frozenset()
    key_creator: str | None = None


#: How deep a chain of keys created by keys is followed before the bound fails closed.
MAX_KEY_CREATOR_DEPTH = 8
#: At most one ``access.api_key.use`` denied audit event per key and scope in this many seconds
#: (per process), so a stale key in a retry loop does not flood the audit log.
CREATOR_DENIAL_AUDIT_INTERVAL_SECONDS = 60.0

#: ``(principal, permission, product_id, tenant_id, creator)`` of a request refused because the
#: key's creator lost access; the platform wires it to the audit log.
DenialHook = Callable[[Principal, str, str | None, str | None, str], None]


def _active_product_role(tx: Tx, product_id: str, user_id: str | None) -> tuple[bool, str | None]:
    """Whether the user is active, and their product role (``None`` without one), in one query.

    The one rule for a disabled or deleted user (delta review N-5): no product or tenant relation, wherever the
    principal comes from (a session, an API key's creator, the creator of a webhook endpoint, a schedule or a
    job). Their memberships stay, so enabling the user again restores them. A principal that is no user has no
    membership and is not subject to this rule. The rule covers relations read here only: platform permissions the
    principal already carries are not re-read (sessions and API keys of a disabled user are refused when they
    are resolved)."""
    if user_id is None:
        return True, None
    row = tx.one(
        "SELECT u.status, m.role FROM axentra_users u LEFT JOIN axentra_product_members m"
        " ON m.user_id = u.id AND m.product_id = %s WHERE u.id = %s",
        (product_id, user_id),
    )
    if row is None or row["status"] != "active":
        return False, None
    return True, row["role"]


class Authorizer:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.on_creator_denied: DenialHook | None = None
        self._denials: dict[tuple[str, str | None, str | None], float] = {}
        self._denials_lock = threading.Lock()

    @staticmethod
    def role_permissions(tx: Tx, product_id: str, role_key: str, scope: str) -> frozenset[str]:
        """The permissions a built-in or custom role confers in ``scope`` of the product (tenant
        roles only grant tenant-scoped permissions), including active product permissions."""
        catalog = load_catalog(tx, product_id)
        custom: dict[str, frozenset[str]] = {}
        if role_key not in BUILTIN_ROLES:
            row = tx.one(
                "SELECT permissions FROM axentra_roles WHERE product_id = %s AND key = %s",
                (product_id, role_key),
            )
            custom = {role_key: frozenset(row["permissions"])} if row else {}
        perms = catalog.role_permissions(role_key, custom)
        return perms & catalog.tenant_mask if scope == "tenant" else perms

    def grant(
        self, principal: Principal, product_id: str | None = None, tenant_id: str | None = None
    ) -> Grant:
        return self._grant(principal, product_id, tenant_id, 0)

    def _grant(
        self, principal: Principal, product_id: str | None, tenant_id: str | None, depth: int
    ) -> Grant:
        g = self._base_grant(principal, product_id, tenant_id)
        if principal.actor.kind is ActorKind.API_KEY and product_id is not None and g.permissions:
            return self._bound_by_creator(principal, g, product_id, tenant_id, depth)
        return g

    def _key_creator(self, key_id: str) -> tuple[str | None, Principal | None]:
        """The key's ``created_by`` and that actor as it stands now (:meth:`actor_principal`), with a
        user creator resolved in the same query."""
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            row = tx.one(
                "SELECT k.created_by, u.status, pr.role FROM axentra_api_keys k"
                " LEFT JOIN axentra_users u ON u.id = k.created_by"
                " LEFT JOIN axentra_platform_roles pr ON pr.user_id = u.id WHERE k.id = %s",
                (key_id,),
            )
        created_by = str(row["created_by"]) if row and row["created_by"] else None
        if created_by is None or not created_by.startswith("usr_"):
            return created_by, self.actor_principal(created_by)
        if row is None or row["status"] != "active":
            return created_by, Principal(actor=Actor(ActorKind.USER, created_by))  # no relation: nothing
        role = PlatformRole(row["role"]) if row["role"] else None
        return created_by, Principal(actor=Actor(ActorKind.USER, created_by), platform_role=role)

    def _creator_permissions(
        self, creator: Principal, product_id: str, tenant_id: str | None, depth: int
    ) -> frozenset[str]:
        """What the creator of a key holds now in the scope (nothing once it lost every relation)."""
        if depth >= MAX_KEY_CREATOR_DEPTH:
            return frozenset()  # fail closed on an unexpectedly long chain
        try:
            return self._grant(creator, product_id, tenant_id, depth + 1).permissions
        except (Forbidden, NotFound):
            return frozenset()

    def key_withheld(
        self, key_id: str, product_id: str, tenant_id: str | None, permissions: Iterable[str]
    ) -> frozenset[str] | None:
        """The key's ``permissions`` that its creator no longer holds in the key's scope (the
        product, or the key's tenant), so requests with the key are refused for them
        (``api_key_creator_lost_access``); empty while the creator holds them all. ``None`` for a
        key created in process by a system caller, which is not bounded. For API key listings."""
        created_by, creator = self._key_creator(key_id)
        if creator is None:
            return None
        del created_by
        held = self._creator_permissions(creator, product_id, tenant_id, 0)
        return frozenset(permissions) - held

    def _bound_by_creator(
        self, principal: Principal, g: Grant, product_id: str, tenant_id: str | None, depth: int
    ) -> Grant:
        """Intersect a key's grant with what its creator holds now (see the module docstring)."""
        created_by, creator = self._key_creator(principal.actor.id)
        if creator is None:
            return g  # created in process by a system caller: trusted, not bounded
        allowed = g.permissions & self._creator_permissions(creator, product_id, tenant_id, depth)
        return Grant(
            permissions=allowed,
            related=True,
            withheld=g.permissions - allowed,
            key_creator=created_by,
        )

    def _base_grant(self, principal: Principal, product_id: str | None, tenant_id: str | None) -> Grant:
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
            catalog: ProductCatalog = load_catalog(tx, product_id)

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
                # Unknown and retired product permissions grant nothing.
                key_perms = (principal.api_key_permissions - PLATFORM) & catalog.known
                return Grant(permissions=key_perms, related=True)

            platform_role = principal.platform_role.value if principal.platform_role is not None else None
            platform_perms = catalog.platform_role(platform_role)
            if principal.is_platform_admin:
                return Grant(permissions=platform_perms, related=True)
            user_id = principal.user_id
            custom: dict[str, frozenset[str]] = {
                r["key"]: frozenset(r["permissions"])
                for r in tx.all(
                    "SELECT key, permissions FROM axentra_roles WHERE product_id = %s", (product_id,)
                )
            }
            active, product_role = _active_product_role(tx, product_id, user_id)
            if not active:
                raise NotFound("tenant not found" if tenant_id else "product not found")
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
        perms |= catalog.role_permissions(product_role, custom)
        if tenant_id is not None:
            perms |= catalog.role_permissions(tenant_role, custom) & catalog.tenant_mask
        # Without a tenant, tenant permissions from product roles apply to all tenants of the product.
        return Grant(
            permissions=frozenset(perms), related=True, product_role=product_role, tenant_role=tenant_role
        )

    def actor_principal(self, actor_id: str | None) -> Principal | None:
        """The principal of a recorded actor id (``created_by``, ``invited_by``) as it stands *now*:
        a user with their current platform role, an API key with its current product, tenant and
        permissions. A disabled or deleted user, or a revoked, expired or deleted key, yields a
        principal without any relation (every grant is refused). ``None`` for other actors (system
        callers in process), which callers treat as trusted."""
        if not actor_id:
            return None
        if actor_id.startswith("usr_"):
            with self.db.transaction(DbScope.platform(), read_only=True) as tx:
                row = tx.one(
                    "SELECT u.status, pr.role FROM axentra_users u"
                    " LEFT JOIN axentra_platform_roles pr ON pr.user_id = u.id WHERE u.id = %s",
                    (actor_id,),
                )
            if row is None or row["status"] != "active":
                return Principal(actor=Actor(ActorKind.USER, actor_id))  # no relation: nothing
            role = PlatformRole(row["role"]) if row["role"] else None
            return Principal(actor=Actor(ActorKind.USER, actor_id), platform_role=role)
        if actor_id.startswith("key_"):
            with self.db.transaction(DbScope.platform(), read_only=True) as tx:
                row = tx.one(
                    "SELECT product_id, tenant_id, permissions FROM axentra_api_keys WHERE id = %s"
                    " AND (revoked_at IS NULL OR revoked_at > now()) AND (expires_at IS NULL OR expires_at > now())",
                    (actor_id,),
                )
            return Principal(
                actor=Actor(ActorKind.API_KEY, actor_id),
                api_key_product_id=row["product_id"] if row else "-",
                api_key_tenant_id=row["tenant_id"] if row else None,
                api_key_permissions=frozenset(row["permissions"]) if row else frozenset(),
            )
        return None

    def tenant_grants(self, principal: Principal, product_id: str) -> dict[str, Grant]:
        """``grant(principal, product_id, tenant_id)`` for every tenant of the product where that
        call would not raise, computed in one transaction with a fixed number of queries (instead
        of one authorization per tenant). Raises ``NotFound`` for an unknown product.

        It applies the same rules as :meth:`grant` (kept next to it; a test compares both)."""
        return self._tenant_grants(principal, product_id, 0)

    def _tenant_grants(self, principal: Principal, product_id: str, depth: int) -> dict[str, Grant]:
        base = self._base_tenant_grants(principal, product_id)
        if principal.actor.kind is not ActorKind.API_KEY or not base:
            return base
        created_by, creator = self._key_creator(principal.actor.id)
        if creator is None:
            return base
        if depth >= MAX_KEY_CREATOR_DEPTH:
            creator_grants: dict[str, Grant] = {}
        else:
            try:
                creator_grants = self._tenant_grants(creator, product_id, depth + 1)
            except NotFound:
                creator_grants = {}
        out: dict[str, Grant] = {}
        for tid, g in base.items():
            if not g.permissions:
                out[tid] = g
                continue
            cg = creator_grants.get(tid)
            allowed = g.permissions & (cg.permissions if cg is not None else frozenset())
            out[tid] = Grant(
                permissions=allowed, related=True, withheld=g.permissions - allowed, key_creator=created_by
            )
        return out

    def _base_tenant_grants(self, principal: Principal, product_id: str) -> dict[str, Grant]:
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            product = tx.one("SELECT status FROM axentra_products WHERE id = %s", (product_id,))
            if product is None:
                raise NotFound("product not found")
            product_active = product["status"] == "active"
            catalog: ProductCatalog = load_catalog(tx, product_id)

            if principal.actor.kind is ActorKind.API_KEY or (
                principal.actor.kind is ActorKind.SYSTEM and principal.api_key_product_id is not None
            ):
                if principal.api_key_product_id != product_id or not product_active:
                    return {}
                sql = "SELECT id FROM axentra_tenants WHERE product_id = %s AND status = 'active'"
                params: list[object] = [product_id]
                if principal.api_key_tenant_id is not None:
                    sql += " AND id = %s"
                    params.append(principal.api_key_tenant_id)
                key_perms = (principal.api_key_permissions - PLATFORM) & catalog.known
                return {r["id"]: Grant(permissions=key_perms, related=True) for r in tx.all(sql, params)}

            platform_role = principal.platform_role.value if principal.platform_role is not None else None
            platform_perms = catalog.platform_role(platform_role)
            if principal.is_platform_admin:
                return {
                    r["id"]: Grant(permissions=platform_perms, related=True)
                    for r in tx.all("SELECT id FROM axentra_tenants WHERE product_id = %s", (product_id,))
                }
            user_id = principal.user_id
            custom: dict[str, frozenset[str]] = {
                r["key"]: frozenset(r["permissions"])
                for r in tx.all(
                    "SELECT key, permissions FROM axentra_roles WHERE product_id = %s", (product_id,)
                )
            }
            active, product_role = _active_product_role(tx, product_id, user_id)
            if not active:
                return {}
            if product_role or platform_perms:
                rows = tx.all(
                    "SELECT t.id, t.status, m.role FROM axentra_tenants t LEFT JOIN axentra_memberships m"
                    " ON m.tenant_id = t.id AND m.product_id = t.product_id AND m.user_id = %s"
                    " WHERE t.product_id = %s",
                    (user_id, product_id),
                )
            else:
                rows = tx.all(
                    "SELECT t.id, t.status, m.role FROM axentra_memberships m JOIN axentra_tenants t"
                    " ON t.id = m.tenant_id AND t.product_id = m.product_id"
                    " WHERE m.product_id = %s AND m.user_id = %s",
                    (product_id, user_id),
                )
        product_perms = catalog.role_permissions(product_role, custom)
        out: dict[str, Grant] = {}
        for r in rows:
            tenant_role = r["role"]
            if not (product_role or tenant_role or platform_perms):
                continue
            if not product_active or r["status"] != "active":
                if platform_perms:
                    out[r["id"]] = Grant(permissions=platform_perms, related=True)
                continue
            perms = (
                platform_perms
                | product_perms
                | (catalog.role_permissions(tenant_role, custom) & catalog.tenant_mask)
            )
            out[r["id"]] = Grant(
                permissions=perms, related=True, product_role=product_role, tenant_role=tenant_role
            )
        return out

    def require(
        self,
        principal: Principal,
        permission: str,
        product_id: str | None = None,
        tenant_id: str | None = None,
    ) -> Grant:
        g = self.grant(principal, product_id, tenant_id)
        if permission not in g.permissions:
            self.refuse(principal, g, permission, product_id, tenant_id)
        return g

    def refuse(
        self,
        principal: Principal,
        g: Grant,
        permission: str,
        product_id: str | None,
        tenant_id: str | None,
        detail: str | None = None,
    ) -> NoReturn:
        """Raise the refusal for a missing ``permission`` in ``g``: ``ApiKeyCreatorLostAccess`` (audited)
        when only the key creator's lost access withholds it, ``Forbidden`` otherwise. For services that
        inspect a :class:`Grant` themselves instead of calling :meth:`require`."""
        if permission in g.withheld and g.key_creator is not None:
            self._creator_denied(principal, permission, product_id, tenant_id, g.key_creator)
            raise ApiKeyCreatorLostAccess(
                f"this API key's creator no longer holds {permission} here; restore the creator's"
                " access, or have an active administrator rotate or replace the key",
                extra={"permission": permission},
            )
        raise Forbidden(detail or f"missing permission {permission}")

    def _creator_denied(
        self,
        principal: Principal,
        permission: str,
        product_id: str | None,
        tenant_id: str | None,
        creator: str,
    ) -> None:
        hook = self.on_creator_denied
        if hook is None:
            return
        key = (principal.actor.id, product_id, tenant_id)
        now = time.monotonic()
        with self._denials_lock:
            last = self._denials.get(key)
            if last is not None and now - last < CREATOR_DENIAL_AUDIT_INTERVAL_SECONDS:
                return
            if len(self._denials) > 10_000:
                self._denials.clear()
            self._denials[key] = now
        hook(principal, permission, product_id, tenant_id, creator)

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
