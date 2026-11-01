"""Products, tenants, operators, memberships and invitations.

All methods take the calling :class:`~axentra.core.context.Principal` and authorize through
:class:`~axentra.access.authorizer.Authorizer` before touching data. Writes run in the narrowest
database scope (product or tenant) so row-level security backs up the explicit filters.
"""

from __future__ import annotations

from datetime import timedelta
import re
from typing import Any

from psycopg import errors as pg_errors
from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.access.permissions import BUILTIN_ROLES
from axentra.audit.log import AuditLog
from axentra.config.settings import DeploymentMode, Settings
from axentra.core.clock import utcnow
from axentra.core.context import Principal
from axentra.core.errors import (
    Conflict,
    Forbidden,
    ModeNotSupported,
    NotFound,
    PreconditionFailed,
    ValidationFailed,
)
from axentra.core.ids import new_id, new_token
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Tx
from axentra.identity.service import normalize_email
from axentra.identity.tokens import hash_token
from axentra.tenancy.models import (
    Invitation,
    Membership,
    NewInvitation,
    Product,
    ProductMember,
    ProductOverview,
    Tenant,
)

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
INVITATION_TTL = timedelta(days=7)
MAX_SETTINGS_BYTES = 32_000


def _check_slug(slug: str) -> str:
    if not _SLUG.match(slug):
        raise ValidationFailed("slug must be 2-63 lowercase letters, digits or dashes")
    return slug


def _check_settings(settings: dict[str, Any]) -> dict[str, Any]:
    if len(str(settings)) > MAX_SETTINGS_BYTES:
        raise ValidationFailed("settings are too large")
    return settings


def _like(q: str) -> str:
    return "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"


class TenancyService:
    def __init__(self, db: Database, settings: Settings, authz: Authorizer, audit: AuditLog) -> None:
        self.db = db
        self.settings = settings
        self.authz = authz
        self.audit = audit

    # -- products ------------------------------------------------------------------------------

    def ensure_single_product(self) -> Product:
        """Single-product mode: create the configured product on first start (idempotent)."""
        cfg = self.settings.product
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one("SELECT * FROM axentra_products WHERE slug = %s", (cfg.slug,))
            if row is None:
                count = tx.scalar("SELECT count(*) FROM axentra_products")
                if count:
                    raise ModeNotSupported(
                        "single-product mode found other products; set product.slug to the existing product"
                    )
                pid = new_id("prd")
                tx.execute(
                    "INSERT INTO axentra_products (id, slug, name) VALUES (%s, %s, %s)",
                    (pid, cfg.slug, cfg.name),
                )
                self.audit.record(
                    tx,
                    Principal.system("startup"),
                    "tenancy.product.create",
                    target_type="product",
                    target_id=pid,
                    product_id=pid,
                    details={"slug": cfg.slug, "mode": "single"},
                )
                row = tx.one_or_404("SELECT * FROM axentra_products WHERE id = %s", (pid,))
        return Product.model_validate(row)

    def single_product(self) -> Product | None:
        if self.settings.mode is not DeploymentMode.SINGLE:
            return None
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            row = tx.one("SELECT * FROM axentra_products WHERE slug = %s", (self.settings.product.slug,))
        return Product.model_validate(row) if row else None

    def list_products(self, principal: Principal, *, include_archived: bool = False) -> list[Product]:
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            if principal.platform_role is not None:
                rows = tx.all("SELECT * FROM axentra_products ORDER BY name, id")
            elif principal.api_key_product_id:
                rows = tx.all("SELECT * FROM axentra_products WHERE id = %s", (principal.api_key_product_id,))
            else:
                rows = tx.all(
                    "SELECT * FROM axentra_products WHERE status = 'active' AND (id IN"
                    " (SELECT product_id FROM axentra_product_members WHERE user_id = %s) OR id IN"
                    " (SELECT product_id FROM axentra_memberships WHERE user_id = %s)) ORDER BY name, id",
                    (principal.user_id, principal.user_id),
                )
        products = [Product.model_validate(r) for r in rows]
        if not include_archived:
            products = [p for p in products if p.status == "active" or principal.is_platform_admin]
        return products

    def create_product(
        self,
        principal: Principal,
        *,
        slug: str,
        name: str,
        description: str = "",
        settings: dict[str, Any] | None = None,
        owner_user_id: str | None = None,
    ) -> Product:
        if self.settings.mode is DeploymentMode.SINGLE:
            raise ModeNotSupported("products cannot be created in single-product mode")
        self.authz.require(principal, "products:create")
        pid = new_id("prd")
        try:
            with self.db.transaction(DbScope.product(pid)) as tx:
                tx.execute(
                    "INSERT INTO axentra_products (id, slug, name, description, settings) VALUES (%s,%s,%s,%s,%s)",
                    (
                        pid,
                        _check_slug(slug),
                        name.strip(),
                        description,
                        Jsonb(_check_settings(settings or {})),
                    ),
                )
                owner = owner_user_id or principal.user_id
                if owner:
                    tx.execute(
                        "INSERT INTO axentra_product_members (product_id, user_id, role) VALUES (%s, %s, 'product_owner')",
                        (pid, owner),
                    )
                self.audit.record(
                    tx,
                    principal,
                    "tenancy.product.create",
                    target_type="product",
                    target_id=pid,
                    product_id=pid,
                    details={"slug": slug, "name": name},
                )
        except pg_errors.UniqueViolation:
            raise Conflict("a product with this slug exists") from None
        except pg_errors.ForeignKeyViolation:
            raise ValidationFailed("the owner user does not exist") from None
        return self.get_product(principal, pid)

    def get_product(self, principal: Principal, product_id: str) -> Product:
        self.authz.require(principal, "product:read", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one_or_404("SELECT * FROM axentra_products WHERE id = %s", (product_id,), what="product")
        return Product.model_validate(row)

    def update_product(
        self,
        principal: Principal,
        product_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        settings: dict[str, Any] | None = None,
        if_match: int | None = None,
    ) -> Product:
        self.authz.require(principal, "product:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_products WHERE id = %s FOR UPDATE", (product_id,), what="product"
            )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the product was changed by someone else")
            changes: dict[str, Any] = {}
            if name is not None and name.strip() != row["name"]:
                if not name.strip():
                    raise ValidationFailed("name must not be empty")
                changes["name"] = name.strip()
            if description is not None and description != row["description"]:
                changes["description"] = description
            if settings is not None:
                changes["settings"] = Jsonb(_check_settings(settings))
            if changes:
                sets = ", ".join(f"{k} = %s" for k in changes)
                tx.execute(
                    f"UPDATE axentra_products SET {sets}, version = version + 1, updated_at = now() WHERE id = %s",
                    [*changes.values(), product_id],
                )
                self.audit.record(
                    tx,
                    principal,
                    "tenancy.product.update",
                    target_type="product",
                    target_id=product_id,
                    product_id=product_id,
                    details={"fields": sorted(changes)},
                )
            row = tx.one_or_404("SELECT * FROM axentra_products WHERE id = %s", (product_id,))
        return Product.model_validate(row)

    def set_product_status(self, principal: Principal, product_id: str, status: str) -> Product:
        if self.settings.mode is DeploymentMode.SINGLE:
            raise ModeNotSupported("the product cannot be archived in single-product mode")
        self.authz.require(principal, "products:archive")
        with self.db.transaction(DbScope.product(product_id)) as tx:
            n = tx.execute(
                "UPDATE axentra_products SET status = %s, version = version + 1, updated_at = now()"
                " WHERE id = %s",
                (status, product_id),
            )
            if n == 0:
                raise NotFound("product not found")
            self.audit.record(
                tx,
                principal,
                f"tenancy.product.{'archive' if status == 'archived' else 'restore'}",
                target_type="product",
                target_id=product_id,
                product_id=product_id,
            )
            row = tx.one_or_404("SELECT * FROM axentra_products WHERE id = %s", (product_id,))
        return Product.model_validate(row)

    def overview(self, principal: Principal, product_id: str) -> ProductOverview:
        product = self.get_product(principal, product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT (SELECT count(*) FROM axentra_tenants WHERE product_id = %(p)s) AS tenants,"
                " (SELECT count(DISTINCT user_id) FROM (SELECT user_id FROM axentra_memberships WHERE product_id = %(p)s"
                "   UNION SELECT user_id FROM axentra_product_members WHERE product_id = %(p)s) u) AS users,"
                " (SELECT count(*) FROM axentra_api_keys WHERE product_id = %(p)s AND revoked_at IS NULL) AS api_keys,"
                " (SELECT count(*) FROM axentra_records WHERE product_id = %(p)s) AS records,"
                " (SELECT count(*) FROM axentra_audit_events WHERE product_id = %(p)s"
                "   AND occurred_at > now() - interval '24 hours') AS audit_events_24h,"
                " (SELECT count(*) FROM axentra_audit_events WHERE product_id = %(p)s AND outcome = 'denied'"
                "   AND occurred_at > now() - interval '24 hours') AS denied_events_24h",
                {"p": product_id},
            )
        return ProductOverview(product=product, **row)

    # -- product operators -------------------------------------------------------------------------

    def _check_role(self, tx: Tx, product_id: str, role: str, scope: str) -> None:
        if role in BUILTIN_ROLES:
            if BUILTIN_ROLES[role].scope != scope:
                raise ValidationFailed(f"role {role} is not a {scope} role")
            return
        row = tx.one("SELECT scope FROM axentra_roles WHERE product_id = %s AND key = %s", (product_id, role))
        if row is None or row["scope"] != scope:
            raise ValidationFailed(f"unknown {scope} role {role}")

    def list_product_members(self, principal: Principal, product_id: str) -> list[ProductMember]:
        self.authz.require(principal, "product_members:read", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT m.product_id, m.user_id, u.email, u.name, m.role, m.created_at"
                " FROM axentra_product_members m JOIN axentra_users u ON u.id = m.user_id"
                " WHERE m.product_id = %s ORDER BY u.email",
                (product_id,),
            )
        return [ProductMember.model_validate(r) for r in rows]

    def set_product_member(
        self,
        principal: Principal,
        product_id: str,
        *,
        role: str,
        user_id: str | None = None,
        email: str | None = None,
    ) -> ProductMember:
        self.authz.require(principal, "product_members:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            self._check_role(tx, product_id, role, "product")
            uid = self._resolve_user(tx, user_id, email)
            if self._would_remove_last_owner(tx, product_id, uid, role):
                raise Conflict("the product needs at least one owner")
            tx.execute(
                "INSERT INTO axentra_product_members (product_id, user_id, role) VALUES (%s, %s, %s)"
                " ON CONFLICT (product_id, user_id) DO UPDATE SET role = EXCLUDED.role",
                (product_id, uid, role),
            )
            self.audit.record(
                tx,
                principal,
                "tenancy.product_member.set",
                target_type="user",
                target_id=uid,
                product_id=product_id,
                details={"role": role},
            )
            row = tx.one_or_404(
                "SELECT m.product_id, m.user_id, u.email, u.name, m.role, m.created_at"
                " FROM axentra_product_members m JOIN axentra_users u ON u.id = m.user_id"
                " WHERE m.product_id = %s AND m.user_id = %s",
                (product_id, uid),
            )
        return ProductMember.model_validate(row)

    def remove_product_member(self, principal: Principal, product_id: str, user_id: str) -> None:
        self.authz.require(principal, "product_members:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            if self._would_remove_last_owner(tx, product_id, user_id, None):
                raise Conflict("the product needs at least one owner")
            n = tx.execute(
                "DELETE FROM axentra_product_members WHERE product_id = %s AND user_id = %s",
                (product_id, user_id),
            )
            if n == 0:
                raise NotFound("member not found")
            self.audit.record(
                tx,
                principal,
                "tenancy.product_member.remove",
                target_type="user",
                target_id=user_id,
                product_id=product_id,
            )

    @staticmethod
    def _would_remove_last_owner(tx: Tx, product_id: str, user_id: str, new_role: str | None) -> bool:
        current = tx.one(
            "SELECT role FROM axentra_product_members WHERE product_id = %s AND user_id = %s",
            (product_id, user_id),
        )
        if not current or current["role"] != "product_owner" or new_role == "product_owner":
            return False
        others = tx.scalar(
            "SELECT count(*) FROM axentra_product_members WHERE product_id = %s AND role = 'product_owner'"
            " AND user_id <> %s",
            (product_id, user_id),
        )
        return bool(others == 0)

    @staticmethod
    def _resolve_user(tx: Tx, user_id: str | None, email: str | None) -> str:
        if user_id:
            row = tx.one("SELECT id FROM axentra_users WHERE id = %s", (user_id,))
        elif email:
            row = tx.one("SELECT id FROM axentra_users WHERE lower(email) = lower(%s)", (email.strip(),))
        else:
            raise ValidationFailed("user_id or email is required")
        if row is None:
            raise NotFound("user not found; invite them to a tenant instead")
        return str(row["id"])

    # -- tenants ---------------------------------------------------------------------------------

    def list_tenants(
        self,
        principal: Principal,
        product_id: str,
        *,
        q: str | None = None,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Tenant]:
        grant = self.authz.grant(principal, product_id)
        limit = clamp_limit(limit)
        where = ["t.product_id = %s"]
        params: list[Any] = [product_id]
        if "tenants:read" not in grant.permissions:
            if principal.user_id is None:
                raise Forbidden("missing permission tenants:read")
            # Tenant members see the tenants they belong to.
            where.append(
                "t.id IN (SELECT tenant_id FROM axentra_memberships WHERE product_id = %s AND user_id = %s)"
            )
            params += [product_id, principal.user_id]
        if q:
            where.append("(t.name ILIKE %s OR t.slug ILIKE %s)")
            params += [_like(q), _like(q)]
        if status:
            where.append("t.status = %s")
            params.append(status)
        after = decode_cursor(cursor)
        if after:
            where.append("t.id > %s")
            params.append(after[0])
        params.append(limit + 1)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT t.*, (SELECT count(*) FROM axentra_memberships m WHERE m.tenant_id = t.id) AS member_count"
                f" FROM axentra_tenants t WHERE {' AND '.join(where)} ORDER BY t.id LIMIT %s",
                params,
            )
        items = [Tenant.model_validate(r) for r in rows[:limit]]
        return Page[Tenant](
            items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > limit else None
        )

    def create_tenant(
        self,
        principal: Principal,
        product_id: str,
        *,
        slug: str,
        name: str,
        settings: dict[str, Any] | None = None,
        owner_user_id: str | None = None,
    ) -> Tenant:
        self.authz.require(principal, "tenants:create", product_id)
        tid = new_id("ten")
        try:
            with self.db.transaction(DbScope.tenant(product_id, tid)) as tx:
                tx.execute(
                    "INSERT INTO axentra_tenants (id, product_id, slug, name, settings) VALUES (%s, %s, %s, %s, %s)",
                    (
                        tid,
                        product_id,
                        _check_slug(slug),
                        name.strip(),
                        Jsonb(_check_settings(settings or {})),
                    ),
                )
                if owner_user_id:
                    uid = self._resolve_user(tx, owner_user_id, None)
                    tx.execute(
                        "INSERT INTO axentra_memberships (id, product_id, tenant_id, user_id, role)"
                        " VALUES (%s, %s, %s, %s, 'tenant_owner')",
                        (new_id("mem"), product_id, tid, uid),
                    )
                self.audit.record(
                    tx,
                    principal,
                    "tenancy.tenant.create",
                    target_type="tenant",
                    target_id=tid,
                    product_id=product_id,
                    tenant_id=tid,
                    details={"slug": slug, "name": name},
                )
        except pg_errors.UniqueViolation:
            raise Conflict("a tenant with this slug exists in the product") from None
        return self.get_tenant(principal, product_id, tid)

    def get_tenant(self, principal: Principal, product_id: str, tenant_id: str) -> Tenant:
        grant = self.authz.grant(principal, product_id, tenant_id)
        if not ({"tenants:read", "tenant:read"} & grant.permissions):
            raise Forbidden("missing permission tenant:read")
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT t.*, (SELECT count(*) FROM axentra_memberships m WHERE m.tenant_id = t.id) AS member_count"
                " FROM axentra_tenants t WHERE t.id = %s AND t.product_id = %s",
                (tenant_id, product_id),
                what="tenant",
            )
        return Tenant.model_validate(row)

    def update_tenant(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        name: str | None = None,
        status: str | None = None,
        settings: dict[str, Any] | None = None,
        if_match: int | None = None,
    ) -> Tenant:
        self.authz.require(principal, "tenants:update", product_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_tenants WHERE id = %s AND product_id = %s FOR UPDATE",
                (tenant_id, product_id),
                what="tenant",
            )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the tenant was changed by someone else")
            changes: dict[str, Any] = {}
            if name is not None and name.strip() != row["name"]:
                if not name.strip():
                    raise ValidationFailed("name must not be empty")
                changes["name"] = name.strip()
            if status is not None and status != row["status"]:
                if status not in ("active", "suspended"):
                    raise ValidationFailed("status must be active or suspended")
                changes["status"] = status
            if settings is not None:
                changes["settings"] = Jsonb(_check_settings(settings))
            if changes:
                sets = ", ".join(f"{k} = %s" for k in changes)
                tx.execute(
                    f"UPDATE axentra_tenants SET {sets}, version = version + 1, updated_at = now() WHERE id = %s",
                    [*changes.values(), tenant_id],
                )
                self.audit.record(
                    tx,
                    principal,
                    "tenancy.tenant.update",
                    target_type="tenant",
                    target_id=tenant_id,
                    product_id=product_id,
                    tenant_id=tenant_id,
                    details={"fields": sorted(changes), "status": status},
                )
        return self.get_tenant(Principal.system("read-back"), product_id, tenant_id)

    def delete_tenant(self, principal: Principal, product_id: str, tenant_id: str) -> None:
        self.authz.require(principal, "tenants:delete", product_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            n = tx.execute(
                "DELETE FROM axentra_tenants WHERE id = %s AND product_id = %s", (tenant_id, product_id)
            )
            if n == 0:
                raise NotFound("tenant not found")
            self.audit.record(
                tx,
                principal,
                "tenancy.tenant.delete",
                target_type="tenant",
                target_id=tenant_id,
                product_id=product_id,
                tenant_id=tenant_id,
            )

    # -- memberships -------------------------------------------------------------------------------

    _MEMBER_SQL = (
        "SELECT m.id, m.product_id, m.tenant_id, m.user_id, u.email, u.name, m.role, m.created_at"
        " FROM axentra_memberships m JOIN axentra_users u ON u.id = m.user_id"
    )

    def list_members(self, principal: Principal, product_id: str, tenant_id: str) -> list[Membership]:
        self.authz.require(principal, "members:read", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(
                self._MEMBER_SQL + " WHERE m.product_id = %s AND m.tenant_id = %s ORDER BY u.email",
                (product_id, tenant_id),
            )
        return [Membership.model_validate(r) for r in rows]

    def set_member(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        role: str,
        user_id: str | None = None,
        email: str | None = None,
    ) -> Membership:
        self.authz.require(principal, "members:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            self._check_role(tx, product_id, role, "tenant")
            uid = self._resolve_user(tx, user_id, email)
            self._guard_last_tenant_owner(tx, tenant_id, uid, role)
            tx.execute(
                "INSERT INTO axentra_memberships (id, product_id, tenant_id, user_id, role) VALUES (%s,%s,%s,%s,%s)"
                " ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role",
                (new_id("mem"), product_id, tenant_id, uid, role),
            )
            self.audit.record(
                tx,
                principal,
                "tenancy.member.set",
                target_type="user",
                target_id=uid,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"role": role},
            )
            row = tx.one_or_404(
                self._MEMBER_SQL + " WHERE m.tenant_id = %s AND m.user_id = %s", (tenant_id, uid)
            )
        return Membership.model_validate(row)

    def remove_member(self, principal: Principal, product_id: str, tenant_id: str, user_id: str) -> None:
        self.authz.require(principal, "members:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            self._guard_last_tenant_owner(tx, tenant_id, user_id, None)
            n = tx.execute(
                "DELETE FROM axentra_memberships WHERE product_id = %s AND tenant_id = %s AND user_id = %s",
                (product_id, tenant_id, user_id),
            )
            if n == 0:
                raise NotFound("member not found")
            self.audit.record(
                tx,
                principal,
                "tenancy.member.remove",
                target_type="user",
                target_id=user_id,
                product_id=product_id,
                tenant_id=tenant_id,
            )

    @staticmethod
    def _guard_last_tenant_owner(tx: Tx, tenant_id: str, user_id: str, new_role: str | None) -> None:
        current = tx.one(
            "SELECT role FROM axentra_memberships WHERE tenant_id = %s AND user_id = %s", (tenant_id, user_id)
        )
        if not current or current["role"] != "tenant_owner" or new_role == "tenant_owner":
            return
        others = tx.scalar(
            "SELECT count(*) FROM axentra_memberships WHERE tenant_id = %s AND role = 'tenant_owner'"
            " AND user_id <> %s",
            (tenant_id, user_id),
        )
        if others == 0:
            raise Conflict("the tenant needs at least one owner")

    # -- invitations -------------------------------------------------------------------------------

    @staticmethod
    def _invitation(row: dict[str, Any]) -> Invitation:
        if row["accepted_at"]:
            status = "accepted"
        elif row["revoked_at"]:
            status = "revoked"
        elif row["expires_at"] <= utcnow():
            status = "expired"
        else:
            status = "pending"
        return Invitation.model_validate({**row, "status": status})

    def list_invitations(self, principal: Principal, product_id: str, tenant_id: str) -> list[Invitation]:
        self.authz.require(principal, "members:read", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT * FROM axentra_invitations WHERE product_id = %s AND tenant_id = %s"
                " ORDER BY created_at DESC LIMIT 500",
                (product_id, tenant_id),
            )
        return [self._invitation(r) for r in rows]

    def invite(
        self, principal: Principal, product_id: str, tenant_id: str, *, email: str, role: str
    ) -> NewInvitation:
        self.authz.require(principal, "members:manage", product_id, tenant_id)
        email = normalize_email(email)
        token = "axinv_" + new_token()
        iid = new_id("inv")
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            self._check_role(tx, product_id, role, "tenant")
            if tx.one(
                "SELECT 1 FROM axentra_invitations WHERE tenant_id = %s AND lower(email) = lower(%s)"
                " AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()",
                (tenant_id, email),
            ):
                raise Conflict("an open invitation for this email exists")
            tx.execute(
                "INSERT INTO axentra_invitations (id, product_id, tenant_id, email, role, token_hash, invited_by,"
                " expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    iid,
                    product_id,
                    tenant_id,
                    email,
                    role,
                    hash_token(token),
                    principal.actor.id,
                    utcnow() + INVITATION_TTL,
                ),
            )
            self.audit.record(
                tx,
                principal,
                "tenancy.invitation.create",
                target_type="invitation",
                target_id=iid,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"email": email, "role": role},
            )
            row = tx.one_or_404("SELECT * FROM axentra_invitations WHERE id = %s", (iid,))
        return NewInvitation(invitation=self._invitation(row), token=token)

    def revoke_invitation(
        self, principal: Principal, product_id: str, tenant_id: str, invitation_id: str
    ) -> None:
        self.authz.require(principal, "members:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            n = tx.execute(
                "UPDATE axentra_invitations SET revoked_at = now() WHERE id = %s AND tenant_id = %s"
                " AND accepted_at IS NULL AND revoked_at IS NULL",
                (invitation_id, tenant_id),
            )
            if n == 0:
                raise NotFound("open invitation not found")
            self.audit.record(
                tx,
                principal,
                "tenancy.invitation.revoke",
                target_type="invitation",
                target_id=invitation_id,
                product_id=product_id,
                tenant_id=tenant_id,
            )

    def accept_invitation(self, principal: Principal, token: str) -> Membership:
        """The logged-in user accepts; the invitation's email must match the user's email."""
        if principal.user_id is None:
            raise Forbidden("only users can accept invitations")
        with self.db.transaction(DbScope.platform()) as tx:
            inv = tx.one(
                "SELECT * FROM axentra_invitations WHERE token_hash = %s FOR UPDATE", (hash_token(token),)
            )
            if inv is None or inv["accepted_at"] or inv["revoked_at"] or inv["expires_at"] <= utcnow():
                raise NotFound("the invitation is invalid or expired")
            email = tx.scalar("SELECT email FROM axentra_users WHERE id = %s", (principal.user_id,))
            if str(email).lower() != inv["email"].lower():
                self.audit.record(
                    tx,
                    principal,
                    "tenancy.invitation.accept",
                    outcome="denied",
                    target_type="invitation",
                    target_id=inv["id"],
                    product_id=inv["product_id"],
                    tenant_id=inv["tenant_id"],
                )
                raise Forbidden("this invitation was sent to another email address")
            tx.execute(
                "INSERT INTO axentra_memberships (id, product_id, tenant_id, user_id, role) VALUES (%s,%s,%s,%s,%s)"
                " ON CONFLICT (tenant_id, user_id) DO NOTHING",
                (new_id("mem"), inv["product_id"], inv["tenant_id"], principal.user_id, inv["role"]),
            )
            tx.execute(
                "UPDATE axentra_invitations SET accepted_at = now(), accepted_by = %s WHERE id = %s",
                (principal.user_id, inv["id"]),
            )
            self.audit.record(
                tx,
                principal,
                "tenancy.invitation.accept",
                target_type="invitation",
                target_id=inv["id"],
                product_id=inv["product_id"],
                tenant_id=inv["tenant_id"],
            )
            row = tx.one_or_404(
                self._MEMBER_SQL + " WHERE m.tenant_id = %s AND m.user_id = %s",
                (inv["tenant_id"], principal.user_id),
            )
        return Membership.model_validate(row)
