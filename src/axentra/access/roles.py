"""Built-in and custom roles of a product."""

from __future__ import annotations

from psycopg import errors as pg_errors

from axentra.access.authorizer import Authorizer
from axentra.access.models import PermissionInfo, Role
from axentra.access.permissions import (
    BUILTIN_ROLES,
    CATALOG,
    PRODUCT,
    READS,
    TENANT,
    TENANT_READ_LIKE,
    validate_permissions,
)
from axentra.access.product_permissions import ProductCatalog, load_catalog
from axentra.audit.log import AuditLog
from axentra.core.context import Principal
from axentra.core.errors import Conflict, NotFound, PreconditionFailed, ValidationFailed
from axentra.core.ids import new_id
from axentra.data.database import Database, DbScope, Tx


def permission_catalog(*, include_platform: bool = True) -> list[PermissionInfo]:
    """The built-in catalog (``GET /v1/permissions``)."""
    return [
        PermissionInfo(
            name=p.name,
            scope=p.scope,
            description=p.description,
            read_like=p.name in READS or p.name in TENANT_READ_LIKE,
        )
        for p in CATALOG
        if include_platform or p.scope != "platform"
    ]


class RoleService:
    def __init__(self, db: Database, authz: Authorizer, audit: AuditLog) -> None:
        self.db = db
        self.authz = authz
        self.audit = audit

    def list_roles(self, principal: Principal, product_id: str) -> list[Role]:
        self.authz.require(principal, "roles:read", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            catalog = load_catalog(tx, product_id)
            rows = tx.all("SELECT * FROM axentra_roles WHERE product_id = %s ORDER BY key", (product_id,))
        # Built-in roles as they apply in this product (including product-defined permissions).
        roles = [
            Role(
                id=None,
                key=r.key,
                name=r.name,
                description=r.description,
                scope=r.scope,
                permissions=sorted(catalog.builtin_role(r.key)),
                builtin=True,
            )
            for r in BUILTIN_ROLES.values()
        ]
        roles += [
            Role(
                id=r["id"],
                key=r["key"],
                name=r["name"],
                description=r["description"],
                scope=r["scope"],
                permissions=sorted(r["permissions"]),
                builtin=False,
                version=r["version"],
            )
            for r in rows
        ]
        return roles

    @staticmethod
    def _check(tx: Tx, product_id: str, scope: str, permissions: list[str]) -> list[str]:
        """Built-in names plus the product's active permissions; tenant roles only tenant-scoped ones."""
        catalog: ProductCatalog = load_catalog(tx, product_id)
        perms = validate_permissions(permissions, product_permissions=catalog.scopes)
        allowed = (PRODUCT | TENANT | catalog.names) if scope == "product" else catalog.tenant_mask
        bad = sorted(perms - allowed)
        if bad:
            raise ValidationFailed(f"permissions not allowed for a {scope} role: {', '.join(bad)}")
        return sorted(perms)

    def create_role(
        self,
        principal: Principal,
        product_id: str,
        *,
        key: str,
        name: str,
        scope: str,
        permissions: list[str],
        description: str = "",
    ) -> Role:
        self.authz.require(principal, "roles:manage", product_id)
        if scope not in ("product", "tenant"):
            raise ValidationFailed("scope must be product or tenant")
        if key in BUILTIN_ROLES:
            raise Conflict("this key belongs to a built-in role")
        rid = new_id("rol")
        try:
            with self.db.transaction(DbScope.product(product_id)) as tx:
                perms = self._check(tx, product_id, scope, permissions)
                tx.execute(
                    "INSERT INTO axentra_roles (id, product_id, key, name, description, scope, permissions)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (rid, product_id, key, name, description, scope, perms),
                )
                self.audit.record(
                    tx,
                    principal,
                    "access.role.create",
                    target_type="role",
                    target_id=rid,
                    product_id=product_id,
                    details={"key": key, "permissions": perms},
                )
        except pg_errors.CheckViolation:
            raise ValidationFailed("key must be 2-41 lowercase letters, digits or underscores") from None
        except pg_errors.UniqueViolation:
            raise Conflict("a role with this key exists") from None
        return next(r for r in self.list_roles(Principal.system(), product_id) if r.id == rid)

    def update_role(
        self,
        principal: Principal,
        product_id: str,
        role_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        permissions: list[str] | None = None,
        if_match: int | None = None,
    ) -> Role:
        self.authz.require(principal, "roles:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_roles WHERE id = %s AND product_id = %s FOR UPDATE",
                (role_id, product_id),
                what="role",
            )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the role was changed by someone else")
            perms = (
                self._check(tx, product_id, row["scope"], permissions)
                if permissions is not None
                else row["permissions"]
            )
            tx.execute(
                "UPDATE axentra_roles SET name = %s, description = %s, permissions = %s, version = version + 1,"
                " updated_at = now() WHERE id = %s",
                (
                    name or row["name"],
                    row["description"] if description is None else description,
                    perms,
                    role_id,
                ),
            )
            self.audit.record(
                tx,
                principal,
                "access.role.update",
                target_type="role",
                target_id=role_id,
                product_id=product_id,
                details={"permissions": perms},
            )
        return next(r for r in self.list_roles(Principal.system(), product_id) if r.id == role_id)

    def delete_role(self, principal: Principal, product_id: str, role_id: str) -> None:
        self.authz.require(principal, "roles:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT key FROM axentra_roles WHERE id = %s AND product_id = %s",
                (role_id, product_id),
                what="role",
            )
            in_use = tx.scalar(
                "SELECT (SELECT count(*) FROM axentra_memberships WHERE product_id = %(p)s AND role = %(k)s)"
                " + (SELECT count(*) FROM axentra_product_members WHERE product_id = %(p)s AND role = %(k)s)",
                {"p": product_id, "k": row["key"]},
            )
            if in_use:
                raise Conflict(f"the role is assigned {in_use} times; reassign those members first")
            tx.execute("DELETE FROM axentra_roles WHERE id = %s", (role_id,))
            self.audit.record(
                tx,
                principal,
                "access.role.delete",
                target_type="role",
                target_id=role_id,
                product_id=product_id,
                details={"key": row["key"]},
            )

    def get_role(self, principal: Principal, product_id: str, role_id: str) -> Role:
        for r in self.list_roles(principal, product_id):
            if r.id == role_id:
                return r
        raise NotFound("role not found")
