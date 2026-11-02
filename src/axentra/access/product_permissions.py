"""Product-defined permissions: definitions, the per-product catalog and the built-in role grants.

A product declares its own permissions next to the built-in catalog
(:data:`axentra.access.permissions.CATALOG`), for example ``crm.deals:approve``. Each one has a
scope (``product`` or ``tenant``; never ``platform``), a description, an optional ``read_like``
flag and optional default grants for built-in roles. Definitions live in
``axentra_product_permissions`` (one row per product and name, row-level security on the
product). Embedding products register them in process (``ax.permissions.register``, mirrored into
the table at :meth:`~axentra.platform.Axentra.start`); products that do not embed Axentra declare
them over the HTTP API (``permissions:manage``). See docs/architecture/SECURITY_MODEL.md.

Effective grants of a product permission (only while it is active, i.e. not retired):

- ``platform_admin``, ``product_owner`` and ``product_admin`` hold every product permission;
  ``tenant_owner`` and ``tenant_admin`` every tenant-scoped one (owners and admins keep "full
  control" and can hand the new permissions out under the role ceiling).
- ``platform_viewer``, ``product_viewer`` and ``product_support`` hold the ``read_like`` ones
  (default: names ending in ``:read``).
- Other built-in roles (``member``, ``viewer``) hold only what the definition lists in
  ``default_roles``.
- Custom roles and API keys hold what they list, validated per product when written.

Retiring a permission never grants anything: a retired name is ignored wherever it is still stored
(custom roles, API keys, job kinds), exactly like an unknown name. Declaring it again restores its
effect for those holders.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from axentra.access.permissions import (
    ALL,
    BUILTIN_ROLES,
    MAX_PRODUCT_PERMISSION_LENGTH,
    PLATFORM_ROLE_PERMISSIONS,
    TENANT,
    is_product_permission_name,
)
from axentra.core.errors import ValidationFailed
from axentra.data.database import Tx

ProductPermScope = Literal["product", "tenant"]

#: Built-in roles that automatically hold every active product permission (of their scope).
FULL_PRODUCT_ROLES = frozenset({"product_owner", "product_admin"})
FULL_TENANT_ROLES = frozenset({"tenant_owner", "tenant_admin"})
#: Built-in roles that automatically hold the active ``read_like`` product permissions.
READ_LIKE_ROLES = frozenset({"product_support", "product_viewer"})
MAX_DESCRIPTION = 500
MAX_PERMISSIONS_PER_PRODUCT = 500


@dataclass(frozen=True, slots=True)
class ProductPermission:
    """A permission a product declares (see the module docstring)."""

    name: str
    scope: ProductPermScope
    description: str = ""
    default_roles: tuple[str, ...] = ()
    """Built-in roles that hold it in addition to the automatic grants (e.g. ``("member",)``)."""
    read_like: bool | None = None
    """Only reads data (granted to viewer/support roles); default: the name ends in ``:read``."""

    @property
    def is_read_like(self) -> bool:
        return self.name.endswith(":read") if self.read_like is None else self.read_like


def check_definition(p: ProductPermission) -> ProductPermission:
    """Validate a definition (422 on errors) and return it normalized."""
    if not isinstance(p.name, str) or not is_product_permission_name(p.name):
        raise ValidationFailed(
            f"invalid product permission name {p.name!r}: use <namespace>.<resource>:<action> with"
            f" lowercase letters, digits and underscores (at most {MAX_PRODUCT_PERMISSION_LENGTH}"
            " characters, e.g. crm.deals:approve)"
        )
    if p.scope not in ("product", "tenant"):
        raise ValidationFailed(f"{p.name}: scope must be product or tenant")
    if not isinstance(p.description, str) or len(p.description) > MAX_DESCRIPTION:
        raise ValidationFailed(f"{p.name}: description must be at most {MAX_DESCRIPTION} characters")
    roles = tuple(sorted(set(p.default_roles)))
    for role in roles:
        builtin = BUILTIN_ROLES.get(role)
        if builtin is None:
            raise ValidationFailed(f"{p.name}: default_roles may only name built-in roles, not {role!r}")
        if builtin.scope == "tenant" and p.scope != "tenant":
            raise ValidationFailed(
                f"{p.name}: the tenant role {role} can only hold tenant-scoped permissions"
            )
    return ProductPermission(
        name=p.name,
        scope=p.scope,
        description=p.description.strip(),
        default_roles=roles,
        read_like=p.is_read_like,
    )


def check_definitions(permissions: Iterable[ProductPermission]) -> tuple[ProductPermission, ...]:
    checked = tuple(check_definition(p) for p in permissions)
    names = [p.name for p in checked]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ValidationFailed(f"duplicate product permissions: {', '.join(duplicates)}")
    if len(checked) > MAX_PERMISSIONS_PER_PRODUCT:
        raise ValidationFailed(f"a product may declare at most {MAX_PERMISSIONS_PER_PRODUCT} permissions")
    return checked


@dataclass(frozen=True, slots=True)
class ProductPermissionRecord:
    """A stored definition (``axentra_product_permissions``)."""

    permission: ProductPermission
    declared_by: Literal["code", "api"]
    version: int
    created_at: datetime
    updated_at: datetime
    retired_at: datetime | None


@dataclass(frozen=True, slots=True)
class ProductCatalog:
    """The active product permissions of one product and what they add to built-in roles."""

    permissions: Mapping[str, ProductPermission] = field(default_factory=dict)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self.permissions)

    @property
    def scopes(self) -> dict[str, str]:
        return {name: p.scope for name, p in self.permissions.items()}

    @property
    def known(self) -> frozenset[str]:
        """Every name that may be granted in the product: built-in and active product permissions."""
        return ALL | self.names

    @property
    def tenant_mask(self) -> frozenset[str]:
        """What a tenant role can confer: built-in and product permissions with tenant scope."""
        return TENANT | frozenset(n for n, p in self.permissions.items() if p.scope == "tenant")

    def builtin_role(self, role_key: str) -> frozenset[str]:
        """A built-in role's permissions in this product (built-in set plus product additions)."""
        base = BUILTIN_ROLES[role_key].permissions
        if not self.permissions:
            return base
        extra = {
            name
            for name, p in self.permissions.items()
            if role_key in FULL_PRODUCT_ROLES
            or (role_key in FULL_TENANT_ROLES and p.scope == "tenant")
            or (role_key in READ_LIKE_ROLES and p.is_read_like)
            or role_key in p.default_roles
        }
        return base | extra

    def platform_role(self, role: str | None) -> frozenset[str]:
        """A platform role's permissions inside this product."""
        if role is None:
            return frozenset()
        base = PLATFORM_ROLE_PERMISSIONS.get(role, frozenset())
        if role == "platform_admin":
            return base | self.names
        if role == "platform_viewer":
            return base | frozenset(n for n, p in self.permissions.items() if p.is_read_like)
        return base

    def role_permissions(self, role_key: str | None, custom: Mapping[str, frozenset[str]]) -> frozenset[str]:
        """The permissions of a built-in or custom role; retired and unknown names grant nothing."""
        if role_key is None:
            return frozenset()
        if role_key in BUILTIN_ROLES:
            return self.builtin_role(role_key)
        return custom.get(role_key, frozenset()) & self.known


EMPTY_CATALOG = ProductCatalog()


def _definition(row: Mapping[str, object]) -> ProductPermission:
    return ProductPermission(
        name=str(row["name"]),
        scope="tenant" if row["scope"] == "tenant" else "product",
        description=str(row["description"]),
        default_roles=tuple(row["default_roles"] or ()),  # type: ignore[arg-type]
        read_like=bool(row["read_like"]),
    )


def load_catalog(tx: Tx, product_id: str) -> ProductCatalog:
    """The active product permissions of ``product_id`` (one indexed query)."""
    rows = tx.all(
        "SELECT name, scope, description, read_like, default_roles FROM axentra_product_permissions"
        " WHERE product_id = %s AND retired_at IS NULL",
        (product_id,),
    )
    if not rows:
        return EMPTY_CATALOG
    return ProductCatalog({r["name"]: _definition(r) for r in rows})


def load_records(tx: Tx, product_id: str, *, include_retired: bool = False) -> list[ProductPermissionRecord]:
    rows = tx.all(
        "SELECT * FROM axentra_product_permissions WHERE product_id = %s"
        + ("" if include_retired else " AND retired_at IS NULL")
        + " ORDER BY name",
        (product_id,),
    )
    return [
        ProductPermissionRecord(
            permission=_definition(r),
            declared_by="api" if r["declared_by"] == "api" else "code",
            version=r["version"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            retired_at=r["retired_at"],
        )
        for r in rows
    ]
