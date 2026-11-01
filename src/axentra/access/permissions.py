"""The permission catalog and the built-in roles.

Permissions are strings ``<resource>:<action>``. Each has a scope:

- ``platform``: installation-wide (only platform roles grant them; never API keys).
- ``product``: about one product as a whole.
- ``tenant``: about data inside one tenant. Product roles that hold a tenant permission hold it
  in every tenant of that product.

Access is denied unless a role or API key grants the permission explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PermScope = Literal["platform", "product", "tenant"]


@dataclass(frozen=True, slots=True)
class PermissionDef:
    name: str
    scope: PermScope
    description: str


CATALOG: tuple[PermissionDef, ...] = (
    # Platform
    PermissionDef("products:create", "platform", "Create products (multi-product mode)"),
    PermissionDef("products:archive", "platform", "Archive and restore products"),
    PermissionDef("users:read", "platform", "List all users of the installation"),
    PermissionDef("users:manage", "platform", "Disable users and revoke their sessions"),
    PermissionDef("platform:settings", "platform", "Read installation settings"),
    PermissionDef("platform:audit", "platform", "Read installation-wide audit events"),
    # Product
    PermissionDef("product:read", "product", "View the product and its overview"),
    PermissionDef("product:manage", "product", "Edit product details and settings"),
    PermissionDef("product_members:read", "product", "View product operators"),
    PermissionDef("product_members:manage", "product", "Add, change and remove product operators"),
    PermissionDef("product_users:read", "product", "View users who belong to the product's tenants"),
    PermissionDef("tenants:read", "product", "List tenants"),
    PermissionDef("tenants:create", "product", "Create tenants"),
    PermissionDef("tenants:update", "product", "Edit and suspend tenants"),
    PermissionDef("tenants:delete", "product", "Delete tenants and all their data"),
    PermissionDef("roles:read", "product", "View roles"),
    PermissionDef("roles:manage", "product", "Create, edit and delete custom roles"),
    PermissionDef("api_keys:read", "product", "View API keys (never their secrets)"),
    PermissionDef("api_keys:manage", "product", "Create, rotate and revoke API keys"),
    PermissionDef("audit:read", "product", "Read the product's audit events"),
    PermissionDef("collections:read", "product", "View record collection statistics"),
    PermissionDef("jobs:read", "product", "View background jobs and events"),
    PermissionDef("jobs:manage", "product", "Enqueue, retry and cancel jobs"),
    PermissionDef("webhooks:read", "product", "View webhooks and deliveries"),
    PermissionDef("webhooks:manage", "product", "Create, edit and delete webhooks"),
    PermissionDef("usage:manage", "product", "Define meters and quotas"),
    PermissionDef("billing:manage", "product", "Manage plans, prices and subscriptions"),
    PermissionDef("notify:manage", "product", "Manage notification templates and send tests"),
    # Tenant
    PermissionDef("tenant:read", "tenant", "View the tenant"),
    PermissionDef("members:read", "tenant", "View tenant members and invitations"),
    PermissionDef("members:manage", "tenant", "Invite, change and remove tenant members"),
    PermissionDef("records:read", "tenant", "Read records"),
    PermissionDef("records:write", "tenant", "Create, change and delete records"),
    PermissionDef("files:read", "tenant", "List and download files"),
    PermissionDef("files:write", "tenant", "Upload and delete files"),
    PermissionDef("events:publish", "tenant", "Publish events and enqueue jobs for the tenant"),
    PermissionDef("usage:read", "tenant", "View usage and quotas"),
    PermissionDef("usage:record", "tenant", "Record usage"),
    PermissionDef("billing:read", "tenant", "View subscription and entitlements"),
    PermissionDef("notify:send", "tenant", "Send notifications"),
    PermissionDef("notify:preferences", "tenant", "Manage notification preferences"),
)

BY_NAME: dict[str, PermissionDef] = {p.name: p for p in CATALOG}
ALL = frozenset(BY_NAME)
PLATFORM = frozenset(p.name for p in CATALOG if p.scope == "platform")
PRODUCT = frozenset(p.name for p in CATALOG if p.scope == "product")
TENANT = frozenset(p.name for p in CATALOG if p.scope == "tenant")
READS = frozenset(p for p in ALL if p.endswith(":read"))


@dataclass(frozen=True, slots=True)
class BuiltinRole:
    key: str
    name: str
    scope: Literal["product", "tenant"]
    description: str
    permissions: frozenset[str]


_TENANT_ADMIN = TENANT
_TENANT_MEMBER = frozenset(
    {
        "tenant:read",
        "members:read",
        "records:read",
        "records:write",
        "files:read",
        "files:write",
        "events:publish",
        "usage:read",
        "usage:record",
        "billing:read",
        "notify:send",
        "notify:preferences",
    }
)
_TENANT_VIEWER = frozenset(
    {"tenant:read", "members:read", "records:read", "files:read", "usage:read", "billing:read"}
)

BUILTIN_ROLES: dict[str, BuiltinRole] = {
    r.key: r
    for r in (
        BuiltinRole(
            "product_owner", "Product owner", "product", "Full control of the product", PRODUCT | TENANT
        ),
        BuiltinRole(
            "product_admin",
            "Product admin",
            "product",
            "Manages tenants, roles, keys and data; cannot manage product operators",
            (PRODUCT - {"product_members:manage"}) | TENANT,
        ),
        BuiltinRole(
            "product_support",
            "Support",
            "product",
            "Reads everything in the product and manages tenant members",
            (PRODUCT & READS) | {"product:read", "members:manage"} | (TENANT & READS) | {"tenant:read"},
        ),
        BuiltinRole(
            "product_viewer",
            "Product viewer",
            "product",
            "Read-only access to the product",
            (PRODUCT & READS) | {"product:read"} | (TENANT & READS) | {"tenant:read"},
        ),
        BuiltinRole("tenant_owner", "Owner", "tenant", "Full control of the tenant", _TENANT_ADMIN),
        BuiltinRole(
            "tenant_admin", "Admin", "tenant", "Manages members and data of the tenant", _TENANT_ADMIN
        ),
        BuiltinRole("member", "Member", "tenant", "Works with the tenant's data", _TENANT_MEMBER),
        BuiltinRole("viewer", "Viewer", "tenant", "Read-only access to the tenant", _TENANT_VIEWER),
    )
}

PLATFORM_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "platform_admin": ALL,
    "platform_viewer": READS | {"product:read", "tenant:read", "platform:settings", "platform:audit"},
}


def validate_permissions(
    perms: list[str] | set[str] | frozenset[str], *, allow_platform: bool = False
) -> frozenset[str]:
    from axentra.core.errors import ValidationFailed

    unknown = sorted(set(perms) - ALL)
    if unknown:
        raise ValidationFailed(f"unknown permissions: {', '.join(unknown)}")
    if not allow_platform and set(perms) & PLATFORM:
        raise ValidationFailed("platform permissions cannot be granted here")
    return frozenset(perms)
