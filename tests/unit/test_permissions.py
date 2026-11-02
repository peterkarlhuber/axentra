from axentra.access.permissions import BUILTIN_ROLES, PLATFORM, PRODUCT, TENANT


def test_builtin_roles_hold_no_platform_permissions():
    for role in BUILTIN_ROLES.values():
        assert not role.permissions & PLATFORM, role.key
        if role.scope == "tenant":
            assert role.permissions <= TENANT, role.key
        else:
            assert role.permissions <= PRODUCT | TENANT


def test_only_owner_manages_product_members():
    holders = {k for k, r in BUILTIN_ROLES.items() if "product_members:manage" in r.permissions}
    assert holders == {"product_owner"}


def test_only_owner_declares_product_permissions():
    holders = {k for k, r in BUILTIN_ROLES.items() if "permissions:manage" in r.permissions}
    assert holders == {"product_owner"}


def test_product_permission_names():
    from axentra.access.permissions import ALL, is_product_permission_name

    for good in ("crm.deals:approve", "my-app.runs:start", "crm.deals.notes:edit", "a.b:c"):
        assert is_product_permission_name(good), good
    for bad in (
        "records:read",
        "crm:approve",
        "Crm.deals:approve",
        "crm.deals",
        "crm.deals:",
        ".x:y",
        "crm..x:y",
    ):
        assert not is_product_permission_name(bad), bad
    assert not any(is_product_permission_name(n) for n in ALL)  # never collides with built-in names


def test_product_catalog_grants():
    from axentra.access.product_permissions import ProductCatalog, ProductPermission, check_definition

    perms = [
        check_definition(ProductPermission("crm.deals:approve", "tenant", default_roles=("member",))),
        check_definition(ProductPermission("crm.deals:read", "tenant")),
        check_definition(ProductPermission("crm.reports:export", "product", read_like=True)),
    ]
    cat = ProductCatalog({p.name: p for p in perms})
    names = {p.name for p in perms}
    assert cat.builtin_role("product_owner") >= names
    assert cat.builtin_role("product_admin") >= names
    assert cat.builtin_role("tenant_owner") & names == {"crm.deals:approve", "crm.deals:read"}
    assert cat.builtin_role("member") & names == {"crm.deals:approve"}
    assert cat.builtin_role("viewer") & names == set()
    assert cat.builtin_role("product_viewer") & names == {"crm.deals:read", "crm.reports:export"}
    assert cat.platform_role("platform_admin") >= names
    assert cat.platform_role("platform_viewer") & names == {"crm.deals:read", "crm.reports:export"}
    assert cat.tenant_mask & names == {"crm.deals:approve", "crm.deals:read"}
    # Custom roles: unknown or retired names grant nothing.
    custom = {"x": frozenset({"crm.deals:approve", "crm.gone:away", "records:read"})}
    assert cat.role_permissions("x", custom) == {"crm.deals:approve", "records:read"}
    assert cat.role_permissions(None, custom) == frozenset()


def test_validate_permissions_per_product():
    import pytest

    from axentra.access.permissions import validate_permissions
    from axentra.core.errors import ValidationFailed

    assert validate_permissions(["crm.x:y"], product_permissions={"crm.x:y": "tenant"}) == {"crm.x:y"}
    with pytest.raises(ValidationFailed):
        validate_permissions(["crm.x:y"])
    with pytest.raises(ValidationFailed):
        validate_permissions(["crm.x:y"], product_permissions={"erp.x:y": "tenant"})
    assert validate_permissions(["crm.x:y"], any_product_name=True) == {"crm.x:y"}
    with pytest.raises(ValidationFailed):
        validate_permissions(["nonsense"], any_product_name=True)
