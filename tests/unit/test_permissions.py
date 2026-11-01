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
