"""Role ceiling for role definitions (security assessment finding A-01).

``roles:manage`` must not let a caller put permissions into a role that it does not hold itself, nor
reshape or delete a role that is stronger than its own grant. Platform admins and system code are
exempt; product owners hold every product permission and so can still define any role.
"""

from __future__ import annotations

from typing import Any

from axentra.access.permissions import PRODUCT, TENANT
from tests.integration.conftest import World

ALL = sorted(PRODUCT | TENANT)


def _ok(r: Any, code: int = 201) -> Any:
    assert r.status_code == code, r.text
    return r.json() if r.content else {}


def _product(world: World) -> tuple[str, str]:
    a = world.admin
    pid = _ok(a.post("/v1/products", json={"slug": "crm", "name": "CRM"}))["id"]
    tid = _ok(a.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}))["id"]
    return pid, tid


def _operator(world: World, pid: str, email: str, role: str) -> Any:
    world.user(email)
    _ok(world.admin.post(f"/v1/products/{pid}/members", json={"email": email, "role": role}))
    return world.login_as(email)


def _role(world: World, pid: str, key: str, permissions: list[str], scope: str = "product") -> str:
    body = {"key": key, "name": key, "scope": scope, "permissions": permissions}
    return str(_ok(world.admin.post(f"/v1/products/{pid}/roles", json=body))["id"])


def _perms(world: World, pid: str, rid: str) -> list[str]:
    roles = _ok(world.admin.get(f"/v1/products/{pid}/roles"), 200)
    return list(next(r for r in roles if r["id"] == rid)["permissions"])


def test_role_manager_cannot_create_or_patch_a_role_above_its_grant(world: World) -> None:
    pid, _ = _product(world)
    _role(world, pid, "role_editor", ["product:read", "roles:read", "roles:manage"])
    editor = _operator(world, pid, "re@example.com", "role_editor")
    r = editor.post(
        f"/v1/products/{pid}/roles",
        json={"key": "reader", "name": "Reader", "scope": "tenant", "permissions": ["records:read"]},
    )
    assert r.status_code == 403, r.text
    assert "records:read" in r.json()["detail"]
    # Within its own grant it may still define roles.
    _ok(
        editor.post(
            f"/v1/products/{pid}/roles",
            json={"key": "viewer2", "name": "Viewer", "scope": "product", "permissions": ["product:read"]},
        )
    )
    other = _role(world, pid, "other", ["product:read"])
    r = editor.patch(
        f"/v1/products/{pid}/roles/{other}", json={"permissions": ["product:read", "tenants:read"]}
    )
    assert r.status_code == 403, r.text
    assert _perms(world, pid, other) == ["product:read"]


def test_role_manager_cannot_escalate_its_own_role(world: World) -> None:
    pid, tid = _product(world)
    rid = _role(world, pid, "role_editor", ["product:read", "roles:read", "roles:manage"])
    editor = _operator(world, pid, "re@example.com", "role_editor")
    r = editor.patch(f"/v1/products/{pid}/roles/{rid}", json={"permissions": ALL})
    assert r.status_code == 403, r.text
    assert _perms(world, pid, rid) == ["product:read", "roles:manage", "roles:read"]
    assert editor.get(f"/v1/products/{pid}/tenants/{tid}/records/notes").status_code == 403
    assert editor.get(f"/v1/products/{pid}/api-keys").status_code == 403


def test_product_admin_cannot_hand_out_owner_only_permissions(world: World) -> None:
    pid, _ = _product(world)
    pa = _operator(world, pid, "pa@example.com", "product_admin")
    for perm in ("permissions:manage", "product_members:manage"):
        r = pa.post(
            f"/v1/products/{pid}/roles",
            json={"key": "super", "name": "Super", "scope": "product", "permissions": ["product:read", perm]},
        )
        assert r.status_code == 403, r.text
    rid = _role(world, pid, "ops", ["product:read"])
    r = pa.patch(f"/v1/products/{pid}/roles/{rid}", json={"permissions": ALL})
    assert r.status_code == 403, r.text
    assert _perms(world, pid, rid) == ["product:read"]
    # A role that is already stronger than the product admin can neither be reshaped nor deleted.
    strong = _role(world, pid, "operators", ["product:read", "product_members:manage"])
    assert (
        pa.patch(f"/v1/products/{pid}/roles/{strong}", json={"permissions": ["product:read"]}).status_code
        == 403
    )
    assert pa.patch(f"/v1/products/{pid}/roles/{strong}", json={"name": "Renamed"}).status_code == 403
    assert pa.delete(f"/v1/products/{pid}/roles/{strong}").status_code == 403
    assert _perms(world, pid, strong) == ["product:read", "product_members:manage"]
    # Everything else it holds, product and tenant permissions alike, it may still put into roles.
    allowed = sorted(set(ALL) - {"permissions:manage", "product_members:manage"})
    _ok(pa.patch(f"/v1/products/{pid}/roles/{rid}", json={"permissions": allowed}), 200)
    _ok(
        pa.post(
            f"/v1/products/{pid}/roles",
            json={"key": "clerk", "name": "Clerk", "scope": "tenant", "permissions": ["records:write"]},
        )
    )


def test_removing_permissions_within_the_ceiling_still_works(world: World) -> None:
    pid, _ = _product(world)
    pa = _operator(world, pid, "pa@example.com", "product_admin")
    rid = _role(world, pid, "ops", ["product:read", "tenants:read", "records:read"])
    _ok(pa.patch(f"/v1/products/{pid}/roles/{rid}", json={"permissions": ["product:read"]}), 200)
    assert _perms(world, pid, rid) == ["product:read"]
    _ok(pa.delete(f"/v1/products/{pid}/roles/{rid}"), 204)
    # The role manager may also shrink its own role.
    own = _role(world, pid, "role_editor", ["product:read", "roles:read", "roles:manage", "tenants:read"])
    editor = _operator(world, pid, "re@example.com", "role_editor")
    _ok(
        editor.patch(
            f"/v1/products/{pid}/roles/{own}",
            json={"permissions": ["product:read", "roles:read", "roles:manage"]},
        ),
        200,
    )


def test_product_owner_and_platform_admin_define_any_role(world: World) -> None:
    pid, _ = _product(world)
    po = _operator(world, pid, "po@example.com", "product_owner")
    rid = _ok(
        po.post(
            f"/v1/products/{pid}/roles",
            json={"key": "all", "name": "All", "scope": "product", "permissions": ALL},
        )
    )["id"]
    _ok(po.patch(f"/v1/products/{pid}/roles/{rid}", json={"permissions": ["product:read"]}), 200)
    _ok(po.patch(f"/v1/products/{pid}/roles/{rid}", json={"permissions": ALL}), 200)
    _ok(po.delete(f"/v1/products/{pid}/roles/{rid}"), 204)
    # The platform admin (world.admin, no product membership) is not bounded.
    rid = _role(world, pid, "all2", ALL)
    _ok(world.admin.patch(f"/v1/products/{pid}/roles/{rid}", json={"permissions": ["product:read"]}), 200)
    _ok(world.admin.delete(f"/v1/products/{pid}/roles/{rid}"), 204)
