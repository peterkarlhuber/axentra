"""``GET /v1/me?tenants=all|memberships|none`` (AX3-03: the response grew with every tenant)."""

from __future__ import annotations


def _tenant_ids(body):  # type: ignore[no-untyped-def]
    return {p["product"]["slug"]: [t["tenant"]["slug"] for t in p["tenants"]] for p in body["products"]}


def test_me_tenant_modes(world):  # type: ignore[no-untyped-def]
    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tids = {}
    for slug in ("acme", "beta", "gamma"):
        tids[slug] = world.admin.post(
            f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug}
        ).json()["id"]
    # An operator of the product who is also a member of one tenant.
    world.user("op@example.com")
    assert (
        world.admin.post(
            f"/v1/products/{pid}/members", json={"email": "op@example.com", "role": "product_admin"}
        ).status_code
        == 201
    )
    r = world.admin.post(
        f"/v1/products/{pid}/tenants/{tids['beta']}/members",
        json={"email": "op@example.com", "role": "viewer"},
    )
    assert r.status_code == 201
    op = world.login_as("op@example.com")
    full = op.get("/v1/me").json()
    assert _tenant_ids(full) == {"crm": ["acme", "beta", "gamma"]}
    assert _tenant_ids(op.get("/v1/me", params={"tenants": "all"}).json()) == _tenant_ids(full)
    mine = op.get("/v1/me", params={"tenants": "memberships"}).json()
    assert _tenant_ids(mine) == {"crm": ["beta"]}
    assert mine["products"][0]["tenants"][0]["role"] == "viewer"
    none = op.get("/v1/me", params={"tenants": "none"}).json()
    assert _tenant_ids(none) == {"crm": []}
    # Product entries and platform data are the same in every mode.
    for body in (mine, none):
        assert [(p["role"], p["permissions"]) for p in body["products"]] == [
            (p["role"], p["permissions"]) for p in full["products"]
        ]
        assert body["user"] == full["user"] and body["platform_permissions"] == full["platform_permissions"]
    # The platform admin is a member of no tenant.
    assert _tenant_ids(world.admin.get("/v1/me", params={"tenants": "memberships"}).json()) == {"crm": []}
    assert op.get("/v1/me", params={"tenants": "some"}).status_code == 422


def test_me_memberships_for_a_tenant_bound_api_key(world):  # type: ignore[no-untyped-def]
    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    t1 = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "beta", "name": "Beta"})
    key = world.admin.post(
        f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["tenant:read"], "tenant_id": t1}
    ).json()["secret"]
    client = world.browser().client
    r = client.get("/v1/me", params={"tenants": "memberships"}, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    assert _tenant_ids(r.json()) == {"crm": ["acme"]}
