from __future__ import annotations

from fastapi.testclient import TestClient


def _setup(world):
    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    t1 = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    t2 = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "globex", "name": "Globex"}).json()[
        "id"
    ]
    return pid, t1, t2


def test_api_key_lifecycle_and_scope(world):
    pid, t1, t2 = _setup(world)
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "acme sync", "permissions": ["records:read", "records:write"], "tenant_id": t1},
    )
    assert r.status_code == 201, r.text
    secret = r.json()["secret"]
    kid = r.json()["key"]["id"]
    assert secret.startswith("axk_")
    # The list never contains the secret or its hash.
    listing = world.admin.get(f"/v1/products/{pid}/api-keys").text
    # The secret part may itself contain "_" (urlsafe base64), so cut it by position, not by split.
    secret_part = secret[len("axk_") + 26 + 1 :]
    assert len(secret_part) >= 32
    assert secret_part not in listing and "secret_hash" not in listing
    c = TestClient(world.app, headers={"Authorization": f"Bearer {secret}"})
    assert c.post(f"/v1/products/{pid}/tenants/{t1}/records/items", json={"n": 1}).status_code == 201
    assert c.get(f"/v1/products/{pid}/tenants/{t2}/records/items").status_code == 404
    assert c.get(f"/v1/products/{pid}/tenants").status_code == 403
    assert (
        c.post(
            f"/v1/products/{pid}/api-keys", json={"name": "x", "permissions": ["records:read"]}
        ).status_code
        == 403
    )
    assert c.get("/v1/users").status_code == 403
    # X-API-Key header works too.
    c2 = TestClient(world.app, headers={"X-API-Key": secret})
    assert c2.get(f"/v1/products/{pid}/tenants/{t1}/records/items").status_code == 200
    # Rotate: the new key works, the old is revoked immediately (no grace).
    r = world.admin.post(f"/v1/products/{pid}/api-keys/{kid}/rotate", json={})
    new_secret = r.json()["secret"]
    assert c.get(f"/v1/products/{pid}/tenants/{t1}/records/items").status_code == 401
    c3 = TestClient(world.app, headers={"Authorization": f"Bearer {new_secret}"})
    assert c3.get(f"/v1/products/{pid}/tenants/{t1}/records/items").status_code == 200
    new_id = r.json()["key"]["id"]
    assert world.admin.post(f"/v1/products/{pid}/api-keys/{new_id}/revoke").json()["status"] == "revoked"
    assert c3.get(f"/v1/products/{pid}/tenants/{t1}/records/items").status_code == 401


def test_api_key_rotation_grace(world):
    pid, t1, _ = _setup(world)
    r = world.admin.post(f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["records:read"]})
    old = r.json()["secret"]
    world.admin.post(
        f"/v1/products/{pid}/api-keys/{r.json()['key']['id']}/rotate", json={"grace_seconds": 600}
    )
    c = TestClient(world.app, headers={"Authorization": f"Bearer {old}"})
    assert c.get(f"/v1/products/{pid}/tenants/{t1}/records/items").status_code == 200


def test_invalid_api_keys(world):
    pid, t1, _ = _setup(world)
    for token in ["axk_nope", "axk_" + "a" * 26 + "_" + "b" * 43, "Bearer"]:
        c = TestClient(world.app, headers={"Authorization": f"Bearer {token}"})
        assert c.get(f"/v1/products/{pid}/tenants/{t1}/records/items").status_code == 401


def test_no_privilege_escalation_through_keys(world):
    pid, t1, _ = _setup(world)
    world.user("sup@example.com")
    world.admin.post(
        f"/v1/products/{pid}/members", json={"email": "sup@example.com", "role": "product_admin"}
    )
    sup = world.login_as("sup@example.com")
    r = sup.post(f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["products:create"]})
    assert r.status_code == 422  # platform permission
    r = sup.post(
        f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["product_members:manage"]}
    )
    assert r.status_code == 403  # does not hold it


def test_custom_roles(world):
    pid, t1, _ = _setup(world)
    perms = world.admin.get("/v1/permissions").json()
    assert any(p["name"] == "records:read" for p in perms)
    r = world.admin.post(
        f"/v1/products/{pid}/roles",
        json={
            "key": "auditor",
            "name": "Auditor",
            "scope": "tenant",
            "permissions": ["records:read", "tenant:read"],
        },
    )
    assert r.status_code == 201, r.text
    role_id = r.json()["id"]
    assert (
        world.admin.post(
            f"/v1/products/{pid}/roles",
            json={"key": "bad", "name": "B", "scope": "tenant", "permissions": ["tenants:delete"]},
        ).status_code
        == 422
    )
    world.user("aud@example.com")
    world.admin.post(
        f"/v1/products/{pid}/tenants/{t1}/members", json={"email": "aud@example.com", "role": "auditor"}
    )
    aud = world.login_as("aud@example.com")
    assert aud.get(f"/v1/products/{pid}/tenants/{t1}/records/x").status_code == 200
    assert aud.post(f"/v1/products/{pid}/tenants/{t1}/records/x", json={}).status_code == 403
    # Grant write by editing the role; effective immediately.
    world.admin.patch(
        f"/v1/products/{pid}/roles/{role_id}",
        json={"permissions": ["records:read", "records:write", "tenant:read"]},
    )
    assert aud.post(f"/v1/products/{pid}/tenants/{t1}/records/x", json={}).status_code == 201
    assert world.admin.delete(f"/v1/products/{pid}/roles/{role_id}").status_code == 409
    roles = world.admin.get(f"/v1/products/{pid}/roles").json()
    assert {r["key"] for r in roles} >= {"product_owner", "member", "auditor"}


def test_unauthenticated_requests(world):
    c = TestClient(world.app)
    for path in ["/v1/me", "/v1/products", "/v1/users", "/v1/audit", "/v1/permissions", "/v1/settings"]:
        assert c.get(path).status_code == 401, path


def test_settings_do_not_leak_secrets(world):
    r = world.admin.get("/v1/settings")
    assert r.status_code == 200
    text = r.text
    assert "master_keys" not in text and world.ax.settings.security.master_keys.split(":")[1] not in text
    assert "postgres" not in text


def test_audit_trail_records_changes(world):
    pid, t1, _ = _setup(world)
    events = world.admin.get("/v1/audit", params={"product_id": pid}).json()["items"]
    actions = {e["action"] for e in events}
    assert {"tenancy.product.create", "tenancy.tenant.create"} <= actions
    page = world.admin.get("/v1/audit", params={"product_id": pid, "limit": 1}).json()
    assert page["next_cursor"]
    page2 = world.admin.get(
        "/v1/audit", params={"product_id": pid, "limit": 1, "cursor": page["next_cursor"]}
    ).json()
    assert page2["items"][0]["id"] != page["items"][0]["id"]
    one = world.admin.get(f"/v1/audit/{events[0]['id']}")
    assert one.status_code == 200
