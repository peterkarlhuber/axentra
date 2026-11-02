from __future__ import annotations


def _product(world, slug="crm"):
    r = world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _tenant(world, pid, slug="acme", browser=None):
    r = (browser or world.admin).post(
        f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug.title()}
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_product_crud_and_versioning(world):
    pid = _product(world)
    r = world.admin.patch(f"/v1/products/{pid}", json={"name": "CRM Pro"}, headers={"If-Match": "1"})
    assert r.status_code == 200 and r.json()["version"] == 2
    r = world.admin.patch(f"/v1/products/{pid}", json={"name": "Stale"}, headers={"If-Match": "1"})
    assert r.status_code == 412
    assert world.admin.post("/v1/products", json={"slug": "crm", "name": "dup"}).status_code == 409
    assert world.admin.post(f"/v1/products/{pid}/archive").json()["status"] == "archived"
    assert world.admin.post(f"/v1/products/{pid}/restore").json()["status"] == "active"
    ov = world.admin.get(f"/v1/products/{pid}/overview").json()
    assert ov["tenants"] == 0


def test_tenant_member_flow_and_invitations(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    world.user("owner@example.com")
    r = world.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/members",
        json={"email": "owner@example.com", "role": "tenant_owner"},
    )
    assert r.status_code == 201
    owner = world.login_as("owner@example.com")
    # The tenant owner invites a colleague.
    r = owner.post(
        f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": "dave@example.com", "role": "member"}
    )
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    assert (
        owner.post(
            f"/v1/products/{pid}/tenants/{tid}/invitations",
            json={"email": "dave@example.com", "role": "member"},
        ).status_code
        == 409
    )
    world.user("dave@example.com")
    eve_id = world.user("eve@example.com")
    eve = world.login_as("eve@example.com")
    assert eve.post("/v1/invitations/accept", json={"token": token}).status_code == 403
    dave = world.login_as("dave@example.com")
    r = dave.post("/v1/invitations/accept", json={"token": token})
    assert r.status_code == 200 and r.json()["role"] == "member"
    assert dave.post("/v1/invitations/accept", json={"token": token}).status_code == 404
    # Dave sees his tenant through /me, but cannot manage members.
    me = dave.get("/v1/me").json()
    assert me["products"][0]["tenants"][0]["tenant"]["id"] == tid
    assert (
        dave.post(
            f"/v1/products/{pid}/tenants/{tid}/members", json={"user_id": eve_id, "role": "member"}
        ).status_code
        == 403
    )
    # Last owner protection.
    owner_id = owner.get("/v1/me").json()["user"]["id"]
    assert owner.delete(f"/v1/products/{pid}/tenants/{tid}/members/{owner_id}").status_code == 409


def test_tenant_isolation_between_tenants(world):
    pid = _product(world)
    t1 = _tenant(world, pid, "acme")
    t2 = _tenant(world, pid, "globex")
    world.user("a@example.com")
    world.user("b@example.com")
    world.admin.post(
        f"/v1/products/{pid}/tenants/{t1}/members", json={"email": "a@example.com", "role": "member"}
    )
    world.admin.post(
        f"/v1/products/{pid}/tenants/{t2}/members", json={"email": "b@example.com", "role": "member"}
    )
    a = world.login_as("a@example.com")
    b = world.login_as("b@example.com")
    r = a.post(f"/v1/products/{pid}/tenants/{t1}/records/notes", json={"text": "secret of acme"})
    assert r.status_code == 201
    rid = r.json()["id"]
    # B supplies the foreign tenant id: no access, no existence oracle.
    assert b.get(f"/v1/products/{pid}/tenants/{t1}/records/notes").status_code == 404
    assert b.get(f"/v1/products/{pid}/tenants/{t1}/records/notes/{rid}").status_code == 404
    assert b.get(f"/v1/products/{pid}/tenants/{t2}/records/notes/{rid}").status_code == 404
    assert b.put(f"/v1/products/{pid}/tenants/{t2}/records/notes/{rid}", json={"x": 1}).status_code == 404
    # Tenant lists are limited to own tenants.
    ids = [t["id"] for t in b.get(f"/v1/products/{pid}/tenants").json()["items"]]
    assert ids == [t2]


def test_product_isolation(world):
    p1 = _product(world, "crm")
    p2 = _product(world, "books")
    world.user("op@example.com")
    world.admin.post(f"/v1/products/{p1}/members", json={"email": "op@example.com", "role": "product_admin"})
    op = world.login_as("op@example.com")
    assert [p["id"] for p in op.get("/v1/products").json()] == [p1]
    assert op.get(f"/v1/products/{p2}").status_code == 404
    assert op.get(f"/v1/products/{p2}/tenants").status_code == 404
    assert op.post(f"/v1/products/{p2}/tenants", json={"slug": "x1", "name": "X"}).status_code == 404
    assert op.get("/v1/audit", params={"product_id": p2}).status_code == 404
    # Product admin cannot create products or manage operators.
    assert op.post("/v1/products", json={"slug": "new1", "name": "N"}).status_code == 403
    assert (
        op.post(
            f"/v1/products/{p1}/members", json={"email": "op@example.com", "role": "product_owner"}
        ).status_code
        == 403
    )
    # But can manage tenants of its product.
    assert op.post(f"/v1/products/{p1}/tenants", json={"slug": "t1", "name": "T1"}).status_code == 201


def test_suspended_tenant_blocks_members(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    world.user("m@example.com")
    world.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/members", json={"email": "m@example.com", "role": "member"}
    )
    m = world.login_as("m@example.com")
    assert m.get(f"/v1/products/{pid}/tenants/{tid}/records/notes").status_code == 200
    world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"})
    assert m.get(f"/v1/products/{pid}/tenants/{tid}/records/notes").status_code == 403


def test_delete_tenant_removes_data(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    world.admin.post(f"/v1/products/{pid}/tenants/{tid}/records/notes", json={"a": 1})
    assert world.admin.delete(f"/v1/products/{pid}/tenants/{tid}").status_code == 204
    assert world.admin.get(f"/v1/products/{pid}/tenants/{tid}").status_code == 404
    assert world.admin.get(f"/v1/products/{pid}/collections").json() == []


def test_single_product_mode(single_world):
    w = single_world
    meta = w.browser().get("/v1/meta").json()
    assert meta["mode"] == "single" and meta["product"]["slug"] == "crm"
    assert w.admin.post("/v1/products", json={"slug": "other", "name": "Other"}).status_code == 409
    pid = meta["product"]["id"]
    assert w.admin.post(f"/v1/products/{pid}/archive").status_code == 409
    assert (
        w.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).status_code == 201
    )


def _operator(world, pid, email, role):
    world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/members", json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    return world.login_as(email)


def _key(world, pid, permissions, tenant_id=None):
    from fastapi.testclient import TestClient

    body = {"name": "k", "permissions": permissions}
    if tenant_id:
        body["tenant_id"] = tenant_id
    r = world.admin.post(f"/v1/products/{pid}/api-keys", json=body)
    assert r.status_code == 201, r.text
    return TestClient(world.app, headers={"Authorization": f"Bearer {r.json()['secret']}"})


def test_product_operators_can_read_and_reactivate_a_suspended_tenant(world):
    """P1-2: the tenant record is product administration metadata; its data stays closed."""
    pid = _product(world)
    tid = _tenant(world, pid)
    world.user("m@example.com")
    world.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/members", json={"email": "m@example.com", "role": "tenant_owner"}
    )
    member = world.login_as("m@example.com")
    owner = _operator(world, pid, "po@example.com", "product_owner")
    admin = _operator(world, pid, "pa@example.com", "product_admin")
    support = _operator(world, pid, "ps@example.com", "product_support")
    viewer = _operator(world, pid, "pv@example.com", "product_viewer")
    assert member.get(f"/v1/products/{pid}/tenants/{tid}/records/notes").status_code == 200

    r = owner.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"})
    assert r.status_code == 200 and r.json()["status"] == "suspended"
    version = r.json()["version"]
    # Suspending again is a no-op: no new version, no new audit event.
    r = owner.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"})
    assert r.status_code == 200 and r.json()["version"] == version

    # Operators with tenants:read see the record of the suspended tenant (as in the tenant list).
    for operator in (owner, admin, support, viewer):
        r = operator.get(f"/v1/products/{pid}/tenants/{tid}")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "suspended" and r.json()["member_count"] == 1
    # The tenant's data stays closed for them (isolation unchanged) ...
    for path in ("members", "invitations", "records/notes"):
        assert owner.get(f"/v1/products/{pid}/tenants/{tid}/{path}").status_code == 403
    assert owner.post(f"/v1/products/{pid}/tenants/{tid}/records/notes", json={"a": 1}).status_code == 403
    # ... and for the tenant's own members, including its owner.
    assert member.get(f"/v1/products/{pid}/tenants/{tid}").status_code == 403
    assert member.get(f"/v1/products/{pid}/tenants/{tid}/records/notes").status_code == 403
    assert member.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"}).status_code == 403
    # Read-only operators cannot reactivate.
    for operator in (support, viewer):
        r = operator.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"})
        assert r.status_code == 403

    # Stale version: refused, nothing changes.
    r = admin.patch(
        f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"}, headers={"If-Match": str(version - 1)}
    )
    assert r.status_code == 412
    r = admin.patch(
        f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"}, headers={"If-Match": str(version)}
    )
    assert r.status_code == 200 and r.json()["status"] == "active" and r.json()["version"] == version + 1
    # Reactivating an active tenant is a no-op.
    r = owner.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"})
    assert r.status_code == 200 and r.json()["version"] == version + 1
    # Members regain access.
    assert member.get(f"/v1/products/{pid}/tenants/{tid}").status_code == 200
    assert member.get(f"/v1/products/{pid}/tenants/{tid}/records/notes").status_code == 200
    assert owner.get(f"/v1/products/{pid}/tenants/{tid}/members").status_code == 200

    # Both changes are audited with the previous status; the no-ops are not.
    events = [
        e
        for e in world.admin.get("/v1/audit", params={"product_id": pid, "limit": 200}).json()["items"]
        if e["action"] == "tenancy.tenant.update" and e.get("target_id") == tid
    ]
    changes = sorted((e["details"].get("previous_status"), e["details"]["status"]) for e in events)
    assert changes == [("active", "suspended"), ("suspended", "active")]


def test_suspended_tenant_record_stays_closed_to_unrelated_principals(world):
    pid = _product(world)
    other_pid = _product(world, "books")
    tid = _tenant(world, pid, "acme")
    t2 = _tenant(world, pid, "globex")
    world.user("b@example.com")
    world.admin.post(
        f"/v1/products/{pid}/tenants/{t2}/members", json={"email": "b@example.com", "role": "tenant_owner"}
    )
    other_tenant_member = world.login_as("b@example.com")
    other_product_owner = _operator(world, other_pid, "op@example.com", "product_owner")
    world.user("nobody@example.com")
    nobody = world.login_as("nobody@example.com")
    bound_key = _key(world, pid, ["tenant:read", "records:read"], tenant_id=tid)
    product_key = _key(world, pid, ["tenants:read"])
    no_read_key = _key(world, pid, ["records:read"])
    assert bound_key.get(f"/v1/products/{pid}/tenants/{tid}").status_code == 200

    world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"})
    url = f"/v1/products/{pid}/tenants/{tid}"
    # No existence oracle for unrelated principals.
    assert nobody.get(url).status_code == 404
    assert other_tenant_member.get(url).status_code == 404
    assert other_product_owner.get(url).status_code == 404
    assert other_product_owner.patch(url, json={"status": "active"}).status_code == 404
    # A tenant-bound key is locked out with its tenant; keys without tenants:read gain nothing.
    assert bound_key.get(url).status_code == 403
    assert bound_key.get(url + "/records/notes").status_code == 403
    assert no_read_key.get(url).status_code == 403
    assert no_read_key.patch(url, json={"status": "active"}).status_code == 403
    # A product-wide key with tenants:read reads the record (as in the list), not the data.
    assert product_key.get(url).json()["status"] == "suspended"
    assert product_key.get(url + "/members").status_code == 403
    assert product_key.patch(url, json={"status": "active"}).status_code == 403
    # Unknown tenant ids stay 404 for operators.
    owner = _operator(world, pid, "po@example.com", "product_owner")
    assert owner.get(f"/v1/products/{pid}/tenants/ten_doesnotexist").status_code == 404
    assert owner.get(f"/v1/products/{other_pid}/tenants/{tid}").status_code == 404
    # Platform admin unchanged.
    assert world.admin.get(url).json()["status"] == "suspended"
    assert world.admin.get(url + "/records/notes").status_code == 200


def test_archived_product_keeps_its_tenants_closed_to_operators(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    owner = _operator(world, pid, "po@example.com", "product_owner")
    world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"})
    assert world.admin.post(f"/v1/products/{pid}/archive").status_code == 200
    assert owner.get(f"/v1/products/{pid}/tenants/{tid}").status_code == 403
    assert owner.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"}).status_code == 403
    assert world.admin.post(f"/v1/products/{pid}/restore").status_code == 200
    assert owner.get(f"/v1/products/{pid}/tenants/{tid}").status_code == 200
