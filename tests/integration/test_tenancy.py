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
