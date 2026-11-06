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


def test_invitation_accept_refusals_are_one_404_and_scoped_to_the_invited_tenant(world):
    from axentra.data.database import DbScope

    pid = _product(world)
    tid = _tenant(world, pid)
    other_tid = _tenant(world, pid, "globex")
    pid2 = _product(world, "erp")
    tid2 = _tenant(world, pid2, "initech")

    def invite(email, tenant=tid, product=pid):
        r = world.admin.post(f"/v1/products/{product}/tenants/{tenant}/invitations", json={"email": email})
        assert r.status_code == 201, r.text
        return r.json()

    world.user("kim@example.com")
    kim = world.login_as("kim@example.com")
    unknown = kim.post("/v1/invitations/accept", json={"token": "axinv_doesnotexist"})
    assert unknown.status_code == 404
    revoked = invite("kim@example.com")
    assert (
        world.admin.delete(f"/v1/products/{pid}/tenants/{tid}/invitations/{revoked['invitation']['id']}")
    ).status_code == 204
    r_revoked = kim.post("/v1/invitations/accept", json={"token": revoked["token"]})
    expired = invite("kim@example.com", tenant=other_tid)
    with world.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_invitations SET expires_at = now() - interval '1 second' WHERE id = %s",
            (expired["invitation"]["id"],),
        )
    r_expired = kim.post("/v1/invitations/accept", json={"token": expired["token"]})
    # Unknown, revoked and expired look the same (no oracle for which one it was).
    for r in (r_revoked, r_expired):
        assert r.status_code == 404
        assert r.json()["detail"] == unknown.json()["detail"] and r.json()["code"] == unknown.json()["code"]
    # Accepting joins exactly the invited tenant of the invited product, nothing else.
    ok = invite("kim@example.com", tenant=tid2, product=pid2)
    r = kim.post("/v1/invitations/accept", json={"token": ok["token"]})
    assert r.status_code == 200 and r.json()["tenant_id"] == tid2 and r.json()["product_id"] == pid2
    assert kim.post("/v1/invitations/accept", json={"token": ok["token"]}).status_code == 404
    me = kim.get("/v1/me").json()
    tenants = {t["tenant"]["id"] for p in me["products"] for t in p["tenants"]}
    assert tenants == {tid2}
    # Without a session the endpoint answers 401 and does not consume anything.
    assert world.browser().post("/v1/invitations/accept", json={"token": ok["token"]}).status_code == 401


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


def test_overview_counts_only_own_tenants_for_tenant_callers(world):
    """AX2-05: product-wide counts need tenants:read on the product; a tenant admin of T1 sees only
    T1's numbers, never T2's, and no product-level counters."""
    pid = _product(world)
    t1, t2 = _tenant(world, pid, "acme"), _tenant(world, pid, "globex")

    def add(tid, email, role):
        world.user(email)
        r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/members", json={"email": email, "role": role})
        assert r.status_code == 201, r.text

    add(t1, "t1admin@example.com", "tenant_admin")
    add(t1, "t1member@example.com", "member")
    for i in range(3):
        add(t2, f"t2user{i}@example.com", "member")
    for tid, n in ((t1, 1), (t2, 4)):
        for i in range(n):
            r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/records/notes", json={"i": i})
            assert r.status_code == 201, r.text
    world.user("viewer@example.com")
    r = world.admin.post(
        f"/v1/products/{pid}/members", json={"email": "viewer@example.com", "role": "product_viewer"}
    )
    assert r.status_code == 201, r.text

    # Product scope (platform admin, product operator): product-wide counts, as before.
    for client in (world.admin, world.login_as("viewer@example.com")):
        ov = client.get(f"/v1/products/{pid}/overview").json()
        assert ov["scope"] == "product"
        # 5 tenant members, the viewer and the product owner (the creating admin).
        assert ov["tenants"] == 2 and ov["users"] == 7 and ov["records"] == 5
        assert isinstance(ov["api_keys"], int) and ov["audit_events_24h"] > 0
        assert isinstance(ov["denied_events_24h"], int)

    # Tenant admin of T1: only T1.
    ov = world.login_as("t1admin@example.com").get(f"/v1/products/{pid}/overview").json()
    assert ov["product"]["id"] == pid
    assert ov["scope"] == "tenant"
    assert (ov["tenants"], ov["users"], ov["records"]) == (1, 2, 1)
    assert ov["api_keys"] is None and ov["audit_events_24h"] is None and ov["denied_events_24h"] is None

    # A product-wide key with product:read only holds no tenant read permission: all zero.
    r = world.admin.post(f"/v1/products/{pid}/api-keys", json={"name": "ro", "permissions": ["product:read"]})
    assert r.status_code == 201, r.text
    from fastapi.testclient import TestClient

    key = TestClient(world.app, headers={"Authorization": f"Bearer {r.json()['secret']}"})
    ov = key.get(f"/v1/products/{pid}/overview").json()
    assert ov["scope"] == "tenant" and (ov["tenants"], ov["users"], ov["records"]) == (0, 0, 0)

    # A user of another product's tenant is not related to this product at all.
    pid2 = _product(world, "erp")
    t3 = _tenant(world, pid2, "initech")
    world.user("other@example.com")
    world.admin.post(
        f"/v1/products/{pid2}/tenants/{t3}/members", json={"email": "other@example.com", "role": "member"}
    )
    assert world.login_as("other@example.com").get(f"/v1/products/{pid}/overview").status_code == 404


def test_tenants_sorted_by_name_with_cursor_paging(world):
    """AXS-B3: pickers list the first N tenants by name (case-insensitive, then id)."""
    pid = _product(world)
    for slug, name in [("t-zeta", "zeta"), ("t-alpha", "Alpha"), ("t-mid", "Mid"), ("t-beta", "beta")]:
        r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": slug, "name": name})
        assert r.status_code == 201, r.text
    url = f"/v1/products/{pid}/tenants"
    by_id = [t["slug"] for t in world.admin.get(url).json()["items"]]
    assert by_id == ["t-zeta", "t-alpha", "t-mid", "t-beta"]  # default: oldest first, unchanged
    first = world.admin.get(url, params={"sort": "name", "limit": 2}).json()
    assert [t["name"] for t in first["items"]] == ["Alpha", "beta"]
    rest = world.admin.get(url, params={"sort": "name", "limit": 2, "cursor": first["next_cursor"]}).json()
    assert [t["name"] for t in rest["items"]] == ["Mid", "zeta"] and rest["next_cursor"] is None
    # A cursor belongs to its sort; a filter combines with it.
    r = world.admin.get(url, params={"cursor": first["next_cursor"]})
    assert r.status_code == 400 and r.json()["code"] == "invalid_cursor"
    assert [t["name"] for t in world.admin.get(url, params={"sort": "name", "q": "ta"}).json()["items"]] == [
        "beta",
        "zeta",
    ]
    assert world.admin.get(url, params={"sort": "slug"}).status_code == 422
