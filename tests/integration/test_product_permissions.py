"""Product-defined permissions (registration, catalog, roles, API keys, retirement, RLS)."""

from __future__ import annotations

from fastapi.testclient import TestClient
import psycopg
import pytest

from axentra.access.product_permissions import ProductPermission
from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import ValidationFailed
from axentra.data.database import DbScope
from axentra.platform import Axentra

APPROVE = ProductPermission("crm.deals:approve", "tenant", "Approve deals", default_roles=("member",))
DEALS_READ = ProductPermission("crm.deals:read", "tenant", "Read deals")
EXPORT = ProductPermission("crm.reports:export", "product", "Export product reports")
PERMS = [APPROVE, DEALS_READ, EXPORT]


def _setup(world):
    a = world.admin
    pid = a.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    other = a.post("/v1/products", json={"slug": "erp", "name": "ERP"}).json()["id"]
    t1 = a.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    t2 = a.post(f"/v1/products/{pid}/tenants", json={"slug": "globex", "name": "Globex"}).json()["id"]
    world.ax.permissions.register("crm", PERMS)
    return pid, other, t1, t2


def _user(uid: str) -> Principal:
    return Principal(actor=Actor(ActorKind.USER, uid))


def _member(world, pid: str, tid: str, email: str, role: str) -> str:
    uid = world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/members", json={"user_id": uid, "role": role})
    assert r.status_code in (200, 201), r.text
    return uid


def _operator(world, pid: str, email: str, role: str) -> str:
    uid = world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/members", json={"user_id": uid, "role": role})
    assert r.status_code in (200, 201), r.text
    return uid


def test_catalog_route_lists_builtin_and_product_permissions(world):
    pid, other, _, _ = _setup(world)
    r = world.admin.get(f"/v1/products/{pid}/permissions")
    assert r.status_code == 200, r.text
    items = {p["name"]: p for p in r.json()}
    assert items["crm.deals:approve"] == {
        "name": "crm.deals:approve",
        "scope": "tenant",
        "description": "Approve deals",
        "source": "product",
        "read_like": False,
        "default_roles": ["member"],
        "declared_by": "code",
        "retired_at": None,
    }
    assert items["crm.deals:read"]["read_like"] is True
    assert items["records:read"]["source"] == "builtin" and items["records:read"]["read_like"] is True
    assert not [p for p in r.json() if p["scope"] == "platform"]
    # Another product has none of them; the global catalog is unchanged.
    names = {p["name"] for p in world.admin.get(f"/v1/products/{other}/permissions").json()}
    assert not {p.name for p in PERMS} & names
    assert "crm.deals:approve" not in {p["name"] for p in world.admin.get("/v1/permissions").json()}


def test_catalog_route_authorization(world):
    pid, _, t1, _ = _setup(world)
    _member(world, pid, t1, "member@example.com", "member")
    _operator(world, pid, "viewer@example.com", "product_viewer")
    world.user("stranger@example.com")
    assert world.login_as("member@example.com").get(f"/v1/products/{pid}/permissions").status_code == 403
    assert world.login_as("viewer@example.com").get(f"/v1/products/{pid}/permissions").status_code == 200
    assert world.login_as("stranger@example.com").get(f"/v1/products/{pid}/permissions").status_code == 404


def test_builtin_role_grants(world):
    pid, _, t1, _ = _setup(world)
    ax: Axentra = world.ax
    owner = _member(world, pid, t1, "owner@example.com", "tenant_owner")
    member = _member(world, pid, t1, "member@example.com", "member")
    viewer = _member(world, pid, t1, "viewer@example.com", "viewer")
    padmin = _operator(world, pid, "padmin@example.com", "product_admin")
    pviewer = _operator(world, pid, "pviewer@example.com", "product_viewer")

    def perms(uid: str, tid: str | None = t1) -> frozenset[str]:
        return ax.authz.grant(_user(uid), pid, tid).permissions & {p.name for p in PERMS}

    assert perms(owner) == {"crm.deals:approve", "crm.deals:read"}  # every tenant-scoped one
    assert perms(member) == {"crm.deals:approve"}  # default_roles
    assert perms(viewer) == set()  # viewer is not in default_roles; read_like is for product roles
    assert perms(padmin) == {p.name for p in PERMS}
    assert perms(padmin, None) == {p.name for p in PERMS}
    assert perms(pviewer) == {"crm.deals:read"}
    # Platform admins hold every product permission.
    assert ax.authz.has(Principal.system(), "crm.reports:export", pid)
    # Built-in roles are listed with their effective permissions.
    roles = {r["key"]: r for r in world.admin.get(f"/v1/products/{pid}/roles").json()}
    assert "crm.deals:approve" in roles["member"]["permissions"]
    assert "crm.reports:export" in roles["product_owner"]["permissions"]
    assert "crm.reports:export" not in roles["tenant_owner"]["permissions"]


def test_custom_role_with_product_permission_authorizes_in_its_tenant_only(world):
    pid, _, t1, t2 = _setup(world)
    a = world.admin
    r = a.post(
        f"/v1/products/{pid}/roles",
        json={
            "key": "approver",
            "name": "Approver",
            "scope": "tenant",
            "permissions": ["tenant:read", "crm.deals:approve"],
        },
    )
    assert r.status_code == 201, r.text
    uid = _member(world, pid, t1, "approver@example.com", "approver")
    p = _user(uid)
    assert world.ax.authz.has(p, "crm.deals:approve", pid, t1)
    world.ax.authz.require(p, "crm.deals:approve", pid, t1)
    assert not world.ax.authz.has(p, "crm.deals:approve", pid, t2)  # tenant isolation
    assert not world.ax.authz.has(p, "crm.deals:approve", pid)  # not at product level
    # A tenant role cannot hold a product-scoped product permission.
    r = a.post(
        f"/v1/products/{pid}/roles",
        json={
            "key": "exporter",
            "name": "Exporter",
            "scope": "tenant",
            "permissions": ["crm.reports:export"],
        },
    )
    assert r.status_code == 422, r.text
    r = a.post(
        f"/v1/products/{pid}/roles",
        json={
            "key": "exporter",
            "name": "Exporter",
            "scope": "product",
            "permissions": ["crm.reports:export"],
        },
    )
    assert r.status_code == 201, r.text
    # Role ceiling: a tenant admin (who holds the tenant-scoped product permissions) can assign the
    # role; a custom manager role without them cannot.
    _member(world, pid, t1, "tadmin@example.com", "tenant_admin")
    tadmin = world.login_as("tadmin@example.com")
    a.post(
        f"/v1/products/{pid}/roles",
        json={
            "key": "manager",
            "name": "Manager",
            "scope": "tenant",
            "permissions": ["members:manage", "members:read", "tenant:read"],
        },
    )
    _member(world, pid, t1, "manager@example.com", "manager")
    manager = world.login_as("manager@example.com")
    uid2 = world.user("third@example.com")
    r = manager.post(f"/v1/products/{pid}/tenants/{t1}/members", json={"user_id": uid2, "role": "approver"})
    assert r.status_code in (403, 404), r.text
    r = tadmin.post(
        f"/v1/products/{pid}/tenants/{t1}/invitations", json={"email": "x@example.com", "role": "approver"}
    )
    assert r.status_code == 201, r.text
    r = manager.post(
        f"/v1/products/{pid}/tenants/{t1}/invitations", json={"email": "y@example.com", "role": "approver"}
    )
    assert r.status_code == 403, r.text
    assert "crm.deals:approve" in r.text


def test_unknown_and_foreign_permissions_are_refused(world):
    pid, other, _, _ = _setup(world)
    a = world.admin
    world.ax.permissions.register("erp", [ProductPermission("erp.orders:ship", "tenant", "Ship orders")])
    for perm in ("erp.orders:ship", "crm.unknown:thing", "nonsense"):
        r = a.post(
            f"/v1/products/{pid}/roles",
            json={"key": "r1", "name": "R1", "scope": "tenant", "permissions": [perm]},
        )
        assert r.status_code == 422, (perm, r.text)
        r = a.post(f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": [perm]})
        assert r.status_code == 422, (perm, r.text)
    # The other product cannot use this product's permissions either.
    r = a.post(f"/v1/products/{other}/api-keys", json={"name": "k", "permissions": ["crm.deals:approve"]})
    assert r.status_code == 422
    # A name that was written into another product's key directly grants nothing there.
    r = a.post(f"/v1/products/{other}/api-keys", json={"name": "k", "permissions": ["erp.orders:ship"]})
    assert r.status_code == 201, r.text
    key_id = r.json()["key"]["id"]
    with world.ax.db.transaction(DbScope.product(other)) as tx:
        tx.execute(
            "UPDATE axentra_api_keys SET permissions = permissions || '{crm.deals:approve}' WHERE id = %s",
            (key_id,),
        )
    c = TestClient(world.app, headers={"Authorization": f"Bearer {r.json()['secret']}"})
    principal = world.ax.api_keys.authenticate(r.json()["secret"])
    assert "crm.deals:approve" not in world.ax.authz.grant(principal, other).permissions
    assert "erp.orders:ship" in world.ax.authz.grant(principal, other).permissions
    assert c.get(f"/v1/products/{pid}/permissions").status_code == 404


def test_api_key_with_product_permission(world):
    pid, _, t1, t2 = _setup(world)
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "bot", "permissions": ["crm.deals:approve", "crm.reports:export"], "tenant_id": t1},
    )
    assert r.status_code == 201, r.text
    p = world.ax.api_keys.authenticate(r.json()["secret"])
    assert world.ax.authz.has(p, "crm.deals:approve", pid, t1)
    assert not world.ax.authz.has(p, "crm.deals:approve", pid, t2)
    # Escalation: a product viewer cannot create a key with a permission it lacks.
    _operator(world, pid, "keys@example.com", "product_viewer")
    world.admin.post(
        f"/v1/products/{pid}/roles",
        json={
            "key": "keymaker",
            "name": "Keymaker",
            "scope": "product",
            "permissions": ["api_keys:manage", "api_keys:read", "crm.deals:read"],
        },
    )
    uid = world.user("km@example.com")
    world.admin.post(f"/v1/products/{pid}/members", json={"user_id": uid, "role": "keymaker"})
    km = world.login_as("km@example.com")
    assert (
        km.post(
            f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["crm.deals:read"]}
        ).status_code
        == 201
    )
    r = km.post(f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["crm.deals:approve"]})
    assert r.status_code == 403, r.text


def test_retire_and_reactivate(world):
    pid, _, t1, _ = _setup(world)
    ax: Axentra = world.ax
    world.admin.post(
        f"/v1/products/{pid}/roles",
        json={"key": "approver", "name": "Approver", "scope": "tenant", "permissions": ["crm.deals:approve"]},
    )
    uid = _member(world, pid, t1, "approver@example.com", "approver")
    member = _member(world, pid, t1, "member@example.com", "member")
    key = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "bot", "permissions": ["crm.deals:approve", "records:read"]},
    ).json()
    kp = ax.api_keys.authenticate(key["secret"])
    assert ax.authz.has(_user(uid), "crm.deals:approve", pid, t1)

    ax.permissions.register("crm", [DEALS_READ, EXPORT])  # approve is no longer declared
    assert not ax.authz.has(_user(uid), "crm.deals:approve", pid, t1)
    assert not ax.authz.has(_user(member), "crm.deals:approve", pid, t1)
    assert not ax.authz.has(kp, "crm.deals:approve", pid, t1)
    assert ax.authz.has(kp, "records:read", pid, t1)
    # Stored roles and keys still list the name; the catalog hides it unless asked.
    roles = {r["key"]: r for r in world.admin.get(f"/v1/products/{pid}/roles").json()}
    assert roles["approver"]["permissions"] == ["crm.deals:approve"]
    assert "crm.deals:approve" not in roles["member"]["permissions"]
    names = {p["name"] for p in world.admin.get(f"/v1/products/{pid}/permissions").json()}
    assert "crm.deals:approve" not in names
    retired = {
        p["name"]: p for p in world.admin.get(f"/v1/products/{pid}/permissions?include_retired=true").json()
    }
    assert retired["crm.deals:approve"]["retired_at"] is not None
    # New grants of a retired name are refused.
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["crm.deals:approve"]}
    )
    assert r.status_code == 422
    # Rotation keeps working and drops the retired name.
    rot = world.admin.post(f"/v1/products/{pid}/api-keys/{key['key']['id']}/rotate", json={})
    assert rot.status_code == 200, rot.text
    assert rot.json()["key"]["permissions"] == ["records:read"]
    # Declaring it again restores the effect for the role that still lists it.
    ax.permissions.register("crm", PERMS)
    assert ax.authz.has(_user(uid), "crm.deals:approve", pid, t1)
    assert ax.authz.has(_user(member), "crm.deals:approve", pid, t1)
    events = [
        e["action"]
        for e in world.admin.get(f"/v1/audit?product_id={pid}&action=access.permission.sync").json()["items"]
    ]
    assert events.count("access.permission.sync") >= 3


def test_register_before_start_syncs_at_start(ax_factory):
    ax = ax_factory()
    product = ax.tenancy.create_product(Principal.system(), slug="crm", name="CRM")
    ax.close()
    ax2 = Axentra.from_settings(ax.settings)
    ax2.permissions.register("crm", PERMS)
    ax2.permissions.register("missing-product", [EXPORT])
    try:
        ax2.start()
        records = ax2.permissions.records(product.id)
        assert sorted(r.permission.name for r in records) == sorted(p.name for p in PERMS)
        assert ax2.authz.has(Principal.system(), "crm.deals:approve", product.id)
        # Idempotent: a second sync changes nothing.
        reports = ax2.permissions.sync()
        assert [r.changed for r in reports if r.product == "crm"] == [False]
        assert [r.skipped for r in reports if r.product == "missing-product"] == [True]
    finally:
        ax2.close()


def test_invalid_definitions_are_refused(world):
    _setup(world)
    bad = [
        ProductPermission("records:read", "tenant"),  # built-in name (no namespace)
        ProductPermission("CRM.deals:approve", "tenant"),
        ProductPermission("crm.deals", "tenant"),
        ProductPermission("crm.deals:approve", "platform"),  # type: ignore[arg-type]
        ProductPermission("crm.deals:approve", "product", default_roles=("member",)),
        ProductPermission("crm.deals:approve", "tenant", default_roles=("approver",)),
        ProductPermission("crm." + "x" * 130 + ":read", "tenant"),
    ]
    for p in bad:
        with pytest.raises(ValidationFailed):
            world.ax.permissions.register("crm", [p])
    with pytest.raises(ValidationFailed):
        world.ax.permissions.register("crm", [APPROVE, APPROVE])


def test_http_declaration(world):
    a = world.admin
    pid = a.post("/v1/products", json={"slug": "ext", "name": "External"}).json()["id"]
    url = f"/v1/products/{pid}/permissions/ext.tickets:close"
    r = a.put(url, json={"scope": "tenant", "description": "Close tickets", "default_roles": ["member"]})
    assert r.status_code == 200, r.text
    assert r.json()["declared_by"] == "api" and r.json()["source"] == "product"
    assert a.put(f"/v1/products/{pid}/permissions/records:read", json={"scope": "tenant"}).status_code == 422
    assert a.put(f"/v1/products/{pid}/permissions/ext.x:y", json={"scope": "platform"}).status_code == 422
    # Only owners (permissions:manage) declare; product admins cannot.
    _operator(world, pid, "padmin@example.com", "product_admin")
    _operator(world, pid, "powner@example.com", "product_owner")
    padmin = world.login_as("padmin@example.com")
    assert padmin.put(f"/v1/products/{pid}/permissions/ext.a:b", json={"scope": "tenant"}).status_code == 403
    assert padmin.delete(url).status_code == 403
    powner = world.login_as("powner@example.com")
    assert powner.put(f"/v1/products/{pid}/permissions/ext.a:b", json={"scope": "product"}).status_code == 200
    # Retire over HTTP (idempotent), declare again to re-activate.
    assert powner.delete(url).status_code == 204
    assert powner.delete(url).status_code == 204
    assert powner.delete(f"/v1/products/{pid}/permissions/ext.none:here").status_code == 404
    names = {p["name"] for p in a.get(f"/v1/products/{pid}/permissions").json()}
    assert "ext.tickets:close" not in names and "ext.a:b" in names
    assert a.put(url, json={"scope": "tenant"}).json()["retired_at"] is None
    # Rows registered by code cannot be changed or retired over HTTP; code takes over API rows.
    world.ax.permissions.register("ext", [ProductPermission("ext.a:b", "product", "from code")])
    assert a.put(f"/v1/products/{pid}/permissions/ext.a:b", json={"scope": "product"}).status_code == 409
    assert a.delete(f"/v1/products/{pid}/permissions/ext.a:b").status_code == 409
    listed = {p["name"]: p for p in a.get(f"/v1/products/{pid}/permissions").json()}
    assert listed["ext.a:b"]["declared_by"] == "code"
    assert listed["ext.tickets:close"]["declared_by"] == "api"  # API rows are not retired by code
    actions = {e["action"] for e in a.get(f"/v1/audit?product_id={pid}").json()["items"]}
    assert {"access.permission.declare", "access.permission.retire", "access.permission.sync"} <= actions


def test_job_kinds_accept_product_permissions(world):
    pid, _, t1, _ = _setup(world)
    spec = world.ax.jobs.declare(
        "crm.approve_deal", enqueue_permission="crm.deals:approve", permissions={"crm.deals:approve"}
    )
    assert spec.permissions == {"crm.deals:approve"}
    with pytest.raises(ValidationFailed):
        world.ax.jobs.declare("crm.bad", permissions={"crm.nonsense"})


def test_product_permissions_rls(world, pg_urls):
    pid, other, _, _ = _setup(world)
    world.ax.permissions.register("erp", [ProductPermission("erp.orders:ship", "tenant")])
    with world.ax.db.transaction(DbScope.product(other), read_only=True) as tx:
        names = {r["name"] for r in tx.all("SELECT name FROM axentra_product_permissions")}
    assert names == {"erp.orders:ship"}
    with world.ax.db.transaction(DbScope.product(pid), read_only=True) as tx:
        names = {r["name"] for r in tx.all("SELECT name FROM axentra_product_permissions")}
    assert names == {p.name for p in PERMS}
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        world.ax.db.transaction(DbScope.product(pid)) as tx,
    ):
        tx.execute(
            "INSERT INTO axentra_product_permissions (product_id, name, scope, declared_by)"
            " VALUES (%s, 'erp.orders:cancel', 'tenant', 'api')",
            (other,),
        )
    with psycopg.connect(pg_urls["admin"]) as conn:
        forced = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'axentra_product_permissions'"
        ).fetchone()
    assert forced == (True, True)
