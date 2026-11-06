"""API keys never do more than their creator could do now (audit round 3, AX3-01).

A key's permissions are intersected on every request with what its creator (``created_by``)
currently holds in the same scope. Nothing is revoked: restoring the creator restores the key.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from axentra.core.context import Principal
from axentra.data.database import DbScope
from tests.integration.conftest import World

CODE = "api_key_creator_lost_access"


def _ok(r: Any, code: int = 201) -> dict[str, Any]:
    assert r.status_code == code, r.text
    return r.json() if r.content else {}


def _setup(world: World) -> tuple[str, str]:
    a = world.admin
    pid = _ok(a.post("/v1/products", json={"slug": "kb", "name": "KB"}))["id"]
    tid = _ok(a.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}))["id"]
    return pid, tid


def _key_client(world: World, secret: str) -> TestClient:
    return TestClient(world.app, headers={"Authorization": f"Bearer {secret}"})


def _create_key(client: Any, pid: str, perms: list[str], tid: str | None = None) -> tuple[str, str]:
    body: dict[str, Any] = {"name": "k", "permissions": perms}
    if tid:
        body["tenant_id"] = tid
    j = _ok(client.post(f"/v1/products/{pid}/api-keys", json=body))
    return j["key"]["id"], j["secret"]


def _denials(world: World, key_id: str) -> list[dict[str, Any]]:
    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return tx.all(
            "SELECT action, outcome, details, product_id, tenant_id FROM axentra_audit_events"
            " WHERE actor_id = %s AND outcome = 'denied'",
            (key_id,),
        )


def test_key_follows_its_creators_product_access_and_is_restored(world: World) -> None:
    pid, tid = _setup(world)
    a = world.admin
    uid = world.user("op@example.com")
    _ok(a.post(f"/v1/products/{pid}/members", json={"email": "op@example.com", "role": "product_admin"}))
    op = world.login_as("op@example.com")
    key_id, secret = _create_key(op, pid, ["records:read", "records:write", "tenants:read"])
    k = _key_client(world, secret)
    rec = f"/v1/products/{pid}/tenants/{tid}/records/notes"
    _ok(k.post(rec, json={"data": {"n": 1}}))

    # The creator is removed from the product: the key keeps existing but can do nothing.
    assert a.delete(f"/v1/products/{pid}/members/{uid}").status_code == 204
    for r in (k.post(rec, json={"data": {"n": 2}}), k.get(rec), k.get(f"/v1/products/{pid}/tenants")):
        assert r.status_code == 403, r.text
        assert r.json()["code"] == CODE
    assert k.post(rec, json={"data": {"n": 2}}).json()["permission"] == "records:write"
    listed = _ok(a.get(f"/v1/products/{pid}/api-keys/{key_id}"), 200)
    assert listed["status"] == "active" and listed["revoked_at"] is None  # not revoked, not deleted

    # Audited once per key and scope within the throttle window (three refusals in the tenant, one
    # at product level), with the reason and the creator.
    rows = sorted(_denials(world, key_id), key=lambda r: r["tenant_id"] or "")
    assert [(r["action"], r["details"]["reason"], r["details"]["creator"], r["tenant_id"]) for r in rows] == [
        ("access.api_key.use", "creator_lost_access", uid, None),
        ("access.api_key.use", "creator_lost_access", uid, tid),
    ]
    assert {r["product_id"] for r in rows} == {pid}

    # Re-adding the creator restores the key.
    _ok(a.post(f"/v1/products/{pid}/members", json={"email": "op@example.com", "role": "product_admin"}))
    _ok(k.post(rec, json={"data": {"n": 3}}))

    # A smaller role bounds the key to that role's permissions.
    _ok(a.patch(f"/v1/products/{pid}/members/{uid}", json={"role": "product_viewer"}), 200)
    _ok(k.get(rec), 200)
    r = k.post(rec, json={"data": {"n": 4}})
    assert r.status_code == 403 and r.json()["code"] == CODE


def test_key_of_a_disabled_creator_and_of_a_demoted_platform_admin(world: World) -> None:
    pid, tid = _setup(world)
    a = world.admin
    uid = world.user("pa@example.com")
    _ok(a.patch(f"/v1/users/{uid}", json={"platform_role": "platform_admin"}), 200)
    pa = world.login_as("pa@example.com")
    _, secret = _create_key(pa, pid, ["records:read"], tid)
    k = _key_client(world, secret)
    rec = f"/v1/products/{pid}/tenants/{tid}/records/notes"
    _ok(k.get(rec), 200)

    _ok(a.patch(f"/v1/users/{uid}", json={"status": "disabled"}), 200)
    r = k.get(rec)
    assert r.status_code == 403 and r.json()["code"] == CODE
    _ok(a.patch(f"/v1/users/{uid}", json={"status": "active"}), 200)
    _ok(k.get(rec), 200)

    _ok(a.patch(f"/v1/users/{uid}", json={"platform_role": "none"}), 200)
    r = k.get(rec)
    assert r.status_code == 403 and r.json()["code"] == CODE


def test_key_created_by_a_key_follows_the_chain(world: World) -> None:
    pid, tid = _setup(world)
    a = world.admin
    uid = world.user("op2@example.com")
    _ok(a.post(f"/v1/products/{pid}/members", json={"email": "op2@example.com", "role": "product_admin"}))
    op = world.login_as("op2@example.com")
    _, parent_secret = _create_key(op, pid, ["api_keys:manage", "records:read"])
    parent = _key_client(world, parent_secret)
    child_id, child_secret = _create_key(parent, pid, ["records:read"], tid)
    child = _key_client(world, child_secret)
    rec = f"/v1/products/{pid}/tenants/{tid}/records/notes"
    _ok(child.get(rec), 200)

    assert a.delete(f"/v1/products/{pid}/members/{uid}").status_code == 204
    r = child.get(rec)
    assert r.status_code == 403 and r.json()["code"] == CODE
    # The bound applies to authorization inside the library as well.
    key_principal = world.ax.authz.actor_principal(child_id)
    assert key_principal is not None
    g = world.ax.authz.grant(key_principal, pid, tid)
    assert g.permissions == frozenset() and g.withheld == frozenset({"records:read"})
    assert world.ax.authz.tenant_grants(key_principal, pid) == {tid: g}

    _ok(a.post(f"/v1/products/{pid}/members", json={"email": "op2@example.com", "role": "product_admin"}))
    _ok(child.get(rec), 200)


def test_unrelated_refusals_keep_the_plain_forbidden_code(world: World) -> None:
    pid, tid = _setup(world)
    _, secret = _create_key(world.admin, pid, ["records:read"], tid)
    r = _key_client(world, secret).post(f"/v1/products/{pid}/tenants/{tid}/records/notes", json={"data": {}})
    assert r.status_code == 403 and r.json()["code"] == "forbidden"


def test_keys_created_in_process_by_system_callers_are_not_bounded(world: World) -> None:
    pid, tid = _setup(world)
    new = world.ax.api_keys.create_key(
        Principal.system("test"), pid, name="sys", permissions=["records:read"]
    )
    _ok(_key_client(world, new.secret).get(f"/v1/products/{pid}/tenants/{tid}/records/notes"), 200)
    listed = _ok(world.admin.get(f"/v1/products/{pid}/api-keys/{new.key.id}"), 200)
    assert listed["creator_has_access"] is None and listed["withheld_permissions"] == []


def test_key_list_shows_the_creators_effective_access(world: World) -> None:
    """AX3-01 follow-up: the list shows whether a key's creator still holds its permissions."""
    pid, tid = _setup(world)
    a = world.admin
    uid = world.user("op3@example.com")
    _ok(a.post(f"/v1/products/{pid}/members", json={"email": "op3@example.com", "role": "product_admin"}))
    op = world.login_as("op3@example.com")
    product_key, _ = _create_key(op, pid, ["records:read", "records:write", "tenants:read"])
    tenant_key, _ = _create_key(op, pid, ["records:read"], tid)

    def listed() -> dict[str, dict[str, Any]]:
        return {k["id"]: k for k in _ok(a.get(f"/v1/products/{pid}/api-keys"), 200)}

    keys = listed()
    for key_id in (product_key, tenant_key):
        assert keys[key_id]["creator_has_access"] is True and keys[key_id]["withheld_permissions"] == []
    # Demoted to viewer: the write permission is withheld, reads still work.
    _ok(a.patch(f"/v1/products/{pid}/members/{uid}", json={"role": "product_viewer"}), 200)
    keys = listed()
    assert keys[product_key]["creator_has_access"] is False
    assert keys[product_key]["withheld_permissions"] == ["records:write"]
    assert keys[tenant_key]["creator_has_access"] is True
    assert _ok(a.get(f"/v1/products/{pid}/api-keys/{product_key}"), 200)["withheld_permissions"] == [
        "records:write"
    ]
    # Removed: everything is withheld; the status stays active (nothing was revoked).
    assert a.delete(f"/v1/products/{pid}/members/{uid}").status_code == 204
    keys = listed()
    assert keys[tenant_key]["status"] == "active" and keys[tenant_key]["creator_has_access"] is False
    assert keys[tenant_key]["withheld_permissions"] == ["records:read"]
    # Revoked keys carry no effective state.
    _ok(a.post(f"/v1/products/{pid}/api-keys/{tenant_key}/revoke"), 200)
    keys = listed()
    assert keys[tenant_key]["creator_has_access"] is None and keys[tenant_key]["withheld_permissions"] == []


def test_rotated_key_shows_its_grace_period(world: World) -> None:
    """AXS-B4: after a rotation with a grace period the old key is active with `grace_until`."""
    pid, _ = _setup(world)
    a = world.admin
    key_id, _ = _create_key(a, pid, ["records:read"])
    assert _ok(a.get(f"/v1/products/{pid}/api-keys/{key_id}"), 200)["grace_until"] is None
    rotated = _ok(a.post(f"/v1/products/{pid}/api-keys/{key_id}/rotate", json={"grace_seconds": 3600}), 200)
    old = _ok(a.get(f"/v1/products/{pid}/api-keys/{key_id}"), 200)
    assert old["status"] == "active" and old["grace_until"] == old["revoked_at"] is not None
    assert rotated["key"]["grace_until"] is None and rotated["key"]["creator_has_access"] is True
    no_grace = _ok(a.post(f"/v1/products/{pid}/api-keys/{rotated['key']['id']}/rotate", json={}), 200)
    old = _ok(a.get(f"/v1/products/{pid}/api-keys/{rotated['key']['id']}"), 200)
    assert old["status"] == "revoked" and old["grace_until"] is None
    assert no_grace["key"]["replaces"] == rotated["key"]["id"]
