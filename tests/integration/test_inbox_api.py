"""HTTP routes of the caller's inbox: ``GET/POST /v1/products/{pid}/notify/inbox/me[...]``."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.integration.conftest import World
from tests.integration.test_notify import _member, _product, _template, _tenant

INBOX = {"subject": "Run {{ name }} failed", "text": "The run {{ name }} failed."}


def _setup(world: World) -> tuple[str, str, str, str, str]:
    pid = _product(world)
    tid = _tenant(world, pid)
    other = _tenant(world, pid, "globex")
    _template(world, pid, key="run.failed", channel="inbox", category="runs", variants={"en": INBOX})
    bob = _member(world, pid, tid, "bob@example.com")
    r = world.admin.post(
        f"/v1/products/{pid}/tenants/{other}/members", json={"email": "bob@example.com", "role": "member"}
    )
    assert r.status_code == 201, r.text
    alice = _member(world, pid, tid, "alice@example.com")
    for name in ("R1", "R2", "R3"):
        world.ax.notify.enqueue_system(
            pid, tid, template_key="run.failed", to_user_id=bob, variables={"name": name}
        )
    world.ax.notify.enqueue_system(
        pid, other, template_key="run.failed", to_user_id=bob, variables={"name": "G1"}
    )
    world.ax.notify.enqueue_system(
        pid, tid, template_key="run.failed", to_user_id=alice, variables={"name": "A1"}
    )
    return pid, tid, other, bob, alice


def test_inbox_list_unread_and_mark_read(world: World) -> None:
    pid, tid, other, _bob, _alice = _setup(world)
    base = f"/v1/products/{pid}/notify/inbox/me"
    bob = world.login_as("bob@example.com")
    alice = world.login_as("alice@example.com")

    r = bob.get(base, params={"tenant_id": tid, "limit": 2})
    assert r.status_code == 200, r.text
    first = r.json()
    assert [m["subject"] for m in first["items"]] == ["Run R3 failed", "Run R2 failed"]
    assert first["next_cursor"]
    r = bob.get(base, params={"tenant_id": tid, "cursor": first["next_cursor"]})
    assert [m["subject"] for m in r.json()["items"]] == ["Run R1 failed"]
    # Product-wide: both tenants.
    assert len(bob.get(base).json()["items"]) == 4
    assert bob.get(f"{base}/unread").json() == {"unread": 4}
    assert bob.get(f"{base}/unread", params={"tenant_id": other}).json() == {"unread": 1}

    # Alice's message id in Bob's request changes nothing.
    alice_ids = [m["id"] for m in alice.get(base, params={"tenant_id": tid}).json()["items"]]
    r = bob.post(f"{base}/read", json={"message_ids": alice_ids})
    assert r.status_code == 200 and r.json() == {"marked": 0}
    assert alice.get(f"{base}/unread").json() == {"unread": 1}

    newest = first["items"][0]["id"]
    assert bob.post(f"{base}/read", json={"message_ids": [newest]}).json() == {"marked": 1}
    assert bob.post(f"{base}/read", json={"message_ids": [newest]}).json() == {"marked": 0}
    unread = bob.get(base, params={"tenant_id": tid, "unread_only": "true"}).json()["items"]
    assert [m["subject"] for m in unread] == ["Run R2 failed", "Run R1 failed"]
    # Without ids: all unread ones in the scope (here one tenant).
    r = bob.post(f"{base}/read", params={"tenant_id": tid}, json={})
    assert r.json() == {"marked": 2}
    assert bob.get(f"{base}/unread").json() == {"unread": 1}
    assert bob.post(f"{base}/read", json={}).json() == {"marked": 1}
    assert bob.get(f"{base}/unread").json() == {"unread": 0}


def test_inbox_refusals(world: World) -> None:
    pid, tid, other, _bob, _alice = _setup(world)
    base = f"/v1/products/{pid}/notify/inbox/me"
    bob = world.login_as("bob@example.com")
    # Too many ids.
    r = bob.post(f"{base}/read", json={"message_ids": [f"m{i}" for i in range(501)]})
    assert r.status_code == 422, r.text
    # Alice is no member of globex (not disclosed: 404).
    alice = world.login_as("alice@example.com")
    assert alice.get(base, params={"tenant_id": other}).status_code == 404
    # A user without any relation to the product.
    world.user("eve@example.com")
    eve = world.login_as("eve@example.com")
    assert eve.get(base).status_code == 404
    assert eve.get(f"{base}/unread").status_code == 404
    # An API key has no inbox.
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "k", "permissions": ["notify:preferences"], "tenant_id": tid},
    )
    assert r.status_code == 201, r.text
    key = TestClient(world.app, headers={"Authorization": f"Bearer {r.json()['secret']}"})
    for resp in (
        key.get(base, params={"tenant_id": tid}),
        key.get(f"{base}/unread", params={"tenant_id": tid}),
        key.post(f"{base}/read", params={"tenant_id": tid}, json={}),
    ):
        assert resp.status_code == 403, resp.text
    # Nothing was marked by the refused requests.
    assert bob.get(f"{base}/unread").json() == {"unread": 4}
    # Signed out: 401.
    assert world.browser().get(base).status_code == 401


def test_suspended_tenant_messages_stay_unread(world: World) -> None:
    pid, tid, other, _bob, _alice = _setup(world)
    base = f"/v1/products/{pid}/notify/inbox/me"
    bob = world.login_as("bob@example.com")
    assert (
        world.admin.patch(f"/v1/products/{pid}/tenants/{other}", json={"status": "suspended"}).status_code
        == 200
    )
    # In the suspended tenant itself the caller is refused; product-wide its message is left as it is.
    assert bob.post(f"{base}/read", params={"tenant_id": other}, json={}).status_code == 403
    assert bob.post(f"{base}/read", json={}).json() == {"marked": 3}
    assert (
        world.admin.patch(f"/v1/products/{pid}/tenants/{other}", json={"status": "active"}).status_code == 200
    )
    assert bob.get(f"{base}/unread", params={"tenant_id": other}).json() == {"unread": 1}
