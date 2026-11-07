"""Per-tenant send limit of ``POST .../notify/send`` (``notify.tenant_send_limit_per_hour``)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from axentra.api.app import create_app
from axentra.data.database import DbScope
from tests.integration.conftest import World, bootstrap_admin
from tests.integration.test_notify import _member, _product, _send, _template, _tenant


def _world(ax_factory: Any, limit: int) -> World:
    ax = ax_factory(notify={"tenant_send_limit_per_hour": limit})
    app = create_app(axentra=ax, start=False)
    return World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


def _age_messages(world: World, pid: str, tid: str, minutes: int) -> None:
    with world.ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
        tx.execute(
            "UPDATE axentra_notify_messages SET created_at = created_at - make_interval(mins => %s)"
            " WHERE product_id = %s AND tenant_id = %s",
            (minutes, pid, tid),
        )


def test_tenant_send_limit_refuses_with_retry_after_and_frees_up(ax_factory):
    world = _world(ax_factory, 3)
    pid = _product(world)
    tid = _tenant(world, pid)
    other = _tenant(world, pid, "globex")
    _template(world, pid)
    _member(world, pid, tid, "bob@example.com")
    _member(world, pid, other, "eve@example.com")
    for _ in range(3):
        r = _send(world.admin, pid, tid, {"email": "bob@example.com"})
        assert r.status_code == 202, r.text
    r = _send(world.admin, pid, tid, {"email": "bob@example.com"})
    assert r.status_code == 429, r.text
    body = r.json()
    assert body["code"] == "rate_limited"
    assert body["limit"] == 3 and body["window_seconds"] == 3600
    assert 3500 <= int(r.headers["Retry-After"]) <= 3600
    # A refused send stores nothing.
    with world.ax.db.transaction(DbScope.tenant(pid, tid), read_only=True) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_notify_messages WHERE tenant_id = %s", (tid,)) == 3
    # The limit is per tenant.
    assert _send(world.admin, pid, other, {"email": "eve@example.com"}).status_code == 202
    # Retry-After follows the oldest message in the window; once it is an hour old a slot is free again.
    _age_messages(world, pid, tid, 50)
    r = _send(world.admin, pid, tid, {"email": "bob@example.com"})
    assert r.status_code == 429 and 500 <= int(r.headers["Retry-After"]) <= 600
    _age_messages(world, pid, tid, 11)
    assert _send(world.admin, pid, tid, {"email": "bob@example.com"}).status_code == 202


def test_idempotent_replay_and_system_sends_are_not_limited(ax_factory):
    world = _world(ax_factory, 2)
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    _member(world, pid, tid, "bob@example.com")
    assert _send(world.admin, pid, tid, {"email": "bob@example.com"}, idem="k1").status_code == 202
    # Messages Axentra sends itself (invitations, account emails) neither count nor are refused.
    for i in range(3):
        world.ax.notify.enqueue_system(
            pid, tid, template_key="welcome", to_email=f"sys{i}@example.com", variables={"name": "x"}
        )
    assert _send(world.admin, pid, tid, {"email": "bob@example.com"}).status_code == 202
    assert _send(world.admin, pid, tid, {"email": "bob@example.com"}).status_code == 429
    # A replay of an accepted request is answered, not refused.
    r = _send(world.admin, pid, tid, {"email": "bob@example.com"}, idem="k1")
    assert r.status_code == 200 and r.headers["Idempotent-Replayed"] == "true"


def test_concurrent_sends_never_overshoot_the_limit(ax_factory):
    world = _world(ax_factory, 4)
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    _member(world, pid, tid, "bob@example.com")

    principal = _admin_principal(world)
    results: list[str] = []

    def attempt(_: int) -> None:
        try:
            world.ax.notify.send(
                principal,
                pid,
                tid,
                template_key="welcome",
                to_email="bob@example.com",
                variables={"name": "x"},
            )
            results.append("ok")
        except Exception as exc:
            results.append(type(exc).__name__)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(attempt, range(10)))
    assert results.count("ok") == 4
    assert results.count("RateLimited") == 6


def test_limit_zero_turns_it_off(ax_factory):
    world = _world(ax_factory, 0)
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    _member(world, pid, tid, "bob@example.com")
    for _ in range(5):
        assert _send(world.admin, pid, tid, {"email": "bob@example.com"}).status_code == 202


def _admin_principal(world: World) -> Any:
    from axentra.core.context import Actor, ActorKind, PlatformRole, Principal

    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        uid = tx.scalar("SELECT id FROM axentra_users WHERE email = 'admin@example.com'")
    return Principal(actor=Actor(ActorKind.USER, str(uid), "admin"), platform_role=PlatformRole.ADMIN)
