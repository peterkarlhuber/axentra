"""Session, setup-token and invitation expiry use the database clock, not the app host's."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import NotFound, Unauthenticated
from axentra.data.database import DbScope


def _skew_app_clock(monkeypatch, delta: timedelta) -> None:  # type: ignore[no-untyped-def]
    import axentra.core.clock as clock

    real = clock.utcnow
    monkeypatch.setattr(clock, "utcnow", lambda: real() + delta)
    for mod in ("axentra.identity.service", "axentra.tenancy.service"):
        module = __import__(mod, fromlist=["x"])
        if hasattr(module, "utcnow"):
            monkeypatch.setattr(module, "utcnow", lambda: real() + delta)


def test_sessions_use_the_database_clock(world, monkeypatch):  # type: ignore[no-untyped-def]
    ax = world.ax
    world.user("clock@example.com")
    new = ax.identity.login_password("clock@example.com", "user password 12345", ip=None, user_agent="t")
    ttl = timedelta(hours=ax.settings.security.session_ttl_hours)
    assert abs(new.info.expires_at - (datetime.now(UTC) + ttl)) < timedelta(minutes=1)
    # An app host whose clock runs a year ahead (or behind) does not expire or extend sessions.
    _skew_app_clock(monkeypatch, timedelta(days=365))
    ax.identity.resolve_session(new.token)
    _skew_app_clock(monkeypatch, timedelta(days=-365))
    ax.identity.resolve_session(new.token)
    # Idle and absolute expiry follow the database.
    idle = ax.settings.security.session_idle_minutes
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_sessions SET last_seen_at = now() - make_interval(mins => %s) - interval '1 second'"
            " WHERE id = %s",
            (idle, new.info.session_id),
        )
    with pytest.raises(Unauthenticated):
        ax.identity.resolve_session(new.token)
    other = ax.identity.login_password("clock@example.com", "user password 12345", ip=None, user_agent="t")
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_sessions SET expires_at = now() - interval '1 second' WHERE id = %s",
            (other.info.session_id,),
        )
    with pytest.raises(Unauthenticated):
        ax.identity.resolve_session(other.token)


def test_invitations_use_the_database_clock(world, monkeypatch):  # type: ignore[no-untyped-def]
    ax = world.ax
    system = Principal.system("t")
    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    inv = ax.tenancy.invite(system, pid, tid, email="inv@example.com", role="member")
    _skew_app_clock(monkeypatch, timedelta(days=365))
    assert [i.status for i in ax.tenancy.list_invitations(system, pid, tid)] == ["pending"]
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_invitations SET expires_at = now() - interval '1 second' WHERE id = %s",
            (inv.invitation.id,),
        )
    assert [i.status for i in ax.tenancy.list_invitations(system, pid, tid)] == ["expired"]
    uid = world.user("inv@example.com")
    with pytest.raises(NotFound):
        ax.tenancy.accept_invitation(Principal(actor=Actor(ActorKind.USER, uid, "inv")), inv.token)


def test_resolving_a_session_is_one_transaction(world, monkeypatch):  # type: ignore[no-untyped-def]
    # Session resolution runs on every request of a host application: the session, its user and a due touch are
    # read and written in one transaction (one snapshot; no second BEGIN/scope/COMMIT for the user).
    ax = world.ax
    world.user("one-tx@example.com")
    new = ax.identity.login_password("one-tx@example.com", "user password 12345", ip=None, user_agent="t")
    opened: list[str] = []
    original = type(ax.db).transaction

    def counting(self, scope, *, read_only=False):  # type: ignore[no-untyped-def]
        opened.append(scope.kind)
        return original(self, scope, read_only=read_only)

    monkeypatch.setattr(type(ax.db), "transaction", counting)
    _principal, info = ax.identity.resolve_session(new.token)
    assert opened == ["platform"]
    assert info.user.email == "one-tx@example.com" and info.session_id == new.info.session_id
    # A due touch is written in the same transaction.
    monkeypatch.setattr(type(ax.db), "transaction", original)
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_sessions SET last_seen_at = now() - interval '5 minutes' WHERE id = %s",
            (new.info.session_id,),
        )
    monkeypatch.setattr(type(ax.db), "transaction", counting)
    opened.clear()
    ax.identity.resolve_session(new.token)
    assert opened == ["platform"]
    monkeypatch.setattr(type(ax.db), "transaction", original)
    with ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        seen = tx.scalar(
            "SELECT now() - last_seen_at < interval '1 minute' FROM axentra_sessions WHERE id = %s",
            (new.info.session_id,),
        )
    assert seen is True
