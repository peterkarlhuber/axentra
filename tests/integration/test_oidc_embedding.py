"""OIDC logins run by an embedding product on its own routes: callback URL, host context, sessions of its own."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from axentra.data.database import DbScope
from axentra.identity.oidc import OidcLoginError, OidcService
from axentra.platform import Axentra
from tests.integration.test_oidc import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIdP

HOST_CALLBACK = "https://host.test/api/auth/callback"


@pytest.fixture
def embedded(ax_factory) -> tuple[Axentra, OidcService, FakeIdP]:  # type: ignore[no-untyped-def]
    idp = FakeIdP(redirect_uri=HOST_CALLBACK)
    ax = ax_factory(
        oidc=[
            {
                "id": "test",
                "name": "Test IdP",
                "issuer": ISSUER,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "allow_signup": True,
                "allow_signup_without_email": True,
                "link_by_verified_email": False,
            }
        ]
    )
    service = OidcService(
        ax.db, ax.settings, ax.identity, ax.secrets, redirect_uri=lambda _provider: HOST_CALLBACK
    )
    service.use_transport(idp.transport(), min_jwks_refresh_seconds=0)
    yield ax, service, idp
    service.close()


def _callback(idp: FakeIdP, location: str, subject: str, **claims: Any) -> dict[str, str]:
    url = idp.authorize(location, subject, **claims)
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def _sessions(ax: Axentra) -> int:
    with ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return int(tx.scalar("SELECT count(*) FROM axentra_sessions"))


def test_the_host_callback_url_and_context_round_trip(embedded: tuple[Axentra, OidcService, FakeIdP]) -> None:
    ax, service, idp = embedded
    started = service.start(
        "test", return_to="/runs", ip="10.0.0.1", context={"tenant": "acme", "setup": "ab12"}
    )
    assert parse_qs(urlsplit(started.authorization_url).query)["redirect_uri"] == [HOST_CALLBACK]
    with ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        stored = tx.one("SELECT host_context FROM axentra_login_states")
    assert stored is not None and "acme" not in stored["host_context"]  # encrypted like the nonce
    query = _callback(idp, started.authorization_url, "alice", email="alice@example.com", name="Alice")
    result = service.finish(
        "test",
        state=query["state"],
        code=query["code"],
        error=None,
        browser_state=started.state,
        ip="10.0.0.1",
        user_agent="host",
        start_session=False,
    )
    assert result.session is None and _sessions(ax) == 0
    assert result.context == {"tenant": "acme", "setup": "ab12"}
    assert result.identity is not None
    assert (
        result.identity.provider,
        result.identity.subject,
        result.identity.email,
        result.identity.name,
    ) == (
        ISSUER,
        "alice",
        "alice@example.com",
        "Alice",
    )
    assert result.return_to == "/runs"


def test_a_login_without_context_returns_an_empty_one_and_a_session(
    embedded: tuple[Axentra, OidcService, FakeIdP],
) -> None:
    ax, service, idp = embedded
    started = service.start("test", return_to="/", ip="10.0.0.2")
    query = _callback(idp, started.authorization_url, "bob", email="bob@example.com", email_verified=False)
    result = service.finish(
        "test",
        state=query["state"],
        code=query["code"],
        error=None,
        browser_state=started.state,
        ip=None,
        user_agent="host",
    )
    assert result.context == {} and result.session is not None and _sessions(ax) == 1
    assert result.identity is not None and result.identity.email == ""  # not verified: never used


def test_two_identities_with_one_address_stay_two_people_without_email_linking(
    embedded: tuple[Axentra, OidcService, FakeIdP],
) -> None:
    ax, service, idp = embedded
    first = service.start("test", return_to="/", ip="10.0.0.3")
    q1 = _callback(idp, first.authorization_url, "carol-1", email="carol@example.com")
    one = service.finish(
        "test",
        state=q1["state"],
        code=q1["code"],
        error=None,
        browser_state=first.state,
        ip=None,
        user_agent="host",
        start_session=False,
    )
    second = service.start("test", return_to="/", ip="10.0.0.3")
    q2 = _callback(idp, second.authorization_url, "carol-2", email="carol@example.com")
    two = service.finish(
        "test",
        state=q2["state"],
        code=q2["code"],
        error=None,
        browser_state=second.state,
        ip=None,
        user_agent="host",
        start_session=False,
    )
    assert one.user_id != two.user_id
    assert ax.identity.get_user(two.user_id).email is None  # the address stays the first account's


def test_the_context_is_bounded() -> None:
    from axentra.identity.oidc import _pack_context

    with pytest.raises(ValueError):
        _pack_context({"x": "y" * 3000})
    with pytest.raises(ValueError):
        _pack_context({"x": 1})  # type: ignore[dict-item]
    assert _pack_context({}) is None


def test_a_replayed_callback_is_refused_with_context(embedded: tuple[Axentra, OidcService, FakeIdP]) -> None:
    _ax, service, idp = embedded
    started = service.start("test", return_to="/", ip="10.0.0.4", context={"tenant": "acme"})
    query = _callback(idp, started.authorization_url, "dave")
    kwargs: dict[str, Any] = {
        "state": query["state"],
        "code": query["code"],
        "error": None,
        "browser_state": started.state,
        "ip": None,
        "user_agent": "host",
        "start_session": False,
    }
    service.finish("test", **kwargs)
    with pytest.raises(OidcLoginError) as refused:
        service.finish("test", **kwargs)
    assert refused.value.code == "login_expired"
