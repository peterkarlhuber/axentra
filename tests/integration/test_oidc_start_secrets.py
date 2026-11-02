"""No invitation token in a stored or logged URL (security review round 3, NF-2/NF-3, AX-R2).

The ``POST`` start takes the invitation in the body; both starts remove secret-carrying query
parameters from ``return_to`` whatever the path spelling, so ``axentra_login_states.return_to``,
the redirect after the login and the audit trail never hold the token.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlsplit

import pytest

from axentra.api.app import create_app
from axentra.data.database import DbScope
from tests.integration.conftest import bootstrap_admin
from tests.integration.test_oidc import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    LOGIN_COOKIE,
    FakeIdP,
    OidcWorld,
    _error,
)

START = "/v1/auth/oidc/test/start"


@pytest.fixture
def world(ax_factory):  # type: ignore[no-untyped-def]
    """``make_world`` of test_oidc.py: an API with the in-test identity provider."""

    def make(**provider: Any) -> OidcWorld:
        idp = FakeIdP()
        config = {
            "id": "test",
            "name": "Test IdP",
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "allow_signup": True,
            **provider,
        }
        ax = ax_factory(oidc=[config])
        assert ax.oidc is not None
        ax.oidc.use_transport(idp.transport(), min_jwks_refresh_seconds=0)
        app = create_app(axentra=ax, start=False)
        return OidcWorld(ax=ax, app=app, admin=bootstrap_admin(ax, app), idp=idp)

    return make


def _invite(w: OidcWorld, email: str) -> tuple[str, str]:
    pid = w.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = w.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    r = w.admin.post(f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": email, "role": "member"})
    assert r.status_code == 201, r.text
    return tid, r.json()["token"]


def _spellings(token: str) -> list[str]:
    """The token as it may appear in stored text: plain, percent-encoded once and twice."""
    once = quote(token, safe="")
    return [token, once, quote(once, safe=""), token.replace("_", "%5F"), token.replace("_", "%5f")]


def _stored_text(w: OidcWorld) -> str:
    """Everything a token could hide in: login states and the whole audit trail."""
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        states = tx.all("SELECT return_to FROM axentra_login_states")
        audit = tx.all("SELECT * FROM axentra_audit_events")
    return json.dumps([states, audit], default=str)


def _assert_nowhere(w: OidcWorld, token: str, *texts: str) -> None:
    secret = token.removeprefix("axinv_")
    for text in (_stored_text(w), *texts):
        for spelling in [*_spellings(token), secret, quote(secret, safe="")]:
            assert spelling not in text


def _post_start(w: OidcWorld, browser: Any, **body: Any) -> Any:
    r = browser.post(START, json=body)
    assert r.status_code == 200, r.text
    return r


# -- POST start ----------------------------------------------------------------------------------


def test_post_start_keeps_the_invitation_out_of_every_url(world) -> None:  # type: ignore[no-untyped-def]
    w = world(allow_signup=False)
    tid, token = _invite(w, "invitee@example.com")
    b = w.browser()
    r = _post_start(w, b, return_to="http://studio.test/invitations/accept", invitation=token)
    location = r.json()["redirect_url"]
    assert location.startswith("https://idp.test/authorize?")
    # The same login cookie as the GET start, bound to the state in the provider URL.
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{LOGIN_COOKIE}=") and "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert r.headers["referrer-policy"] == "no-referrer" and r.headers["cache-control"] == "no-store"
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        row = tx.one("SELECT return_to, invitation_token FROM axentra_login_states")
    assert row is not None and row["return_to"] == "http://studio.test/invitations/accept"
    assert row["invitation_token"] and token not in str(row["invitation_token"])
    _assert_nowhere(w, token, location)

    callback = w.idp.authorize(location, "inv-sub", email="invitee@example.com")
    done = b.get(callback, follow_redirects=False)
    # The invited address could sign up (allow_signup is off) and the invitation was accepted.
    assert done.status_code == 302, done.text
    assert done.headers["location"] == f"http://studio.test/invitations/accept?invitation_accepted={tid}"
    assert done.headers["referrer-policy"] == "no-referrer"
    assert b.get("/v1/me").json()["products"][0]["tenants"][0]["tenant"]["id"] == tid
    _assert_nowhere(w, token, done.headers["location"], callback)


def test_post_start_without_invitation_is_a_plain_login(world) -> None:  # type: ignore[no-untyped-def]
    w = world()
    b = w.browser()
    r = _post_start(w, b, return_to="/app?tab=1")
    done = b.get(
        w.idp.authorize(r.json()["redirect_url"], "p-sub", email="p@example.com"), follow_redirects=False
    )
    assert done.status_code == 302 and done.headers["location"] == "/app?tab=1"
    assert b.get("/v1/auth/session").status_code == 200
    # An empty body is the same as no return_to.
    r = _post_start(w, w.browser())
    assert r.json()["redirect_url"].startswith("https://idp.test/authorize?")


def test_post_start_refusals(world) -> None:  # type: ignore[no-untyped-def]
    w = world()
    b = w.browser()
    # A page on another origin cannot start a login with this browser.
    r = b.post(START, json={"return_to": "/"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert b.post("/v1/auth/oidc/nope/start", json={}).status_code == 404
    assert b.post(START, json={"invitation": "x" * 201}).status_code == 422
    assert b.post(START, json={"return_to": "/" + "a" * 2000}).status_code == 422
    # A login that cannot start answers the login page with the error code (no cookie, no state).
    w.ax.settings.security.login_rate_per_minute = 0
    r = b.post(START, json={"return_to": "http://studio.test/x"})
    assert r.status_code == 200, r.text
    assert r.json()["redirect_url"] == "http://studio.test/login?login_error=rate_limited"
    assert "set-cookie" not in r.headers


def test_get_start_contract_for_plain_login_is_unchanged(world) -> None:  # type: ignore[no-untyped-def]
    w = world()
    b, r = w.login("g-sub", params={"return_to": "/inside/path?x=1#frag"}, email="g@example.com")
    assert r.status_code == 302 and r.headers["location"] == "/inside/path?x=1#frag"
    start = b.get(START, params={"return_to": "/"}, follow_redirects=False)
    assert start.status_code == 302 and start.headers["referrer-policy"] == "no-referrer"


# -- return_to never stores a token, whatever the path spelling -----------------------------------------


def _variants(token: str) -> list[tuple[str, str]]:
    """(return_to as a frontend may send it, what Axentra must store)."""
    enc = quote(token, safe="")
    nested = quote(f"/invitations/accept?token={token}", safe="")
    return [
        (f"/invitations/accept?token={token}", "/invitations/accept"),
        (f"/invitations/accept/?token={token}", "/invitations/accept/"),
        (f"/INVITATIONS/Accept?token={token}", "/INVITATIONS/Accept"),
        (f"/invitations//accept?token={token}", "/invitations//accept"),
        (f"/invitations/%61ccept?token={token}", "/invitations/%61ccept"),
        (f"/invitations/accept?x=1&token={token}&y=2#top", "/invitations/accept?x=1&y=2#top"),
        (f"/invitations/accept?token={token}&token={token}", "/invitations/accept"),
        (f"/invitations/accept?TOKEN={enc}", "/invitations/accept"),
        (f"/invitations/accept?%74oken={token}", "/invitations/accept"),
        (f"/accept-invitation?token={token}", "/accept-invitation"),
        (f"/invitations/accept?invitation={token}", "/invitations/accept"),
        (f"/somewhere/else?t={token.replace('_', '%5F')}&keep=1", "/somewhere/else?keep=1"),
        (f"/login?return_to={nested}&tab=2", "/login?tab=2"),
        (f"/login?return_to={quote(nested, safe='')}", "/login"),
        (f"/invitations/accept#token={token}", "/invitations/accept"),
        (f"/invitations/accept%3Ftoken%3D{token}", "/"),
        (f"http://studio.test/invitations/accept/?token={token}", "http://studio.test/invitations/accept/"),
        (f"http://studio.test/Invitations/Accept?token={enc}", "http://studio.test/Invitations/Accept"),
    ]


@pytest.mark.parametrize("how", ["get", "post"])
def test_return_to_variants_never_store_the_token(world, how: str) -> None:  # type: ignore[no-untyped-def]
    w = world()
    _, token = _invite(w, "nobody@example.com")
    for return_to, expected in _variants(token):
        b = w.browser()
        if how == "get":
            r = w.start(b, return_to=return_to)
            location = r.headers["location"]
        else:
            location = _post_start(w, b, return_to=return_to).json()["redirect_url"]
        with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
            stored = tx.all("SELECT return_to FROM axentra_login_states")
        assert [s["return_to"] for s in stored] == [expected], return_to
        _assert_nowhere(w, token, location)
        # The redirect after the login carries no token either (another address: not accepted).
        done = b.get(w.idp.authorize(location, "n-sub", email="lee@example.com"), follow_redirects=False)
        assert _error(done) is None
        assert done.headers["location"] == expected, return_to
        _assert_nowhere(w, token, done.headers["location"])


@pytest.mark.parametrize("how", ["get", "post"])
@pytest.mark.parametrize(
    "path",
    [
        "/invitations/accept/?token={t}",
        "/INVITATIONS/accept?token={t}",
        "/invitations/accept?token={enc}",
        "http://studio.test/accept-invitation?token={t}",
    ],
)
def test_token_from_return_to_is_kept_encrypted_and_accepted(world, how: str, path: str) -> None:  # type: ignore[no-untyped-def]
    """A frontend that still put the invitation link into return_to: the token is removed from it,
    kept encrypted like the ``invitation`` field and accepted after the login of the invited address."""
    w = world(allow_signup=False)
    tid, token = _invite(w, "kim@example.com")
    return_to = path.format(t=token, enc=quote(token, safe=""))
    b = w.browser()
    if how == "get":
        location = w.start(b, return_to=return_to).headers["location"]
    else:
        location = _post_start(w, b, return_to=return_to).json()["redirect_url"]
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        row = tx.one("SELECT return_to, invitation_token FROM axentra_login_states")
    assert row is not None and row["invitation_token"] is not None
    _assert_nowhere(w, token, location)
    done = b.get(w.idp.authorize(location, "kim-sub", email="kim@example.com"), follow_redirects=False)
    assert _error(done) is None, done.headers["location"]
    target = urlsplit(done.headers["location"])
    assert target.query == f"invitation_accepted={tid}"
    assert target.path.lower().rstrip("/") in ("/invitations/accept", "/accept-invitation")
    _assert_nowhere(w, token, done.headers["location"])


def test_explicit_invitation_wins_over_one_in_return_to(world) -> None:  # type: ignore[no-untyped-def]
    w = world()
    tid, token = _invite(w, "kim@example.com")
    b = w.browser()
    other = "axinv_" + "Z" * 43  # unknown token in the link: never used, never stored
    location = _post_start(w, b, return_to=f"/invitations/accept?token={other}", invitation=token).json()[
        "redirect_url"
    ]
    done = b.get(w.idp.authorize(location, "kim-sub", email="kim@example.com"), follow_redirects=False)
    assert done.headers["location"] == f"/invitations/accept?invitation_accepted={tid}"
    _assert_nowhere(w, other)


def test_refused_login_audit_and_error_redirect_hold_no_token(world) -> None:  # type: ignore[no-untyped-def]
    w = world()
    _, token = _invite(w, "kim@example.com")
    w.idp.tamper = {"aud": "other"}
    b = w.browser()
    location = _post_start(
        w, b, return_to=f"http://studio.test/invitations/accept/?token={quote(token, safe='')}"
    ).json()["redirect_url"]
    done = b.get(w.idp.authorize(location, "kim-sub", email="kim@example.com"), follow_redirects=False)
    assert done.headers["location"] == "http://studio.test/login?login_error=login_failed"
    events = w.admin.get("/v1/audit", params={"action": "identity.login", "outcome": "denied"}).json()
    assert events["items"]
    _assert_nowhere(w, token, json.dumps(events))
