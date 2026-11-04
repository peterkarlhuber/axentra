"""OpenID Connect login through the HTTP API against an in-test identity provider.

The fake provider serves discovery, JWKS and the token endpoint through an ``httpx.MockTransport``
injected into the OIDC client (no network). It checks PKCE and the client authentication like a
real provider and signs ID tokens with its own RSA key; tests tamper with claims, headers and keys.
"""

# Adapted from peterkarlhuber/nodestro-api tests/stub_oidc.py at e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea (MIT, Copyright (c) 2026 Peter Karlhuber)

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
import json
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlsplit

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest

from axentra.api.app import create_app
from axentra.data.database import DbScope
from tests.integration.conftest import Browser, World, bootstrap_admin

ISSUER = "https://idp.test"
CLIENT_ID = "axentra-test"
CLIENT_SECRET = "test-client-secret"
PUBLIC_URL = "http://127.0.0.1:8080"
REDIRECT_URI = f"{PUBLIC_URL}/v1/auth/oidc/test/callback"
LOGIN_COOKIE = "axentra-login"
SESSION_COOKIE = "axentra-session"


@dataclass
class _Grant:
    nonce: str
    challenge: str
    claims: dict[str, Any]


@dataclass
class FakeIdP:
    keys: list[tuple[str, Any]] = field(
        default_factory=lambda: [("k1", rsa.generate_private_key(public_exponent=65537, key_size=2048))]
    )
    issuer_in_discovery: str = ISSUER
    auth_method: str = "client_secret_basic"
    grants: dict[str, _Grant] = field(default_factory=dict)
    #: Changes to the next ID token's claims (``None`` removes a claim), then cleared.
    tamper: dict[str, Any] = field(default_factory=dict)
    #: Replaces the next token entirely: ``f(claims) -> token``, then cleared.
    forge: Callable[[dict[str, Any]], str] | None = None
    jwks_requests: int = 0
    token_requests: int = 0
    redirect_uri: str = REDIRECT_URI

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def rotate(self) -> None:
        self.keys = [
            (f"k{len(self.keys) + 1}", rsa.generate_private_key(public_exponent=65537, key_size=2048))
        ]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": self.issuer_in_discovery,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/jwks",
                },
            )
        if url == f"{ISSUER}/jwks":
            self.jwks_requests += 1
            out = []
            for kid, key in self.keys:
                jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
                out.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
            return httpx.Response(200, json={"keys": out})
        if url == f"{ISSUER}/token" and request.method == "POST":
            return self._token(request)
        return httpx.Response(404)

    def authorize(self, location: str, subject: str = "sub-1", **claims: Any) -> str:
        """What the provider does after the person logged in: the callback URL with a fresh code."""
        assert location.startswith(f"{ISSUER}/authorize?")
        query = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        assert query["client_id"] == CLIENT_ID and query["redirect_uri"] == self.redirect_uri
        assert query["response_type"] == "code" and query["code_challenge_method"] == "S256"
        assert set(query["scope"].split()) >= {"openid", "email"}
        code = secrets.token_urlsafe(16)
        self.grants[code] = _Grant(query["nonce"], query["code_challenge"], {"sub": subject, **claims})
        return f"/v1/auth/oidc/test/callback?code={code}&state={query['state']}"

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.token_requests += 1
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if self.auth_method == "client_secret_basic":
            raw = base64.b64decode(request.headers.get("authorization", "Basic ")[6:]).decode()
            cid, _, secret = raw.partition(":")
            ok = unquote_plus(cid) == CLIENT_ID and unquote_plus(secret) == CLIENT_SECRET
        else:
            ok = form.get("client_id") == CLIENT_ID and form.get("client_secret") == CLIENT_SECRET
        if not ok:
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self.grants.pop(form.get("code", ""), None)
        if grant is None or form.get("redirect_uri") != self.redirect_uri:
            return httpx.Response(400, json={"error": "invalid_grant"})
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(
            b"="
        )
        if challenge.decode() != grant.challenge:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "PKCE"})
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "nonce": grant.nonce,
            "iat": now,
            "exp": now + 300,
            "email_verified": True,
            **grant.claims,
            **self.tamper,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        forge, self.forge, self.tamper = self.forge, None, {}
        if forge is not None:
            token = forge(claims)
        else:
            kid, key = self.keys[0]
            token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})
        return httpx.Response(200, json={"id_token": token, "access_token": "unused", "token_type": "Bearer"})


@dataclass
class OidcWorld(World):
    idp: FakeIdP = field(default_factory=FakeIdP)

    def start(self, browser: Browser, **params: Any) -> httpx.Response:
        r = browser.get("/v1/auth/oidc/test/start", params=params, follow_redirects=False)
        assert r.status_code == 302, r.text
        return r

    def login(
        self,
        subject: str = "sub-1",
        *,
        browser: Browser | None = None,
        params: dict[str, Any] | None = None,
        **claims: Any,
    ) -> tuple[Browser, httpx.Response]:
        b = browser or self.browser()
        params = params or {}
        if "invitation" in params:
            # Only the Origin-checked POST start carries an invitation (the GET start refuses one).
            started = b.post("/v1/auth/oidc/test/start", json=params)
            assert started.status_code == 200, started.text
            location = started.json()["redirect_url"]
        else:
            location = self.start(b, **params).headers["location"]
        callback = self.idp.authorize(location, subject, **claims)
        return b, b.get(callback, follow_redirects=False)


@pytest.fixture
def make_world(ax_factory):  # type: ignore[no-untyped-def]
    def make(idp: FakeIdP | None = None, **provider: Any) -> OidcWorld:
        idp = idp or FakeIdP()
        config = {
            "id": "test",
            "name": "Test IdP",
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "allow_signup": True,
            "token_endpoint_auth_method": idp.auth_method,
            **provider,
        }
        ax = ax_factory(oidc=[config])
        assert ax.oidc is not None
        ax.oidc.use_transport(idp.transport(), min_jwks_refresh_seconds=0)
        app = create_app(axentra=ax, start=False)
        return OidcWorld(ax=ax, app=app, admin=bootstrap_admin(ax, app), idp=idp)

    return make


@pytest.fixture
def w(make_world) -> OidcWorld:  # type: ignore[no-untyped-def]
    return make_world()


def _error(r: httpx.Response) -> str | None:
    assert r.status_code == 302, r.text
    query = parse_qs(urlsplit(r.headers["location"]).query)
    return query.get("login_error", [None])[0]


def _identities(w: OidcWorld) -> list[dict[str, Any]]:
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return tx.all("SELECT * FROM axentra_user_identities ORDER BY created_at")


# -- happy path --------------------------------------------------------------------------------


def test_full_login_flow(w: OidcWorld) -> None:
    b = w.browser()
    r = w.start(b, return_to="/app/home?tab=1")
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert len(query["state"][0]) >= 40 and len(query["nonce"][0]) >= 30
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{LOGIN_COOKIE}=")
    assert (
        "HttpOnly" in cookie and "SameSite=lax" in cookie and "Max-Age=600" in cookie and "Path=/" in cookie
    )
    assert "Domain" not in cookie
    assert b.client.cookies.get(LOGIN_COOKIE) == query["state"][0]
    # The state is stored hashed, the nonce and verifier encrypted.
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        row = tx.one("SELECT * FROM axentra_login_states")
    assert row is not None and row["state_hash"] != query["state"][0]
    assert query["nonce"][0] not in row["nonce"] and row["return_to"] == "/app/home?tab=1"

    callback = w.idp.authorize(r.headers["location"], "alice-sub", email="alice@example.com", name="Alice")
    r = b.get(callback, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/app/home?tab=1"
    assert r.headers["cache-control"] == "no-store"
    assert b.client.cookies.get(SESSION_COOKIE)
    assert b.client.cookies.get(LOGIN_COOKIE) is None  # cleared
    s = b.get("/v1/auth/session")
    assert s.status_code == 200
    assert s.json()["user"]["email"] == "alice@example.com" and s.json()["user"]["name"] == "Alice"
    assert s.json()["user"]["has_password"] is False
    sessions = b.get("/v1/auth/sessions").json()
    assert sessions[0]["auth_method"] == "oidc:test"
    ids = _identities(w)
    assert [(i["provider"], i["subject"]) for i in ids] == [(ISSUER, "alice-sub")]
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_login_states") == 0

    # A second login with the same subject finds the same user, even with another email.
    b2, r = w.login(subject="alice-sub", email="alice.new@example.com")
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert b2.get("/v1/auth/session").json()["user"]["id"] == s.json()["user"]["id"]
    assert len(_identities(w)) == 1


def test_client_secret_post(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(FakeIdP(auth_method="client_secret_post"))
    b, r = w.login(email="post@example.com")
    assert r.headers["location"] == "/" and b.get("/v1/auth/session").status_code == 200


def test_existing_user_is_linked_by_verified_email(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(allow_signup=False)
    uid = w.user("bob@example.com")
    b, r = w.login(subject="bob-sub", email="BOB@example.com")
    assert _error(r) is None
    assert b.get("/v1/auth/session").json()["user"]["id"] == uid
    assert w.login_as("bob@example.com").get("/v1/auth/session").status_code == 200  # password still works


# -- state and browser binding -----------------------------------------------------------------------


def test_unknown_state_is_refused(w: OidcWorld) -> None:
    b = w.browser()
    r = b.get("/v1/auth/oidc/test/callback?code=abc&state=forged", follow_redirects=False)
    assert r.headers["location"] == "/login?login_error=login_expired"
    r = b.get("/v1/auth/oidc/test/callback?code=abc", follow_redirects=False)
    assert _error(r) == "login_expired"
    assert w.idp.token_requests == 0


def test_callback_from_another_browser_logs_nobody_in(w: OidcWorld) -> None:
    victim, attacker = w.browser(), w.browser()
    r = w.start(attacker)
    callback = w.idp.authorize(r.headers["location"], "attacker", email="attacker@example.com")
    r = victim.get(callback, follow_redirects=False)  # no login cookie
    assert _error(r) == "login_expired"
    assert victim.client.cookies.get(SESSION_COOKIE) is None
    # The state was consumed: the leaked URL is worthless for the attacker too.
    assert _error(attacker.get(callback, follow_redirects=False)) == "login_expired"
    assert w.idp.token_requests == 0


def test_mismatched_login_cookie_is_refused(w: OidcWorld) -> None:
    b = w.browser()
    first = w.start(b)
    w.start(b)  # a second login overwrites the cookie
    callback = w.idp.authorize(first.headers["location"], email="x@example.com")
    r = b.get(callback, follow_redirects=False)
    assert _error(r) == "login_expired"
    assert "axentra-login=" in r.headers["set-cookie"] and "Max-Age=0" in r.headers["set-cookie"]


def test_replayed_state_is_refused(w: OidcWorld) -> None:
    b = w.browser()
    r = w.start(b)
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    callback = w.idp.authorize(r.headers["location"], email="r@example.com")
    assert _error(b.get(callback, follow_redirects=False)) is None
    replay = w.browser()
    replay.client.cookies.set(LOGIN_COOKIE, state)
    assert _error(replay.get(callback, follow_redirects=False)) == "login_expired"


def test_expired_state_is_refused(w: OidcWorld) -> None:
    b = w.browser()
    r = w.start(b)
    with w.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute("UPDATE axentra_login_states SET expires_at = now() - interval '1 second'")
    callback = w.idp.authorize(r.headers["location"], email="late@example.com")
    assert _error(b.get(callback, follow_redirects=False)) == "login_expired"


def test_provider_error_is_not_echoed(w: OidcWorld) -> None:
    b = w.browser()
    r = w.start(b)
    state = parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    r = b.get(
        "/v1/auth/oidc/test/callback",
        params={"state": state, "error": "access_denied", "error_description": "<script>x</script>"},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/login?login_error=access_denied"


def test_unknown_provider_is_404(w: OidcWorld) -> None:
    assert w.browser().get("/v1/auth/oidc/nope/start", follow_redirects=False).status_code == 404
    assert w.browser().get("/v1/auth/oidc/nope/callback?state=x", follow_redirects=False).status_code == 404


def test_no_providers_configured_is_404(world) -> None:  # type: ignore[no-untyped-def]
    assert world.ax.oidc is None
    assert world.browser().get("/v1/auth/oidc/test/start", follow_redirects=False).status_code == 404


# -- ID token checks -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tamper",
    [
        {"nonce": "another-login"},
        {"nonce": None},
        {"aud": "another-client"},
        {"aud": [CLIENT_ID, "other"]},  # several audiences without azp
        {"aud": [CLIENT_ID, "other"], "azp": "other"},
        {"azp": "other"},
        {"iss": "https://evil.test"},
        {"iss": ISSUER + "/"},
        {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200},
        {"exp": None},
        {"iat": None},
        {"iat": int(time.time()) + 3600, "exp": int(time.time()) + 7200},
    ],
    ids=[
        "wrong-nonce",
        "no-nonce",
        "wrong-aud",
        "multi-aud-no-azp",
        "multi-aud-wrong-azp",
        "wrong-azp",
        "wrong-iss",
        "iss-trailing-slash",
        "expired",
        "no-exp",
        "no-iat",
        "iat-in-future",
    ],
)
def test_invalid_id_tokens_are_refused(w: OidcWorld, tamper: dict[str, Any]) -> None:
    w.idp.tamper = tamper
    b, r = w.login(email="t@example.com")
    assert _error(r) == "login_failed"
    assert b.client.cookies.get(SESSION_COOKIE) is None
    assert _identities(w) == []


def test_multiple_audiences_with_matching_azp_are_accepted(w: OidcWorld) -> None:
    w.idp.tamper = {"aud": [CLIENT_ID, "api"], "azp": CLIENT_ID}
    _, r = w.login(email="azp@example.com")
    assert _error(r) is None


def test_small_clock_skew_is_tolerated(w: OidcWorld) -> None:
    w.idp.tamper = {"iat": int(time.time()) + 30, "exp": int(time.time()) - 30}
    _, r = w.login(email="skew@example.com")
    assert _error(r) is None


def _b64(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


@pytest.mark.parametrize("kind", ["none", "hs256", "foreign-key", "bad-signature"])
def test_forged_tokens_are_refused(w: OidcWorld, kind: str) -> None:
    def forge(claims: dict[str, Any]) -> str:
        if kind == "none":
            return f"{_b64({'alg': 'none', 'typ': 'JWT', 'kid': 'k1'})}.{_b64(claims)}."
        if kind == "hs256":
            return jwt.encode(
                claims, "a-shared-secret-of-sufficient-length", algorithm="HS256", headers={"kid": "k1"}
            )
        if kind == "foreign-key":
            other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            return jwt.encode(claims, other, algorithm="RS256", headers={"kid": "k1"})
        good = jwt.encode(claims, w.idp.keys[0][1], algorithm="RS256", headers={"kid": "k1"})
        head, body, _sig = good.split(".")
        return f"{head}.{_b64({**claims, 'sub': 'someone-else'})}.{_sig}"

    w.idp.forge = forge
    b, r = w.login(email="forged@example.com")
    assert _error(r) == "login_failed"
    assert b.client.cookies.get(SESSION_COOKIE) is None


def test_unknown_kid_triggers_jwks_refresh(w: OidcWorld) -> None:
    _, r = w.login("u1", email="u1@example.com")
    assert _error(r) is None and w.idp.jwks_requests == 1
    _, r = w.login("u1", email="u1@example.com")
    assert _error(r) is None and w.idp.jwks_requests == 1  # cached
    w.idp.rotate()
    _, r = w.login("u1", email="u1@example.com")
    assert _error(r) is None and w.idp.jwks_requests == 2
    # A kid the provider never published fails after one refresh.
    w.idp.forge = lambda c: jwt.encode(c, w.idp.keys[0][1], algorithm="RS256", headers={"kid": "invented"})
    _, r = w.login("u1", email="u1@example.com")
    assert _error(r) == "login_failed" and w.idp.jwks_requests == 3


def test_jwks_refresh_is_rate_limited(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world()
    assert w.ax.oidc is not None
    w.ax.oidc.use_transport(w.idp.transport(), min_jwks_refresh_seconds=3600)
    _, r = w.login(email="a@example.com")
    assert _error(r) is None
    for _ in range(3):
        w.idp.forge = lambda c: jwt.encode(
            c, w.idp.keys[0][1], algorithm="RS256", headers={"kid": "invented"}
        )
        _, r = w.login(email="a@example.com")
        assert _error(r) == "login_failed"
    assert w.idp.jwks_requests == 1


def test_discovery_with_other_issuer_is_refused(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(FakeIdP(issuer_in_discovery="https://idp.test/other"))
    r = w.browser().get("/v1/auth/oidc/test/start", params={"return_to": "/x"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login?login_error=provider_unavailable"
    assert "set-cookie" not in r.headers


# -- account rules ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("verified", [False, "true", None])
def test_unverified_email_is_not_used(w: OidcWorld, verified: Any) -> None:
    w.user("victim@example.com")
    _, r = w.login("attacker-sub", email="victim@example.com", email_verified=verified)
    assert _error(r) == "email_not_verified"
    assert _identities(w) == []


def test_signup_disabled(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(allow_signup=False)
    _, r = w.login("new-sub", email="stranger@example.com")
    assert _error(r) == "signup_disabled"
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        assert tx.one("SELECT 1 FROM axentra_users WHERE email = 'stranger@example.com'") is None


def test_allowed_email_domains(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(allowed_email_domains=["Example.COM"])
    _, r = w.login("s1", email="ok@example.com")
    assert _error(r) is None
    _, r = w.login("s2", email="no@other.com")
    assert _error(r) == "domain_not_allowed"
    _, r = w.login("s3", email="sub@mail.example.com")
    assert _error(r) == "domain_not_allowed"
    # Checked on every login: a linked identity whose email moved to another domain is refused.
    _, r = w.login("s1", email="ok@other.com")
    assert _error(r) == "domain_not_allowed"
    _, r = w.login("s1", email="ok@example.com", email_verified=False)
    assert _error(r) == "email_not_verified"


def test_invitation_allows_signup_and_is_accepted(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(allow_signup=False)
    pid = w.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = w.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    r = w.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/invitations",
        json={"email": "invitee@example.com", "role": "member"},
    )
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    # Another email with the token does not get an account.
    _, r = w.login("x-sub", params={"invitation": token}, email="someone@example.com")
    assert _error(r) == "signup_disabled"
    b, r = w.login(
        "inv-sub", params={"invitation": token, "return_to": "/welcome"}, email="invitee@example.com"
    )
    # The frontend learns that (and where) the invitation was accepted during the login.
    assert r.headers["location"] == f"/welcome?invitation_accepted={tid}"
    me = b.get("/v1/me").json()
    assert me["products"][0]["tenants"][0]["tenant"]["id"] == tid
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        assert tx.scalar("SELECT accepted_at FROM axentra_invitations") is not None
        stored = tx.all("SELECT invitation_token FROM axentra_login_states")
    assert all(token not in str(s) for s in stored)


def test_invitation_accepted_marker_keeps_return_to_and_is_absent_when_not_accepted(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world()
    pid = w.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = w.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    token = w.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": "kim@example.com", "role": "member"}
    ).json()["token"]
    # Another address: the login stands, the invitation stays open, no marker.
    _, r = w.login("other-sub", params={"invitation": token, "return_to": "/a?x=1"}, email="lee@example.com")
    assert r.headers["location"] == "/a?x=1"
    # The invited address: the marker is added to the existing query, the fragment is kept.
    _, r = w.login(
        "kim-sub", params={"invitation": token, "return_to": "/a?x=1#top"}, email="kim@example.com"
    )
    assert r.headers["location"] == f"/a?x=1&invitation_accepted={tid}#top"
    # A used token: login without marker.
    _, r = w.login("kim-sub", params={"invitation": token, "return_to": "/a"}, email="kim@example.com")
    assert r.headers["location"] == "/a"


def test_open_invitation_alone_allows_signup(make_world) -> None:  # type: ignore[no-untyped-def]
    """link_external_identity lets an email with an open invitation sign up, even without the token."""
    w = make_world(allow_signup=False)
    pid = w.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = w.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    w.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": "inv2@example.com", "role": "member"}
    )
    b, r = w.login("inv2", email="inv2@example.com")
    assert _error(r) is None
    assert b.get("/v1/me").json()["products"] == []  # not accepted without the token


def test_disabled_user_is_refused(w: OidcWorld) -> None:
    b, r = w.login("dis-sub", email="dis@example.com")
    uid = b.get("/v1/auth/session").json()["user"]["id"]
    assert w.admin.patch(f"/v1/users/{uid}", json={"status": "disabled"}).status_code == 200
    assert b.get("/v1/auth/session").status_code == 401  # sessions revoked
    _, r = w.login("dis-sub", email="dis@example.com")
    assert _error(r) == "account_disabled"
    events = w.admin.get("/v1/audit", params={"action": "identity.login", "outcome": "denied"}).json()[
        "items"
    ]
    assert any(e["details"].get("reason") == "account_disabled" for e in events)


# -- return_to -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("return_to", "expected"),
    [
        ("https://evil.example/steal", "/"),
        ("//evil.example/steal", "/"),
        ("/\\evil.example", "/"),
        ("\\\\evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("http://studio.test@evil.example/", "/"),
        ("http://studio.test.evil.example/", "/"),
        ("/ok\r\nSet-Cookie: x=1", "/"),
        ("http://studio.test/app?x=1", "http://studio.test/app?x=1"),
        ("/inside/path", "/inside/path"),
    ],
)
def test_return_to_cannot_redirect_elsewhere(w: OidcWorld, return_to: str, expected: str) -> None:
    _, r = w.login(params={"return_to": return_to}, email="rt@example.com")
    assert r.status_code == 302 and r.headers["location"] == expected


def test_error_redirect_goes_to_login_page_of_return_to_origin(w: OidcWorld) -> None:
    w.idp.tamper = {"aud": "other"}
    _, r = w.login(params={"return_to": "http://studio.test/app"}, email="e@example.com")
    assert r.headers["location"] == "http://studio.test/login?login_error=login_failed"
    w.idp.tamper = {"aud": "other"}
    _, r = w.login(params={"return_to": "https://evil.example/app"}, email="e@example.com")
    assert r.headers["location"] == "/login?login_error=login_failed"


# -- users without email and account linking options ---------------------------------------------


def test_identity_without_email_needs_explicit_opt_in(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world()  # allow_signup = true, allow_signup_without_email = false (default)
    _, r = w.login("anon-sub", email=None)
    assert _error(r) == "email_not_verified"
    assert _identities(w) == []


def test_signup_without_email(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(allow_signup_without_email=True)
    b, r = w.login("anon-sub", email=None, name="No Mail")
    assert _error(r) is None
    session = b.get("/v1/auth/session").json()
    user = session["user"]
    assert user["email"] is None and user["name"] == "No Mail"
    b.csrf = session["csrf_token"]
    # The next login with the same subject finds the same user; a second identity another user.
    b2, _ = w.login("anon-sub", email=None)
    assert b2.get("/v1/auth/session").json()["user"]["id"] == user["id"]
    b3, _ = w.login("other-sub", email=None)
    assert b3.get("/v1/auth/session").json()["user"]["id"] != user["id"]
    # Listed by the admin with a null email; no password can be set.
    listed = {u["id"]: u for u in w.admin.get("/v1/users").json()["items"]}
    assert listed[user["id"]]["email"] is None
    r = b.post("/v1/me/password", json={"current_password": "", "new_password": "a long new password 1"})
    assert r.status_code == 403 and "email address" in r.json()["detail"], r.text


def test_link_by_verified_email_disabled(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(link_by_verified_email=False)
    uid = w.user("bob@example.com")
    b, r = w.login("bob-sub", email="bob@example.com")
    assert _error(r) is None
    new_user = b.get("/v1/auth/session").json()["user"]
    # Never linked to the existing account: a separate user without an email address.
    assert new_user["id"] != uid and new_user["email"] is None
    assert w.login_as("bob@example.com").get("/v1/auth/session").json()["user"]["id"] == uid
    ids = _identities(w)
    assert ids[0]["user_id"] == new_user["id"] and ids[0]["email"] == "bob@example.com"
    # A free address is used for the new user.
    b2, _ = w.login("carol-sub", email="carol@example.com")
    assert b2.get("/v1/auth/session").json()["user"]["email"] == "carol@example.com"


def test_link_by_verified_email_disabled_without_signup(make_world) -> None:  # type: ignore[no-untyped-def]
    w = make_world(link_by_verified_email=False, allow_signup=False)
    w.user("bob@example.com")
    _, r = w.login("bob-sub", email="bob@example.com")
    assert _error(r) == "signup_disabled"
    assert _identities(w) == []


# -- request context of the audit events (audit round 3) -------------------------------------------


def _audit(w: OidcWorld, action: str, outcome: str = "success") -> list[dict[str, Any]]:
    with w.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return tx.all(
            "SELECT * FROM axentra_audit_events WHERE action = %s AND outcome = %s ORDER BY occurred_at, id",
            (action, outcome),
        )


def test_login_audit_events_carry_request_context(w: OidcWorld) -> None:
    b = w.browser()
    callback = w.idp.authorize(w.start(b).headers["location"], "ctx-sub", email="ctx@example.com", name="Ctx")
    r = b.get(callback, follow_redirects=False, headers={"X-Request-ID": "req-oidc-ok"})
    assert _error(r) is None and b.client.cookies.get(SESSION_COOKIE)
    for action in ("identity.external.link", "identity.login"):
        (event,) = [e for e in _audit(w, action) if e["request_id"] == "req-oidc-ok"]
        assert event["actor_kind"] == "user" and event["actor_display"] == "ctx@example.com"
        assert event["ip"] == "testclient"
        text = str(event)
        assert b.client.cookies.get(SESSION_COOKIE) not in text and "code=" not in text


def test_refused_login_audit_event_carries_request_context(w: OidcWorld) -> None:
    b = w.browser()
    state = parse_qs(urlsplit(w.start(b).headers["location"]).query)["state"][0]
    r = b.get(
        "/v1/auth/oidc/test/callback",
        params={"state": state, "error": "access_denied"},
        follow_redirects=False,
        headers={"X-Request-ID": "req-oidc-denied"},
    )
    assert _error(r) == "access_denied"
    (event,) = _audit(w, "identity.login", "denied")
    assert event["details"] == {"method": "oidc", "provider": "test", "reason": "access_denied"}
    assert event["request_id"] == "req-oidc-denied" and event["ip"] == "testclient"
    assert state not in str(event)
