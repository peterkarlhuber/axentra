# ruff: noqa: S105
"""Create the synthetic Keycloak realm ``lc`` used by check_oidc.py (idempotent: drops and recreates it).

Keycloak runs in dev mode (``start-dev``) on 127.0.0.1:19180; the bootstrap admin is synthetic.
Clients: ``axentra`` (confidential, PKCE S256 required, RS256 ID tokens) and ``axentra-hs``
(ID tokens signed with HS256, which Axentra must refuse). Users (all synthetic, @lc.example.com):
alice (verified), bob (email not verified), carol (verified, no Axentra account) and admin
(verified, same address as Axentra's first platform admin).
"""

from __future__ import annotations

import os

import httpx

KC = os.environ.get("LC_KC_URL", "http://127.0.0.1:19180")
ADMIN = os.environ.get("LC_KC_ADMIN", "lcadmin")
ADMIN_PASSWORD = os.environ.get("LC_KC_ADMIN_PASSWORD", "lc-kc-admin-synthetic")
REALM = "lc"
CLIENT_SECRET = os.environ.get("LC_KC_CLIENT_SECRET", "lc-kc-client-secret-synthetic-0001")
USER_PASSWORD = "lc-kc-user-password-1"
USERS = {
    "alice": ("alice@lc.example.com", True),
    "bob": ("bob@lc.example.com", False),
    "carol": ("carol@lc.example.com", True),
    "lcadmin-user": ("admin@lc.example.com", True),
}


def _admin_client() -> httpx.Client:
    tok = httpx.post(
        f"{KC}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN,
            "password": ADMIN_PASSWORD,
        },
        timeout=30,
    )
    tok.raise_for_status()
    return httpx.Client(
        base_url=f"{KC}/admin/realms",
        headers={"Authorization": f"Bearer {tok.json()['access_token']}"},
        timeout=30,
    )


def _create_user(c: httpx.Client, username: str) -> None:
    email, verified = USERS[username]
    c.post(
        f"/{REALM}/users",
        json={
            "username": username,
            "email": email,
            "emailVerified": verified,
            "enabled": True,
            "firstName": username.title(),
            "lastName": "Synthetic",
            "requiredActions": [],
            "credentials": [{"type": "password", "value": USER_PASSWORD, "temporary": False}],
        },
    ).raise_for_status()


def recreate_user(username: str) -> None:
    """Delete and create the user again: same address, new subject (``sub``)."""
    c = _admin_client()
    for u in c.get(f"/{REALM}/users", params={"username": username, "exact": "true"}).json():
        c.delete(f"/{REALM}/users/{u['id']}").raise_for_status()
    _create_user(c, username)


def setup(axentra_base: str, provider_ids: list[str]) -> None:
    c = _admin_client()
    c.delete(f"/{REALM}")
    c.post("", json={"realm": REALM, "enabled": True, "sslRequired": "none"}).raise_for_status()
    redirects = [f"{axentra_base}/v1/auth/oidc/{p}/callback" for p in provider_ids]
    common = {
        "protocol": "openid-connect",
        "publicClient": False,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "secret": CLIENT_SECRET,
        "redirectUris": redirects,
        "webOrigins": [],
    }
    c.post(
        f"/{REALM}/clients",
        json={**common, "clientId": "axentra", "attributes": {"pkce.code.challenge.method": "S256"}},
    ).raise_for_status()
    c.post(
        f"/{REALM}/clients",
        json={
            **common,
            "clientId": "axentra-hs",
            "attributes": {"id.token.signed.response.alg": "HS256"},
        },
    ).raise_for_status()
    for username in USERS:
        _create_user(c, username)


if __name__ == "__main__":
    import sys

    setup(sys.argv[1], sys.argv[2:])
    print("realm lc ready")
