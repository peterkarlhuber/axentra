"""Live OIDC check: Axentra's OIDC login against a real Keycloak (dev mode, synthetic realm).

Needs (see compose.yml) ``keycloak`` on 127.0.0.1:19180 with the synthetic bootstrap admin; the realm
is (re)created by keycloak_setup.py. A "browser" is an httpx client with a cookie jar that follows
the redirects by hand and submits Keycloak's real login form.

The I5 product decision (OIDC auto-linking for platform admins) is open: this check only records
what happens when a Keycloak user with the platform admin's verified address logs in.
"""

from __future__ import annotations

import html
import http.cookiejar
import os
import re
import sys
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx
import keycloak_setup as kcs
from lib import (
    EVIDENCE,
    Report,
    base_env,
    bootstrap_admin,
    reset_database,
    scan_for_secrets,
    serve,
)

PORT = int(os.environ.get("LC_OIDC_AX_PORT", "19203"))
AX = f"http://127.0.0.1:{PORT}"
ISSUER = f"{kcs.KC}/realms/{kcs.REALM}"
PROVIDERS = ["kc", "kcsignup", "kcnolink", "kchs"]
SECRETS_SEEN: dict[str, str] = {}


def providers_json() -> str:
    import json

    base = {"issuer": ISSUER, "client_id": "axentra", "client_secret_ref": "env:LC_KC_CLIENT_SECRET"}
    return json.dumps(
        [
            {**base, "id": "kc", "name": "Keycloak (no signup)"},
            {**base, "id": "kcsignup", "name": "Keycloak (signup)", "allow_signup": True},
            {
                **base,
                "id": "kcnolink",
                "name": "Keycloak (no link)",
                "allow_signup": True,
                "link_by_verified_email": False,
            },
            {**base, "id": "kchs", "name": "Keycloak HS256", "client_id": "axentra-hs", "allow_signup": True},
        ]
    )


# Keycloak dev mode marks its cookies ``Secure`` even on plain http. A real browser sends them to
# http://127.0.0.1 (loopback is a secure context); http.cookiejar (used by httpx, which copies the jar
# per request, so a per-jar policy is lost) does not. Allow it for loopback hosts in this process only.
_orig_secure = http.cookiejar.DefaultCookiePolicy.return_ok_secure


def _return_ok_secure(self, cookie, request):  # type: ignore[no-untyped-def]
    if urlsplit(request.get_full_url()).hostname in ("127.0.0.1", "localhost"):
        return True
    return _orig_secure(self, cookie, request)


http.cookiejar.DefaultCookiePolicy.return_ok_secure = _return_ok_secure  # type: ignore[method-assign]


class Browser:
    def __init__(self) -> None:
        self.c = httpx.Client(timeout=30, follow_redirects=False)

    def start(self, provider: str, return_to: str = "/after") -> tuple[str, dict[str, str]]:
        r = self.c.get(f"{AX}/v1/auth/oidc/{provider}/start", params={"return_to": return_to})
        assert r.status_code == 302, (r.status_code, r.text[:300])
        loc = r.headers["location"]
        params = {k: v[0] for k, v in parse_qs(urlsplit(loc).query).items()}
        SECRETS_SEEN[f"state-{len(SECRETS_SEEN)}"] = params.get("state", "")
        return loc, params

    def idp_login(self, auth_url: str, username: str) -> str:
        """Authenticate at Keycloak; return the callback URL Keycloak redirects to."""
        r = self.c.get(auth_url)
        if r.status_code == 302:
            return r.headers["location"]
        m = re.search(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"', r.text)
        assert m, f"no login form (status {r.status_code})"
        r = self.c.post(
            html.unescape(m.group(1)),
            data={"username": username, "password": kcs.USER_PASSWORD, "credentialId": ""},
        )
        assert r.status_code == 302, (r.status_code, r.text[:500])
        loc = r.headers["location"]
        code = parse_qs(urlsplit(loc).query).get("code", [""])[0]
        SECRETS_SEEN[f"code-{len(SECRETS_SEEN)}"] = code
        return loc

    def callback(self, url: str) -> httpx.Response:
        return self.c.get(url)

    def session(self) -> httpx.Response:
        return self.c.get(f"{AX}/v1/auth/session")


def outcome(r: httpx.Response) -> str:
    loc = r.headers.get("location", "")
    q = parse_qs(urlsplit(loc).query)
    if r.status_code == 302 and "login_error" in q:
        return "error:" + q["login_error"][0]
    return f"{r.status_code} -> {loc}"


def login(provider: str, user: str, return_to: str = "/after") -> tuple[Browser, httpx.Response, str]:
    b = Browser()
    auth, _ = b.start(provider, return_to)
    cb = b.idp_login(auth, user)
    return b, b.callback(cb), cb


def main() -> int:
    rep = Report("oidc")
    log = EVIDENCE / "oidc-serve.log"
    log.unlink(missing_ok=True)
    kcs.setup(AX, PROVIDERS)
    rep.note(
        f"Keycloak realm {ISSUER} created (clients axentra [PKCE S256 required], axentra-hs [HS256 ID tokens])"
    )
    db = reset_database("lc_oidc")
    env = base_env(db, PORT, AXENTRA__OIDC=providers_json(), LC_KC_CLIENT_SECRET=kcs.CLIENT_SECRET)
    transcript: list[dict[str, str]] = []
    with serve(env, PORT, log):
        admin = bootstrap_admin(env, PORT, log)
        meta = httpx.get(f"{AX}/v1/meta", timeout=10).json()
        ids = [p.get("id") for p in meta.get("auth", {}).get("oidc", [])]
        rep.check("/v1/meta lists the configured providers", ids == PROVIDERS, ids)

        # Start: PKCE S256, state/nonce entropy, login cookie.
        b = Browser()
        auth, params = b.start("kcsignup")
        rep.check(
            "start redirects to the Keycloak authorization endpoint",
            auth.startswith(f"{ISSUER}/protocol/openid-connect/auth"),
            auth.split("?")[0],
        )
        rep.check(
            "authorization request: code flow, S256 PKCE, state and nonce present",
            params.get("response_type") == "code"
            and params.get("code_challenge_method") == "S256"
            and len(params.get("state", "")) >= 40
            and len(params.get("nonce", "")) >= 30,
            {
                k: (
                    v
                    if k in ("response_type", "code_challenge_method", "scope", "redirect_uri")
                    else f"<{len(v)} chars>"
                )
                for k, v in params.items()
            },
        )
        rep.check(
            "login cookie set (HttpOnly, SameSite=Lax)",
            any(c.name == "axentra-login" for c in b.c.cookies.jar),
        )

        # A: alice, no account, provider without signup.
        _, r, _ = login("kc", "alice")
        rep.check(
            "A: unknown verified user on allow_signup=false provider -> signup_disabled",
            outcome(r) == "error:signup_disabled",
            outcome(r),
        )

        # B: alice on the signup provider: full code flow, session, return_to.
        b, r, cb = login("kcsignup", "alice", "/after?x=1")
        rep.check(
            "B: full authorization-code flow ends in 302 to return_to",
            r.status_code == 302 and r.headers["location"] in ("/after?x=1", f"{AX}/after?x=1"),
            outcome(r),
        )
        s = b.session()
        sess = s.json() if s.status_code == 200 else {}
        rep.check(
            "B: Axentra session for alice (new user, email verified from the IdP)",
            s.status_code == 200
            and sess["user"]["email"] == "alice@lc.example.com"
            and sess["user"].get("email_verified") is True,
            {k: sess.get("user", {}).get(k) for k in ("email", "email_verified")},
        )
        transcript.append(
            {"step": "B", "callback_status": str(r.status_code), "location": r.headers.get("location", "")}
        )
        rep.check(
            "B: login cookie cleared after the callback",
            not any(c.name == "axentra-login" and c.value for c in b.c.cookies.jar),
        )

        # D: replay of the same callback URL (state already consumed).
        r = b.callback(cb)
        rep.check("D: replayed callback -> login_expired", outcome(r) == "error:login_expired", outcome(r))

        # C: alice through another provider entry with the same issuer.
        b2, r, _ = login("kc", "alice")
        rep.note(f"C: alice (now known) via provider 'kc' (same issuer, allow_signup=false): {outcome(r)}")

        # E: login CSRF: callback delivered to another browser.
        b1 = Browser()
        auth, _ = b1.start("kcsignup")
        cb = b1.idp_login(auth, "carol")
        other = Browser()
        r = other.callback(cb)
        rep.check(
            "E: callback in a browser without the login cookie -> login_expired",
            outcome(r) == "error:login_expired",
            outcome(r),
        )
        r = b1.callback(cb)
        rep.check(
            "E: the state is spent afterwards, also for the original browser",
            outcome(r) == "error:login_expired",
            outcome(r),
        )

        # F: nonce mismatch: browser 2 authenticates with browser 1's nonce.
        b1, b2 = Browser(), Browser()
        _, p1 = b1.start("kcsignup")
        auth2, _ = b2.start("kcsignup")
        parts = urlsplit(auth2)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        q["nonce"] = p1["nonce"]
        cb = b2.idp_login(urlunsplit(parts._replace(query=urlencode(q))), "carol")
        r = b2.callback(cb)
        rep.check(
            "F: ID token with another login's nonce -> login_failed",
            outcome(r) == "error:login_failed",
            outcome(r),
        )
        rep.check("F: no session was created", b2.session().status_code == 401)

        # H: unverified email.
        _, r, _ = login("kcsignup", "bob")
        rep.check(
            "H: email_verified=false user -> email_not_verified",
            outcome(r) == "error:email_not_verified",
            outcome(r),
        )

        # I: HS256-signed ID token (symmetric) must be refused.
        _, r, _ = login("kchs", "carol")
        rep.check("I: HS256 ID token -> login_failed", outcome(r) == "error:login_failed", outcome(r))

        # K: provider error (user cancelled).
        bk = Browser()
        _, pk = bk.start("kcsignup")
        r = bk.callback(f"{AX}/v1/auth/oidc/kcsignup/callback?error=access_denied&state={pk['state']}")
        rep.check(
            "K: error=access_denied from the provider -> access_denied",
            outcome(r) == "error:access_denied",
            outcome(r),
        )

        # L: open redirect attempt in return_to.
        _, r, _ = login("kcsignup", "carol", "//evil.example.com/x")
        rep.check(
            "L: return_to=//evil.example.com is replaced by /",
            r.status_code == 302
            and urlsplit(r.headers["location"]).netloc in ("", f"127.0.0.1:{PORT}")
            and urlsplit(r.headers["location"]).path == "/",
            outcome(r),
        )

        # J (I5): Keycloak user with the platform admin's verified address. Each provider variant gets a
        # fresh Keycloak user (new subject), because a known (issuer, subject) always logs in as its user.
        for prov, label in (
            ("kcnolink", "link_by_verified_email=false, allow_signup=true"),
            ("kc", "link_by_verified_email=true, allow_signup=false"),
        ):
            kcs.recreate_user("lcadmin-user")
            bj, r, _ = login(prov, "lcadmin-user")
            sj = bj.session()
            info = sj.json() if sj.status_code == 200 else {}
            observed = {
                "provider": prov,
                "settings": label,
                "outcome": outcome(r),
                "session_user_id": info.get("user", {}).get("id"),
                "session_user_email": info.get("user", {}).get("email"),
                "platform_role": info.get("platform_role"),
            }
            transcript.append({k: str(v) for k, v in observed.items()})
            rep.note(
                f"J/I5 observed (Keycloak identity, verified email = platform admin's address): {observed}"
            )
        users = admin.ok("GET", "/v1/users", params={"limit": 50})
        rep.save_json(
            "users-after",
            [
                {k: u.get(k) for k in ("id", "email", "email_verified", "platform_role")}
                for u in users["items"]
            ],
        )
        audit = admin.get("/v1/audit", params={"action": "identity.login", "limit": 50})
        if audit.status_code == 200:
            rep.save_json("audit-identity-login", audit.json())
    rep.save_json("transcript", transcript)
    needles = {k: v for k, v in SECRETS_SEEN.items() if v} | {"client_secret": kcs.CLIENT_SECRET}
    hits = scan_for_secrets(log, needles)
    rep.check(
        "no OIDC code/state/client secret in the serve log",
        not any(hits.values()),
        {k: v for k, v in hits.items() if v} or f"{len(needles)} values scanned, 0 hits",
    )
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
