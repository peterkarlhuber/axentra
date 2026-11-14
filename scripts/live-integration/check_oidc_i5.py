"""Live OIDC check of decision I5 (no automatic linking of platform users by verified email).

Run against a source tree that implements I5 (``LC_AXENTRA_SRC=<worktree>/src``); same Keycloak
service as check_oidc.py. Cases:

1. a Keycloak identity whose verified email belongs to the platform admin is refused
   (``login_error=explicit_link_required``) and no session is created;
2. the platform admin links it explicitly (``POST /v1/users/{id}/identities`` with the issuer and
   the Keycloak subject); the same login then succeeds as the platform admin;
3. a normal (non-platform) user is still linked by verified email (new Keycloak subject, same user);
4. ``link_platform_users_by_verified_email = true`` on a provider restores the old behaviour.
"""

from __future__ import annotations

import json
import sys

import check_oidc as co
import keycloak_setup as kcs
from lib import EVIDENCE, SRC, Report, base_env, bootstrap_admin, reset_database, serve

PROVIDERS = ["kc", "kcsignup", "kclegacy"]


def providers_json() -> str:
    base = {"issuer": co.ISSUER, "client_id": "axentra", "client_secret_ref": "env:LC_KC_CLIENT_SECRET"}
    return json.dumps(
        [
            {**base, "id": "kc", "name": "Keycloak (no signup)"},
            {**base, "id": "kcsignup", "name": "Keycloak (signup)", "allow_signup": True},
            {
                **base,
                "id": "kclegacy",
                "name": "Keycloak (legacy linking)",
                "link_platform_users_by_verified_email": True,
            },
        ]
    )


def kc_subject(username: str) -> str:
    c = kcs._admin_client()
    return c.get(f"/{kcs.REALM}/users", params={"username": username, "exact": "true"}).json()[0]["id"]


def main() -> int:
    rep = Report("oidc-i5")
    rep.note(f"Axentra source under test: {SRC}")
    log = EVIDENCE / "oidc-i5-serve.log"
    log.unlink(missing_ok=True)
    kcs.setup(co.AX, PROVIDERS)
    env = base_env(
        reset_database("lc_oidc_i5"),
        co.PORT,
        AXENTRA__OIDC=providers_json(),
        LC_KC_CLIENT_SECRET=kcs.CLIENT_SECRET,
    )
    observed: list[dict] = []
    with serve(env, co.PORT, log):
        admin = bootstrap_admin(env, co.PORT, log)
        admin_id = admin.ok("GET", "/v1/auth/session")["user"]["id"]

        # 1. Platform admin's address: refused, no session, no identity row.
        b, r, _ = co.login("kc", "lcadmin-user")
        observed.append({"case": 1, "outcome": co.outcome(r)})
        rep.check(
            "1: platform admin's verified email -> explicit_link_required",
            co.outcome(r) == "error:explicit_link_required",
            co.outcome(r),
        )
        rep.check("1: no session created", b.session().status_code == 401)
        ids = admin.ok("GET", f"/v1/users/{admin_id}/identities")
        rep.check("1: nothing linked to the admin", ids == [], ids)
        b, r, _ = co.login("kcsignup", "lcadmin-user")
        rep.check(
            "1b: also refused on a signup provider (no second account with the address)",
            co.outcome(r) == "error:explicit_link_required",
            co.outcome(r),
        )

        # 2. Explicit link by the platform admin, then the login succeeds.
        sub = kc_subject("lcadmin-user")
        r = admin.post(f"/v1/users/{admin_id}/identities", json={"provider": co.ISSUER, "subject": sub})
        rep.check(
            "2: POST /v1/users/{id}/identities links the Keycloak subject",
            r.status_code in (200, 201),
            f"{r.status_code} {r.text[:200]}",
        )
        b, r, _ = co.login("kc", "lcadmin-user")
        s = b.session().json() if b.session().status_code == 200 else {}
        observed.append(
            {
                "case": 2,
                "outcome": co.outcome(r),
                "user": s.get("user", {}).get("id"),
                "platform_role": s.get("platform_role"),
            }
        )
        rep.check(
            "2: login after the explicit link -> session as the platform admin",
            r.status_code == 302
            and s.get("user", {}).get("id") == admin_id
            and s.get("platform_role") == "platform_admin",
            observed[-1],
        )

        # 3. Normal user: first login creates carol; a new Keycloak subject with the same verified email links.
        b, r, _ = co.login("kcsignup", "carol")
        carol = b.session().json()["user"]["id"] if b.session().status_code == 200 else None
        kcs.recreate_user("carol")
        b, r, _ = co.login("kc", "carol")
        s = b.session().json() if b.session().status_code == 200 else {}
        observed.append(
            {"case": 3, "outcome": co.outcome(r), "same_user": s.get("user", {}).get("id") == carol}
        )
        rep.check(
            "3: non-platform user with a new IdP subject is still linked by verified email",
            carol is not None and s.get("user", {}).get("id") == carol and s.get("platform_role") is None,
            observed[-1],
        )
        rep.check(
            "3: carol now has two identities", len(admin.ok("GET", f"/v1/users/{carol}/identities")) == 2
        )

        # 4. Opt-in legacy behaviour on one provider.
        kcs.recreate_user("lcadmin-user")
        b, r, _ = co.login("kclegacy", "lcadmin-user")
        s = b.session().json() if b.session().status_code == 200 else {}
        observed.append({"case": 4, "outcome": co.outcome(r), "platform_role": s.get("platform_role")})
        rep.check(
            "4: link_platform_users_by_verified_email=true -> auto-linked to the platform admin",
            s.get("user", {}).get("id") == admin_id,
            observed[-1],
        )
        audit = admin.get("/v1/audit", params={"action": "identity.login", "limit": 50})
        if audit.status_code == 200:
            rep.save_json("audit-identity-login", audit.json())
    rep.save_json("observed", observed)
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
