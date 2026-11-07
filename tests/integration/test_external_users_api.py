"""HTTP API for users without an email address and their external identities."""

from __future__ import annotations

from axentra.data.database import DbScope

ISSUER = "https://idp.example"


def _audit_actions(world, user_id):  # type: ignore[no-untyped-def]
    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return [
            r["action"]
            for r in tx.all(
                "SELECT action FROM axentra_audit_events WHERE target_id = %s ORDER BY occurred_at, id",
                (user_id,),
            )
        ]


def test_create_list_link_and_unlink(world):  # type: ignore[no-untyped-def]
    r = world.admin.post(
        "/v1/users/external",
        json={"provider": ISSUER, "subject": "sub-1", "email": "Imp@Example.com", "name": "Imported"},
    )
    assert r.status_code == 201, r.text
    user = r.json()
    assert user["email"] is None and user["name"] == "Imported" and user["has_password"] is False
    uid = user["id"]
    r = world.admin.get(f"/v1/users/{uid}/identities")
    assert r.status_code == 200
    assert [(i["provider"], i["subject"], i["email"]) for i in r.json()] == [
        (ISSUER, "sub-1", "Imp@Example.com")
    ]
    # A verified email becomes the user's address; a taken identity or address is a conflict.
    r = world.admin.post(
        "/v1/users/external",
        json={"provider": ISSUER, "subject": "sub-2", "email": "ver@example.com", "email_verified": True},
    )
    assert r.status_code == 201 and r.json()["email"] == "ver@example.com"
    assert (
        world.admin.post("/v1/users/external", json={"provider": ISSUER, "subject": "sub-1"}).status_code
        == 409
    )
    assert (
        world.admin.post(
            "/v1/users/external",
            json={"provider": ISSUER, "subject": "sub-9", "email": "ver@example.com", "email_verified": True},
        ).status_code
        == 409
    )
    # Link a second identity; the same identity again is a conflict, also for another user.
    r = world.admin.post(
        f"/v1/users/{uid}/identities", json={"provider": "https://other.example", "subject": "x"}
    )
    assert (
        r.status_code == 201 and r.json()["provider"] == "https://other.example" and r.json()["email"] == ""
    )
    again = world.admin.post(f"/v1/users/{uid}/identities", json={"provider": ISSUER, "subject": "sub-2"})
    assert again.status_code == 409
    assert (
        world.admin.post("/v1/users/usr_nope/identities", json={"provider": "p", "subject": "s"}).status_code
        == 404
    )
    # Unlink: sessions end; the last way to sign in cannot be removed.
    with world.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "INSERT INTO axentra_sessions (id, user_id, token_hash, csrf_token, auth_method, user_agent, expires_at)"
            " VALUES ('ses_ext', %s, 'h-ext', 'c', 'oidc', '', now() + interval '1 hour')",
            (uid,),
        )
    r = world.admin.delete(
        f"/v1/users/{uid}/identities", params={"provider": "https://other.example", "subject": "x"}
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"revoked": 1}
    r = world.admin.delete(f"/v1/users/{uid}/identities", params={"provider": ISSUER, "subject": "sub-1"})
    assert r.status_code == 409 and r.json()["reason"] == "last_sign_in_method"
    assert len(world.admin.get(f"/v1/users/{uid}/identities").json()) == 1  # nothing removed
    r = world.admin.delete(f"/v1/users/{uid}/identities", params={"provider": ISSUER, "subject": "nope"})
    assert r.status_code == 404
    assert _audit_actions(world, uid) == [
        "identity.external.create",
        "identity.external.link",
        "identity.external.unlink",
    ]


def test_unlink_keeps_password_users_able_to_sign_in(world):  # type: ignore[no-untyped-def]
    uid = world.user("pw@example.com")
    assert (
        world.admin.post(
            f"/v1/users/{uid}/identities", json={"provider": ISSUER, "subject": "pw"}
        ).status_code
        == 201
    )
    browser = world.login_as("pw@example.com")
    r = world.admin.delete(f"/v1/users/{uid}/identities", params={"provider": ISSUER, "subject": "pw"})
    assert r.status_code == 200 and r.json()["revoked"] == 1
    assert browser.get("/v1/me").status_code == 401  # the session ended
    world.login_as("pw@example.com")  # the password still works


def test_only_platform_admins_manage_identities(world):  # type: ignore[no-untyped-def]
    uid = world.user("plain@example.com")
    viewer_id = world.user("viewer@example.com")
    assert (
        world.admin.patch(f"/v1/users/{viewer_id}", json={"platform_role": "platform_viewer"}).status_code
        == 200
    )
    for who in ("plain@example.com", "viewer@example.com"):
        b = world.login_as(who)
        assert b.post("/v1/users/external", json={"provider": ISSUER, "subject": "z"}).status_code == 403
        assert (
            b.post(f"/v1/users/{uid}/identities", json={"provider": ISSUER, "subject": "z"}).status_code
            == 403
        )
        assert b.get(f"/v1/users/{uid}/identities").status_code == 403
        r = b.delete(f"/v1/users/{uid}/identities", params={"provider": ISSUER, "subject": "z"})
        assert r.status_code == 403
    # Validation: provider and subject are required and bounded.
    assert world.admin.post("/v1/users/external", json={"provider": "", "subject": "s"}).status_code == 422
    assert (
        world.admin.post("/v1/users/external", json={"provider": "p", "subject": "s" * 501}).status_code
        == 422
    )
    assert world.admin.get("/v1/users/usr_nope/identities").status_code == 404
