from __future__ import annotations

from axentra.api.app import create_app
from axentra.core.errors import Conflict, EmailTaken, SetupAlreadyCompleted
from axentra.data.database import DbScope
from tests.integration.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, Browser


def test_meta_reports_setup_state_and_mode(ax, world):
    r = world.browser().get("/v1/meta")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "multi"
    assert body["api_version"]["major"] == 1
    assert body["setup_required"] is False
    assert r.headers["Axentra-API-Version"].startswith("1.")
    assert r.headers["X-Request-ID"]


def test_setup_token_is_single_use(world):
    token = world.ax.identity.create_setup_token()
    r = world.browser().post(
        "/v1/auth/setup",
        json={"setup_token": token, "email": "x@example.com", "password": "another long password"},
    )
    assert r.status_code == 409  # an admin exists already
    assert r.json()["code"] == "setup_already_completed"
    assert r.json()["type"] == "urn:axentra:problem:setup_already_completed"
    r = world.browser().post(
        "/v1/auth/setup",
        json={"setup_token": "axsetup_wrong", "email": "y@example.com", "password": "another long password"},
    )
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["code"] == "unauthenticated"


def test_login_session_logout(world):
    b = world.browser()
    assert b.get("/v1/auth/session").status_code == 401
    info = b.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    assert info["platform_role"] == "platform_admin"
    cookie = b.client.cookies.get("axentra-session")
    assert cookie and len(cookie) > 30
    s = b.get("/v1/auth/session")
    assert s.status_code == 200
    assert s.json()["csrf_token"] == info["csrf_token"]
    assert b.post("/v1/auth/logout").status_code == 204
    # The old token no longer works even if replayed.
    replay = Browser(world.app)
    replay.client.cookies.set("axentra-session", cookie)
    assert replay.get("/v1/auth/session").status_code == 401


def test_wrong_password_is_rejected_and_audited(world):
    r = world.browser().post(
        "/v1/auth/login/password", json={"email": ADMIN_EMAIL, "password": "wrong password!!"}
    )
    assert r.status_code == 401
    events = world.admin.get("/v1/audit", params={"action": "identity.login", "outcome": "denied"}).json()[
        "items"
    ]
    assert events and events[0]["details"].get("method") == "password"
    assert "password" not in str(events[0]["details"]).replace("'method': 'password'", "")


def test_login_rate_limit(ax_factory):
    from axentra.api.app import create_app

    ax = ax_factory(security={"login_rate_per_minute": 3})
    app = create_app(axentra=ax, start=False)
    b = Browser(app)
    codes = [
        b.post(
            "/v1/auth/login/password", json={"email": "nobody@example.com", "password": "x" * 12}
        ).status_code
        for _ in range(5)
    ]
    assert codes[:3] == [401, 401, 401]
    assert codes[-1] == 429


def test_csrf_required_for_cookie_writes(world):
    b = world.browser()
    b.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    csrf = b.csrf
    b.csrf = None
    r = b.post("/v1/products", json={"slug": "crm", "name": "CRM"})
    assert r.status_code == 403
    r = b.post("/v1/products", json={"slug": "crm", "name": "CRM"}, headers={"X-Axentra-CSRF": "nope"})
    assert r.status_code == 403
    r = b.post(
        "/v1/products",
        json={"slug": "crm", "name": "CRM"},
        headers={"X-Axentra-CSRF": csrf, "Origin": "https://evil.example"},
    )
    assert r.status_code == 403
    r = b.post("/v1/products", json={"slug": "crm", "name": "CRM"}, headers={"X-Axentra-CSRF": csrf})
    assert r.status_code == 201


def test_login_from_foreign_origin_is_refused(world):
    b = world.browser()
    r = b.post(
        "/v1/auth/login/password",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 403


def test_bearer_session_token_works_without_csrf(world):
    b = world.browser()
    b.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    token = b.client.cookies.get("axentra-session")
    from fastapi.testclient import TestClient

    c = TestClient(world.app)
    r = c.post(
        "/v1/products", json={"slug": "books", "name": "Books"}, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 201


def test_revoke_session_and_password_change(world):
    uid = world.user("alice@example.com")
    a1 = world.login_as("alice@example.com")
    a2 = world.login_as("alice@example.com")
    sessions = a1.get("/v1/auth/sessions").json()
    assert len(sessions) == 2
    other = next(s for s in sessions if not s["current"])
    assert a1.delete(f"/v1/auth/sessions/{other['id']}").status_code == 204
    assert a2.get("/v1/me").status_code == 401
    # Password change revokes other sessions, keeps the current one.
    a3 = world.login_as("alice@example.com")
    r = a1.post(
        "/v1/me/password",
        json={"current_password": "user password 12345", "new_password": "new secret pass 987"},
    )
    assert r.status_code == 204
    assert a1.get("/v1/me").status_code == 200
    assert a3.get("/v1/me").status_code == 401
    # Admin revokes everything.
    r = world.admin.post(f"/v1/users/{uid}/sessions/revoke")
    assert r.status_code == 200 and r.json()["revoked"] >= 1
    assert a1.get("/v1/me").status_code == 401


def test_disabled_user_cannot_log_in(world):
    uid = world.user("bob@example.com")
    b = world.login_as("bob@example.com")
    r = world.admin.patch(f"/v1/users/{uid}", json={"status": "disabled"})
    assert r.status_code == 200 and r.json()["status"] == "disabled"
    assert b.get("/v1/me").status_code == 401
    r = world.browser().post(
        "/v1/auth/login/password", json={"email": "bob@example.com", "password": "user password 12345"}
    )
    assert r.status_code == 401


def test_password_policy(world):
    world.user("carol@example.com")
    c = world.login_as("carol@example.com")
    r = c.post("/v1/me/password", json={"current_password": "user password 12345", "new_password": "short"})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "validation_failed" and body["reason"] == "too_short"
    assert body["min_length"] == 12
    assert body["errors"] == [
        {"loc": ["body", "new_password"], "msg": "the password must have at least 12 characters"}
    ]
    for new_password, reason in (
        ("carol@example.com", "equals_email"),
        ("aaaabbbbaaaabbbb", "too_simple"),
    ):
        r = c.post(
            "/v1/me/password", json={"current_password": "user password 12345", "new_password": new_password}
        )
        assert r.status_code == 422 and r.json()["reason"] == reason, r.text
        assert r.json()["errors"][0]["loc"] == ["body", "new_password"]


def test_setup_password_refusal_marks_the_password_field(ax):
    app = create_app(axentra=ax, start=False)
    token = ax.identity.create_setup_token()
    r = Browser(app).post(
        "/v1/auth/setup", json={"setup_token": token, "email": ADMIN_EMAIL, "password": "too short"}
    )
    assert r.status_code == 422
    assert r.json()["reason"] == "too_short"
    assert r.json()["errors"] == [
        {"loc": ["body", "password"], "msg": "the password must have at least 12 characters"}
    ]
    # The refused setup did not use up the token.
    assert ax.identity.setup_required()


def test_meta_reports_the_password_policy(ax_factory):
    ax = ax_factory(security={"password_min_length": 16})
    body = Browser(create_app(axentra=ax, start=False)).get("/v1/meta").json()
    assert body["auth"]["password_policy"] == {"min_length": 16, "max_length": 1024}


def test_profile_update(world):
    r = world.admin.patch("/v1/me", json={"name": "Ada", "locale": "de", "preferences": {"theme": "dark"}})
    assert r.status_code == 200
    assert r.json()["locale"] == "de" and r.json()["preferences"] == {"theme": "dark"}


def test_security_headers(world):
    r = world.browser().get("/v1/meta")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_request_id_is_propagated_or_replaced(world):
    c = world.browser()
    assert c.get("/v1/meta", headers={"X-Request-ID": "abc-123"}).headers["X-Request-ID"] == "abc-123"
    assert c.get("/v1/meta", headers={"X-Request-ID": "bad id\n"}).headers["X-Request-ID"].startswith("req_")


def test_setup_with_a_taken_email_is_a_distinct_conflict(ax):
    """Both setup conflicts stay 409 (and ``Conflict`` subclasses) but carry their own codes."""
    assert issubclass(SetupAlreadyCompleted, Conflict) and issubclass(EmailTaken, Conflict)
    assert SetupAlreadyCompleted.status == EmailTaken.status == 409
    app = create_app(axentra=ax, start=False)
    # A user without a platform role (for example created by an OIDC sign-in) has the address.
    with ax.db.transaction(DbScope.platform()) as tx:
        ax.identity.create_user(tx, email="Taken@Example.com", name="Taken")
    token = ax.identity.create_setup_token()
    r = Browser(app).post(
        "/v1/auth/setup",
        json={"setup_token": token, "email": "taken@example.com", "password": "another long password"},
    )
    assert r.status_code == 409
    assert r.json()["code"] == "email_taken"
    assert r.json()["detail"] == "a user with this email address exists"
    # The token was not used up: setup with another address succeeds.
    r = Browser(app).post(
        "/v1/auth/setup",
        json={"setup_token": token, "email": "admin2@example.com", "password": "another long password"},
    )
    assert r.status_code == 200, r.text


# -- request context of login and setup audit events (audit round 3) ---------------------------------


def _audit_rows(ax, action: str, outcome: str = "success") -> list[dict]:  # type: ignore[no-untyped-def]
    with ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return tx.all(
            "SELECT * FROM axentra_audit_events WHERE action = %s AND outcome = %s ORDER BY occurred_at, id",
            (action, outcome),
        )


def test_setup_audit_events_carry_request_context(ax):
    app = create_app(axentra=ax, start=False)
    token = ax.identity.create_setup_token()
    r = Browser(app).post(
        "/v1/auth/setup",
        json={"setup_token": token, "email": ADMIN_EMAIL, "name": "Admin", "password": ADMIN_PASSWORD},
        headers={"X-Request-ID": "req-setup-1"},
    )
    assert r.status_code == 200, r.text
    for action in ("identity.setup.complete", "identity.login"):
        (event,) = _audit_rows(ax, action)
        assert event["actor_kind"] == "user" and event["actor_id"] == r.json()["user"]["id"]
        assert event["actor_display"] == ADMIN_EMAIL
        assert event["request_id"] == "req-setup-1"
        assert event["ip"] == "testclient"  # TestClient's peer address
        assert ADMIN_PASSWORD not in str(event) and token not in str(event)


def test_password_login_audit_events_carry_request_context(world):
    b = world.browser()
    r = b.post(
        "/v1/auth/login/password",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"X-Request-ID": "req-login-ok"},
    )
    assert r.status_code == 200, r.text
    (event,) = [e for e in _audit_rows(world.ax, "identity.login") if e["request_id"] == "req-login-ok"]
    assert event["actor_kind"] == "user" and event["actor_id"] == r.json()["user"]["id"]
    assert event["actor_display"] == ADMIN_EMAIL
    assert event["ip"] == "testclient"
    assert event["target_type"] == "session" and event["details"] == {"method": "password"}
    assert ADMIN_PASSWORD not in str(event)
    cookie = b.client.cookies.get("axentra-session")
    assert cookie and cookie not in str(event)


def test_denied_password_login_audit_event_carries_request_context(world):
    typed = "Admin@Example.com"
    r = world.browser().post(
        "/v1/auth/login/password",
        json={"email": typed, "password": "wrong password!!"},
        headers={"X-Request-ID": "req-login-denied"},
    )
    assert r.status_code == 401
    (event,) = _audit_rows(world.ax, "identity.login", "denied")
    assert event["actor_kind"] == "anonymous" and event["actor_display"] == typed
    assert event["request_id"] == "req-login-denied"
    assert event["ip"] == "testclient"
    assert "wrong password" not in str(event)
