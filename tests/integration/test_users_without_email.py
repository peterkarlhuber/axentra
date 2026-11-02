"""Users without an email address and explicit external-identity linking (library API)."""

from __future__ import annotations

import pytest

from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from axentra.data.database import DbScope

SYSTEM = Principal.system("import")
ISSUER = "https://idp.example"


def _user_principal(uid: str) -> Principal:
    return Principal(actor=Actor(ActorKind.USER, uid, uid))


def test_create_user_without_email(world):  # type: ignore[no-untyped-def]
    ax = world.ax
    with ax.db.transaction(DbScope.platform()) as tx:
        a = ax.identity.create_user(tx, email=None, name="A")
        b = ax.identity.create_user(tx, email=None, name="B")  # NULLs do not collide
        with pytest.raises(ValidationFailed, match="password needs an email"):
            ax.identity.create_user(tx, email=None, name="C", password="a long password 123")
    user = ax.identity.get_user(a)
    assert user.email is None and user.display == "A" and a != b
    with pytest.raises(Forbidden, match="email address"):
        ax.identity.change_password(_user_principal(a), "", "a long password 123")


def test_create_external_user_and_link_identity(world):  # type: ignore[no-untyped-def]
    ax = world.ax
    imported = ax.identity.create_external_user(
        SYSTEM, provider=ISSUER, subject="s-1", email="Imp@Example.com", email_verified=False, name="Imp"
    )
    assert imported.email is None  # unverified: kept on the identity only
    assert ax.identity.list_identities(imported.id)[0]["email"] == "Imp@Example.com"
    verified = ax.identity.create_external_user(
        SYSTEM, provider=ISSUER, subject="s-2", email="ver@example.com", email_verified=True
    )
    assert verified.email == "ver@example.com"
    with pytest.raises(Conflict, match="already linked"):
        ax.identity.create_external_user(SYSTEM, provider=ISSUER, subject="s-1")
    with pytest.raises(Conflict, match="email"):
        ax.identity.create_external_user(
            SYSTEM, provider=ISSUER, subject="s-3", email="ver@example.com", email_verified=True
        )
    # Explicit link of a second identity; duplicates and unknown users are refused.
    ax.identity.link_identity(SYSTEM, imported.id, provider="https://other.example", subject="x")
    with pytest.raises(Conflict):
        ax.identity.link_identity(SYSTEM, verified.id, provider="https://other.example", subject="x")
    with pytest.raises(NotFound):
        ax.identity.link_identity(SYSTEM, "usr_missing", provider=ISSUER, subject="y")
    with pytest.raises(Forbidden):
        ax.identity.link_identity(_user_principal(imported.id), imported.id, provider=ISSUER, subject="z")
    assert len(ax.identity.list_identities(imported.id)) == 2
    # The login path finds the imported user by (provider, subject), without an email.
    assert (
        ax.identity.link_external_identity(
            provider="https://other.example",
            subject="x",
            email="",
            name="",
            email_verified=False,
            allow_signup=False,
            allowed_domains=[],
        )
        == imported.id
    )
    actions = [e.action for e in ax.audit.list(DbScope.platform(), action="identity.external.*").items]
    assert sorted(actions) == [
        "identity.external.create",
        "identity.external.create",
        "identity.external.link",
    ]


def test_invitation_and_membership_with_user_without_email(world):  # type: ignore[no-untyped-def]
    ax = world.ax
    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    user = ax.identity.create_external_user(SYSTEM, provider=ISSUER, subject="m-1", name="Nomail")
    inv = ax.tenancy.invite(SYSTEM, pid, tid, email="someone@example.com", role="member")
    with pytest.raises(Forbidden, match="another email address"):
        ax.tenancy.accept_invitation(_user_principal(user.id), inv.token)
    # Added directly by id instead; listed with a null email.
    ax.tenancy.set_member(SYSTEM, pid, tid, role="member", user_id=user.id)
    members = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/members").json()
    assert [(m["user_id"], m["email"]) for m in members] == [(user.id, None)]

    # Notify: the email channel skips the user with a clear reason; nothing crashes.
    body = {
        "key": "welcome",
        "category": "transactional",
        "variables": ["name"],
        "sample_data": {"name": "S"},
        "variants": {"en": {"subject": "Hi {{ name }}", "text": "Hello {{ name }}"}},
    }
    assert world.admin.post(f"/v1/products/{pid}/notify/templates", json=body).status_code == 201
    r = world.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/notify/send",
        json={"template_key": "welcome", "to": {"user_id": user.id}, "variables": {"name": "N"}},
    )
    assert r.status_code in (200, 201, 202), r.text
    msg = r.json()
    assert msg["status"] == "suppressed" and msg["last_error"] == "the recipient has no email address"
    assert msg["recipient_user_id"] == user.id and msg["recipient"] == ""


def test_provider_option_validation():
    from axentra.config.settings import OidcProviderSettings

    base = {"id": "p", "name": "P", "issuer": ISSUER, "client_id": "c"}
    with pytest.raises(ValueError, match="requires allow_signup"):
        OidcProviderSettings(**base, allow_signup_without_email=True)
    with pytest.raises(ValueError, match="allowed_email_domains"):
        OidcProviderSettings(
            **base, allow_signup=True, allow_signup_without_email=True, allowed_email_domains=["x.org"]
        )
    ok = OidcProviderSettings(**base, allow_signup=True, allow_signup_without_email=True)
    assert ok.link_by_verified_email is True
