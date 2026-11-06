"""Product-level invitations for operators (the product team, ``axentra_product_members``).

Before, ``POST /v1/products/{id}/members`` resolved only users the caller can see, so a product
owner who is not a platform admin could not add an operator without a visible account.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from axentra.data.database import DbScope
from tests.integration.conftest import World
from tests.integration.test_oidc import OidcWorld
from tests.integration.test_oidc_start_secrets import START, _post_start
from tests.integration.test_oidc_start_secrets import world as oidc_world  # noqa: F401 (fixture)

ACCEPT = "/v1/product-invitations/accept"


def _ok(r: Any, code: int = 200) -> Any:
    assert r.status_code == code, r.text
    return r.json() if r.content else None


def _product(world: World, slug: str = "crm") -> str:
    return str(_ok(world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()}), 201)["id"])


def _owner(world: World, pid: str, email: str = "owner@example.com") -> Any:
    """A product owner who is not a platform admin (cannot see users outside the product)."""
    world.user(email)
    _ok(world.admin.post(f"/v1/products/{pid}/members", json={"email": email, "role": "product_owner"}), 201)
    return world.login_as(email)


def _audit(world: World, action: str) -> list[Any]:
    return world.ax.audit.list(DbScope.platform(), action=action).items


def test_owner_invites_an_operator_without_a_visible_account(world: World) -> None:
    pid = _product(world)
    owner = _owner(world, pid)
    # The direct add cannot resolve an account the owner cannot see (unchanged behaviour).
    world.user("ops@example.com")
    r = owner.post(f"/v1/products/{pid}/members", json={"email": "ops@example.com", "role": "product_admin"})
    assert r.status_code == 404
    # The invitation works for that account and for an address without one.
    new = _ok(
        owner.post(
            f"/v1/products/{pid}/invitations", json={"email": "Ops@Example.com", "role": "product_admin"}
        ),
        201,
    )
    token = new["token"]
    assert token.startswith("axpinv_")
    inv = new["invitation"]
    assert inv["email"] == "Ops@example.com" and inv["role"] == "product_admin" and inv["status"] == "pending"
    assert "tenant_id" not in inv
    # One open invitation per address; listed for product_members:read.
    r = owner.post(
        f"/v1/products/{pid}/invitations", json={"email": "ops@example.com", "role": "product_viewer"}
    )
    assert r.status_code == 409
    assert [i["id"] for i in _ok(owner.get(f"/v1/products/{pid}/invitations"))] == [inv["id"]]
    # Not a tenant invitation: the tenant accept endpoint does not take the token, and the other way round.
    ops = world.login_as("ops@example.com")
    assert ops.post("/v1/invitations/accept", json={"token": token}).status_code == 404
    member = _ok(ops.post(ACCEPT, json={"token": token}))
    assert member["product_id"] == pid and member["role"] == "product_admin"
    assert member["email"] == "ops@example.com"  # the account's own address (matched case-insensitively)
    # Accepted once; the operator now sees the product.
    assert ops.post(ACCEPT, json={"token": token}).status_code == 404
    assert pid in [p["id"] for p in _ok(ops.get("/v1/products"))]
    assert _ok(owner.get(f"/v1/products/{pid}/invitations"))[0]["status"] == "accepted"
    actions = {e.action for e in world.ax.audit.list(DbScope.platform(), product_id=pid).items}
    assert {"tenancy.product_invitation.create", "tenancy.product_invitation.accept"} <= actions


def test_role_scope_ceiling_and_permissions(world: World) -> None:
    pid = _product(world)
    owner = _owner(world, pid)
    url = f"/v1/products/{pid}/invitations"
    # Only product roles.
    assert owner.post(url, json={"email": "a@example.com", "role": "member"}).status_code == 422
    assert owner.post(url, json={"email": "a@example.com", "role": "nope"}).status_code == 422
    # A product admin cannot invite above its own level (role ceiling) ...
    world.user("padmin@example.com")
    _ok(
        world.admin.post(
            f"/v1/products/{pid}/members", json={"email": "padmin@example.com", "role": "product_admin"}
        ),
        201,
    )
    padmin = world.login_as("padmin@example.com")
    assert padmin.post(url, json={"email": "b@example.com", "role": "product_owner"}).status_code == 403
    # ... and a viewer cannot invite at all, nor list.
    world.user("pviewer@example.com")
    _ok(
        world.admin.post(
            f"/v1/products/{pid}/members", json={"email": "pviewer@example.com", "role": "product_viewer"}
        ),
        201,
    )
    viewer = world.login_as("pviewer@example.com")
    assert viewer.post(url, json={"email": "c@example.com", "role": "product_viewer"}).status_code == 403
    # A tenant member has no product-level member rights.
    tid = _ok(world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}), 201)[
        "id"
    ]
    world.user("tm@example.com")
    _ok(
        world.admin.post(
            f"/v1/products/{pid}/tenants/{tid}/members",
            json={"email": "tm@example.com", "role": "tenant_owner"},
        ),
        201,
    )
    tm = world.login_as("tm@example.com")
    assert tm.post(url, json={"email": "d@example.com", "role": "product_viewer"}).status_code in (403, 404)
    assert tm.get(url).status_code in (403, 404)
    # Product invitations are not listed with the tenant's invitations.
    _ok(owner.post(url, json={"email": "e@example.com", "role": "product_viewer"}), 201)
    assert _ok(world.admin.get(f"/v1/products/{pid}/tenants/{tid}/invitations")) == []


def test_refusals_carry_a_reason_and_are_audited(world: World) -> None:
    pid = _product(world)
    owner = _owner(world, pid)
    url = f"/v1/products/{pid}/invitations"
    token = _ok(owner.post(url, json={"email": "x@example.com", "role": "product_admin"}), 201)["token"]
    world.user("other@example.com")
    r = world.login_as("other@example.com").post(ACCEPT, json={"token": token})
    assert r.status_code == 403 and r.json()["reason"] == "email_mismatch"
    world.user("x@example.com")
    x = world.login_as("x@example.com")
    # An archived product: refused, the invitation stays open.
    _ok(world.admin.post(f"/v1/products/{pid}/archive"))
    r = x.post(ACCEPT, json={"token": token})
    assert r.status_code == 403 and r.json()["reason"] == "scope_inactive"
    _ok(world.admin.post(f"/v1/products/{pid}/restore"))
    # The inviter is demoted below the invited role: refused.
    owner_id = _ok(owner.get("/v1/me"))["user"]["id"]
    _ok(world.admin.patch(f"/v1/products/{pid}/members/{owner_id}", json={"role": "product_viewer"}))
    r = x.post(ACCEPT, json={"token": token})
    assert r.status_code == 403 and r.json()["reason"] == "inviter_lost_access"
    reasons = [e.details.get("reason") for e in _audit(world, "tenancy.product_invitation.accept")]
    assert sorted(reasons) == ["email_mismatch", "inviter_lost_access", "scope_inactive"]
    # Restored: accepted.
    _ok(world.admin.patch(f"/v1/products/{pid}/members/{owner_id}", json={"role": "product_owner"}))
    assert _ok(x.post(ACCEPT, json={"token": token}))["role"] == "product_admin"


def test_revoke_and_existing_role_is_kept(world: World) -> None:
    pid = _product(world)
    owner = _owner(world, pid)
    url = f"/v1/products/{pid}/invitations"
    new = _ok(owner.post(url, json={"email": "r@example.com", "role": "product_viewer"}), 201)
    assert owner.delete(f"{url}/{new['invitation']['id']}").status_code == 204
    assert owner.delete(f"{url}/{new['invitation']['id']}").status_code == 404
    world.user("r@example.com")
    assert world.login_as("r@example.com").post(ACCEPT, json={"token": new["token"]}).status_code == 404
    # An invitation never lowers a role the user already has.
    world.user("keep@example.com")
    _ok(
        world.admin.post(
            f"/v1/products/{pid}/members", json={"email": "keep@example.com", "role": "product_admin"}
        ),
        201,
    )
    token = _ok(owner.post(url, json={"email": "keep@example.com", "role": "product_viewer"}), 201)["token"]
    assert (
        _ok(world.login_as("keep@example.com").post(ACCEPT, json={"token": token}))["role"] == "product_admin"
    )
    # A tenant invitation's token is not accepted here.
    tid = _ok(world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}), 201)[
        "id"
    ]
    world.user("t@example.com")
    ttoken = _ok(
        world.admin.post(f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": "t@example.com"}),
        201,
    )["token"]
    assert world.login_as("t@example.com").post(ACCEPT, json={"token": ttoken}).status_code == 404


def test_product_rows_are_read_only_in_tenant_scope(world: World, pg_urls: dict[str, str]) -> None:
    """RLS: a tenant-bound transaction may read but never write the product's invitations."""
    pid = _product(world)
    tid = _ok(world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}), 201)[
        "id"
    ]
    iid = _ok(world.admin.post(f"/v1/products/{pid}/invitations", json={"email": "z@example.com"}), 201)[
        "invitation"
    ]["id"]
    with world.ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_invitations WHERE id = %s", (iid,)) == 1
        assert tx.execute("UPDATE axentra_invitations SET revoked_at = now() WHERE id = %s", (iid,)) == 0
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        world.ax.db.transaction(DbScope.tenant(pid, tid)) as tx,
    ):
        tx.execute(
            "INSERT INTO axentra_invitations (id, product_id, tenant_id, email, role, token_hash, expires_at)"
            " VALUES ('inv_forged', %s, NULL, 'f@example.com', 'product_owner', 'h', now() + interval '1 day')",
            (pid,),
        )
    # Deleting the product removes its invitations (own foreign key for product rows).
    with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
        conn.execute("DELETE FROM axentra_products WHERE id = %s", (pid,))
        assert conn.execute("SELECT count(*) FROM axentra_invitations WHERE id = %s", (iid,)).fetchone() == (
            0,
        )


def test_invitation_email_is_enqueued_with_the_accept_link(world: World) -> None:
    pid = _product(world)
    new = _ok(world.admin.post(f"/v1/products/{pid}/invitations", json={"email": "mail@example.com"}), 201)
    assert new["accept_url"].endswith("/accept-invitation?token=" + new["token"])
    msgs = _ok(
        world.admin.get(f"/v1/products/{pid}/notify/messages", params={"template_key": "product_invitation"})
    )
    (msg,) = msgs["items"]
    assert msg["recipient"] == "mail@example.com" and msg["tenant_id"] is None
    # System-only: an API caller can never send it with chosen variables.
    tid = _ok(world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}), 201)[
        "id"
    ]
    r = world.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/notify/send",
        json={"template_key": "product_invitation", "to_email": "x@example.com", "variables": {}},
    )
    assert r.status_code in (403, 422), r.text


def test_oidc_login_signs_up_the_invited_operator_and_accepts(oidc_world) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    w: OidcWorld = oidc_world(allow_signup=False)
    pid = _ok(w.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}), 201)["id"]
    token = _ok(
        w.admin.post(
            f"/v1/products/{pid}/invitations", json={"email": "sso-op@example.com", "role": "product_admin"}
        ),
        201,
    )["token"]
    b = w.browser()
    location = _post_start(w, b, return_to="http://studio.test/accept-invitation", invitation=token).json()[
        "redirect_url"
    ]
    done = b.get(w.idp.authorize(location, "op-sub", email="sso-op@example.com"), follow_redirects=False)
    assert done.status_code == 302, done.text
    assert (
        done.headers["location"] == f"http://studio.test/accept-invitation?product_invitation_accepted={pid}"
    )
    me = _ok(b.get("/v1/me"))
    assert [(p["product"]["id"], p["role"]) for p in me["products"]] == [(pid, "product_admin")]
    assert START  # the POST start is the only start that takes an invitation
