"""Regression tests for the security review of 2026-11-01 (docs/security/REVIEW-2026-11-01.md).

Each test ports the reviewer's proof of concept (F1-F8) and asserts the fixed behavior; I1-I4 cover
the informational items that were fixed as well.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import ipaddress
import threading
import time
from typing import Any

import pytest

from axentra.config.settings import load_settings
from axentra.core.clock import utcnow
from axentra.core.context import Principal
from axentra.core.errors import ConfigurationError, Conflict, RateLimited, Unauthenticated
from axentra.data.database import DbScope
from axentra.events.http_client import _blocked
from axentra.tenancy.service import TenancyService
from tests.integration.conftest import World

SYS = Principal.system("test")


def _product(world: World, slug: str) -> str:
    r = world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _tenant(world: World, pid: str, slug: str) -> str:
    r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug.title()})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _member(world: World, pid: str, tid: str, email: str, role: str, name: str = "") -> str:
    uid = world.user(email, name=name)
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/members", json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    return uid


def _operator(world: World, pid: str, email: str, role: str) -> str:
    uid = world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/members", json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    return uid


# -- F1: role ceiling ---------------------------------------------------------------------------------


def test_F1_product_support_cannot_promote_itself(world: World) -> None:
    pid = _product(world, "crm")
    tid = _tenant(world, pid, "acme")
    sup_id = _operator(world, pid, "support@example.com", "product_support")
    sup = world.login_as("support@example.com")
    base = f"/v1/products/{pid}/tenants/{tid}"
    assert sup.post(f"{base}/records/notes", json={"data": {"x": 1}}).status_code == 403
    # Self-promotion (and any role above its own permissions) is refused.
    for role in ("tenant_owner", "tenant_admin", "member"):
        r = sup.post(f"{base}/members", json={"user_id": sup_id, "role": role})
        assert r.status_code == 403, (role, r.text)
        assert (
            sup.post(f"{base}/invitations", json={"email": "x@example.com", "role": role}).status_code == 403
        )
    assert sup.post(f"{base}/records/notes", json={"data": {"x": 1}}).status_code == 403
    # Within its ceiling (viewer) support still manages members.
    mid = _member(world, pid, tid, "m@example.com", "member")
    assert (
        sup.post(f"{base}/invitations", json={"email": "y@example.com", "role": "viewer"}).status_code == 201
    )
    vid = _member(world, pid, tid, "viewer@example.com", "viewer")
    assert sup.patch(f"{base}/members/{vid}", json={"role": "viewer"}).status_code == 200
    # ... but cannot touch a member whose role exceeds its own.
    assert sup.patch(f"{base}/members/{mid}", json={"role": "viewer"}).status_code == 403
    assert sup.delete(f"{base}/members/{mid}").status_code == 403
    assert sup.delete(f"{base}/members/{vid}").status_code == 204


def test_F1_tenant_admin_cannot_touch_owners(world: World) -> None:
    pid = _product(world, "crm")
    tid = _tenant(world, pid, "acme")
    base = f"/v1/products/{pid}/tenants/{tid}"
    owner_id = _member(world, pid, tid, "owner@example.com", "tenant_owner")
    admin_id = _member(world, pid, tid, "tadmin@example.com", "tenant_admin")
    mem_id = _member(world, pid, tid, "m@example.com", "member")
    adm = world.login_as("tadmin@example.com")
    assert adm.patch(f"{base}/members/{owner_id}", json={"role": "member"}).status_code == 403
    assert adm.delete(f"{base}/members/{owner_id}").status_code == 403
    assert adm.patch(f"{base}/members/{admin_id}", json={"role": "tenant_owner"}).status_code == 403
    assert adm.patch(f"{base}/members/{mem_id}", json={"role": "tenant_owner"}).status_code == 403
    assert (
        adm.post(f"{base}/invitations", json={"email": "z@example.com", "role": "tenant_owner"}).status_code
        == 403
    )
    # Equal and lower roles stay manageable.
    assert adm.patch(f"{base}/members/{mem_id}", json={"role": "tenant_admin"}).status_code == 200
    assert adm.patch(f"{base}/members/{mem_id}", json={"role": "viewer"}).status_code == 200
    # Owners manage owners; product operators too.
    own = world.login_as("owner@example.com")
    assert own.patch(f"{base}/members/{admin_id}", json={"role": "tenant_owner"}).status_code == 200
    assert own.patch(f"{base}/members/{admin_id}", json={"role": "tenant_admin"}).status_code == 200
    _operator(world, pid, "pa@example.com", "product_admin")
    pa = world.login_as("pa@example.com")
    assert pa.patch(f"{base}/members/{mem_id}", json={"role": "tenant_owner"}).status_code == 200


def test_F1_product_operator_ceiling(world: World) -> None:
    pid = _product(world, "crm")
    owner_id = _operator(world, pid, "po@example.com", "product_owner")
    world.admin.post(
        f"/v1/products/{pid}/roles",
        json={
            "key": "ops_lead",
            "name": "Ops lead",
            "scope": "product",
            "permissions": [
                "product:read",
                "product_members:manage",
                "product_members:read",
                "product_users:read",
            ],
        },
    )
    lead_id = _operator(world, pid, "lead@example.com", "ops_lead")
    sup_id = _operator(world, pid, "sup@example.com", "product_support")
    lead = world.login_as("lead@example.com")
    r = lead.post(f"/v1/products/{pid}/members", json={"user_id": lead_id, "role": "product_owner"})
    assert r.status_code == 403
    assert lead.delete(f"/v1/products/{pid}/members/{owner_id}").status_code == 403
    assert lead.delete(f"/v1/products/{pid}/members/{sup_id}").status_code == 403
    po = world.login_as("po@example.com")
    r = po.post(f"/v1/products/{pid}/members", json={"user_id": sup_id, "role": "product_admin"})
    assert r.status_code == 201, r.text


# -- F2: no installation-wide user directory -------------------------------------------------------------


def test_F2_no_user_oracle_across_products(world: World) -> None:
    pa = _product(world, "alpha")
    ta = _tenant(world, pa, "acme")
    ta2 = _tenant(world, pa, "acme-two")
    pb = _product(world, "beta")
    tb = _tenant(world, pb, "other")
    _member(world, pa, ta, "owner-a@example.com", "tenant_owner")
    victim_id = _member(world, pb, tb, "victim@corp.example", "member", name="Victim Person")
    colleague_id = _member(world, pa, ta2, "colleague@example.com", "member")
    owner = world.login_as("owner-a@example.com")
    base = f"/v1/products/{pa}/tenants/{ta}/members"

    def probe(body: dict[str, Any]) -> tuple[int, Any]:
        r = owner.post(base, json={**body, "role": "viewer"})
        return r.status_code, r.json().get("detail")

    unknown = probe({"email": "nobody@corp.example"})
    assert unknown[0] == 404
    # A user of another product, or of another tenant of this product, looks exactly like nobody.
    assert probe({"email": "victim@corp.example"}) == unknown
    assert probe({"user_id": victim_id}) == unknown
    assert probe({"email": "colleague@example.com"}) == unknown
    assert probe({"user_id": colleague_id}) == unknown
    assert probe({"user_id": "usr_doesnotexist"}) == unknown
    # The way in is an invitation, which answers the same for every address.
    for email in ("victim@corp.example", "nobody@corp.example"):
        r = owner.post(f"/v1/products/{pa}/tenants/{ta}/invitations", json={"email": email, "role": "viewer"})
        assert r.status_code == 201 and set(r.json()) >= {"invitation", "token"}
    # Product operators see the product's users (not other products' users).
    _operator(world, pa, "pa@example.com", "product_admin")
    op = world.login_as("pa@example.com")
    r = op.post(base, json={"email": "colleague@example.com", "role": "viewer"})
    assert r.status_code == 201, r.text
    r = op.post(base, json={"email": "victim@corp.example", "role": "viewer"})
    assert (r.status_code, r.json()["detail"]) == unknown
    r = op.post(f"/v1/products/{pa}/tenants", json={"slug": "new", "name": "N", "owner_user_id": victim_id})
    assert r.status_code == 404
    r = op.post(
        f"/v1/products/{pa}/tenants", json={"slug": "new", "name": "N", "owner_user_id": colleague_id}
    )
    assert r.status_code == 201, r.text
    # Product owners adding operators: the same rule.
    _operator(world, pa, "po@example.com", "product_owner")
    po = world.login_as("po@example.com")
    r = po.post(f"/v1/products/{pa}/members", json={"email": "victim@corp.example", "role": "product_viewer"})
    assert r.status_code == 404
    r = po.post(
        f"/v1/products/{pa}/members", json={"email": "colleague@example.com", "role": "product_viewer"}
    )
    assert r.status_code == 201
    # Platform admins may add anyone.
    r = world.admin.post(base, json={"email": "victim@corp.example", "role": "viewer"})
    assert r.status_code == 201
    # Once the victim is a member of this tenant the owner can change the role.
    assert owner.patch(f"{base}/{victim_id}", json={"role": "member"}).status_code == 200


# -- F3: first password needs a fresh login ---------------------------------------------------------------


def test_F3_first_password_requires_recent_login(world: World) -> None:
    with world.ax.db.transaction(DbScope.platform()) as tx:
        uid = world.ax.identity.create_user(tx, email="sso@example.com", name="SSO")
    stale = world.ax.identity.start_session(uid, "oidc:corp", ip=None, user_agent="")
    with world.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_sessions SET created_at = now() - interval '10 minutes' WHERE id = %s",
            (stale.info.session_id,),
        )
    b = world.browser()
    b.client.cookies.set("axentra-session", stale.token)
    b.csrf = stale.info.csrf_token
    r = b.post("/v1/me/password", json={"current_password": "", "new_password": "attacker chosen pw 1"})
    assert r.status_code == 403 and r.json()["code"] == "reauthentication_required", r.text
    with pytest.raises(AssertionError):
        world.login_as("sso@example.com", "attacker chosen pw 1")
    # Right after a fresh login the user may set a first password.
    fresh = world.ax.identity.start_session(uid, "oidc:corp", ip=None, user_agent="")
    b2 = world.browser()
    b2.client.cookies.set("axentra-session", fresh.token)
    b2.csrf = fresh.info.csrf_token
    assert (
        b2.post(
            "/v1/me/password", json={"current_password": "", "new_password": "my own password 1"}
        ).status_code
        == 204
    )
    world.login_as("sso@example.com", "my own password 1")
    # Installations can switch first passwords off entirely.
    world.ax.settings.security.first_password = "disabled"
    with world.ax.db.transaction(DbScope.platform()) as tx:
        uid2 = world.ax.identity.create_user(tx, email="sso2@example.com", name="SSO 2")
    s2 = world.ax.identity.start_session(uid2, "oidc:corp", ip=None, user_agent="")
    b3 = world.browser()
    b3.client.cookies.set("axentra-session", s2.token)
    b3.csrf = s2.info.csrf_token
    r = b3.post("/v1/me/password", json={"current_password": "", "new_password": "my own password 2"})
    assert r.status_code == 403 and r.json()["code"] == "forbidden"


# -- F4: job kinds open to tenant members, confined handler principal ---------------------------------


def test_F4_members_enqueue_only_declared_kinds_and_handlers_are_confined(world: World) -> None:
    pid = _product(world, "crm")
    tid = _tenant(world, pid, "acme")
    m_id = _member(world, pid, tid, "m@example.com", "member")
    m = world.login_as("m@example.com")
    r = m.post(
        f"/v1/products/{pid}/jobs", json={"kind": "reports.admin_cleanup", "tenant_id": tid, "payload": {}}
    )
    assert r.status_code == 403, r.text
    world.ax.jobs.declare(
        "reports.export",
        enqueue_permission="events:publish",
        permissions={"records:read", "members:manage", "files:write"},
    )
    with pytest.raises(ValueError):
        world.ax.jobs.declare("reports.loose", enqueue_permission="events:publish")
    with pytest.raises(ValueError):
        world.ax.jobs.declare("axentra.mine", enqueue_permission="events:publish", permissions=set())
    r = m.post(
        f"/v1/products/{pid}/jobs", json={"kind": "reports.export", "tenant_id": tid, "payload": {"a": 1}}
    )
    assert r.status_code == 201, r.text
    job = world.ax.jobs.queue.get(r.json()["id"])
    assert job is not None
    p = world.ax.jobs.principal_for(job)
    # Declared set intersected with what the member holds: no members:manage.
    assert world.ax.authz.has(p, "records:read", pid, tid)
    assert world.ax.authz.has(p, "files:write", pid, tid)
    assert not world.ax.authz.has(p, "members:manage", pid, tid)
    assert not world.ax.authz.has(p, "records:write", pid, tid)
    # The enqueuer loses access: the job can do nothing any more.
    world.ax.tenancy.remove_member(SYS, pid, tid, m_id)
    p = world.ax.jobs.principal_for(job)
    assert not world.ax.authz.has(p, "records:read", pid, tid)
    # Operators (jobs:manage) enqueue any kind; undeclared kinds keep the trusted default.
    r = world.admin.post(f"/v1/products/{pid}/jobs", json={"kind": "reports.admin_cleanup", "tenant_id": tid})
    assert r.status_code == 201
    job2 = world.ax.jobs.queue.get(r.json()["id"])
    assert job2 is not None
    assert world.ax.authz.has(world.ax.jobs.principal_for(job2), "members:manage", pid, tid)


def test_enqueueable_job_kinds_are_listed_per_caller(world: World) -> None:
    pid = _product(world, "crm")
    tid = _tenant(world, pid, "acme")
    _member(world, pid, tid, "m@example.com", "member")
    _member(world, pid, tid, "v@example.com", "viewer")
    world.ax.jobs.declare("reports.export", enqueue_permission="events:publish", permissions={"records:read"})
    world.ax.jobs.declare("reports.trusted")
    world.ax.jobs.register("reports.cleanup", lambda ctx: None)
    world.ax.jobs.declare("axentra.internal")  # reserved kinds are never listed
    url = f"/v1/products/{pid}/jobs/kinds"
    # A member holding events:publish sees only the kind opened to it.
    m = world.login_as("m@example.com")
    r = m.get(url, params={"tenant_id": tid})
    assert r.status_code == 200, r.text
    assert r.json() == {
        "any_kind": False,
        "items": [{"kind": "reports.export", "enqueue_permission": "events:publish"}],
    }
    # ... and nothing at product level, where only jobs:manage enqueues.
    assert m.get(url).json() == {"any_kind": False, "items": []}
    # A viewer (no events:publish) sees no kind; what it lists matches what enqueue accepts.
    v = world.login_as("v@example.com")
    assert v.get(url, params={"tenant_id": tid}).json() == {"any_kind": False, "items": []}
    r = v.post(f"/v1/products/{pid}/jobs", json={"kind": "reports.export", "tenant_id": tid})
    assert r.status_code == 403
    # An operator (jobs:manage) may enqueue any kind: all known kinds are listed.
    for params in ({}, {"tenant_id": tid}):
        body = world.admin.get(url, params=params).json()
        assert body["any_kind"] is True
        assert [k["kind"] for k in body["items"]] == ["reports.cleanup", "reports.export", "reports.trusted"]
    # A stranger has no access to the scope.
    world.user("x@example.com")
    assert world.login_as("x@example.com").get(url, params={"tenant_id": tid}).status_code in (403, 404)


# -- F5: derived API keys ----------------------------------------------------------------------------


def test_F5_child_keys_are_capped_and_revoked_with_parent(world: World) -> None:
    pid = _product(world, "crm")
    parent_expiry = utcnow() + timedelta(hours=1)
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={
            "name": "short",
            "permissions": ["api_keys:manage", "records:read"],
            "expires_at": parent_expiry.isoformat(),
        },
    )
    assert r.status_code == 201, r.text
    parent_id, secret = r.json()["key"]["id"], r.json()["secret"]
    c = world.browser().client
    c.headers.pop("Origin", None)

    def create(token: str, **body: Any) -> Any:
        return c.post(f"/v1/products/{pid}/api-keys", headers={"Authorization": f"Bearer {token}"}, json=body)

    r = create(secret, name="forever", permissions=["api_keys:manage", "records:read"])
    assert r.status_code == 201, r.text
    child_exp = datetime.fromisoformat(r.json()["key"]["expires_at"])
    assert abs((child_exp - parent_expiry).total_seconds()) < 1
    child = r.json()["secret"]
    later = (parent_expiry + timedelta(days=1)).isoformat()
    assert create(secret, name="later", permissions=["records:read"], expires_at=later).status_code == 422
    r = create(child, name="grandchild", permissions=["records:read"])
    assert r.status_code == 201
    grandchild = r.json()["secret"]
    # Revoking the parent revokes its descendants.
    assert world.admin.post(f"/v1/products/{pid}/api-keys/{parent_id}/revoke").status_code == 200
    assert create(child, name="again", permissions=["records:read"]).status_code == 401
    r = c.get(f"/v1/products/{pid}/api-keys", headers={"Authorization": f"Bearer {grandchild}"})
    assert r.status_code == 401
    keys = world.admin.get(f"/v1/products/{pid}/api-keys").json()
    assert {k["name"]: k["status"] for k in keys} == {
        "short": "revoked",
        "forever": "revoked",
        "grandchild": "revoked",
    }


# -- F6: notify relay ------------------------------------------------------------------------------


def test_F6_members_cannot_send_invitations_or_mail_strangers(world: World) -> None:
    pid = _product(world, "crm")
    tid = _tenant(world, pid, "acme")
    _member(world, pid, tid, "m@example.com", "member")
    _member(world, pid, tid, "colleague@example.com", "member")
    m = world.login_as("m@example.com")
    send = f"/v1/products/{pid}/tenants/{tid}/notify/send"
    variables = {
        "product_name": "CRM",
        "tenant_name": "Payroll",
        "inviter_name": "IT Security",
        "role": "tenant_owner",
        "accept_url": "https://evil.example/sso-login",
        "expires_at": "today",
    }
    for to in ({"email": "ceo@victim-corp.example"}, {"email": "colleague@example.com"}):
        r = m.post(send, json={"template_key": "invitation", "to": to, "variables": variables})
        assert r.status_code == 403, r.text
    # Even platform admins cannot send the system-only template through the API.
    r = world.admin.post(
        send, json={"template_key": "invitation", "to": {"email": "a@example.com"}, "variables": variables}
    )
    assert r.status_code == 403
    tpl = world.admin.get(f"/v1/products/{pid}/notify/templates/invitation").json()
    assert tpl["system_only"] is True
    r = world.admin.post(
        f"/v1/products/{pid}/notify/templates",
        json={
            "key": "hello",
            "category": "transactional",
            "variables": ["name"],
            "sample_data": {"name": "x"},
            "variants": {"en": {"subject": "Hi {{ name }}", "text": "Hello {{ name }}"}},
        },
    )
    assert r.status_code == 201, r.text
    body = {"template_key": "hello", "variables": {"name": "Bob"}}
    unknown = m.post(send, json={**body, "to": {"email": "ceo@victim-corp.example"}})
    assert unknown.status_code == 403
    world.user("exists-elsewhere@example.com")
    other = m.post(send, json={**body, "to": {"email": "exists-elsewhere@example.com"}})
    assert (other.status_code, other.json()["detail"]) == (403, unknown.json()["detail"])
    assert m.post(send, json={**body, "to": {"email": "colleague@example.com"}}).status_code == 202
    # Product roles hold notify:send_external.
    _operator(world, pid, "pa@example.com", "product_admin")
    pa = world.login_as("pa@example.com")
    assert pa.post(send, json={**body, "to": {"email": "ceo@victim-corp.example"}}).status_code == 202
    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        n = tx.scalar("SELECT count(*) FROM axentra_notify_messages WHERE template_key = 'invitation'")
    assert n == 0


# -- F7: last-owner race ------------------------------------------------------------------------------


def test_F7_concurrent_demotions_keep_an_owner(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    pid = _product(world, "crm")
    tid = _tenant(world, pid, "acme")
    a = _member(world, pid, tid, "a@example.com", "tenant_owner")
    b = _member(world, pid, tid, "b@example.com", "tenant_owner")
    orig = TenancyService._guard_last_tenant_owner

    def slow(tx: Any, tenant_id: str, user_id: str, new_role: str | None) -> None:
        orig(tx, tenant_id, user_id, new_role)
        time.sleep(0.3)  # widen the window between the guard and the write

    monkeypatch.setattr(TenancyService, "_guard_last_tenant_owner", staticmethod(slow))
    errs: list[Exception] = []

    def demote(uid: str) -> None:
        try:
            world.ax.tenancy.set_member(SYS, pid, tid, role="member", user_id=uid)
        except Exception as exc:
            errs.append(exc)

    ts = [threading.Thread(target=demote, args=(u,)) for u in (a, b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    roles = [m.role for m in world.ax.tenancy.list_members(SYS, pid, tid)]
    assert len(errs) == 1 and isinstance(errs[0], Conflict), errs
    assert roles.count("tenant_owner") == 1


def test_F7_concurrent_product_owner_removals_keep_an_owner(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = _product(world, "crm")
    # The admin created the product and is its first owner; add a second one.
    a = _operator(world, pid, "a@example.com", "product_owner")
    owners = [m.user_id for m in world.ax.tenancy.list_product_members(SYS, pid) if m.role == "product_owner"]
    assert a in owners and len(owners) == 2
    orig = TenancyService._would_remove_last_owner

    def slow(tx: Any, product_id: str, user_id: str, new_role: str | None) -> bool:
        result = orig(tx, product_id, user_id, new_role)
        time.sleep(0.3)
        return result

    monkeypatch.setattr(TenancyService, "_would_remove_last_owner", staticmethod(slow))
    errs: list[Exception] = []

    def remove(uid: str) -> None:
        try:
            world.ax.tenancy.remove_product_member(SYS, pid, uid)
        except Exception as exc:
            errs.append(exc)

    ts = [threading.Thread(target=remove, args=(u,)) for u in owners]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(errs) == 1 and isinstance(errs[0], Conflict), errs
    left = [m for m in world.ax.tenancy.list_product_members(SYS, pid) if m.role == "product_owner"]
    assert len(left) == 1


# -- F8: idempotency replays ------------------------------------------------------------------------


def test_F8_idempotency_replay_needs_same_request_and_reader(world: World) -> None:
    pid = _product(world, "crm")
    tid = _tenant(world, pid, "acme")
    _member(world, pid, tid, "m@example.com", "member")
    world.ax.jobs.declare(
        "reports.payroll", enqueue_permission="events:publish", permissions={"records:read"}
    )
    body = {"kind": "reports.payroll", "tenant_id": tid, "payload": {"employee": "Alice", "salary": 123456}}
    r = world.admin.post(f"/v1/products/{pid}/jobs", json={**body, "idempotency_key": "payroll-2026-11"})
    assert r.status_code == 201, r.text
    jid = r.json()["id"]
    m = world.login_as("m@example.com")
    assert m.get(f"/v1/products/{pid}/jobs/{jid}").status_code == 403
    for payload in ({}, body["payload"]):
        r = m.post(
            f"/v1/products/{pid}/jobs",
            json={**body, "payload": payload, "idempotency_key": "payroll-2026-11"},
        )
        assert r.status_code == 409, r.text
        assert "salary" not in r.text and jid not in r.text
    # The same caller (or a reader) gets the replay; a different request does not.
    r = world.admin.post(f"/v1/products/{pid}/jobs", json={**body, "idempotency_key": "payroll-2026-11"})
    assert r.status_code == 201 and r.json()["id"] == jid
    r = world.admin.post(
        f"/v1/products/{pid}/jobs", json={**body, "payload": {"x": 1}, "idempotency_key": "payroll-2026-11"}
    )
    assert r.status_code == 409
    # Members replay their own requests.
    mine = {"kind": "reports.payroll", "tenant_id": tid, "payload": {"n": 1}, "idempotency_key": "mine"}
    first = m.post(f"/v1/products/{pid}/jobs", json=mine)
    assert first.status_code == 201
    assert m.post(f"/v1/products/{pid}/jobs", json=mine).json()["id"] == first.json()["id"]
    # Events: the same rules.
    ev = f"/v1/products/{pid}/tenants/{tid}/events"
    r = world.admin.post(
        ev, json={"type": "pay.run", "data": {"secret": 1}}, headers={"Idempotency-Key": "e-1"}
    )
    assert r.status_code == 201, r.text
    assert (
        m.post(
            ev, json={"type": "pay.run", "data": {"secret": 1}}, headers={"Idempotency-Key": "e-1"}
        ).status_code
        == 409
    )
    assert (
        m.post(ev, json={"type": "pay.run", "data": {}}, headers={"Idempotency-Key": "e-1"}).status_code
        == 409
    )
    again = world.admin.post(
        ev, json={"type": "pay.run", "data": {"secret": 1}}, headers={"Idempotency-Key": "e-1"}
    )
    assert again.status_code == 201 and again.json()["id"] == r.json()["id"]


# -- informational items ----------------------------------------------------------------------------


def test_I1_production_refuses_private_webhook_targets_without_override() -> None:
    base: dict[str, Any] = {
        "environ": {},
        "environment": "production",
        "security": {"public_url": "https://api.example.com", "master_keys_ref": "env:X"},
    }
    with pytest.raises(ConfigurationError, match="webhook_allow_private_targets"):
        load_settings(None, **base, events={"webhook_allow_private_targets": True}).validate_security()
    load_settings(
        None,
        **base,
        events={"webhook_allow_private_targets": True, "webhook_allow_private_targets_in_production": True},
    ).validate_security()


def test_I2_ipv6_site_local_is_blocked() -> None:
    assert _blocked(ipaddress.ip_address("fec0::1"))
    assert _blocked(ipaddress.ip_address("feff::1"))
    assert not _blocked(ipaddress.ip_address("2606:4700::1111"))


def test_I3_audit_lookup_is_not_an_existence_oracle(world: World) -> None:
    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        platform_event = tx.scalar("SELECT id FROM axentra_audit_events WHERE product_id IS NULL LIMIT 1")
    assert platform_event
    world.user("u@example.com")
    u = world.login_as("u@example.com")
    real = u.get(f"/v1/audit/{platform_event}")
    fake = u.get("/v1/audit/aud_doesnotexist")
    assert real.status_code == fake.status_code == 404
    assert real.json()["detail"] == fake.json()["detail"]
    assert world.admin.get(f"/v1/audit/{platform_event}").status_code == 200


def test_I4_login_throttling_is_atomic(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    # Pin the one-minute window: fixed windows allow up to twice the budget across a boundary
    # (documented in SECURITY_MODEL.md), which would make this test fail when it straddles one.
    window = utcnow().replace(second=0, microsecond=0)
    monkeypatch.setattr(world.ax.identity, "_window", lambda: window)
    world.user("t@example.com")
    limit = world.ax.settings.security.login_rate_per_minute
    results: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        try:
            world.ax.identity.login_password(
                "t@example.com", "wrong password 123", ip="10.0.0.1", user_agent=""
            )
            outcome = "ok"
        except Unauthenticated:
            outcome = "verified"
        except RateLimited:
            outcome = "limited"
        with lock:
            results.append(outcome)

    ts = [threading.Thread(target=attempt) for _ in range(limit * 2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    # Never more password checks than the budget, however many arrive at once.
    assert results.count("verified") == limit and results.count("limited") == limit
    # A successful login gives its attempt back (only failures use the budget).
    world.user("ok@example.com")
    for _ in range(limit + 2):
        world.ax.identity.login_password(
            "ok@example.com", "user password 12345", ip="10.0.0.2", user_agent=""
        )
