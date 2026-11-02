"""Contract tests: the SDK against a real in-process Axentra server (see conftest.py)."""

from __future__ import annotations

from decimal import Decimal
import io
from pathlib import Path

import pytest

from axentra_client import API_VERSION, AsyncAxentraClient, AxentraApiError, AxentraClient
from axentra_client.models import Membership, NewApiKey, Page, Record, Tenant

from .conftest import ADMIN_EMAIL, Server, unique

pytestmark = pytest.mark.integration

TENANT_PERMS = [
    "tenant:read",
    "records:read",
    "records:write",
    "files:read",
    "files:write",
    "usage:read",
    "usage:record",
    "billing:read",
    "notify:send",
    "members:read",
]


def _key(admin: AxentraClient, product: str, perms: list[str], tenant: str | None = None) -> NewApiKey:
    return admin.api_keys.create(product, unique("key"), perms, tenant_id=tenant)


def test_meta_and_compatibility(admin: AxentraClient) -> None:
    meta = admin.check_compatibility()
    assert meta.name == "axentra" and meta.mode == "multi"
    assert (meta.api_version.major, meta.api_version.minor) >= API_VERSION
    assert meta.setup_required is False
    assert "usage" in meta.modules


def test_password_login_session_and_logout(server: Server, admin: AxentraClient) -> None:
    server.user("login-user@example.com")
    c = server.login("login-user@example.com")
    me = c.me.get()
    assert me.actor_kind == "user" and me.user is not None and me.user.email == "login-user@example.com"
    session = c.auth.session()
    assert session.user.email == "login-user@example.com" and session.csrf_token
    assert any(s.current for s in c.auth.sessions())
    # Bearer session tokens need no CSRF header for changes.
    assert c.me.update(name="Renamed").name == "Renamed"
    token = c.token
    c.auth.logout()
    with pytest.raises(AxentraApiError) as ei:
        AxentraClient(server.url, session_token=token).me.get()
    assert ei.value.status == 401 and ei.value.code == "unauthenticated"
    with pytest.raises(AxentraApiError) as ei:
        server.client().auth.login_password("login-user@example.com", "wrong password!!")
    assert ei.value.status == 401
    assert admin.me.get().platform_role is not None


def test_products_with_optimistic_concurrency(admin: AxentraClient) -> None:
    p = admin.products.create(unique("prod"), "Name", description="d")
    assert admin.products.get(p.id).description == "d"
    assert any(x.id == p.id for x in admin.products.list())
    updated = admin.products.update(p.id, name="New", version=p.version)
    assert updated.version == p.version + 1
    with pytest.raises(AxentraApiError) as ei:
        admin.products.update(p.id, name="Stale", version=p.version)
    assert (ei.value.status, ei.value.code) == (412, "precondition_failed")


def test_tenants_crud_pagination_and_validation(admin: AxentraClient, product: str) -> None:
    created = [admin.tenants.create(product, unique("t"), f"T{i}") for i in range(5)]
    page = admin.tenants.list(product, limit=2)
    assert isinstance(page, Page) and len(page.items) == 2 and page.next_cursor
    all_ids = [t.id for t in admin.tenants.iter(product, page_size=2)]
    assert sorted(all_ids) == sorted(t.id for t in created)
    t = admin.tenants.update(product, created[0].id, name="Renamed", version=created[0].version)
    assert isinstance(t, Tenant) and t.name == "Renamed"
    admin.tenants.delete(product, created[1].id)
    with pytest.raises(AxentraApiError) as ei:
        admin.tenants.get(product, created[1].id)
    assert ei.value.code == "not_found" and ei.value.request_id
    with pytest.raises(AxentraApiError) as ei:
        admin.tenants.create(product, "NOT A SLUG", "x")
    assert ei.value.status == 422 and ei.value.code == "validation_failed"


def test_operators_members_invitations_and_roles(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    op = server.user(f"{unique('op')}@example.com")
    pm = admin.operators.add(product, "product_viewer", user_id=op)
    assert pm.role == "product_viewer"
    assert admin.operators.change(product, op, "product_support").role == "product_support"
    assert any(m.user_id == op for m in admin.operators.list(product))
    admin.operators.remove(product, op)

    email = f"{unique('member')}@example.com"
    uid = server.user(email)
    m = admin.members.add(product, tenant, "member", email=email)
    assert isinstance(m, Membership) and m.user_id == uid
    assert admin.members.change(product, tenant, uid, "viewer").role == "viewer"
    assert [x.user_id for x in admin.members.list(product, tenant)] == [uid]
    admin.members.remove(product, tenant, uid)
    assert admin.members.list(product, tenant) == []

    invited = f"{unique('inv')}@example.com"
    inv = admin.invitations.create(product, tenant, invited, role="member")
    assert inv.token and inv.invitation.status == "pending"
    assert [i.id for i in admin.invitations.list(product, tenant)] == [inv.invitation.id]
    server.user(invited)
    accepted = server.login(invited).invitations.accept(inv.token)
    assert accepted.tenant_id == tenant
    other = admin.invitations.create(product, tenant, f"{unique('inv')}@example.com")
    admin.invitations.revoke(product, tenant, other.invitation.id)

    role = admin.roles.create(product, unique("r").replace("-", "_"), "Auditors", "tenant", ["records:read"])
    assert role.id is not None and not role.builtin
    role = admin.roles.update(
        product, role.id, permissions=["records:read", "files:read"], version=role.version
    )
    assert set(role.permissions) == {"records:read", "files:read"}
    assert any(r.key == "tenant_owner" and r.builtin for r in admin.roles.list(product))
    assert role.id is not None
    admin.roles.delete(product, role.id)


def test_api_keys_lifecycle_and_permissions(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    new = _key(admin, product, ["tenants:read"])
    assert new.secret.startswith("axk_") and new.key.status == "active"
    with server.client(api_key=new.secret) as key_client:
        assert key_client.me.get().actor_kind == "api_key"
        assert key_client.tenants.list(product).items
        with pytest.raises(AxentraApiError) as ei:
            key_client.tenants.create(product, unique("t"), "nope")
        assert ei.value.status == 403 and ei.value.code == "forbidden"
    assert admin.api_keys.get(product, new.key.id).name == new.key.name
    assert any(k.id == new.key.id for k in admin.api_keys.list(product))
    rotated = admin.api_keys.rotate(product, new.key.id, grace_seconds=0)
    assert rotated.secret != new.secret and rotated.key.replaces == new.key.id
    assert admin.api_keys.revoke(product, rotated.key.id).status == "revoked"
    with pytest.raises(AxentraApiError) as ei:
        server.client(api_key=rotated.secret).me.get()
    assert ei.value.status == 401


def test_records_crud_iteration_and_isolation(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    key = _key(admin, product, TENANT_PERMS, tenant=tenant)
    c = server.client(api_key=key.secret)
    r = c.records.create(product, tenant, "notes", {"title": "a", "status": "open"})
    assert isinstance(r, Record) and r.version == 1 and r.data["title"] == "a"
    assert c.records.get(product, tenant, "notes", r.id).data == {"title": "a", "status": "open"}
    r2 = c.records.replace(product, tenant, "notes", r.id, {"title": "b", "status": "done"}, version=1)
    assert r2.version == 2
    with pytest.raises(AxentraApiError) as ei:
        c.records.replace(product, tenant, "notes", r.id, {"title": "stale"}, version=1)
    assert ei.value.code == "precondition_failed"
    for i in range(5):
        c.records.create(product, tenant, "notes", {"title": f"n{i}", "status": "open"})
    assert len(list(c.records.iter(product, tenant, "notes", page_size=2))) == 6
    assert len(list(c.records.iter(product, tenant, "notes", where={"status": "open"}, page_size=2))) == 5
    # A key scoped to tenant A sees nothing of tenant B (404, not 403: no existence oracle).
    other = admin.tenants.create(product, unique("t"), "Tenant B").id
    foreign = admin.records.create(product, other, "notes", {"title": "secret"})
    with pytest.raises(AxentraApiError) as ei:
        c.records.get(product, other, "notes", foreign.id)
    assert ei.value.status in (403, 404)
    c.records.delete(product, tenant, "notes", r.id, version=2)
    with pytest.raises(AxentraApiError) as ei:
        c.records.get(product, tenant, "notes", r.id)
    assert ei.value.status == 404


def test_files_upload_stream_download(
    server: Server, admin: AxentraClient, product: str, tenant: str, tmp_path: Path
) -> None:
    key = _key(admin, product, TENANT_PERMS, tenant=tenant)
    c = server.client(api_key=key.secret)
    payload = bytes(range(256)) * 12_000  # ~3 MB, several chunks
    src = tmp_path / "blob.bin"
    src.write_bytes(payload)
    info = c.files.upload(
        product, tenant, src, content_type="application/octet-stream", metadata={"kind": "test"}
    )
    assert info.size == len(payload) and info.name == "blob.bin" and info.metadata == {"kind": "test"}
    assert c.files.download(product, tenant, info.id) == payload
    dest = tmp_path / "copy.bin"
    assert c.files.download_to(product, tenant, info.id, dest) == len(payload)
    assert dest.read_bytes() == payload
    with c.files.stream(product, tenant, info.id) as resp:
        chunks = list(resp.iter_bytes())
    assert len(chunks) > 1 and b"".join(chunks) == payload
    small = c.files.upload(
        product, tenant, io.BytesIO(b"hello"), filename="hello.txt", content_type="text/plain"
    )
    assert small.content_type.startswith("text/plain")
    assert any(f.id == small.id for f in c.files.iter(product, tenant))
    renamed = c.files.update(product, tenant, small.id, name="greeting.txt", version=small.version)
    assert renamed.name == "greeting.txt"
    url = c.files.download_url(product, tenant, small.id, ttl_seconds=60)
    assert url.kind == "signed" and url.url
    c.files.delete(product, tenant, small.id)
    with pytest.raises(AxentraApiError) as ei:
        c.files.download(product, tenant, small.id)
    assert ei.value.status == 404


def test_usage_idempotency_quotas_and_summary(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    admin.usage.create_meter(product, "api_calls", unit="calls", default_limit=10, default_enforcement="hard")
    assert [m.key for m in admin.usage.meters(product)] == ["api_calls"]
    key = _key(admin, product, TENANT_PERMS, tenant=tenant)
    c = server.client(api_key=key.secret)
    first = c.usage.record(product, tenant, "api_calls", 3, idempotency_key="req-1")
    again = c.usage.record(product, tenant, "api_calls", 3, idempotency_key="req-1")
    assert first.replayed is False and again.replayed is True and again.event.id == first.event.id
    with pytest.raises(AxentraApiError) as ei:
        c.usage.record(product, tenant, "api_calls", 4, idempotency_key="req-1")
    assert ei.value.code == "conflict"
    with pytest.raises(AxentraApiError) as ei:
        c.usage.record(product, tenant, "api_calls", 8, idempotency_key="req-2", enforce=True)
    assert ei.value.status == 429 and ei.value.code == "quota_exceeded"
    summary = {m.meter: m for m in c.usage.summary(product, tenant)}
    assert summary["api_calls"].value == Decimal(3) and summary["api_calls"].remaining == Decimal(7)
    assert [e.id for e in c.usage.iter_events(product, tenant, meter="api_calls")] == [first.event.id]
    assert c.usage.quotas(product, tenant)[0].source == "meter"
    q = admin.usage.set_quota(product, tenant, "api_calls", Decimal(100), enforcement="soft")
    assert q.limit == Decimal(100) and q.source == "quota"
    assert admin.usage.delete_quota(product, tenant, "api_calls").source == "meter"


def test_billing_plans_subscription_entitlements(admin: AxentraClient, product: str, tenant: str) -> None:
    plan = admin.billing.create_plan(
        product, "free", "Free", entitlements={"feature.export": True, "limit.api_calls": 50}
    )
    assert plan.free and plan.entitlements["feature.export"] is True
    assert [p.key for p in admin.billing.plans(product)] == ["free"]
    assert [p.key for p in admin.billing.tenant_plans(product, tenant)] == ["free"]
    with pytest.raises(AxentraApiError) as ei:
        admin.billing.subscription(product, tenant)
    assert ei.value.status == 404
    sub = admin.billing.subscribe(product, tenant, "free")
    assert sub.status == "active" and sub.plan_key == "free"
    assert admin.billing.subscription(product, tenant).id == sub.id
    ent = admin.billing.entitlements(product, tenant)
    assert ent.features == {"export": True} and ent.limits == {"api_calls": Decimal(50)}
    assert admin.billing.subscriptions(product).items[0].id == sub.id
    canceled = admin.billing.cancel(product, tenant, at_period_end=True)
    assert canceled.cancel_at_period_end is True
    assert admin.billing.resume(product, tenant).cancel_at_period_end is False


def test_notify_send_idempotent_and_messages(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    admin.request_json(
        "POST",
        f"/v1/products/{product}/notify/templates",
        json={
            "key": "welcome",
            "name": "Welcome",
            "variables": ["name"],
            "variants": {"en": {"subject": "Hi {{ name }}", "text": "Hello {{ name }}"}},
        },
    )
    key = _key(admin, product, TENANT_PERMS, tenant=tenant)
    c = server.client(api_key=key.secret)
    # notify:send reaches members of the tenant; free-form addresses need notify:send_external.
    bob = f"{unique('bob')}@example.com"
    server.user(bob)
    admin.members.add(product, tenant, "member", email=bob)
    msg = c.notify.send(
        product,
        tenant,
        "welcome",
        to_email=bob,
        variables={"name": "Bob"},
        idempotency_key="n-1",
    )
    assert msg.status == "queued" and msg.recipient == bob and msg.subject == "Hi Bob"
    again = c.notify.send(
        product,
        tenant,
        "welcome",
        to_email=bob,
        variables={"name": "Bob"},
        idempotency_key="n-1",
    )
    assert again.id == msg.id
    page = admin.notify.messages(product, tenant_id=tenant)
    assert [m.id for m in page.items] == [msg.id]
    assert [m.id for m in c.notify.iter_messages(product, tenant_id=tenant)] == [msg.id]
    full = admin.notify.message(product, msg.id)
    assert full.content is not None and full.content.text == "Hello Bob"


def test_audit_list_iter_get(admin: AxentraClient, product: str, tenant: str) -> None:
    admin.records.create(product, tenant, "audited", {"x": 1})
    page = admin.audit.list(product_id=product, limit=2)
    assert page.items and all(e.product_id == product for e in page.items)
    events = list(admin.audit.iter(product_id=product, page_size=2))
    assert {"tenancy.product.create", "tenancy.tenant.create"} <= {e.action for e in events}
    assert admin.audit.get(events[0].id).id == events[0].id
    assert all(e.actor_kind == "user" and e.actor_display == ADMIN_EMAIL for e in events)


@pytest.mark.anyio
async def test_async_client_end_to_end(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    email = f"{unique('async')}@example.com"
    server.user(email)
    admin.members.add(product, tenant, "member", email=email)
    async with AsyncAxentraClient(server.url) as c:
        meta = await c.check_compatibility()
        assert meta.api_version.major == API_VERSION[0]
        await c.auth.login_password(email, "sdk user password 123")
        me = await c.me.get()
        assert me.user is not None and me.user.email == email
        for i in range(3):
            await c.records.create(product, tenant, "async_notes", {"i": i})
        seen = [r.data["i"] async for r in c.records.iter(product, tenant, "async_notes", page_size=2)]
        assert sorted(seen) == [0, 1, 2]
        payload = b"x" * 200_000
        info = await c.files.upload(product, tenant, payload, filename="a.bin")
        async with c.files.stream(product, tenant, info.id) as resp:
            got = b"".join([chunk async for chunk in resp.aiter_bytes()])
        assert got == payload
        with pytest.raises(AxentraApiError) as ei:
            await c.tenants.create(product, unique("t"), "no permission")
        assert ei.value.status in (403, 404)
        await c.auth.logout()
        assert c.token is None
