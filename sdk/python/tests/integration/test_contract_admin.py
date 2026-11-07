"""Contract tests for the operations typed in the TODO abatement round 4: notify templates and
preferences, usage reservations, billing checkout, the users admin and external identities,
product invitations, permission declarations, search batches and the event/job streams."""

from __future__ import annotations

from decimal import Decimal

import pytest

from axentra_client import AsyncAxentraClient, AxentraApiError, AxentraClient
from axentra_client.models import StreamMessage

from .conftest import Server, unique

pytestmark = pytest.mark.integration

EN = {"subject": "Hi {{ name }}", "text": "Hello {{ name }}"}


def test_notify_templates_and_preferences(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    created = admin.notify.create_template(
        product,
        "digest",
        {"en": EN},
        category="digest",
        name="Digest",
        variables=["name"],
        sample_data={"name": "Sample"},
    )
    assert (
        created.key == "digest" and created.version == 1 and created.variants["en"].subject == EN["subject"]
    )
    keys = {t.key: t for t in admin.notify.templates(product)}
    assert "digest" in keys and keys["invitation"].builtin is True
    assert admin.notify.template(product, "digest").name == "Digest"
    preview = admin.notify.preview_template(product, "digest", variables={"name": "Ann"})
    assert preview.subject == "Hi Ann" and preview.locale == "en"
    assert admin.notify.preview_template(product, "digest").text == "Hello Sample"
    draft = admin.notify.preview_draft(
        product, {"en": {"subject": "S {{ x }}", "text": "T"}}, variables=["x"], values={"x": "1"}
    )
    assert draft.subject == "S 1"
    updated = admin.notify.update_template(product, "digest", name="Daily digest", version=1)
    assert updated.version == 2 and updated.name == "Daily digest"
    with pytest.raises(AxentraApiError) as stale:
        admin.notify.update_template(product, "digest", name="x", version=1)
    assert stale.value.status == 412
    # The caller's own preferences.
    email = f"{unique('pref')}@example.com"
    server.user(email)
    admin.members.add(product, tenant, "member", email=email)
    with server.login(email) as user:
        prefs = user.notify.preferences(product)
        assert prefs.opted_out == [] and "digest" in prefs.available_categories
        changed = user.notify.set_preferences(product, ["digest"], version=prefs.version)
        assert changed.opted_out == ["digest"]
        with pytest.raises(AxentraApiError) as locked:
            user.notify.set_preferences(product, ["security"])
        assert locked.value.status == 422
        assert user.notify.preferences(product, tenant_id=tenant).tenant_id == tenant
    admin.notify.delete_template(product, "digest", version=2)
    with pytest.raises(AxentraApiError) as gone:
        admin.notify.template(product, "digest")
    assert gone.value.status == 404


def test_inbox_and_me_tenant_filter(server: Server, admin: AxentraClient, product: str, tenant: str) -> None:
    other = admin.tenants.create(product, unique("t"), "Tenant B").id
    admin.notify.create_template(
        product, "run.failed", {"en": EN}, channel="inbox", category="runs", variables=["name"]
    )
    email = f"{unique('inbox')}@example.com"
    uid = server.user(email)
    admin.members.add(product, tenant, "member", email=email)
    for name in ("R1", "R2"):
        server.ax.notify.enqueue_system(
            product, tenant, template_key="run.failed", to_user_id=uid, variables={"name": name}
        )
    with server.login(email) as user:
        page = user.notify.inbox(product, tenant_id=tenant)
        assert [m.subject for m in page.items] == ["Hi R2", "Hi R1"] and page.items[0].read_at is None
        assert user.notify.unread_count(product) == 2
        assert user.notify.mark_read(product, [page.items[0].id]) == 1
        assert [m.subject for m in user.notify.inbox(product, unread_only=True).items] == ["Hi R1"]
        assert user.notify.mark_read(product, tenant_id=tenant) == 1
        assert user.notify.unread_count(product, tenant_id=tenant) == 0
        with pytest.raises(AxentraApiError) as foreign:
            user.notify.inbox(product, tenant_id=other)
        assert foreign.value.status == 404
        # /v1/me: only the tenants the user belongs to, or none.
        mine = user.me.get(tenants="memberships")
        access = next(p for p in mine.products if p.product.id == product)
        assert [t.tenant.id for t in access.tenants] == [tenant]
        bare = next(p for p in user.me.get(tenants="none").products if p.product.id == product)
        assert bare.tenants == []
    key = admin.api_keys.create(product, "k", ["notify:preferences"], tenant_id=tenant)
    with server.client(api_key=key.secret) as by_key:  # an API key has no inbox
        with pytest.raises(AxentraApiError) as no_inbox:
            by_key.notify.inbox(product, tenant_id=tenant)
        assert no_inbox.value.status == 403


def test_usage_reservations(admin: AxentraClient, product: str, tenant: str) -> None:
    admin.usage.create_meter(product, "tokens", unit="tokens", default_limit=100, default_enforcement="hard")
    r = admin.usage.reserve(product, tenant, "tokens", 60, ttl_seconds=120, idempotency_key="res-1")
    assert r.status == "active" and r.quantity == Decimal(60)
    assert (
        admin.usage.reserve(product, tenant, "tokens", 60, ttl_seconds=120, idempotency_key="res-1").id
        == r.id
    )
    with pytest.raises(AxentraApiError) as full:
        admin.usage.reserve(product, tenant, "tokens", 50)
    assert full.value.status == 429
    assert admin.usage.reservation(product, tenant, r.id).id == r.id
    committed = admin.usage.commit(product, tenant, r.id, quantity=Decimal("42.5"), properties={"model": "m"})
    assert committed.event.quantity == Decimal("42.5") and committed.event.reservation_id == r.id
    other = admin.usage.reserve(product, tenant, "tokens", 10)
    released = admin.usage.release(product, tenant, other.id)
    assert released.status == "released"


def test_billing_checkout_error_is_mapped(admin: AxentraClient, product: str, tenant: str) -> None:
    admin.billing.create_plan(product, unique("pro"), "Pro")
    with pytest.raises(AxentraApiError) as ei:
        admin.billing.checkout(
            product,
            tenant,
            "missing-plan",
            success_url="https://x.example/ok",
            cancel_url="https://x.example/no",
        )
    assert ei.value.status in (404, 409, 422)


def test_users_admin_and_external_identities(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    email = f"{unique('adm')}@example.com"
    uid = server.user(email)
    admin.members.add(product, tenant, "viewer", email=email)
    assert admin.users.get(uid).email == email
    assert uid in [u.id for u in admin.users.iter(q=email.split("@")[0], page_size=1)]
    assert [u.id for u in admin.users.list(product_id=product).items] != []
    memberships = admin.users.memberships(uid)
    assert [(t.tenant_id, t.role) for t in memberships.tenants] == [(tenant, "viewer")]
    with server.login(email):
        assert len(admin.users.sessions(uid)) == 1
        assert admin.users.revoke_sessions(uid) == 1
    assert admin.users.update(uid, status="disabled").status == "disabled"
    assert admin.users.update(uid, status="active").status == "active"
    ext = admin.users.create_external("https://idp.example", unique("sub"), email="X@Example.com", name="Ext")
    assert ext.email is None and ext.name == "Ext"
    linked = admin.users.link_identity(ext.id, "https://other.example", "s-2")
    assert linked.provider == "https://other.example"
    assert len(admin.users.identities(ext.id)) == 2
    assert admin.users.unlink_identity(ext.id, "https://other.example", "s-2") == 0
    with pytest.raises(AxentraApiError) as last:
        admin.users.unlink_identity(
            ext.id, admin.users.identities(ext.id)[0].provider, admin.users.identities(ext.id)[0].subject
        )
    assert last.value.status == 409 and last.value.problem.get("reason") == "last_sign_in_method"


def test_product_invitations_and_permission_declarations(
    server: Server, admin: AxentraClient, product: str
) -> None:
    email = f"{unique('op')}@example.com"
    server.user(email)
    new = admin.product_invitations.create(product, email, role="product_admin")
    assert new.token and new.invitation.status == "pending"
    assert [i.id for i in admin.product_invitations.list(product)] == [new.invitation.id]
    with server.login(email) as invitee:
        member = invitee.product_invitations.accept(new.token)
        assert member.role == "product_admin"
    second = admin.product_invitations.create(product, f"{unique('op2')}@example.com")
    admin.product_invitations.revoke(product, second.invitation.id)
    statuses = {i.id: i.status for i in admin.product_invitations.list(product)}
    assert statuses[second.invitation.id] == "revoked"
    # Product permissions declared over the API.
    info = admin.roles.declare_permission(
        product, "sdkrep.reports:export", scope="tenant", description="Export reports"
    )
    assert info.name == "sdkrep.reports:export" and info.scope == "tenant"
    assert "sdkrep.reports:export" in [p.name for p in admin.roles.permissions(product)]
    admin.roles.retire_permission(product, "sdkrep.reports:export")
    assert "sdkrep.reports:export" not in [p.name for p in admin.roles.permissions(product)]
    assert "sdkrep.reports:export" in [p.name for p in admin.roles.permissions(product, include_retired=True)]
    assert "records:read" in [p.name for p in admin.roles.all_permissions()]


def test_search_batch_metadata_and_remove_kind(admin: AxentraClient, product: str, tenant: str) -> None:
    result = admin.search.index_batch(
        product,
        tenant,
        [
            {"kind": "ticket", "ref_id": "a", "title": "printer broken", "metadata": {"status": "open"}},
            {"kind": "ticket", "ref_id": "b", "title": "printer jam", "metadata": {"status": "closed"}},
        ],
    )
    assert (result.created, result.updated) == (2, 0) and [d.ref_id for d in result.documents] == ["a", "b"]
    assert [
        h.ref_id for h in admin.search.query(product, tenant, "printer", metadata={"status": "open"}).items
    ] == ["a"]
    assert [
        h.ref_id for h in admin.search.iter(product, tenant, "printer", metadata={"status": "closed"})
    ] == ["b"]
    assert admin.search.remove_kind(product, tenant, "ticket") == 2
    assert admin.search.query(product, tenant, "printer").items == []


def test_event_and_job_streams(admin: AxentraClient, product: str, tenant: str) -> None:
    first = admin.events.publish(product, tenant, "invoice.paid", {"n": 1})
    admin.events.publish(product, tenant, "order.created", {"n": 2})
    admin.events.publish(product, tenant, "invoice.paid", {"n": 3})
    stream = admin.events.stream(product, tenant_id=tenant, types=["invoice.*"], last_event_id="0")
    try:
        got = [next(stream), next(stream)]
    finally:
        stream.close()  # type: ignore[attr-defined]
    assert [(m.event, m.data["data"]["n"]) for m in got] == [("invoice.paid", 1), ("invoice.paid", 3)]
    assert got[0].data["id"] == first.id and got[0].id is not None and int(got[1].id or 0) > int(got[0].id)
    # Resuming after the first message skips it.
    stream = admin.events.stream(product, tenant_id=tenant, types=["invoice.*"], last_event_id=got[0].id)
    try:
        assert next(stream).data["data"]["n"] == 3
    finally:
        stream.close()  # type: ignore[attr-defined]
    job = admin.jobs.enqueue(product, "sdk.stream", tenant_id=tenant, delay_seconds=3600)
    jobs = admin.jobs.stream(product, tenant_id=tenant, last_event_id="0")
    try:
        # Publishing events queued fan-out jobs too; ours follows them.
        changes: dict[str, StreamMessage] = {}
        while job.id not in changes and len(changes) < 20:
            message = next(jobs)
            changes[message.data["id"]] = message
    finally:
        jobs.close()  # type: ignore[attr-defined]
    assert changes[job.id].event == "job.queued" and changes[job.id].data["status"] == "queued"
    with pytest.raises(AxentraApiError) as bad:
        next(admin.events.stream(product, last_event_id="not-a-position"))
    assert bad.value.status == 422


@pytest.mark.anyio
async def test_async_streams_and_users(
    server: Server, admin: AxentraClient, product: str, tenant: str
) -> None:
    admin.events.publish(product, tenant, "async.evt", {"n": 7})
    token = admin.token
    async with AsyncAxentraClient(server.url, session_token=token) as c:
        agen = c.events.stream(product, tenant_id=tenant, types=["async.*"], last_event_id="0")
        message = await agen.__anext__()
        await agen.aclose()  # type: ignore[attr-defined]
        assert message.event == "async.evt" and message.data["data"] == {"n": 7}
        page = await c.users.list(limit=1)
        assert len(page.items) == 1
