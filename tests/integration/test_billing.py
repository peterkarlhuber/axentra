from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json

from fastapi.testclient import TestClient
import pytest

from axentra.api.app import create_app
from axentra.core.context import Principal
from axentra.core.errors import QuotaExceeded
from tests.integration.conftest import World, bootstrap_admin

SYSTEM = Principal.system("test")


def _product(world, slug="crm"):
    r = world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _tenant(world, pid, slug="acme"):
    r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug.title()})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _plan(world, pid, key="pro", **kw):
    body = {"key": key, "name": key.title(), **kw}
    r = world.admin.post(f"/v1/products/{pid}/billing/plans", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _member(world, pid, tid, email, role="member"):
    world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/members", json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    return world.login_as(email)


PRO_PRICES = [
    {"amount_minor": 1900, "currency": "eur", "interval": "month", "provider_price_id": "price_pro"}
]


@pytest.fixture
def fake_world(ax_factory):
    ax = ax_factory(billing={"provider": "fake"})
    app = create_app(axentra=ax, start=False)
    return World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


def test_plan_crud_and_validation(world):
    pid = _product(world)
    plan = _plan(
        world,
        pid,
        prices=PRO_PRICES,
        entitlements={"feature.sso": True, "limit.api_calls": 10000},
        trial_days=14,
    )
    assert (
        plan["free"] is False
        and plan["prices"][0]["currency"] == "EUR"
        and plan["prices"][0]["id"].startswith("prc_")
    )
    assert plan["entitlements"] == {"feature.sso": True, "limit.api_calls": 10000}
    free = _plan(world, pid, "free")
    assert free["free"] is True and free["prices"] == []
    base = f"/v1/products/{pid}/billing/plans"
    assert world.admin.post(base, json={"key": "pro", "name": "dup"}).status_code == 409
    assert (
        world.admin.post(base, json={"key": "x", "name": "x", "entitlements": {"sso": True}}).status_code
        == 422
    )
    assert (
        world.admin.post(base, json={"key": "x", "name": "x", "entitlements": {"feature.a": 3}}).status_code
        == 422
    )
    assert (
        world.admin.post(base, json={"key": "x", "name": "x", "entitlements": {"limit.a": True}}).status_code
        == 422
    )
    r = world.admin.patch(
        f"{base}/{plan['id']}",
        json={"prices": [{"id": plan["prices"][0]["id"], "amount_minor": 2900, "currency": "EUR"}]},
        headers={"If-Match": "1"},
    )
    assert r.status_code == 200 and r.json()["prices"][0]["id"] == plan["prices"][0]["id"]
    assert r.json()["prices"][0]["amount_minor"] == 2900
    assert (
        world.admin.patch(f"{base}/{plan['id']}", json={"name": "y"}, headers={"If-Match": "1"}).status_code
        == 412
    )
    assert world.admin.patch(f"{base}/{free['id']}", json={"active": False}).json()["active"] is False
    tid = _tenant(world, pid)
    keys = [p["key"] for p in world.admin.get(f"/v1/products/{pid}/tenants/{tid}/billing/plans").json()]
    assert keys == ["pro"]  # tenants only see active plans
    assert world.admin.delete(f"{base}/{free['id']}").status_code == 204


def test_manual_subscription_lifecycle_and_state_machine(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _plan(world, pid, prices=PRO_PRICES, trial_days=7)
    _plan(world, pid, "team", prices=[{"amount_minor": 4900, "currency": "EUR", "interval": "year"}])
    base = f"/v1/products/{pid}/tenants/{tid}/billing/subscription"
    assert world.admin.get(base).status_code == 404
    r = world.admin.post(base, json={"plan": "pro"})
    assert r.status_code == 201, r.text
    sub = r.json()
    assert sub["status"] == "trialing" and sub["provider"] == "manual" and sub["plan_key"] == "pro"
    assert world.admin.post(base, json={"plan": "pro"}).status_code == 409  # one current subscription
    assert world.admin.post(base + "/status", json={"status": "incomplete"}).status_code == 409  # not allowed
    assert world.admin.post(base + "/status", json={"status": "active"}).json()["status"] == "active"
    assert world.admin.post(base + "/status", json={"status": "past_due"}).json()["status"] == "past_due"
    assert world.admin.post(base + "/status", json={"status": "active"}).json()["status"] == "active"
    r = world.admin.post(base + "/change-plan", json={"plan": "team"})
    assert r.status_code == 200 and r.json()["plan_key"] == "team" and r.json()["price"]["interval"] == "year"
    r = world.admin.post(base + "/cancel", json={"at_period_end": True})
    assert r.json()["cancel_at_period_end"] is True and r.json()["status"] == "active"
    assert world.admin.post(base + "/resume").json()["cancel_at_period_end"] is False
    r = world.admin.post(base + "/cancel", json={"at_period_end": False})
    assert r.json()["status"] == "canceled" and r.json()["canceled_at"]
    assert world.admin.get(base).json()["status"] == "canceled"  # latest, canceled
    assert world.admin.post(base + "/status", json={"status": "active"}).status_code == 404  # no current one
    assert world.admin.post(base + "/resume").status_code == 404
    # A new subscription can start after cancellation.
    assert world.admin.post(base, json={"plan": "team"}).status_code == 201
    # Every change was audited.
    actions = [e["action"] for e in world.admin.get(f"/v1/audit?product_id={pid}&limit=200").json()["items"]]
    for action in ("create", "status", "change_plan", "cancel", "resume"):
        assert f"billing.subscription.{action}" in actions


def test_advance_periods_for_manual_subscriptions(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _plan(world, pid, prices=PRO_PRICES)
    t0 = datetime(2026, 1, 31, 10, 0, tzinfo=UTC)
    ax.billing.clock = lambda: t0
    sub = ax.billing.create_subscription(SYSTEM, pid, tid, plan="pro")
    assert sub.current_period_end == datetime(2026, 2, 28, 10, 0, tzinfo=UTC)
    assert ax.billing.advance_periods(datetime(2026, 2, 1, tzinfo=UTC)) == 0
    assert ax.billing.advance_periods(datetime(2026, 3, 5, tzinfo=UTC)) == 1
    sub = ax.billing.get_subscription(SYSTEM, pid, tid)
    assert sub.current_period_start == datetime(2026, 2, 28, 10, 0, tzinfo=UTC)
    assert sub.current_period_end == datetime(2026, 3, 31, 10, 0, tzinfo=UTC)  # anchor day 31 kept
    ax.billing.cancel(SYSTEM, pid, tid, at_period_end=True)
    assert ax.billing.advance_periods(datetime(2026, 4, 1, tzinfo=UTC)) == 1
    assert ax.billing.get_subscription(SYSTEM, pid, tid).status == "canceled"


def test_entitlements_feed_usage_quotas(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    world.admin.post(
        f"/v1/products/{pid}/usage/meters", json={"key": "api_calls", "default_limit": 100}
    ).raise_for_status()
    _plan(world, pid, "starter", entitlements={"feature.export": True, "limit.api_calls": 3})
    base = f"/v1/products/{pid}/tenants/{tid}"
    assert world.admin.get(f"{base}/usage/quotas").json()[0]["source"] == "meter"
    assert world.admin.post(f"{base}/billing/subscription", json={"plan": "starter"}).status_code == 201
    ent = world.admin.get(f"{base}/billing/entitlements").json()
    assert (
        ent["features"] == {"export": True}
        and ent["limits"] == {"api_calls": 3}
        and ent["plan_key"] == "starter"
    )
    q = world.admin.get(f"{base}/usage/quotas").json()[0]
    assert q["source"] == "plan" and q["limit"] == 3
    for i in range(3):
        ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 1, f"k{i}")
    with pytest.raises(QuotaExceeded):
        ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 1, "k3")
    # Per-tenant entitlement override
    r = world.admin.put(
        f"{base}/billing/entitlements/overrides", json={"entitlements": {"limit.api_calls": 5}}
    )
    assert r.status_code == 200 and r.json()["limits"] == {"api_calls": 5}
    ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 1, "k4")
    # An explicit usage quota beats the plan.
    world.admin.put(f"{base}/usage/quotas/api_calls", json={"limit": None}).raise_for_status()
    ax.usage.check_and_record(SYSTEM, pid, tid, "api_calls", 50, "k5")
    world.admin.delete(f"{base}/usage/quotas/api_calls").raise_for_status()
    # Library call (trusted) gives the same result.
    assert ax.billing.entitlements(pid, tid).limits == {"api_calls": 5.0}
    # Canceled: the plan no longer applies; overrides still do.
    world.admin.put(f"{base}/billing/entitlements/overrides", json={"entitlements": {}}).raise_for_status()
    world.admin.post(f"{base}/billing/subscription/cancel", json={"at_period_end": False}).raise_for_status()
    assert world.admin.get(f"{base}/billing/entitlements").json()["plan_key"] is None
    assert world.admin.get(f"{base}/usage/quotas").json()[0]["source"] == "meter"


def test_usage_billing_period_follows_subscription_anchor(ax, world):
    pid = _product(world)
    tid = _tenant(world, pid)
    world.admin.post(
        f"/v1/products/{pid}/usage/meters", json={"key": "api_calls", "reset_period": "billing_period"}
    ).raise_for_status()
    _plan(world, pid, "free")
    t0 = datetime(2026, 1, 31, 10, 0, tzinfo=UTC)
    ax.billing.clock = lambda: t0
    ax.billing.create_subscription(SYSTEM, pid, tid, plan="free")
    now = datetime(2026, 3, 2, tzinfo=UTC)
    ax.usage.clock = lambda: now
    ax.usage.record(SYSTEM, pid, tid, "api_calls", 4, "a", occurred_at=datetime(2026, 2, 27, tzinfo=UTC))
    ax.usage.record(SYSTEM, pid, tid, "api_calls", 1, "b", occurred_at=datetime(2026, 3, 1, tzinfo=UTC))
    feb = ax.usage.summary(SYSTEM, pid, tid, at=datetime(2026, 2, 27, tzinfo=UTC))[0]
    assert feb.period_start == t0 and feb.period_end == datetime(2026, 2, 28, 10, 0, tzinfo=UTC)
    assert feb.value == 4
    cur = ax.usage.summary(SYSTEM, pid, tid)[0]
    assert cur.period_start == datetime(2026, 2, 28, 10, 0, tzinfo=UTC) and cur.value == 1


def test_billing_permissions_and_isolation(world):
    pid = _product(world)
    t1, t2 = _tenant(world, pid, "acme"), _tenant(world, pid, "globex")
    _plan(world, pid, "free", entitlements={"feature.a": True})
    world.admin.post(
        f"/v1/products/{pid}/tenants/{t1}/billing/subscription", json={"plan": "free"}
    ).raise_for_status()
    viewer = _member(world, pid, t1, "v@example.com", role="viewer")
    b1 = f"/v1/products/{pid}/tenants/{t1}/billing"
    b2 = f"/v1/products/{pid}/tenants/{t2}/billing"
    assert viewer.get(b1 + "/subscription").status_code == 200
    assert viewer.get(b1 + "/entitlements").json()["features"] == {"a": True}
    assert viewer.post(b1 + "/subscription/cancel").status_code == 403
    assert (
        viewer.post(
            b1 + "/checkout", json={"plan": "free", "success_url": "x", "cancel_url": "y"}
        ).status_code
        == 403
    )
    assert viewer.put(b1 + "/entitlements/overrides", json={"entitlements": {}}).status_code == 403
    assert viewer.get(b2 + "/subscription").status_code == 404
    assert viewer.get(b2 + "/entitlements").status_code == 404
    assert viewer.get(f"/v1/products/{pid}/billing/subscriptions").status_code == 403
    assert viewer.post(f"/v1/products/{pid}/billing/plans", json={"key": "x", "name": "x"}).status_code == 403
    subs = world.admin.get(f"/v1/products/{pid}/billing/subscriptions").json()
    assert [s["tenant_id"] for s in subs["items"]] == [t1]
    pid2 = _product(world, "erp")
    assert (
        world.admin.post(
            f"/v1/products/{pid2}/tenants/{t1}/billing/subscription", json={"plan": "free"}
        ).status_code
        == 404
    )
    t3 = _tenant(world, pid2, "initech")
    # Plans of another product are invisible.
    assert (
        world.admin.post(
            f"/v1/products/{pid2}/tenants/{t3}/billing/subscription", json={"plan": "free"}
        ).status_code
        == 404
    )


def test_manual_provider_has_no_webhooks_and_checkout_completes_locally(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _plan(world, pid, prices=PRO_PRICES)
    assert world.browser().post("/v1/billing/webhooks/manual", content=b"{}").status_code == 404
    assert world.browser().post("/v1/billing/webhooks/stripe", content=b"{}").status_code == 404
    r = world.admin.post(
        f"/v1/products/{pid}/tenants/{tid}/billing/checkout",
        json={"plan": "pro", "success_url": "http://studio.test/ok", "cancel_url": "http://studio.test/no"},
    )
    assert r.status_code == 201, r.text
    assert (
        r.json()["completed"] is True
        and r.json()["url"] is None
        and r.json()["subscription"]["status"] == "active"
    )


# -- fake provider: checkout + signed webhooks ---------------------------------------------------


def _hook(client: TestClient, body: bytes, headers: dict[str, str]):
    return client.post("/v1/billing/webhooks/fake", content=body, headers=headers)


def test_fake_checkout_and_webhooks(fake_world):
    w = fake_world
    fake = w.ax.billing.provider
    pid = _product(w)
    tid = _tenant(w, pid)
    t_other = _tenant(w, pid, "globex")
    _plan(w, pid, prices=PRO_PRICES, entitlements={"limit.api_calls": 1000})
    base = f"/v1/products/{pid}/tenants/{tid}/billing"
    urls = {"success_url": "http://studio.test/ok", "cancel_url": "http://studio.test/cancel"}
    assert (
        w.admin.post(
            base + "/checkout",
            json={"plan": "pro", "success_url": "https://evil.example/x", "cancel_url": urls["cancel_url"]},
        ).status_code
        == 422
    )
    # Paid plans cannot be subscribed directly with a real provider.
    assert w.admin.post(base + "/subscription", json={"plan": "pro"}).status_code == 409
    r = w.admin.post(base + "/checkout", json={"plan": "pro", **urls})
    assert r.status_code == 201, r.text
    co = r.json()
    assert co["completed"] is False and co["url"].startswith("https://checkout.fake.invalid/")
    assert co["subscription"]["status"] == "incomplete"
    assert w.admin.get(base + "/entitlements").json()["plan_key"] is None  # not entitled yet

    anon = TestClient(w.app)
    # Invalid signature, wrong secret, expired timestamp, missing header.
    body, headers = fake.complete_checkout(co["checkout_id"])
    assert _hook(anon, body, {"Stripe-Signature": headers["Stripe-Signature"][:-2] + "00"}).status_code == 400
    assert _hook(anon, body, {}).status_code == 400
    b2, h2 = fake.signed_event("checkout.session.completed", {"id": co["checkout_id"]}, secret="wrong")
    assert _hook(anon, b2, h2).status_code == 400
    old = int(datetime.now(UTC).timestamp()) - 301
    b3, h3 = fake.signed_event("checkout.session.completed", {"id": co["checkout_id"]}, signed_at=old)
    r = _hook(anon, b3, h3)
    assert r.status_code == 400 and r.json()["code"] == "invalid_signature"
    assert w.admin.get(base + "/subscription").json()["status"] == "incomplete"
    # Valid event activates; replay is a no-op.
    r = _hook(anon, body, headers)
    assert r.status_code == 200 and r.json()["outcome"] == "applied", r.text
    sub = w.admin.get(base + "/subscription").json()
    assert sub["status"] == "active" and sub["provider_subscription_id"].startswith("sub_fake_")
    assert _hook(anon, body, headers).json()["outcome"] == "duplicate"
    assert w.admin.get(base + "/entitlements").json()["limits"] == {"api_calls": 1000}
    psub = sub["provider_subscription_id"]

    # Out-of-order: the newer event wins, an older one arriving later is ignored.
    now = int(datetime.now(UTC).timestamp())
    newer, nh = fake.signed_event(
        "customer.subscription.updated", {"id": psub, "status": "past_due"}, created=now + 10
    )
    older, oh = fake.signed_event(
        "customer.subscription.updated", {"id": psub, "status": "active"}, created=now + 5
    )
    assert _hook(anon, newer, nh).json()["outcome"] == "applied"
    assert _hook(anon, older, oh).json()["outcome"] == "stale"
    assert w.admin.get(base + "/subscription").json()["status"] == "past_due"
    paid, ph = fake.signed_event("invoice.paid", {"subscription": psub}, created=now + 20)
    assert _hook(anon, paid, ph).json()["outcome"] == "applied"
    assert w.admin.get(base + "/subscription").json()["status"] == "active"

    # Metadata never redirects an event to another tenant: resolution uses stored provider ids.
    sneaky, sh = fake.signed_event(
        "customer.subscription.updated",
        {
            "id": "sub_unknown_1",
            "status": "active",
            "metadata": {"axentra_tenant_id": t_other, "axentra_product_id": pid},
        },
        created=now + 21,
    )
    assert _hook(anon, sneaky, sh).json()["outcome"] == "unmatched"
    assert w.admin.get(f"/v1/products/{pid}/tenants/{t_other}/billing/subscription").status_code == 404
    other, oth = fake.signed_event("customer.created", {"id": "cus_1"})
    assert _hook(anon, other, oth).json()["outcome"] == "ignored"

    # Cancel goes to the provider; the deletion webhook finalizes. Then no transition back.
    r = w.admin.post(base + "/subscription/cancel", json={"at_period_end": True})
    assert r.json()["cancel_at_period_end"] is True
    assert ("cancel", {"id": psub, "at_period_end": True}) in fake.calls
    gone, gh = fake.signed_event(
        "customer.subscription.deleted", {"id": psub, "status": "canceled"}, created=now + 30
    )
    assert _hook(anon, gone, gh).json()["outcome"] == "applied"
    assert w.admin.get(base + "/subscription").json()["status"] == "canceled"
    back, bh = fake.signed_event(
        "customer.subscription.updated", {"id": psub, "status": "active"}, created=now + 40
    )
    assert _hook(anon, back, bh).json()["outcome"] == "rejected_transition"
    assert w.admin.get(base + "/subscription").json()["status"] == "canceled"
    assert w.admin.get(base + "/entitlements").json()["plan_key"] is None
    # Webhook-driven changes are audited as a system actor.
    events = w.admin.get(f"/v1/audit?product_id={pid}&action=billing.subscription.webhook").json()["items"]
    assert events and events[0]["actor_id"] == "billing-webhook:fake"
    # The fake provider's route answers; the stripe route does not exist with this configuration.
    assert _hook(anon, b"x" * 10, {}).status_code == 400
    assert anon.post("/v1/billing/webhooks/stripe", content=body, headers=headers).status_code == 404


def test_fake_trial_checkout_and_subscription_event_before_checkout(fake_world):
    w = fake_world
    fake = w.ax.billing.provider
    pid = _product(w)
    tid = _tenant(w, pid)
    _plan(w, pid, prices=PRO_PRICES, trial_days=14)
    base = f"/v1/products/{pid}/tenants/{tid}/billing"
    co = w.admin.post(
        base + "/checkout",
        json={"plan": "pro", "success_url": "http://studio.test/", "cancel_url": "http://studio.test/"},
    ).json()
    customer = co["subscription"]["provider_customer_id"]
    assert customer
    now = int(datetime.now(UTC).timestamp())
    start, end = now, int((datetime.now(UTC) + timedelta(days=14)).timestamp())
    # customer.subscription.created arrives before checkout.session.completed: matched by our customer id.
    body, h = fake.signed_event(
        "customer.subscription.created",
        {
            "id": "sub_fake_000001",
            "customer": customer,
            "status": "trialing",
            "current_period_start": start,
            "current_period_end": end,
            "trial_end": end,
            "items": {"data": [{"price": {"id": "price_pro"}}]},
        },
        created=now,
    )
    anon = TestClient(w.app)
    r = anon.post("/v1/billing/webhooks/fake", content=body, headers=h)
    assert r.json()["outcome"] == "applied", r.text
    sub = w.admin.get(base + "/subscription").json()
    assert sub["status"] == "trialing" and sub["provider_subscription_id"] == "sub_fake_000001"
    body, h = fake.complete_checkout(co["checkout_id"], created=now + 1)
    assert anon.post("/v1/billing/webhooks/fake", content=body, headers=h).json()["outcome"] == "applied"
    assert w.admin.get(base + "/subscription").json()["status"] == "trialing"
    # Replay with the same event id but tampered body is rejected by the signature.
    tampered = json.loads(body)
    tampered["data"]["object"]["subscription"] = "sub_other"
    raw = json.dumps(tampered).encode()
    assert anon.post("/v1/billing/webhooks/fake", content=raw, headers=h).status_code == 400
