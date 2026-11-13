from __future__ import annotations

from datetime import UTC, datetime
import time
from urllib.parse import parse_qs

import httpx
import pytest

from axentra.billing.models import PaymentProviderError, PaymentProviderNotConfigured, WebhookSignatureInvalid
from axentra.billing.providers import (
    CheckoutRequest,
    FakeProvider,
    StripeProvider,
    sign_payload,
    verify_signature,
)
from axentra.billing.state import TRANSITIONS, can_transition, check_transition
from axentra.config.settings import BillingSettings
from axentra.core.errors import Conflict
from axentra.usage.periods import EPOCH, add_months, anchored_period, period_for


def d(*a: int) -> datetime:
    return datetime(*a, tzinfo=UTC)


def test_periods():
    assert period_for("month", d(2026, 2, 14, 5)) == (d(2026, 2, 1), d(2026, 3, 1))
    assert period_for("day", d(2026, 2, 14, 5)) == (d(2026, 2, 14), d(2026, 2, 15))
    assert period_for("none", d(2026, 2, 14)) == (EPOCH, None)
    assert period_for("month", d(2026, 12, 31, 23)) == (d(2026, 12, 1), d(2027, 1, 1))
    assert add_months(d(2026, 1, 31), 1) == d(2026, 2, 28)
    assert add_months(d(2024, 1, 31), 1) == d(2024, 2, 29)
    anchor = d(2026, 1, 31, 10)
    assert anchored_period(anchor, d(2026, 2, 27)) == (d(2026, 1, 31, 10), d(2026, 2, 28, 10))
    assert anchored_period(anchor, d(2026, 2, 28, 10)) == (d(2026, 2, 28, 10), d(2026, 3, 31, 10))
    assert anchored_period(anchor, d(2026, 1, 1)) == (d(2025, 12, 31, 10), d(2026, 1, 31, 10))
    assert anchored_period(anchor, d(2027, 3, 1), months=12) == (d(2027, 1, 31, 10), d(2028, 1, 31, 10))
    with pytest.raises(ValueError):
        period_for("month", datetime(2026, 1, 1))  # naive


def test_state_machine():
    assert can_transition("incomplete", "active") and can_transition("past_due", "active")
    assert not can_transition("canceled", "active") and not can_transition("active", "trialing")
    assert not can_transition("active", "incomplete")
    assert all(can_transition(s, s) for s in TRANSITIONS)
    assert all("canceled" in TRANSITIONS[s] for s in TRANSITIONS if s != "canceled")
    with pytest.raises(Conflict):
        check_transition("canceled", "past_due")


def test_signature_scheme():
    body = b'{"id":"evt_1"}'
    now = int(time.time())
    header = sign_payload("whsec_x", body, now)
    assert verify_signature("whsec_x", body, header, now=now) == now
    assert verify_signature("whsec_x", body, f"v1=deadbeef,{header}", now=now + 300) == now
    for bad in (None, "", "t=1", "v1=abc", f"t={now},v1=00"):
        with pytest.raises(WebhookSignatureInvalid):
            verify_signature("whsec_x", body, bad, now=now)
    with pytest.raises(WebhookSignatureInvalid):
        verify_signature("whsec_x", body + b" ", header, now=now)
    with pytest.raises(WebhookSignatureInvalid):
        verify_signature("other", body, header, now=now)
    with pytest.raises(WebhookSignatureInvalid):
        verify_signature("whsec_x", body, header, now=now + 301)


def test_fake_provider_is_deterministic():
    a, b = FakeProvider("s"), FakeProvider("s")
    req = CheckoutRequest("sub_1", "prd_1", "ten_1", "pro", "price_1", 0, "https://x/", "https://x/")
    assert a.create_checkout(req) == b.create_checkout(req)
    assert a.create_checkout(req).checkout_id == "cs_fake_000002_sub_1"


def test_fake_provider_ids_survive_a_restart():
    # A new process starts counting at 1 again; the subscription id keeps the checkout id unique.
    first = FakeProvider("s").create_checkout(
        CheckoutRequest("sub_a", "prd_1", "ten_1", "pro", "price_1", 0, "https://x/", "https://x/")
    )
    after_restart = FakeProvider("s").create_checkout(
        CheckoutRequest("sub_b", "prd_1", "ten_1", "pro", "price_1", 0, "https://x/", "https://x/")
    )
    assert first.checkout_id != after_restart.checkout_id
    assert first.customer_id != after_restart.customer_id


REQ = CheckoutRequest(
    "sub_1", "prd_1", "ten_1", "pro", "price_123", 7, "https://app.test/ok", "https://app.test/no"
)


def _stripe(monkeypatch, key: str | None, **settings):
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/v1/customers":
            return httpx.Response(200, json={"id": "cus_123"})
        if request.url.path == "/v1/checkout/sessions":
            return httpx.Response(200, json={"id": "cs_test_1", "url": "https://checkout.stripe.com/c/1"})
        return httpx.Response(402, json={"error": {"type": "card_error", "message": "secret details"}})

    if key is not None:
        monkeypatch.setenv("TEST_STRIPE_KEY", key)
    cfg = BillingSettings(**{"provider": "stripe", "api_key_ref": "env:TEST_STRIPE_KEY", **settings})
    return StripeProvider(cfg, transport=httpx.MockTransport(handler)), calls


def test_stripe_refuses_without_configuration(monkeypatch):
    monkeypatch.delenv("TEST_STRIPE_KEY", raising=False)
    for settings in (
        BillingSettings(provider="manual", api_key_ref="env:TEST_STRIPE_KEY"),
        BillingSettings(provider="stripe"),
        BillingSettings(provider="stripe", api_key_ref="env:TEST_STRIPE_KEY"),  # does not resolve
    ):

        def never(request: httpx.Request) -> httpx.Response:
            raise AssertionError("no request may be sent")

        p = StripeProvider(settings, transport=httpx.MockTransport(never))
        with pytest.raises(PaymentProviderNotConfigured):
            p.create_checkout(REQ)
    p, calls = _stripe(monkeypatch, "pk_test_publishable")
    with pytest.raises(PaymentProviderNotConfigured):
        p.create_checkout(REQ)
    with pytest.raises(PaymentProviderNotConfigured):
        p.webhook_secret()
    assert calls == []


def test_stripe_live_key_guard(monkeypatch):
    p, calls = _stripe(monkeypatch, "sk_live_abc")
    with pytest.raises(PaymentProviderNotConfigured, match="live_payments"):
        p.create_checkout(REQ)
    assert calls == []
    p, calls = _stripe(monkeypatch, "sk_live_abc", live_payments=True)
    assert p.create_checkout(REQ).checkout_id == "cs_test_1"


def test_stripe_checkout_and_errors_over_mock_transport(monkeypatch):
    p, calls = _stripe(monkeypatch, "sk_test_abc")
    result = p.create_checkout(REQ)
    assert result.checkout_id == "cs_test_1" and result.customer_id == "cus_123"
    assert result.url == "https://checkout.stripe.com/c/1" and result.completed is False
    assert [c.url.host for c in calls] == ["api.stripe.com", "api.stripe.com"]
    assert calls[1].headers["authorization"] == "Bearer sk_test_abc" and calls[1].headers["idempotency-key"]
    form = parse_qs(calls[1].content.decode())
    assert form["mode"] == ["subscription"] and form["line_items[0][price]"] == ["price_123"]
    assert form["subscription_data[trial_period_days]"] == ["7"]
    assert form["client_reference_id"] == ["sub_1"] and form["customer"] == ["cus_123"]
    with pytest.raises(PaymentProviderError) as exc:
        p.cancel_subscription("sub_123", at_period_end=False)
    assert "sk_test" not in str(exc.value) and "secret details" not in str(exc.value)
    assert calls[-1].method == "DELETE" and calls[-1].url.path == "/v1/subscriptions/sub_123"
    with pytest.raises(PaymentProviderError):
        p.cancel_subscription("../evil", at_period_end=True)
