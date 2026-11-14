"""Payment provider adapters behind one protocol.

Axentra performs NO payment processing and stores NO card data: a provider's hosted checkout
collects payment details; Axentra keeps only provider ids (customer, subscription, checkout) and
the subscription state reported by signed webhooks.

- :class:`ManualProvider`: the operator sets subscription states; no money moves.
- :class:`FakeProvider`: deterministic in-process test double that simulates hosted checkout and
  signs webhook events with the Stripe signature scheme and its own secret.
- :class:`StripeProvider`: talks to the Stripe REST API over HTTPS (httpx). It refuses to run
  unless ``billing.provider = "stripe"``, ``billing.api_key_ref`` resolves to a Stripe secret key
  and, for live keys (``sk_live_``/``rk_live_``), ``billing.live_payments = true``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import contextlib
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import itertools
import json
import re
from typing import TYPE_CHECKING, Any, Protocol

from axentra.billing.models import (
    PaymentProviderError,
    PaymentProviderNotConfigured,
    WebhookSignatureInvalid,
)
from axentra.config.secrets import resolve_secret
from axentra.config.settings import BillingSettings
from axentra.core.clock import utcnow
from axentra.core.errors import ConfigurationError
from axentra.core.ids import new_token

if TYPE_CHECKING:
    import httpx

SIGNATURE_TOLERANCE_SECONDS = 300
_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_]{1,255}$")


# -- signatures (Stripe scheme: "Stripe-Signature: t=<unix>,v1=<hex hmac-sha256(secret, f'{t}.{body}')>") --


def sign_payload(secret: str, payload: bytes, timestamp: int) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify_signature(
    secret: str,
    payload: bytes,
    header: str | None,
    *,
    now: int,
    tolerance: int = SIGNATURE_TOLERANCE_SECONDS,
) -> int:
    """Check a ``Stripe-Signature`` header; returns its timestamp or raises :class:`WebhookSignatureInvalid`."""
    if not header or len(header) > 4096:
        raise WebhookSignatureInvalid("missing signature header")
    timestamp: int | None = None
    candidates: list[str] = []
    for part in header.split(","):
        key, sep, value = part.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                raise WebhookSignatureInvalid("malformed signature header") from None
        elif key == "v1":
            candidates.append(value)
    if timestamp is None or not candidates:
        raise WebhookSignatureInvalid("malformed signature header")
    if abs(now - timestamp) > tolerance:
        raise WebhookSignatureInvalid("signature timestamp outside the tolerance window")
    expected = sign_payload(secret, payload, timestamp).split("v1=", 1)[1]
    if not any(hmac.compare_digest(expected, c) for c in candidates):
        raise WebhookSignatureInvalid("signature mismatch")
    return timestamp


def check_provider_id(value: Any, what: str = "provider id") -> str:
    if not isinstance(value, str) or not _PROVIDER_ID.match(value):
        raise PaymentProviderError(f"invalid {what}")
    return value


# -- protocol ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CheckoutRequest:
    subscription_id: str
    product_id: str
    tenant_id: str
    plan_key: str
    provider_price_id: str | None
    trial_days: int
    success_url: str
    cancel_url: str
    customer_id: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderCheckout:
    checkout_id: str | None
    url: str | None
    customer_id: str | None
    completed: bool


class PaymentProvider(Protocol):
    name: str

    def create_checkout(self, request: CheckoutRequest) -> ProviderCheckout: ...

    def cancel_subscription(self, provider_subscription_id: str, *, at_period_end: bool) -> None: ...

    def resume_subscription(self, provider_subscription_id: str) -> None: ...

    def webhook_secret(self) -> str | None:
        """The webhook signing secret, or ``None`` if the provider sends no webhooks."""
        ...


class ManualProvider:
    """Operator-managed subscriptions: checkout completes locally, nothing is charged."""

    name = "manual"

    def create_checkout(self, request: CheckoutRequest) -> ProviderCheckout:
        return ProviderCheckout(checkout_id=None, url=None, customer_id=None, completed=True)

    def cancel_subscription(self, provider_subscription_id: str, *, at_period_end: bool) -> None:
        return None

    def resume_subscription(self, provider_subscription_id: str) -> None:
        return None

    def webhook_secret(self) -> str | None:
        return None


class FakeProvider:
    """Deterministic test double of a Stripe-like provider.

    Ids count up per instance and carry the subscription id of the request, so they stay unique across
    process restarts (the database requires a unique checkout id per subscription)."""

    name = "fake"

    def __init__(self, secret: str | None = None, *, clock: Callable[[], datetime] = utcnow) -> None:
        self._secret = secret or new_token()
        self._clock = clock
        self._seq = itertools.count(1)
        self._event_seq = itertools.count(1)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.checkouts: dict[str, CheckoutRequest] = {}

    def create_checkout(self, request: CheckoutRequest) -> ProviderCheckout:
        suffix = f"{next(self._seq):06d}_{request.subscription_id}"
        checkout_id = f"cs_fake_{suffix}"
        customer = request.customer_id or f"cus_fake_{suffix}"
        self.checkouts[checkout_id] = request
        self.calls.append(("create_checkout", {"checkout_id": checkout_id, "plan": request.plan_key}))
        return ProviderCheckout(
            checkout_id=checkout_id,
            url=f"https://checkout.fake.invalid/{checkout_id}",
            customer_id=customer,
            completed=False,
        )

    def cancel_subscription(self, provider_subscription_id: str, *, at_period_end: bool) -> None:
        self.calls.append(("cancel", {"id": provider_subscription_id, "at_period_end": at_period_end}))

    def resume_subscription(self, provider_subscription_id: str) -> None:
        self.calls.append(("resume", {"id": provider_subscription_id}))

    def webhook_secret(self) -> str | None:
        return self._secret

    # -- simulation helpers (tests, local development) --

    def signed_event(
        self,
        event_type: str,
        obj: Mapping[str, Any],
        *,
        event_id: str | None = None,
        created: int | None = None,
        signed_at: int | None = None,
        secret: str | None = None,
    ) -> tuple[bytes, dict[str, str]]:
        """A webhook body and its ``Stripe-Signature`` header, as the provider would send them."""
        now = int(self._clock().timestamp())
        body = json.dumps(
            {
                "id": event_id or f"evt_fake_{next(self._event_seq):06d}",
                "object": "event",
                "type": event_type,
                "created": now if created is None else created,
                "data": {"object": dict(obj)},
            },
            separators=(",", ":"),
        ).encode()
        header = sign_payload(secret or self._secret, body, now if signed_at is None else signed_at)
        return body, {"Stripe-Signature": header, "Content-Type": "application/json"}

    def _checkout_session(self, checkout_id: str, payment_status: str) -> dict[str, Any]:
        req = self.checkouts[checkout_id]
        n = checkout_id.removeprefix("cs_fake_")
        return {
            "id": checkout_id,
            "object": "checkout.session",
            "customer": req.customer_id or f"cus_fake_{n}",
            "subscription": f"sub_fake_{n}",
            "client_reference_id": req.subscription_id,
            "payment_status": payment_status,
        }

    def complete_checkout(
        self, checkout_id: str, *, payment_status: str = "paid", **kw: Any
    ) -> tuple[bytes, dict[str, str]]:
        """``checkout.session.completed`` for a checkout created by this instance (``payment_status``
        ``unpaid`` simulates a delayed payment method such as SEPA debit)."""
        obj = self._checkout_session(checkout_id, payment_status)
        return self.signed_event("checkout.session.completed", obj, **kw)

    def settle_checkout(
        self, checkout_id: str, *, succeeded: bool, **kw: Any
    ) -> tuple[bytes, dict[str, str]]:
        """``checkout.session.async_payment_succeeded`` or ``_failed``: the outcome of a delayed payment."""
        if succeeded:
            obj = self._checkout_session(checkout_id, "paid")
            return self.signed_event("checkout.session.async_payment_succeeded", obj, **kw)
        obj = self._checkout_session(checkout_id, "unpaid")
        return self.signed_event("checkout.session.async_payment_failed", obj, **kw)


def _form(data: Mapping[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Stripe's form encoding: nested ``a[b][0][c]=v``."""
    out: list[tuple[str, str]] = []
    for key, value in data.items():
        name = f"{prefix}[{key}]" if prefix else str(key)
        if value is None:
            continue
        if isinstance(value, Mapping):
            out += _form(value, name)
        elif isinstance(value, list | tuple):
            for i, item in enumerate(value):
                if isinstance(item, Mapping):
                    out += _form(item, f"{name}[{i}]")
                else:
                    out.append((f"{name}[{i}]", str(item)))
        elif isinstance(value, bool):
            out.append((name, "true" if value else "false"))
        else:
            out.append((name, str(value)))
    return out


class StripeProvider:
    """Stripe REST adapter. Never called in tests except through ``httpx.MockTransport``."""

    name = "stripe"
    API_BASE = "https://api.stripe.com"

    def __init__(
        self,
        settings: BillingSettings,
        *,
        transport: httpx.BaseTransport | None = None,
        resolve: Callable[[str], str] = resolve_secret,
        timeout: float = 15.0,
    ) -> None:
        self.settings = settings
        self._transport = transport
        self._resolve = resolve
        self._timeout = timeout

    def _api_key(self) -> str:
        if self.settings.provider != "stripe":
            raise PaymentProviderNotConfigured("billing.provider is not 'stripe'")
        if not self.settings.api_key_ref:
            raise PaymentProviderNotConfigured("billing.api_key_ref is not set")
        try:
            key = self._resolve(self.settings.api_key_ref)
        except ConfigurationError:
            raise PaymentProviderNotConfigured("billing.api_key_ref does not resolve") from None
        if not key.startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_")):
            raise PaymentProviderNotConfigured("billing.api_key_ref is not a Stripe secret key")
        if key.startswith(("sk_live_", "rk_live_")) and not self.settings.live_payments:
            raise PaymentProviderNotConfigured(
                "refusing to use a live Stripe key: set billing.live_payments = true to accept real payments"
            )
        return key

    def _request(
        self,
        method: str,
        path: str,
        data: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        key = self._api_key()
        import httpx

        headers = {"Authorization": f"Bearer {key}"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            with httpx.Client(
                base_url=self.API_BASE, transport=self._transport, timeout=self._timeout
            ) as client:
                resp = client.request(method, path, data=dict(_form(data or {})) or None, headers=headers)
        except httpx.HTTPError as exc:
            raise PaymentProviderError(f"Stripe request failed: {type(exc).__name__}") from None
        if resp.status_code >= 400:
            kind = ""
            with contextlib.suppress(ValueError, AttributeError):
                kind = str(resp.json().get("error", {}).get("type", ""))[:80]
            raise PaymentProviderError(f"Stripe returned HTTP {resp.status_code} {kind}".strip())
        try:
            body = resp.json()
        except ValueError:
            raise PaymentProviderError("Stripe returned an invalid response") from None
        if not isinstance(body, dict):
            raise PaymentProviderError("Stripe returned an invalid response")
        return body

    def create_checkout(self, request: CheckoutRequest) -> ProviderCheckout:
        if not request.provider_price_id:
            raise PaymentProviderNotConfigured("the price has no provider_price_id (the Stripe price id)")
        meta = {
            "axentra_subscription_id": request.subscription_id,
            "axentra_product_id": request.product_id,
            "axentra_tenant_id": request.tenant_id,
        }
        customer = request.customer_id
        if customer is None:
            created = self._request(
                "POST",
                "/v1/customers",
                {"metadata": meta},
                idempotency_key=f"axentra-cus-{request.subscription_id}",
            )
            customer = check_provider_id(created.get("id"), "customer id")
        payload: dict[str, Any] = {
            "mode": "subscription",
            "customer": customer,
            "line_items": [{"price": request.provider_price_id, "quantity": 1}],
            "success_url": request.success_url,
            "cancel_url": request.cancel_url,
            "client_reference_id": request.subscription_id,
            "metadata": meta,
            "subscription_data": {"metadata": meta},
        }
        if request.trial_days:
            payload["subscription_data"]["trial_period_days"] = request.trial_days
        session = self._request(
            "POST",
            "/v1/checkout/sessions",
            payload,
            idempotency_key=f"axentra-cs-{request.subscription_id}-{request.provider_price_id}",
        )
        url = session.get("url")
        return ProviderCheckout(
            checkout_id=check_provider_id(session.get("id"), "checkout id"),
            url=url if isinstance(url, str) and url.startswith("https://") else None,
            customer_id=customer,
            completed=False,
        )

    def cancel_subscription(self, provider_subscription_id: str, *, at_period_end: bool) -> None:
        sid = check_provider_id(provider_subscription_id, "subscription id")
        if at_period_end:
            self._request("POST", f"/v1/subscriptions/{sid}", {"cancel_at_period_end": True})
        else:
            self._request("DELETE", f"/v1/subscriptions/{sid}")

    def resume_subscription(self, provider_subscription_id: str) -> None:
        sid = check_provider_id(provider_subscription_id, "subscription id")
        self._request("POST", f"/v1/subscriptions/{sid}", {"cancel_at_period_end": False})

    def webhook_secret(self) -> str | None:
        if not self.settings.webhook_secret_ref:
            raise PaymentProviderNotConfigured("billing.webhook_secret_ref is not set")
        try:
            return self._resolve(self.settings.webhook_secret_ref)
        except ConfigurationError:
            raise PaymentProviderNotConfigured("billing.webhook_secret_ref does not resolve") from None


def build_provider(settings: BillingSettings, *, clock: Callable[[], datetime] = utcnow) -> PaymentProvider:
    if settings.provider == "stripe":
        return StripeProvider(settings)
    if settings.provider == "fake":
        secret = resolve_secret(settings.webhook_secret_ref) if settings.webhook_secret_ref else None
        return FakeProvider(secret, clock=clock)
    return ManualProvider()
