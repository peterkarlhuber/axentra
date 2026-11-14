# ruff: noqa: S106
"""MOCK - NOT A LIVE STRIPE TEST. Request-shape check of Axentra's StripeProvider against stripe-mock.

stripe/stripe-mock validates requests against Stripe's OpenAPI specification and answers with fixture
data. It moves no money, keeps no state, sends no webhooks and does not check keys beyond the
``sk_test_`` prefix. Passing here means only: the form parameters Axentra sends to /v1/customers,
/v1/checkout/sessions and /v1/subscriptions/{id} are accepted by the API specification, and Axentra
parses the answers. The Stripe webhook events below are SIMULATED (built and signed locally with a
synthetic secret); they exercise Axentra's webhook handling, not Stripe.

StripeProvider.API_BASE is a class constant (https://api.stripe.com, not configurable), so this check
runs the app in process and overrides the constant to a local recording proxy in front of stripe-mock.
The real Stripe test mode check is ``stripe_test_mode.sh`` (see STRIPE_TEST_MODE.md); it was not run.
"""

from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
import sys
import threading
import time
from urllib.parse import parse_qsl

import httpx
from lib import EVIDENCE, REPO, Api, Report, base_env, reset_database, scan_for_secrets

sys.path.insert(0, str(REPO / "src"))

PORT = int(os.environ.get("LC_STRIPE_AX_PORT", "19205"))
MOCK = os.environ.get("LC_STRIPE_MOCK_URL", "http://127.0.0.1:19111")
PROXY_PORT = int(os.environ.get("LC_STRIPE_PROXY_PORT", "19292"))
# Synthetic values for stripe-mock, split so that secret scanners do not report a key-shaped literal.
API_KEY = "sk_" + "test_" + "lcSyntheticMockKey000000000000"
WHSEC = "whsec_" + "lcSyntheticMockWebhookSecret0000"
RECORDED: list[dict] = []


class RecordingProxy(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        pass

    def _forward(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
        hdrs = {
            k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")
        }
        r = httpx.request(self.command, MOCK + self.path, content=body, headers=hdrs, timeout=30)
        RECORDED.append(
            {
                "method": self.command,
                "path": self.path,
                "idempotency_key": self.headers.get("Idempotency-Key"),
                "auth_scheme": (self.headers.get("Authorization") or "").split(" ")[0],
                "auth_is_test_key": (self.headers.get("Authorization") or "").startswith("Bearer sk_test_"),
                "form": parse_qsl(body.decode()),
                "mock_status": r.status_code,
                "mock_error": r.json().get("error", {}).get("message") if r.status_code >= 400 else None,
            }
        )
        self.send_response(r.status_code)
        out = r.content
        self.send_header("Content-Type", r.headers.get("content-type", "application/json"))
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_DELETE = _forward


def signed(event: dict) -> tuple[bytes, str]:
    body = json.dumps(event).encode()
    t = int(time.time())
    sig = hmac.new(WHSEC.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return body, f"t={t},v1={sig}"


def main() -> int:
    rep = Report("stripe-mock")
    rep.note(
        "MOCK: stripe/stripe-mock (OpenAPI request validation + fixtures). NOT a live Stripe test-mode run."
    )
    log = EVIDENCE / "stripe-mock-app.log"
    log.unlink(missing_ok=True)
    proxy = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), RecordingProxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    db = reset_database("lc_bill")
    env = base_env(
        db,
        PORT,
        AXENTRA__BILLING__PROVIDER="stripe",
        AXENTRA__BILLING__API_KEY_REF="env:LC_STRIPE_KEY",
        AXENTRA__BILLING__WEBHOOK_SECRET_REF="env:LC_STRIPE_WHSEC",
        LC_STRIPE_KEY=API_KEY,
        LC_STRIPE_WHSEC=WHSEC,
    )
    os.environ.update({k: v for k, v in env.items() if k.startswith(("AXENTRA__", "LC_STRIPE"))})

    import uvicorn

    from axentra.api.app import create_app
    from axentra.audit.logging import configure_logging
    from axentra.billing.providers import PaymentProviderNotConfigured, StripeProvider
    from axentra.config.settings import BillingSettings, load_settings
    from axentra.platform import Axentra

    StripeProvider.API_BASE = f"http://127.0.0.1:{PROXY_PORT}"  # MOCK ONLY: point the adapter at stripe-mock
    configure_logging("DEBUG", "json")
    fh = logging.FileHandler(log)
    fh.setFormatter(logging.getLogger().handlers[0].formatter)
    logging.getLogger().addHandler(fh)

    ax = Axentra.from_settings(load_settings(None))
    ax.migrate()
    app = create_app(axentra=ax)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning", access_log=False)
    )
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.2)
    try:
        token = ax.identity.create_setup_token()
        admin = Api(PORT)
        admin.csrf = admin.ok(
            "POST",
            "/v1/auth/setup",
            json={
                "setup_token": token,
                "email": "admin@lc.example.com",
                "name": "LC",
                "password": "lc synthetic admin password 1",
            },
        )["csrf_token"]
        pid = admin.ok("POST", "/v1/products", json={"slug": "lcbill", "name": "LC Bill"})["id"]
        t1 = admin.ok("POST", f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"})["id"]
        t2 = admin.ok("POST", f"/v1/products/{pid}/tenants", json={"slug": "globex", "name": "Globex"})["id"]
        admin.ok(
            "POST",
            f"/v1/products/{pid}/billing/plans",
            json={
                "key": "pro",
                "name": "Pro",
                "prices": [
                    {
                        "amount_minor": 1900,
                        "currency": "EUR",
                        "interval": "month",
                        "provider_price_id": "price_1LcSyntheticPro",
                    }
                ],
                "entitlements": {"feature.sso": True},
            },
        )
        base = f"http://127.0.0.1:{PORT}"
        co = {}
        for name, tid in (("acme", t1), ("globex", t2)):
            co[name] = admin.ok(
                "POST",
                f"/v1/products/{pid}/tenants/{tid}/billing/checkout",
                json={
                    "plan": "pro",
                    "success_url": f"{base}/billing/ok",
                    "cancel_url": f"{base}/billing/cancel",
                },
            )
        rep.save_json("checkout", co)
        rep.check(
            "checkout via stripe-mock -> 201, provider stripe, cs_ id, incomplete",
            all(
                c["provider"] == "stripe"
                and c["checkout_id"].startswith("cs_")
                and c["subscription"]["status"] == "incomplete"
                for c in co.values()
            ),
            {k: (v["checkout_id"], v["url"]) for k, v in co.items()},
        )
        cus = [r for r in RECORDED if r["path"] == "/v1/customers"]
        css = [r for r in RECORDED if r["path"] == "/v1/checkout/sessions"]
        rep.check(
            "POST /v1/customers accepted by the API spec (stripe-mock 200), with Idempotency-Key",
            cus
            and all(
                r["mock_status"] == 200 and (r["idempotency_key"] or "").startswith("axentra-cus-")
                for r in cus
            ),
            [(r["mock_status"], r["mock_error"]) for r in cus],
        )
        rep.check(
            "POST /v1/checkout/sessions accepted by the API spec (stripe-mock 200), with Idempotency-Key",
            css
            and all(
                r["mock_status"] == 200 and (r["idempotency_key"] or "").startswith("axentra-cs-")
                for r in css
            ),
            [(r["mock_status"], r["mock_error"]) for r in css],
        )
        form = dict(css[0]["form"]) if css else {}
        rep.check(
            "checkout session form: mode=subscription, price line item, client_reference_id, metadata",
            form.get("mode") == "subscription"
            and form.get("line_items[0][price]") == "price_1LcSyntheticPro"
            and form.get("line_items[0][quantity]") == "1"
            and form.get("client_reference_id", "").startswith("sub_")
            and "metadata[axentra_tenant_id]" in form
            and "subscription_data[metadata][axentra_subscription_id]" in form,
            sorted(form),
        )
        rep.check(
            "Authorization is Bearer with the sk_test_ key; key never in a response",
            all(r["auth_is_test_key"] for r in RECORDED) and API_KEY not in json.dumps(co),
        )

        # SIMULATED webhook events (signed locally), resolved via ids Axentra stored at checkout.
        sub_acme = co["acme"]["subscription"]
        cust = sub_acme.get("provider_customer_id") or ""
        W = f"{base}/v1/billing/webhooks/stripe"

        def post_event(ev: dict, sig: str | None = None) -> httpx.Response:
            body, s = signed(ev)
            return httpx.post(
                W,
                content=body,
                headers={"Stripe-Signature": sig or s, "Content-Type": "application/json"},
                timeout=30,
            )

        now = int(time.time())
        unpaid = {
            "id": "evt_lc_1",
            "type": "checkout.session.completed",
            "created": now,
            "data": {
                "object": {
                    "id": co["acme"]["checkout_id"],
                    "object": "checkout.session",
                    "customer": cust,
                    "subscription": "sub_lcSynthetic1",
                    "payment_status": "unpaid",
                    "mode": "subscription",
                }
            },
        }
        r = post_event(unpaid)
        st = admin.ok("GET", f"/v1/products/{pid}/tenants/{t1}/billing/subscription")
        rep.check(
            "simulated checkout.session.completed (unpaid, SEPA-like) -> applied, stays incomplete",
            r.json().get("outcome") == "applied" and st["status"] == "incomplete",
            (r.json(), st["status"]),
        )
        r = post_event(unpaid)
        rep.check("same event id again -> duplicate", r.json().get("outcome") == "duplicate", r.json())
        body, _ = signed(unpaid | {"id": "evt_lc_forged"})
        r = httpx.post(W, content=body, headers={"Stripe-Signature": f"t={now},v1={'0' * 64}"}, timeout=30)
        rep.check(
            "bad signature -> 400 invalid_signature",
            r.status_code == 400 and r.json().get("code") == "invalid_signature",
            r.status_code,
        )
        succ = {
            "id": "evt_lc_2",
            "type": "checkout.session.async_payment_succeeded",
            "created": now + 1,
            "data": {"object": unpaid["data"]["object"] | {"payment_status": "paid"}},
        }
        r = post_event(succ)
        st = admin.ok("GET", f"/v1/products/{pid}/tenants/{t1}/billing/subscription")
        ent = admin.ok("GET", f"/v1/products/{pid}/tenants/{t1}/billing/entitlements")
        rep.check(
            "simulated async_payment_succeeded -> active, entitled",
            st["status"] == "active" and ent["features"].get("sso") is True,
            (r.json(), st["status"], ent["features"]),
        )
        g = co["globex"]
        failed_ev = {
            "id": "evt_lc_3",
            "type": "checkout.session.async_payment_failed",
            "created": now,
            "data": {
                "object": {
                    "id": g["checkout_id"],
                    "object": "checkout.session",
                    "customer": g["subscription"].get("provider_customer_id"),
                    "subscription": "sub_lcSynthetic2",
                    "payment_status": "unpaid",
                }
            },
        }
        post_event(failed_ev | {"id": "evt_lc_3a", "type": "checkout.session.completed"})
        r = post_event(failed_ev)
        st2 = admin.ok("GET", f"/v1/products/{pid}/tenants/{t2}/billing/subscription")
        ent2 = admin.ok("GET", f"/v1/products/{pid}/tenants/{t2}/billing/entitlements")
        rep.check(
            "simulated async_payment_failed -> stays incomplete, not entitled",
            st2["status"] == "incomplete" and not ent2["features"].get("sso"),
            (r.json(), st2["status"]),
        )

        # Cancel / resume reach stripe-mock with a valid request shape.
        n = len(RECORDED)
        c = admin.ok(
            "POST",
            f"/v1/products/{pid}/tenants/{t1}/billing/subscription/cancel",
            json={"at_period_end": True},
        )
        rs = admin.ok("POST", f"/v1/products/{pid}/tenants/{t1}/billing/subscription/resume")
        calls = RECORDED[n:]
        rep.check(
            "cancel at period end + resume -> POST /v1/subscriptions/sub_lcSynthetic1 accepted by stripe-mock",
            [(x["path"], dict(x["form"]).get("cancel_at_period_end"), x["mock_status"]) for x in calls]
            == [
                ("/v1/subscriptions/sub_lcSynthetic1", "true", 200),
                ("/v1/subscriptions/sub_lcSynthetic1", "false", 200),
            ],
            [(x["path"], x["form"], x["mock_status"]) for x in calls],
        )
        rep.check(
            "local state follows: cancel_at_period_end true, then false",
            c["cancel_at_period_end"] is True and rs["cancel_at_period_end"] is False,
        )

        # Live key refused without live_payments (no request leaves the process).
        n = len(RECORDED)
        os.environ["LC_STRIPE_LIVE"] = "sk_" + "live_" + "lcSyntheticNeverReal0000"  # split: no key-shaped literal
        try:
            StripeProvider(
                BillingSettings(provider="stripe", api_key_ref="env:LC_STRIPE_LIVE")
            ).cancel_subscription("sub_x", at_period_end=True)
            refused = False
        except PaymentProviderNotConfigured as exc:
            refused = "live" in str(exc)
        rep.check(
            "sk_live_ key without billing.live_payments is refused before any request",
            refused and len(RECORDED) == n,
        )
        rep.save_json("recorded-requests", RECORDED)
    finally:
        server.should_exit = True
        time.sleep(1)
        proxy.shutdown()
        ax.close()
    hits = scan_for_secrets(log, {"api_key": API_KEY, "webhook_secret": WHSEC})
    rep.check("Stripe key / webhook secret not in the app log", not any(hits.values()), hits)
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
