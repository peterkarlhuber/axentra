# ruff: noqa: S106, S603, S607
"""Stripe TEST MODE end-to-end run (needs real Stripe test keys; never live keys). See STRIPE_TEST_MODE.md.

NOT RUN by the harness author: no Stripe test account was available. Run it yourself:

    export STRIPE_TEST_SECRET_KEY=sk_test_...          # Dashboard > Developers > API keys (test mode)
    python scripts/live-integration/stripe_test_mode.py [--price price_...] [--skip-browser]

What it does:
1. refuses anything but an ``sk_test_``/``rk_test_`` key;
2. creates (or reuses ``--price``) a monthly EUR test price in YOUR Stripe test account;
3. gets the webhook signing secret from ``stripe listen --print-secret`` and starts
   ``stripe listen --forward-to`` towards a local ``axentra serve`` (provider ``stripe``);
4. creates two Axentra checkouts (tenant "sepa-ok", tenant "sepa-fail") and prints their Checkout URLs;
5. you pay them in a browser with the SEPA test IBANs (succeeds: DE89370400440532013000,
   fails: DE62370400440532013001); the script waits for
   checkout.session.completed (payment_status=unpaid -> Axentra keeps the subscription incomplete) and then
   checkout.session.async_payment_succeeded (-> active) / _failed (-> stays incomplete);
6. ``stripe trigger`` smoke tests for the async events (these create their own sessions, which Axentra
   must answer with outcome ``unmatched``: proves forwarding + signature, not the mapping);
7. cancels the created test subscriptions in Stripe and writes evidence to $LC_EVIDENCE (default ./evidence).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

import httpx
from lib import EVIDENCE, Report, base_env, bootstrap_admin, product_and_tenant, reset_database, serve

PORT = int(os.environ.get("LC_STRIPE_TEST_AX_PORT", "19206"))
LISTEN_EVENTS = ",".join(
    [
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
        "checkout.session.async_payment_failed",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
        "invoice.payment_succeeded",
        "invoice.payment_failed",
    ]
)


def stripe_api(key: str, method: str, path: str, data: dict | None = None) -> dict:
    r = httpx.request(method, f"https://api.stripe.com{path}", data=data, auth=(key, ""), timeout=30)
    r.raise_for_status()
    return r.json()


def wait_status(admin, pid: str, tid: str, want: set[str], timeout: float) -> dict:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while True:
        sub = admin.ok("GET", f"/v1/products/{pid}/tenants/{tid}/billing/subscription")
        if sub["status"] in want or time.monotonic() > deadline:
            return sub
        time.sleep(5)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--price", help="existing test-mode price id (EUR, monthly); default: create one")
    ap.add_argument("--skip-browser", action="store_true", help="only the stripe trigger smoke test")
    ap.add_argument(
        "--wait-minutes", type=float, default=15, help="how long to wait for the async SEPA outcome"
    )
    args = ap.parse_args()

    key = os.environ.get("STRIPE_TEST_SECRET_KEY", "")
    if not key.startswith(("sk_test_", "rk_test_")):
        print(
            "STRIPE_TEST_SECRET_KEY must be a Stripe TEST key (sk_test_/rk_test_). Live keys are refused.",
            file=sys.stderr,
        )
        return 2
    if not shutil.which("stripe"):
        print("the Stripe CLI (`stripe`) is required: https://docs.stripe.com/stripe-cli", file=sys.stderr)
        return 2

    rep = Report("stripe-test-mode")
    rep.note("LIVE Stripe TEST MODE run (real Stripe API, test keys, no real money)")
    price = args.price
    if not price:
        prod = stripe_api(
            key,
            "POST",
            "/v1/products",
            {"name": "Axentra LC test plan", "metadata[lc]": "axentra-live-integration"},
        )
        price = stripe_api(
            key,
            "POST",
            "/v1/prices",
            {"product": prod["id"], "currency": "eur", "unit_amount": "1900", "recurring[interval]": "month"},
        )["id"]
    rep.note(f"price {price}")

    whsec = subprocess.run(
        ["stripe", "listen", "--api-key", key, "--print-secret"], capture_output=True, text=True, check=True
    ).stdout.strip()
    listen_log = EVIDENCE / "stripe-test-mode-listen.log"
    listen = subprocess.Popen(
        [
            "stripe",
            "listen",
            "--api-key",
            key,
            "--events",
            LISTEN_EVENTS,
            "--forward-to",
            f"http://127.0.0.1:{PORT}/v1/billing/webhooks/stripe",
        ],
        stdout=listen_log.open("ab"),
        stderr=subprocess.STDOUT,
    )
    created_subs: list[str] = []
    try:
        db = reset_database("lc_stripe_test")
        env = base_env(
            db,
            PORT,
            AXENTRA__BILLING__PROVIDER="stripe",
            AXENTRA__BILLING__API_KEY_REF="env:STRIPE_TEST_SECRET_KEY",
            AXENTRA__BILLING__WEBHOOK_SECRET_REF="env:LC_STRIPE_WHSEC",
            STRIPE_TEST_SECRET_KEY=key,
            LC_STRIPE_WHSEC=whsec,
            AXENTRA__OBSERVABILITY__LOG_LEVEL="INFO",
        )
        log = EVIDENCE / "stripe-test-mode-serve.log"
        with serve(env, PORT, log):
            admin = bootstrap_admin(env, PORT, log)
            pid, t_ok = product_and_tenant(admin, "lcstripe", "sepa-ok")
            t_fail = admin.ok(
                "POST", f"/v1/products/{pid}/tenants", json={"slug": "sepa-fail", "name": "Sepa Fail"}
            )["id"]
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
                            "provider_price_id": price,
                        }
                    ],
                    "entitlements": {"feature.sso": True},
                },
            )
            base = f"http://127.0.0.1:{PORT}"
            co = {
                name: admin.ok(
                    "POST",
                    f"/v1/products/{pid}/tenants/{tid}/billing/checkout",
                    json={
                        "plan": "pro",
                        "success_url": f"{base}/billing/ok",
                        "cancel_url": f"{base}/billing/cancel",
                    },
                )
                for name, tid in (("sepa-ok", t_ok), ("sepa-fail", t_fail))
            }
            rep.save_json("checkouts", co)
            rep.check(
                "Axentra created real test-mode Checkout Sessions",
                all(
                    c["checkout_id"].startswith("cs_test_")
                    and (c["url"] or "").startswith("https://checkout.stripe.com/")
                    for c in co.values()
                ),
                {k: v["checkout_id"] for k, v in co.items()},
            )

            if not args.skip_browser:
                print("\nOpen in a browser and pay with SEPA Direct Debit (synthetic name/email):")
                print(f"  sepa-ok   IBAN DE89370400440532013000  {co['sepa-ok']['url']}")
                print(f"  sepa-fail IBAN DE62370400440532013001  {co['sepa-fail']['url']}")
                print(
                    "(SEPA Direct Debit must be enabled for test mode in Dashboard > Settings > Payment methods.)\n"
                )
                input("Press Enter after both checkouts were submitted... ")
                time.sleep(10)
                for name, tid in (("sepa-ok", t_ok), ("sepa-fail", t_fail)):
                    sub = admin.ok("GET", f"/v1/products/{pid}/tenants/{tid}/billing/subscription")
                    if sub.get("provider_subscription_id"):
                        created_subs.append(sub["provider_subscription_id"])
                    rep.check(
                        f"{name}: after checkout.session.completed (unpaid) the subscription is incomplete and linked",
                        sub["status"] == "incomplete" and bool(sub.get("provider_subscription_id")),
                        (sub["status"], sub.get("provider_subscription_id")),
                    )
                ok = wait_status(admin, pid, t_ok, {"active", "trialing"}, args.wait_minutes * 60)
                rep.check(
                    "sepa-ok: async_payment_succeeded -> active", ok["status"] == "active", ok["status"]
                )
                ent = admin.ok("GET", f"/v1/products/{pid}/tenants/{t_ok}/billing/entitlements")
                rep.check("sepa-ok: entitled", ent["features"].get("sso") is True, ent["features"])
                fail = wait_status(admin, pid, t_fail, {"canceled", "active"}, 120)
                rep.check(
                    "sepa-fail: never active (incomplete or canceled after async_payment_failed)",
                    fail["status"] in ("incomplete", "canceled"),
                    fail["status"],
                )

            for ev in ("checkout.session.async_payment_succeeded", "checkout.session.async_payment_failed"):
                trig = subprocess.run(
                    ["stripe", "trigger", ev, "--api-key", key], capture_output=True, text=True
                )
                rep.note(f"stripe trigger {ev}: exit {trig.returncode}")
            time.sleep(15)
            text = listen_log.read_text(errors="replace")
            rep.check("stripe listen forwarded events and Axentra answered 200", "[200]" in text, text[-800:])
            rep.check("no 400 (signature) answers from Axentra", "[400]" not in text)
    finally:
        for sid in created_subs:
            try:
                stripe_api(key, "DELETE", f"/v1/subscriptions/{sid}")
            except httpx.HTTPError as exc:
                rep.note(f"could not cancel {sid}: {exc}")
        listen.terminate()
    hits = {"api_key": (EVIDENCE / "stripe-test-mode-serve.log").read_text(errors="replace").count(key)}
    rep.check("test secret key not in the serve log", hits["api_key"] == 0, hits)
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
