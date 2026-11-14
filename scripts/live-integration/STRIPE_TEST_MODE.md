# Stripe test mode runbook

`stripe_test_mode.py` checks Axentra's Stripe adapter against the **real Stripe API in test mode**.
It has **not been run** yet (no test keys were available when it was written). The stripe-mock check
(`check_stripe_mock.py`) only validates request shapes and is no substitute.

Test mode moves no money. The script refuses any key that does not start with `sk_test_` or
`rk_test_`, and Axentra itself refuses live keys unless `billing.live_payments = true` (never set here).

## Prerequisites

1. A Stripe account in **test mode**; its secret key from Dashboard > Developers > API keys.
2. Dashboard (test mode) > Settings > Payment methods: enable **SEPA Direct Debit** (and keep cards).
3. The [Stripe CLI](https://docs.stripe.com/stripe-cli) (`stripe version`), no login needed: the script
   passes `--api-key`.
4. The local prerequisites of `run.sh` (PostgreSQL superuser URL in `LC_PG_ADMIN_URL`, `LC_PYTHON`).
   No containers are needed.

## Run

```bash
export STRIPE_TEST_SECRET_KEY=sk_test_...     # never commit it; the script reads it from the environment
export LC_PYTHON=/path/to/venv/bin/python LC_PG_ADMIN_URL=postgresql://postgres:...@127.0.0.1:5432/postgres
cd scripts/live-integration
PYTHONPATH=../../src $LC_PYTHON stripe_test_mode.py            # creates a EUR 19.00/month test price
PYTHONPATH=../../src $LC_PYTHON stripe_test_mode.py --price price_...   # or reuse one
```

The script:

1. creates a test product + monthly EUR price (metadata `lc=axentra-live-integration`) unless `--price`;
2. reads the webhook signing secret with `stripe listen --print-secret` and starts
   `stripe listen --events checkout.session.completed,checkout.session.async_payment_succeeded,checkout.session.async_payment_failed,customer.subscription.*,invoice.* --forward-to http://127.0.0.1:19206/v1/billing/webhooks/stripe`;
3. starts `axentra serve` with `billing.provider = "stripe"`, `api_key_ref = env:STRIPE_TEST_SECRET_KEY`,
   `webhook_secret_ref = env:LC_STRIPE_WHSEC` on a fresh database `lc_stripe_test`;
4. creates two Axentra checkouts and prints the Checkout URLs. Open them in a browser and pay with
   **SEPA Direct Debit**, synthetic name and e-mail:
   - tenant `sepa-ok`: IBAN `DE89370400440532013000` (payment succeeds after a delay);
   - tenant `sepa-fail`: IBAN `DE62370400440532013001` (payment fails after a delay);
5. after you press Enter it expects, per tenant, `checkout.session.completed` with
   `payment_status = unpaid`: subscription **incomplete** and linked to the Stripe subscription;
6. waits (default 15 minutes, `--wait-minutes`) for `checkout.session.async_payment_succeeded`:
   `sepa-ok` must become **active** and entitled; `sepa-fail` must never become active
   (`checkout.session.async_payment_failed`, later possibly `customer.subscription.deleted` -> canceled);
7. runs `stripe trigger checkout.session.async_payment_succeeded` and `..._failed`. These create their
   own sessions that Axentra does not know, so the expected answer is `200` with outcome `unmatched`:
   this proves forwarding and signature verification, not the state mapping;
8. cancels the created test subscriptions and writes `evidence/stripe-test-mode-*`
   (results, checkouts, `stripe listen` log, server log; the key must not appear in the log).

`--skip-browser` runs only steps 1-3 and 7 (checkouts are created but not paid).

## Expected evidence

`evidence/stripe-test-mode-results.txt` with all lines `[PASS]` and `stripe-test-mode: PASSED`.
Report any `[FAIL]` with the result file, `stripe-test-mode-listen.log` and the server log.

## Cleanup

Test-mode objects can stay (they cost nothing); delete the product in the Dashboard if you like. Run
`DROP DATABASE lc_stripe_test` locally when done.
