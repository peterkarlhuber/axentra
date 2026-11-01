# Billing module (`axentra.billing`)

Plans with prices and entitlements, tenant subscriptions with a strict state machine, entitlement
resolution, which also provides the default usage quotas, and payment provider adapters with
signed webhooks.

> **Axentra does no payment processing and stores no card data.** Payment details are entered
> only on the provider's hosted checkout page (for example Stripe Checkout). Axentra stores
> provider *ids* (customer, subscription, checkout session), prices as plan configuration and the
> subscription state reported by signed webhooks. Invoicing, taxes, receipts, refunds, dunning
> e-mails and PCI DSS scope are handled by the payment provider and the operator.

## Operator responsibilities

- Choose the provider: `billing.provider = "manual" | "fake" | "stripe"`. `fake` is refused in
  production, and `live_payments` requires `stripe`.
- With `stripe`, configure `billing.api_key_ref` (for example `env:STRIPE_SECRET_KEY`) and
  `billing.webhook_secret_ref`. Register the endpoint `https://<public_url>/v1/billing/webhooks/stripe`
  in the Stripe dashboard with the events listed below. Create the Stripe prices yourself and put
  their ids into the plan prices (`provider_price_id`).
- Live keys (`sk_live_`/`rk_live_`) are refused unless `billing.live_payments = true`. Turn that on
  only after you have reviewed the plans, prices, taxes and your terms.
- `manual` provider: you collect payment outside Axentra and set the subscription status yourself
  (for example `past_due` when an invoice is not paid). Schedule `ax.billing.advance_periods()`
  (for example hourly) so that trials end, periods roll forward and cancel-at-period-end takes effect.
- Keep your legal and tax obligations (prices incl./excl. VAT, invoices, consumer rights). Axentra
  does not model them.

## Concepts

| Concept | Description |
|---|---|
| **Plan** | Per product: `key`, `name`, `description`, `active`, `trial_days` (0..365), `prices[]` and `entitlements`. A plan with no prices, or only zero prices, is `free`. Plans that a subscription uses cannot be deleted, only deactivated. |
| **Price** | `{id (prc_), amount_minor (integer minor units), currency (ISO 4217), interval month\|year, provider_price_id?}`. Subscriptions keep a snapshot of their price. |
| **Entitlements** | A flat map: `feature.<name>: true/false` and `limit.<meter key>: number \| null` (null = unlimited). Per-tenant **overrides** replace single keys. The effective entitlements are the plan's (when the subscription is `trialing`, `active` or `past_due`) merged with the overrides. |
| **Subscription** | One current (not canceled) subscription per tenant: `status`, `plan`, `price`, `current_period_start/end`, `trial_end`, `cancel_at_period_end`, `canceled_at`, `provider` + provider ids, `version`. |

### State machine

```
incomplete -> trialing | active | canceled
trialing   -> active | past_due | canceled
active     -> past_due | canceled
past_due   -> active | canceled
canceled   (terminal; start a new subscription)
```

Any other transition is refused (`409` via the API, `rejected_transition` for webhooks).
`past_due` keeps the entitlements as a grace period. Every change is audited
(`billing.subscription.<create|change_plan|cancel|resume|status|renew|webhook>`) and, when an
events module is wired (`ax.events.publish_in_tx` exists), published in the same transaction as an
event of the same name (outbox, delivered at least once).

## Providers (`PaymentProvider` protocol)

| Provider | Behaviour |
|---|---|
| `ManualProvider` | Checkout completes locally (`completed: true`, no URL). The operator sets statuses. No webhooks; the webhook route returns `404`. |
| `FakeProvider` | A deterministic test double. Checkout returns `cs_fake_000001` and `https://checkout.fake.invalid/...`. `signed_event()` and `complete_checkout()` produce webhook bodies signed with the Stripe scheme and the fake's own secret (`billing.webhook_secret_ref`, or a random one per process). |
| `StripeProvider` | httpx calls to `api.stripe.com`: create customer, create Checkout Session (`mode=subscription`, trial days, metadata), cancel (now or at period end), resume. It refuses to run unless `billing.provider = "stripe"`, `api_key_ref` resolves to a Stripe secret key and, for live keys, `live_payments = true`. POSTs carry idempotency keys. Errors never contain the key or the provider's message. Tests use only `httpx.MockTransport`. |

Plan changes for Stripe subscriptions are made in Stripe (for example the customer portal).
The `customer.subscription.updated` webhook then maps the Stripe price id back to the plan.

## Webhooks

`POST /v1/billing/webhooks/{provider}` is public and authenticated by its signature:

1. Only the configured provider is served (`fake` or `stripe`). Anything else returns `404`. The
   body may be at most 256 KB.
2. `Stripe-Signature: t=<unix>,v1=<hex>` with `HMAC-SHA256(secret, "<t>.<raw body>")` and a
   tolerance of 300 s. Several `v1` values are accepted, which supports secret rotation. Failure
   returns `400 invalid_signature`.
3. **Replay protection:** processed event ids are stored in `axentra_billing_webhook_events`
   (primary key `(provider, event_id)`). Inserting the id and applying the change happen in one
   transaction, so a repeated event returns `200 {outcome: "duplicate"}` and changes nothing.
4. **Product and tenant resolution** uses only ids that Axentra stored itself: the checkout session
   id (stored at checkout), the provider subscription id, or the customer id that Axentra created
   (for a subscription event that arrives before `checkout.session.completed`). Metadata such as
   `axentra_tenant_id` in the payload is never trusted.
5. **Out-of-order safety:** events whose `created` is older than the last applied event for the
   subscription are recorded as `stale` and ignored.
6. Mapping: `checkout.session.completed` changes incomplete to trialing (if the plan has a trial)
   or active and links the subscription and customer ids. `customer.subscription.created|updated`
   maps the provider status (`unpaid`/`paused` become past_due, `incomplete_expired` becomes
   canceled) and copies periods, trial end, cancel-at-period-end and the plan (by price id).
   `customer.subscription.deleted` cancels. `invoice.paid|payment_succeeded` changes past_due or
   incomplete to active. `invoice.payment_failed` changes active or trialing to past_due.
   Other types are acknowledged as `ignored`.

The response is `200 {received: true, event_id, outcome}`, where `outcome` is one of `applied`,
`duplicate`, `stale`, `ignored`, `unmatched` or `rejected_transition`.

## Library usage

```python
plan = ax.billing.create_plan(principal, pid, key="pro", name="Pro", trial_days=14,
    prices=[{"amount_minor": 1900, "currency": "EUR", "interval": "month", "provider_price_id": "price_..."}],
    entitlements={"feature.sso": True, "limit.api_calls": 10_000})
session = ax.billing.create_checkout(principal, pid, tid, plan="pro",
    success_url="https://app.example.com/billing/ok", cancel_url="https://app.example.com/billing")
ent = ax.billing.entitlements(pid, tid)          # trusted call, no principal
if ent.features.get("sso"): ...
ax.billing.advance_periods()                     # scheduled, manual provider
```

`success_url`/`cancel_url` must start with `security.public_url` or one of `security.allowed_origins`
(no open redirects).

## HTTP endpoints

Paths are under `/v1/products/{product_id}`. Product-level `billing:read` means product roles
(the tenant permission `billing:read` held through a product role).

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/billing/plans` | `billing:read` (product level) | `Plan[]` |
| POST | `/billing/plans` | `billing:manage` | `201 Plan` |
| GET | `/billing/plans/{plan_id}` | `billing:read` (product level) | `Plan` (+`ETag`) |
| PATCH | `/billing/plans/{plan_id}` | `billing:manage`, `If-Match` | `Plan` |
| DELETE | `/billing/plans/{plan_id}` | `billing:manage` | `204` / `409` if in use |
| GET | `/billing/subscriptions?status&plan&limit&cursor` | `billing:read` (product level) | `Page[Subscription]` |
| GET | `/tenants/{tid}/billing/plans` | `billing:read` | active `Plan[]` |
| GET | `/tenants/{tid}/billing/subscription` | `billing:read` | `Subscription` (current, else latest canceled) / `404` |
| POST | `/tenants/{tid}/billing/subscription` `{plan, price_id?}` | `billing:manage` | `201 Subscription` (free plans, or any plan with `manual`) |
| POST | `/tenants/{tid}/billing/subscription/change-plan` `{plan, price_id?}` | `billing:manage`, `If-Match` | `Subscription` |
| POST | `/tenants/{tid}/billing/subscription/cancel` `{at_period_end=true}` | `billing:manage` | `Subscription` |
| POST | `/tenants/{tid}/billing/subscription/resume` | `billing:manage` | `Subscription` |
| POST | `/tenants/{tid}/billing/subscription/status` `{status}` | `billing:manage` (manual only) | `Subscription` |
| POST | `/tenants/{tid}/billing/checkout` `{plan, price_id?, success_url, cancel_url}` | `billing:manage` | `201 CheckoutSession` |
| GET | `/tenants/{tid}/billing/entitlements` | `billing:read` | `Entitlements` |
| PUT | `/tenants/{tid}/billing/entitlements/overrides` `{entitlements}` | `billing:manage` | `Entitlements` |
| POST | `/v1/billing/webhooks/{provider}` | public, signature | `WebhookResult` |

Response shapes:

- `Plan`: `{id, product_id, key, name, description, active, trial_days, prices: [Price], free, entitlements, version, created_at, updated_at}`
- `Subscription`: `{id, product_id, tenant_id, plan_id, plan_key, status, price, current_period_start, current_period_end, trial_end, cancel_at_period_end, canceled_at, provider, provider_customer_id, provider_subscription_id, version, created_at, updated_at}`
- `Entitlements`: `{product_id, tenant_id, plan_key, subscription_id, subscription_status, features: {name: bool}, limits: {meter: number|null}, overrides}`
- `CheckoutSession`: `{provider, checkout_id, url, completed, subscription}`

## Guarantees

- Subscription changes, their audit event and (if wired) the outbox event commit atomically.
- Webhooks are processed idempotently (once per provider event id) and in timestamp order per
  subscription. Events with the same `created` second are applied in arrival order.
- Provider calls (checkout, cancel, resume) happen outside database transactions. If the local
  update fails after a successful provider call, the provider's webhook brings Axentra back in sync.

## Security notes

- Checkout is a `billing:manage` operation. Tenant self-service goes through the product backend
  (an API key with `billing:manage`), which decides what a tenant may buy.
- Secrets (`api_key_ref`, `webhook_secret_ref`) are references (`env:`/`file:`) and are never
  returned or logged. Errors from the provider are reduced to the HTTP status and error type.
- RLS is forced on all billing tables. Webhook lookup by provider id runs in a read-only platform
  scope; the change itself runs in the resolved tenant's scope.

## Limitations / TODO

- No proration, coupons, taxes, invoices, seat quantities or metered (usage-based) prices.
- There is no customer portal endpoint and no Stripe plan change through Axentra.
- Provider statuses outside the mapping (for example new Stripe statuses) are ignored.
- The tenant permission set has no self-service checkout permission (see Security notes).
