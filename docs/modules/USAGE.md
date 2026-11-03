# Usage module (`axentra.usage`)

Generic usage metering for SaaS products: meters, idempotent usage events, aggregated counters,
per-tenant quotas with hard/soft enforcement, reservations, and statistics for charts.
It knows nothing about AI tokens or any specific product. The meter key is the product's business.

## Concepts

| Concept | Description |
|---|---|
| **Meter** | Per product: `key` (`^[a-z][a-z0-9_.]{0,62}$`, e.g. `api_calls`, `storage_bytes`, `reports`), `unit`, `aggregation` (`sum` \| `max` \| `last`), `reset_period` (`none` \| `day` \| `month` \| `billing_period`), `description`, optional `default_limit` + `default_enforcement`. Key, aggregation and reset period cannot change after creation. Meters with usage cannot be deleted, only deactivated (`active=false`). |
| **Usage event** | Append-only: tenant, meter, `quantity` (decimal, 0..1e15, at most 6 decimal places), `occurred_at` (at most 5 min in the future, at most 400 days in the past; before the tenant's current billing period only with `usage:manage`, see "Backdating"), `properties` (JSON object, at most 4 KB), `idempotency_key` (unique per tenant). |
| **Counter** | Aggregates per tenant, meter and period (`sum` adds, `max` keeps the maximum, `last` keeps the value of the latest `occurred_at`), plus daily buckets for time series. They are updated in the same transaction as the event (`INSERT ... ON CONFLICT DO UPDATE`). |
| **Period** | `none`: never resets. `day`: UTC days. `month`: UTC calendar months. `billing_period`: the tenant's subscription cycle, anchored at the subscription's period anchor (a day like the 31st is clamped in short months), when the billing module is enabled and the tenant has an entitled subscription. Otherwise it is the calendar month. Events count in the period that contains their `occurred_at`. |
| **Limit** | The effective limit of a tenant for a meter. The first match wins: a per-tenant **quota override** (`source: quota`), then the plan entitlement `limit.<meter key>` (`source: plan`, via billing), then the meter's `default_limit` (`source: meter`). Without any of these the meter is unlimited (`source: none`). `limit: null` means unlimited. |
| **Enforcement** | `hard`: `check_and_record` and `reserve` refuse with `429 quota_exceeded` when the limit would be exceeded. `soft`: the usage is recorded and `quota.over_limit` reports the excess. |
| **Reservation** | Holds a quantity of a `sum` meter against the limit for a TTL (1 s to 24 h). **Commit** records the actual usage (default: the reserved quantity). Commit is idempotent and is never refused. **Release** gives the quantity back. Active, unexpired reservations count against the limit. Expired reservations stop counting at their expiry; `sweep_expired_reservations()` marks them `expired`. |

How the hard check works: `used + reserved + quantity > limit` for `sum` meters, and `quantity > limit` for `max`/`last` meters.

## Library usage

```python
from axentra.core.context import Principal

ax.usage.create_meter(principal, pid, key="api_calls", unit="calls", default_limit=10_000)

# Usage that must respect the limit (raises QuotaExceeded -> HTTP 429):
result = ax.usage.check_and_record(principal, pid, tid, "api_calls", 1, idempotency_key=request_id)
result.replayed, result.quota.remaining

# Usage that already happened (never refused; result.quota.over_limit tells):
ax.usage.record(principal, pid, tid, "storage_bytes", 52_428_800, "snapshot-2026-11-01",
                occurred_at=measured_at, properties={"bucket": "media"})

# Long-running work: reserve, then commit the actual amount (or release)
res = ax.usage.reserve(principal, pid, tid, "reports", 1, ttl_seconds=600)
ax.usage.commit_reservation(principal, pid, tid, res.id, quantity=1)

ax.usage.summary(principal, pid, tid)               # current period per meter, with limits
ax.usage.timeseries(principal, pid, "api_calls", tenant_id=tid, since=date(2026, 10, 1))
ax.usage.sweep_expired_reservations()               # run periodically (worker / cron)
```

Repeating an idempotency key with the same body (meter, quantity, explicit `occurred_at`, properties)
returns the original event with `replayed: true`. A different body returns `409 conflict`. If
`occurred_at` is omitted, the server time is used and does not count as part of the body.

**Backdating** (AX2-08). Usage with an explicit `occurred_at` before the start of the tenant's
current billing period (the subscription cycle, or the calendar month without one) changes a
closed period, so it needs `usage:manage` held at product level (product owners and admins,
platform admins, product-wide API keys with that permission). Everyone else, including tenant
admins, members (the built-in `member` role keeps `usage:record`) and tenant-bound keys, gets
`403` with code `backdating_not_permitted` and `period_start` (the earliest allowed
`occurred_at`) in the problem body. The check runs after the idempotency lookup, so retrying an
accepted request still replays after the period has closed. `record_in` and the library calls
apply the same rule; `Principal.system` holds every permission.

Plan limits and billing periods come from the billing module through the small `UsagePolicy`
protocol (`plan_limits(tx, pid, tid)`, `billing_period(tx, pid, tid, at)`), which is registered at
wiring time (`ax.usage.set_policy(ax.billing.usage_policy())`). Usage never imports billing
(an import-linter contract enforces this). A product can register its own policy instead.

## HTTP endpoints

All paths are under `/v1/products/{product_id}`. "Product level" means the permission is checked
without a tenant, so only product roles, platform roles and product-wide API keys have it.

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/usage/meters` | `usage:read` (product level) | `Meter[]` |
| POST | `/usage/meters` | `usage:manage` | `201 Meter` |
| GET | `/usage/meters/{meter_id}` | `usage:read` (product level) | `Meter` (+`ETag`) |
| PATCH | `/usage/meters/{meter_id}` | `usage:manage`, `If-Match` optional | `Meter` |
| DELETE | `/usage/meters/{meter_id}` | `usage:manage` | `204`, or `409` when usage exists |
| GET | `/usage/summary?since&until&meter&limit&cursor` | `usage:read` (product level) | `Page[{tenant_id, meter, value, event_count}]` |
| GET | `/usage/timeseries?meter&since&until` | `usage:read` (product level) | `TimeSeries` (all tenants summed) |
| POST | `/tenants/{tid}/usage/events` (header `Idempotency-Key` required) | `usage:record`. `enforce=false`, and an `occurred_at` before the current billing period, also need product-level `usage:manage` | `201` new / `200` replayed: `{event, replayed, quota}`. `429` on a hard limit, `403 backdating_not_permitted` |
| GET | `/tenants/{tid}/usage/events?meter&since&until&limit&cursor` | `usage:read` | `Page[UsageEvent]` (newest first) |
| GET | `/tenants/{tid}/usage/summary?at` | `usage:read` | `MeterUsage[]` |
| GET | `/tenants/{tid}/usage/timeseries?meter&since&until` | `usage:read` | `TimeSeries` |
| GET | `/tenants/{tid}/usage/quotas` | `usage:read` | `EffectiveLimit[]` |
| PUT | `/tenants/{tid}/usage/quotas/{meter_key}` `{limit, enforcement}` | `usage:manage` | `EffectiveLimit` |
| DELETE | `/tenants/{tid}/usage/quotas/{meter_key}` | `usage:manage` | `EffectiveLimit` (now plan or default) |
| POST | `/tenants/{tid}/usage/reservations` `{meter, quantity, ttl_seconds}` (optional `Idempotency-Key`) | `usage:record` | `201 Reservation`, `429` |
| GET | `/tenants/{tid}/usage/reservations/{id}` | `usage:read` | `Reservation` |
| POST | `/tenants/{tid}/usage/reservations/{id}/commit` `{quantity?, properties?}` | `usage:record` | `{event, replayed, quota}` |
| POST | `/tenants/{tid}/usage/reservations/{id}/release` | `usage:record` | `Reservation` |

Response shapes (quantities are JSON numbers):

- `Meter`: `{id, product_id, key, name, unit, aggregation, reset_period, description, default_limit, default_enforcement, active, version, created_at, updated_at}`
- `UsageEvent`: `{id, product_id, tenant_id, meter, quantity, idempotency_key, occurred_at, recorded_at, period_start, properties, reservation_id}`
- `quota` / `QuotaStatus`: `{meter, period_start, period_end, used, reserved, limit, remaining, enforcement, source, over_limit}`
- `MeterUsage`: `{meter, name, unit, aggregation, reset_period, period_start, period_end, value, event_count, reserved, limit, remaining, enforcement, source, over_limit}`
- `EffectiveLimit`: `{meter, limit, enforcement, source, period}`
- `Reservation`: `{id, product_id, tenant_id, meter, quantity, status (active|committed|released|expired), period_start, expires_at, event_id, committed_quantity, created_at, updated_at}`
- `TimeSeries`: `{meter, unit, aggregation, tenant_id, since, until, points: [{day, value, event_count}]}`. Every day in the range has a point; at most 400 days; the default range is the last 30 days.
- 429 problem: `{code: "quota_exceeded", meter, limit, used, reserved, requested, period_end?}` with `Retry-After`.

## Guarantees

- **Exactly-once per idempotency key and tenant.** The event, its counters and the quota decision
  commit together or not at all. Concurrent requests with the same key record once; the others
  get the original event.
- **Hard limits are never overshot under concurrency.** All writes for a tenant, meter and period
  serialize on the period's counter row (`SELECT ... FOR UPDATE`). This is tested with 30 threads
  against a limit of 10.
- Counters are exact for `sum`/`max`. For `last`, the value of the event with the newest
  `occurred_at` wins, whatever the arrival order.
- Late events (backdated `occurred_at`) count in the period they belong to, even if it has already ended.

## Security notes

- Tenant data (events, counters, quotas, reservations) uses tenant-scoped transactions with
  forced row-level security. A foreign tenant or product returns `404`.
- Tenant members can record and read their own usage but cannot change quotas or meters
  (`usage:manage` is a product permission). They also cannot bypass quotas: `enforce=false` needs
  product-level `usage:manage`, which tenant-bound API keys never have at product level.
- Meter changes and quota changes are audited. Individual usage events are not audited because of
  their volume; the events table is itself an append-only record with `actor_id`.

## Limitations / TODO

- A quota's period is the meter's reset period. There are no separate quota windows such as
  "per hour" (use a `day` meter, or a separate meter).
- Reservations exist only for `sum` meters. Commit does not re-check the limit, because the work
  is already done.
- The product-wide summary aggregates daily buckets (UTC days). For `max` meters, the time series
  across tenants is the sum of the per-tenant maxima.
- No export to a provider's metered billing yet. The events table is the source for such a job.
- `sweep_expired_reservations()` and billing's `advance_periods()` must be scheduled by the
  operator (worker or cron); no scheduler is bundled.
