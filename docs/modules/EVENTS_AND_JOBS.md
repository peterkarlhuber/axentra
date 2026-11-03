# Events and jobs (module `events`)

Background work for Axentra and the products built on it. Everything is stored in PostgreSQL, so
you do not need a broker:

- a **persistent job queue** with workers, leases, retries, dead letters and cancellation;
- **schedules** that enqueue jobs at intervals or on cron times;
- **events** written through a transactional outbox, with in-process subscribers;
- **outgoing webhooks** with signed, retried deliveries;
- **realtime streams** (SSE) of new events and job status changes.

Code: `src/axentra/events/` (domain, no web framework) and `src/axentra/api/routes/events.py`
(HTTP). Migration: `src/axentra/data/sql/0002_events.sql`. Settings: section `[events]`
(`axentra.config.settings.EventsSettings`) and `observability.job_retention_days`.

The services are always constructed (`ax.jobs`, `ax.events`, `ax.schedules`, `ax.webhooks`), so
other modules can enqueue jobs and publish events. The module flag `events` controls only the HTTP
routes and the `axentra worker` command.

## Guarantees (precise)

| What | Guarantee |
| --- | --- |
| Job execution | **At least once** while attempts remain. A job may run more than once: after a crash, after a lost lease, or when a handler finished but its `complete` call did not reach the database. **Axentra does not execute anything exactly once.** Handlers must be idempotent, for example with a natural key or an idempotency key at the receiving side. |
| Exclusive claim | A queued job is handed to exactly one worker per attempt (`FOR UPDATE SKIP LOCKED`). While a worker holds a valid lease, no other worker gets the job. |
| Lease fencing | `complete`/`fail` take effect only when the worker still owns the running job (`worker = me AND status = 'running'`). When a lease has expired and the job was reaped, the late worker's result is discarded. Its side effects are not undone: a hung handler can still be running while the next attempt starts. |
| Retries | Every failed attempt is re-queued after `min(cap, base·2^(n-1))`, randomized between 50 % and 100 % ("equal jitter"), until `max_attempts`. After that the status is `dead` (the dead letter). A `PermanentJobError` gives `failed` at once. |
| Crash recovery | A worker that dies stops renewing its leases. After `events.lease_seconds` the reaper (every worker, every `reap_interval_seconds`) re-queues the job with backoff if attempts remain (`attempts` counts the lost attempt), otherwise marks it `dead`. |
| Ordering | No FIFO guarantee. Claims prefer higher `priority`, then earlier `run_after`, then older id. Retries and concurrency reorder jobs. |
| Idempotency keys (jobs) | Unique per **(product, tenant, kind, key)** for as long as the job row exists, which includes finished jobs until the retention purge (`observability.job_retention_days`, default 30). Enqueueing an existing key returns the existing job unchanged. A different tenant or kind is a separate key space. Through `JobService.enqueue` (the API) a replay is returned only for the same request (payload and priority) and only to the job's creator or a caller with `jobs:read` in its scope; otherwise `409` without the stored job. |
| Events | `publish_in_tx` writes the event and its dispatch job in the caller's transaction, so the event exists if and only if the caller's writes commit (transactional outbox). Dispatch and every subscriber run **at least once**. Fan-out is idempotent (one subscriber job per (event, subscriber), one delivery per (endpoint, event)). Idempotency keys for events are unique per (product, tenant, key) until retention. `EventService.publish` (the API) returns a replay only for the same type and data, to the event's actor or a caller with `jobs:read`; otherwise `409`. |
| Webhooks | **At least once** per (endpoint, event), up to `webhook_max_attempts` attempts, plus manual redeliveries. Receivers must deduplicate by `Axentra-Event-Id` (= body `id`). There is no ordering guarantee between events. |
| Schedules | At most one scheduler fires at a time (session advisory lock on a dedicated connection). **Each slot fires at most once**, because the `(schedule_id, slot)` primary key is inserted in the same transaction as the job and the advance of `next_run_at`. This also holds when two leaders overlap. Missed slots (no worker running) are **coalesced**: the overdue slot fires once, and then the next slot after now is used. The fired job itself has the usual at-least-once execution. |
| Streams (SSE) | A client that resumes with `Last-Event-ID` gets every event committed after that position, as long as retention has not purged it. Positions are assigned after commit, in visibility order, so a late-committing transaction cannot slip behind a position already seen. The jobs stream shows the **latest** state of each changed job; intermediate states can be skipped. |

## Concepts

### Jobs

Table `axentra_jobs`: `product_id`, `tenant_id` (NULL for product-level jobs), `kind`
(`^[a-z][a-z0-9_.:-]{0,99}$`), `payload` (JSON object, at most 64 KB), `status`, `priority`
(-100..100), `run_after`, `attempts`, `max_attempts` (1..100), backoff parameters, `lease_until`,
`worker`, `cancel_requested`, `last_error` (redacted, at most 2000 chars), `idempotency_key`,
`result` (handler return value as JSON, at most 64 KB), `schedule_id`, timestamps.

Statuses:

```
queued ──claim──> running ──ok──────────────> succeeded
  ^  │               │ error, attempts left ──> queued (run_after = now + backoff)
  │  │               │ error, none left ──────> dead
  │  │               │ PermanentJobError ─────> failed
  │  │               │ cancel requested ──────> cancelled
  │  └─cancel──> cancelled
  └──── manual retry (failed | dead; attempts reset to 0)
```

Kinds starting with `axentra.` are reserved for Axentra's own jobs (`axentra.event.dispatch`,
`axentra.event.handle`, `axentra.webhook.deliver`) and cannot be enqueued through the public API.

**Cancellation:** a queued job becomes `cancelled` at once. A running job gets
`cancel_requested = true`. The handler sees this through `ctx.cancel_requested()` (refreshed by
every heartbeat) and raises `JobCancelled`. If the handler raises anything else after a cancel
request, the job also ends as `cancelled`. If it returns normally, the job is `succeeded`, because
the work was done.

**Wake-up:** enqueue, retry and re-queue send `NOTIFY axentra_jobs` (the payload is only the
kind). Workers `LISTEN` on a dedicated connection and still poll every `poll_interval_seconds`,
so a missed notification only adds latency.

### Workers

```python
from axentra.events import JobWorker, PermanentJobError

def send_report(ctx):                       # ctx: JobContext
    ctx.job.payload                          # the stored payload
    with ctx.transaction() as tx:            # DbScope of the job (product or tenant): RLS applies
        tx.one("SELECT ...")
    ax.records.create(ctx.principal, ctx.job.product_id, ctx.job.tenant_id, "reports", {...})
    for chunk in work:
        if not ctx.heartbeat():              # renew the lease; False = lost, stop now
            return
        if ctx.cancel_requested():
            raise JobCancelled()
    return {"sent": 3}                       # stored as the job's result

ax.jobs.register("reports.send", send_report)
JobWorker(ax, kinds=["reports.send"], concurrency=4).run()     # blocking; or .start() / .stop()
```

`ctx.principal` (built by `ax.jobs.principal_for(job)`) is a system principal **confined to the
job's product (and tenant)**, never with platform permissions, so service calls made with it
cannot reach another product or tenant. (The authorizer treats a system actor with
`api_key_product_id` like an API key.) Its permissions are:

- the kind's declared `permissions` (see below), or all product and tenant permissions for kinds
  that declare none (trusted kinds: enqueued by product code, schedules or `jobs:manage` holders);
- for jobs a user or API key enqueued through `POST /jobs`, further intersected with what that
  enqueuer holds in the job's scope *when the handler runs* (a removed member's queued job can do
  nothing). Jobs fired by a schedule (`created_by = schedule:<id>`) follow the same rule with the
  schedule's creator: once the creator lost access (or the schedule was deleted) the handler holds
  no permissions; schedules created in process (`Principal.system`) keep the kind's permissions.
  `ctx.transaction()` is raw database access in the job's scope (RLS applies) and is not
  limited by these permissions, so handlers must still treat the payload as untrusted input.

**Who may enqueue a kind through the API.** `jobs:manage` holders may enqueue any kind not starting
with `axentra.`. Tenant callers with only `events:publish` (the `member` role) may enqueue a kind
only when the product opened it explicitly, in every API process (and worker) that runs:

```python
ax.jobs.register(
    "reports.export",
    export_report,
    enqueue_permission="events:publish",           # tenant members may enqueue it
    permissions={"records:read", "files:write"},  # all the handler may do (required with enqueue_permission)
)
# An API process that does not run the handler declares the kind only:
ax.jobs.declare("reports.export", enqueue_permission="events:publish", permissions={"records:read", "files:write"})
```

Any other kind answers `403` to such callers.

`axentra worker [--kinds a,b] [--concurrency N] [--once] [--no-scheduler] [--shutdown-timeout S]
[--load my.module]` runs a worker process. `--load` imports a module and calls its `setup(ax)` to
register handlers and subscribers. SIGTERM/SIGINT stop claiming new jobs and wait up to the
shutdown timeout for running handlers, with their leases still renewed. A handler that is still
running after the timeout loses its lease, and its job is retried elsewhere.

Every worker reaps expired leases. The worker that holds the scheduler leader lock also fires
schedules (every `scheduler_interval_seconds`) and runs the hourly retention purge. The purge
removes finished jobs, delivered or dead deliveries, events with no pending deliveries, and
schedule firings older than `job_retention_days`.

**Archived products and suspended tenants.** The worker does not run a claimed job of an archived
product or a suspended tenant (the same status rule the authorizer applies to every request). The
job ends as `failed` with `last_error` `skipped: the product or tenant is not active`, is kept and can
be retried (`POST /jobs/{id}/retry`) once the product or tenant is active again. A skipped webhook
delivery ends as `dead` with the same reason and can be redelivered. The scheduler does not fire
schedules of an archived product or a suspended tenant: the slot is recorded as a firing without a
job, the schedule moves on to its next slot and is kept, and the first skipped slot of an inactive
period records the audit event `events.schedule.skip` (`details.reason = product_or_tenant_inactive`).

### Schedules

`interval_seconds` (10 s .. 366 days) or `cron` (exactly one of them). Interval slots are
multiples of the interval since the Unix epoch (UTC), so all processes compute the same slots.
Cron is a 5-field expression in **UTC** (`minute hour day-of-month month day-of-week`) with `*`,
numbers, ranges, lists and steps. Day of week is 0-7, where 0 and 7 are Sunday. When both
day-of-month and day-of-week are restricted, a day matches if either one matches (Vixie cron).
Names, `L`, `W`, `#`, `@daily` and time zones are not supported. An expression that never
matches is rejected.

### Events and subscribers

```python
# Atomically with your own writes (transactional outbox, no authorization inside):
with ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
    tx.execute("INSERT INTO crm_invoices ...")
    ax.events.publish_in_tx(tx, pid, tid, "invoice.created", {"invoice_id": inv}, idempotency_key=inv)

# Or authorized, in its own transaction:
ax.events.publish(principal, pid, tid, "invoice.created", {"invoice_id": inv})

# In-process subscribers, run in workers through jobs (register them in every worker process):
ax.events.subscribe("invoice.*", lambda ctx, event: ..., name="crm.invoice_mailer")
```

Event types use `^[a-z][a-z0-9_.:-]{0,149}$`, and `axentra.` is reserved. Data is a JSON object of
at most 64 KB. Subscriber patterns are globs (`*`). The subscriber `name` is stored in its jobs.
A job whose subscriber is not registered in the worker that runs it fails and is retried, up to
`dead`.

### Webhooks

An endpoint has a `url`, `event_types` (glob patterns, e.g. `["invoice.*"]` or `["*"]`), an
optional `tenant_id` filter (only that tenant's events) and `enabled`. The signing secret
`whsec_...` is generated by Axentra and returned **only** by create and rotate-secret. It is
stored encrypted with `ax.secrets`, with the context bound to the endpoint id. Rotation can keep
the previous secret valid for a grace period of up to 7 days. During that time, requests carry two
`v1` signatures.

Every request is `POST` with a JSON body
`{"id","type","product_id","tenant_id","occurred_at","data"}` and these headers:

```
Content-Type: application/json
Axentra-Event: invoice.created
Axentra-Event-Id: evt_...
Axentra-Delivery: dlv_...
Axentra-Signature: t=1767225600,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>[,v1=<previous>]
```

Verify on the receiving side (Python helper: `axentra.events.verify_signature(secret, header,
body)`). Compute the HMAC over `f"{t}.".encode() + raw_body`, compare it in constant time with any
`v1` value, reject timestamps older than about 5 minutes, and deduplicate by event id.

A 2xx response counts as success. Any other response, a timeout or a connection error is retried
through the job queue, up to `webhook_max_attempts`. Then the delivery becomes `dead`.

Webhook retries have their own schedule, independent of the job backoff (`backoff_*`, seconds to
minutes), so that a receiver that is down for a while does not lose events: the wait after
failed attempt *n* is `min(webhook_backoff_base_seconds * 2^(n-1), webhook_backoff_max_seconds)`,
with the same "equal jitter" as jobs (a random value between half and all of that step). With the
defaults (`webhook_backoff_base_seconds` 120, `webhook_backoff_max_seconds` 21600,
`webhook_max_attempts` 8) the waits are about 2, 4, 8, 16, 32, 64 and 128 minutes (each halved at
most by jitter): the last attempt runs about **2.1 to 4.2 hours** after the first, so receiver
outages up to about two hours are always bridged. Raise `webhook_max_attempts` for a longer window
(each further attempt doubles the wait until the 6 hour cap: 9 attempts about 4.2 to 8.5 hours,
10 attempts about 6.2 to 12.5 hours). After that, **Redeliver** sends a dead delivery again. Redirects are not followed. The first `webhook_response_max_bytes` of the response body
are stored with the delivery (status code, duration, error, next attempt). Redeliver queues a
delivery again (`409` while one is queued or running). Test sends a signed `axentra.ping`
synchronously (no retries) and returns the recorded delivery.

**SSRF protection:** only `https` (`http` only outside production with `webhook_allow_http`,
which is refused in production). URLs must not contain credentials or fragments. `localhost` and
`*.local`, `*.localhost`, `*.internal` are refused. Before every delivery the host is resolved and
**every** address is checked. Private, loopback, link-local, multicast, reserved, unspecified,
IPv6 site-local (`fec0::/10`) and IPv4-mapped forms of these are refused unless
`webhook_allow_private_targets = true` (tests and development; production refuses to start with it
unless `webhook_allow_private_targets_in_production = true` is also set, for receivers on a private
network). The connection goes to the checked address (no second lookup, so DNS rebinding
does not work), and TLS verifies the certificate for the host name. A refused target makes the
delivery `dead` with no further retries. A host that does not resolve is retried.

### Streams (SSE)

`GET /v1/products/{pid}/events/stream` and `GET /v1/products/{pid}/jobs/stream` (both need
`jobs:read`; with `?tenant_id=` the check is made in that tenant, so tenant-bound API keys can
stream their tenant). Messages look like this:

```
id: 1234
event: invoice.created          (jobs stream: job.queued | job.running | job.succeeded | ...)
data: {...event or job JSON...}
```

- Without `Last-Event-ID` the stream starts with new items. With it, the stream resumes after that
  position. `Last-Event-ID: 0` replays everything that is retained.
- `?types=invoice.*,user.created` filters the events stream.
- The stream re-authenticates every `sse_reauth_seconds`: it checks the session or API key again
  and the permission. When this fails, it sends `event: error` and closes. This covers a revoked
  session, a revoked key and a removed role.
- It sends keep-alive comments every `sse_keepalive_seconds` and closes after `sse_max_seconds`.
  EventSource clients reconnect automatically with `Last-Event-ID`.
- Implementation: an async generator that polls the database in the threadpool every
  `sse_poll_seconds`. Before each poll, committed rows that have no position yet get one. One
  assigner runs at a time (transaction advisory lock), so positions follow commit order.

## HTTP endpoints

All endpoints are under `/v1/products/{product_id}`. Callers outside the scope get `404`. Callers
with a relation to the product but without the permission get `403`.

| Method and path | Permission | Response |
| --- | --- | --- |
| `GET /jobs?status=&kind=&tenant_id=&limit=&cursor=` | `jobs:read` (in the tenant when `tenant_id` is given) | `Page[Job]` newest first |
| `GET /jobs/stats?tenant_id=` | `jobs:read` | `JobStats` |
| `GET /jobs/stream?tenant_id=` | `jobs:read` | SSE |
| `POST /jobs` (+ `Idempotency-Key`) | `jobs:manage`; tenant jobs: `jobs:manage`, or the kind's declared `enqueue_permission` (e.g. `events:publish`) in the tenant | `201 Job`; `403` for kinds not opened to the caller; `409` when the key was used for a different request or by another caller without `jobs:read` |
| `GET /jobs/{job_id}` | `jobs:read` (in the job's tenant) | `Job` |
| `POST /jobs/{job_id}/retry` | `jobs:manage` | `Job` (`409` unless failed/dead) |
| `POST /jobs/{job_id}/cancel` | `jobs:manage` | `Job` (`409` when finished) |
| `GET /schedules?tenant_id=` · `POST /schedules` | `jobs:read` · `jobs:manage` | `Page[Schedule]` · `201 Schedule` |
| `GET/PATCH/DELETE /schedules/{id}` (`If-Match`) | `jobs:read` / `jobs:manage` | `Schedule` (ETag) / `Schedule` / `204` |
| `GET /events?tenant_id=&type=a.b or a.*` | `jobs:read` | `Page[Event]` newest first |
| `GET /events/stream?tenant_id=&types=` | `jobs:read` | SSE |
| `GET /events/{event_id}` | `jobs:read` | `Event` |
| `POST /tenants/{tenant_id}/events` (+ `Idempotency-Key`) | `events:publish` | `201 Event`; `409` on a key reused for a different request or by another caller without `jobs:read` |
| `GET /webhooks` · `POST /webhooks` | `webhooks:read` · `webhooks:manage` | `Page[WebhookEndpoint]` · `201 {endpoint, secret}` |
| `GET/PATCH/DELETE /webhooks/{id}` (`If-Match`) | `webhooks:read` / `webhooks:manage` | `WebhookEndpoint` / `204` |
| `POST /webhooks/{id}/rotate-secret` `{grace_seconds}` | `webhooks:manage` | `{endpoint, secret}` |
| `POST /webhooks/{id}/test` | `webhooks:manage` | `Delivery` |
| `GET /webhooks/{id}/deliveries?status=` | `webhooks:read` | `Page[Delivery]` newest first |
| `GET /webhooks/{id}/deliveries/{dlv}` | `webhooks:read` | `Delivery` |
| `POST /webhooks/{id}/deliveries/{dlv}/redeliver` | `webhooks:manage` | `202 Delivery` |

Shapes (see `openapi/axentra-v1.json`):

- `Job`: `id, product_id, tenant_id, kind, payload, status, priority, run_after, attempts,
  max_attempts, lease_until, worker, cancel_requested, last_error, idempotency_key, result,
  schedule_id, created_by, created_at, updated_at, started_at, finished_at`. `payload` and
  `result` are redacted in API responses.
- `JobStats`: `counts{queued,running,succeeded,failed,dead,cancelled}, failed_last_24h,
  succeeded_last_24h, oldest_queued_at, by_kind[{kind, <status counts>}]`.
- `Schedule`: `id, product_id, tenant_id, name, kind, payload, interval_seconds, cron, enabled,
  priority, max_attempts, next_run_at, last_run_at, last_job_id, version, created_*, updated_at`.
- `Event`: `id, product_id, tenant_id, type, data, idempotency_key, actor_kind, actor_id,
  request_id, occurred_at`.
- `WebhookEndpoint`: `id, product_id, tenant_id, url, description, event_types, enabled, version,
  has_previous_secret, previous_secret_expires_at, created_by, created_at, updated_at`. The secret
  is never returned here.
- `Delivery`: `id, product_id, tenant_id, endpoint_id, event_id, event_type, status
  (pending|succeeded|failed|dead), attempts, response_code, response_body, duration_ms,
  last_error, next_attempt_at, job_id, created_at, updated_at, delivered_at`.

## Security notes

- Every table has `product_id` (and `tenant_id`) and forced row-level security. Handlers run in
  the job's product or tenant scope, while claiming, reaping and scheduling run in platform scope
  inside the trusted worker.
- Tenant-scoped transactions also see product-level rows (`tenant_id IS NULL`), as defined by the
  policy of migration 0001. Services always filter by tenant explicitly.
- Errors stored on jobs and deliveries are redacted (tokens, API keys, bearer values, DB URLs).
  Payloads are redacted in API responses but stored as given, so do not put secrets in payloads:
  pass ids and read secrets inside the handler.
- Webhook secrets are encrypted at rest and shown once. Signatures carry a timestamp so receivers
  can reject replays.
- Changes are audited in the same transaction: `events.job.enqueue|retry|cancel`,
  `events.schedule.*` (`events.schedule.skip` by the scheduler), `events.webhook.create|update|delete|rotate_secret|test|redeliver`.

## Configuration (`[events]`)

`lease_seconds` (60), `poll_interval_seconds` (1), `listen_notify` (true), `reap_interval_seconds`
(15), `scheduler_interval_seconds` (5), `default_max_attempts` (5), `backoff_base_seconds` (2),
`backoff_max_seconds` (3600), `webhook_max_attempts` (8), `webhook_backoff_base_seconds` (120;
greater than 0, at most 86400), `webhook_backoff_max_seconds` (21600; at least the base, at most
604800), `webhook_timeout_seconds` (10),
`webhook_response_max_bytes` (4096), `webhook_allow_private_targets` (false; in production only
with `webhook_allow_private_targets_in_production`), `webhook_allow_http`
(false; refused in production), `sse_poll_seconds` (1), `sse_reauth_seconds` (15),
`sse_keepalive_seconds` (15), `sse_max_seconds` (3600). Retention:
`observability.job_retention_days` (30).

## Limitations

- No exactly-once execution and no global ordering (see Guarantees).
- No at-most-once mode beyond `max_attempts=1` (a lost lease then makes the job `dead`, but the
  old worker's handler is not stopped and nothing marks the product's own record), and no unique
  key for *active* jobs only (idempotency keys deduplicate until retention). A product whose work
  must never repeat a paid or external effect keeps a queue with those semantics of its own
  (Nodestro does for its runs, gap G-8) or makes every effect idempotent at its target.
  `tests/integration/test_job_delivery_semantics.py` shows the at-least-once behaviour after a
  lost lease with a still-running handler.
- The webhook timeout applies to connect and to each socket read, not to the whole request. A
  server that trickles bytes can hold a worker slot longer, bounded by
  `webhook_response_max_bytes`.
- There is no automatic disabling of endpoints that keep failing, and no per-endpoint rate limit.
- Cron is UTC only and has no names or macros.
- Subscribers are in-process: every worker that runs `axentra.event.handle` jobs must register the
  same subscribers.
- Stream positions are assigned by readers. When nobody streams, rows stay unpositioned until the
  next stream starts, which is harmless. Very high event rates are positioned in batches of 1000
  per poll.
- The API readiness check (`/v1/health/ready`) does not include workers, on purpose: an API must
  not become unready because workers are down. Monitor `GET /jobs/stats`
  (`oldest_queued_at`) instead.
- Payload JSON schemas per kind are not enforced.

## Provenance

The SQL core of the queue (claim with SKIP LOCKED, lease heartbeat, fenced finish, reaping,
cancellation), the leader lock and the schedule firings were adapted from
peterkarlhuber/nodestro-runtime `src/nodestro_runtime/jobs.py` at
a42b6724702821849af478ee9dd0bfa13617e28b (MIT, Copyright (c) 2026 Peter Karlhuber). Nodestro
never retries reaped jobs; Axentra retries them with backoff.
