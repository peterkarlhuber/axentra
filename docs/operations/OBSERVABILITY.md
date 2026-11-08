# Observability

Package `axentra.observability` (no web framework imports) plus `axentra.api.observability`
(HTTP wiring) and `axentra.api.routes.observability` (`GET /metrics`).

## Metrics

A small, dependency-free registry (`axentra.observability.metrics.MetricsRegistry`) available as
`ax.metrics`, rendered in the Prometheus text format 0.0.4 at `GET /metrics`.

| Metric | Type | Labels |
|---|---|---|
| `axentra_http_requests_total` | counter | `method`, `route` (route template, e.g. `/v1/products/{product_id}`; `unmatched` for 404 paths), `status` |
| `axentra_http_request_duration_seconds` | histogram | `method`, `route` |
| `axentra_auth_failures_total` | counter | `reason` = `unauthenticated` (401), `forbidden` (403), `metrics_token` |
| `axentra_db_pool_size`, `axentra_db_pool_available`, `axentra_db_pool_max` | gauge | – |
| `axentra_db_pool_requests_waiting`, `_requests_num`, `_requests_errors`, `_connections_errors` | gauge | – (psycopg_pool statistics) |
| `axentra_notify_messages_enqueued_total` | counter | `status` |
| `axentra_notify_deliveries_total` | counter | `provider`, `outcome` (`sent`, `retried`, `failed`, `lease_lost`) |
| `axentra_notify_send_duration_seconds` | histogram | `provider` |

Other modules and product backends add their own metrics:

```python
jobs = ax.metrics.counter("axentra_jobs_total", "Jobs run", ("queue", "outcome"))
jobs.inc(queue="default", outcome="ok")
ax.metrics.histogram("myapp_render_seconds", "Render time").observe(0.2)
ax.metrics.gauge("myapp_queue_depth", "Depth", callback=lambda: [({}, depth())])
```

Embedding hosts (a product that runs Axentra as a library next to its own code) reuse the registry
instead of building their own:

```python
from axentra.observability import CachedCallback, register_pool_metrics

# Several named pools (the host's and Axentra's, or one shared pool): <prefix>_db_pool_*{pool="..."}
register_pool_metrics(ax.metrics, lambda: {"app": app_pool, "axentra": ax.db.pool}, prefix="myapp")
# Totals the host counts itself, exposed as a counter at scrape time:
ax.metrics.counter_callback("myapp_ops_total", "Operations", ("outcome",), lambda: [({"outcome": "ok"}, n)])
# An expensive database count, run at most once a minute (a failure keeps the last value):
backlog = CachedCallback(count_backlog, 60)
ax.metrics.gauge("myapp_backlog", "Backlog", callback=lambda: [({}, backlog())])
```

Metrics are per process (no shared state between API workers); scrape every process (or run one
worker per container). Each metric keeps at most 2 000 label combinations; more are folded into a
series whose labels are `other`. Never use ids or user input as label values.

### Access to `/metrics` (secure default)

| Configuration | Result |
|---|---|
| `observability.metrics_enabled = false` | 404 |
| `observability.metrics_token_ref = "env:AXENTRA_METRICS_TOKEN"` | `Authorization: Bearer <token>` required (401 otherwise, compared in constant time) |
| no token, `environment = "production"` | 404 – disabled until a token is configured (a warning is logged at startup) |
| no token, development/test | open |

Prometheus: `authorization: {credentials_file: /run/secrets/axentra_metrics_token}`.

## Tracing (OpenTelemetry)

Optional: `observability.otel_enabled = true` **and** `pip install axentra[otel]`. Without the
extra (or when disabled) `ax.tracing` is a no-op and nothing imports OpenTelemetry. When enabled,
an HTTP middleware creates one server span per request named `<METHOD> <route template>` with
`http.request.method`, `http.route`, `http.response.status_code` and `axentra.request_id`
(the `X-Request-ID`); 5xx responses set the span status to error. Spans are exported with
OTLP/HTTP (`observability.otel_endpoint` or the standard `OTEL_EXPORTER_OTLP_*` variables) through a
batch processor; the tracer provider belongs to the Axentra instance (the global OpenTelemetry
provider is not replaced). Code can add spans with `with ax.tracing.span("name", {"k": "v"}):`.
There is no automatic database instrumentation yet.

## Health

- `GET /v1/health/live`: the process answers.
- `GET /v1/health/ready`: database ping plus registered checks (`app.state.readiness_checks`);
  includes `notify_provider` (configuration only, no network calls). 503 when a check fails.

## Logs

JSON logs (`observability.log_format = "json"`) carry `request_id`, method, path, status and
duration; messages and exceptions are redacted (API keys, bearer tokens, JWTs, invitation tokens,
database passwords). Database errors are logged without the values of the server's `DETAIL` text: a log record
names the SQLSTATE and the constraint (`unique violation (SQLSTATE 23505, constraint users_email_key)`; JSON logs
also carry `db_sqlstate` and `db_constraint`). Applications that install their own logging handlers add
`axentra.core.db_errors.DbErrorRedactionFilter` to them.

## Maintenance and retention

Run regularly (e.g. daily cron or a scheduled job):

```
axentra maintenance purge
```

It runs audit retention (`observability.audit_retention_days`, default 365), deletes expired
sessions/login states/setup tokens, applies notification retention (`notify.content_retention_days`,
`notify.message_retention_days`) and every callable registered in `ax.maintenance_hooks`
(`name -> callable`). It prints a JSON report and exits with 1 if a task failed (the other tasks
still run).

Notification delivery runs separately: `axentra notify-dispatch --loop` (or call
`ax.notify.dispatcher().run_once()` from a job worker).
