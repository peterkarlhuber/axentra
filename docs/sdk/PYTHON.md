# Python SDK (`axentra-client`)

A small, typed HTTP client for the Axentra API with a synchronous (`AxentraClient`) and an
asynchronous (`AsyncAxentraClient`) flavour. Location: `sdk/python` (package `axentra_client`,
its own `pyproject.toml`). Status: alpha, not published to PyPI yet.

- **Pure HTTP client**: depends only on `httpx` and `pydantic`, never imports the `axentra`
  server package (a unit test and the CI job `sdk-python` check this by installing the client
  alone). Use it from any Python service, script or notebook, against any Axentra deployment.
- Python >= 3.11. Typed (`py.typed`, `mypy --strict` clean).
- Written against API **1.0** (`axentra_client.API_VERSION`).

The `axentra` package itself is also a Python *library* (in-process use, see the module docs).
Use `axentra-client` when your code talks to an Axentra server over HTTP.

## Install

```bash
pip install ./sdk/python          # from a checkout of the repository
```

## Usage

```python
from axentra_client import AxentraClient, AxentraApiError, IncompatibleApiError

ax = AxentraClient("https://api.example.com", api_key="axk_...")
ax.check_compatibility()                          # IncompatibleApiError on a wrong server version

pid = "prd_..."
tenant = ax.tenants.create(pid, slug="acme", name="Acme")
note = ax.records.create(pid, tenant.id, "notes", {"title": "Hello", "status": "open"})
note = ax.records.replace(pid, tenant.id, "notes", note.id, {"title": "Hi"}, version=note.version)
for rec in ax.records.iter(pid, tenant.id, "notes", where={"status": "open"}, page_size=100):
    ...

info = ax.files.upload(pid, tenant.id, "report.pdf", content_type="application/pdf")   # streamed
ax.files.download_to(pid, tenant.id, info.id, "/tmp/report.pdf")                       # streamed
with ax.files.stream(pid, tenant.id, info.id) as resp:
    for chunk in resp.iter_bytes():
        ...

res = ax.usage.record(pid, tenant.id, "api_calls", 1, idempotency_key=request_id)
res.replayed, res.quota.remaining

try:
    ax.usage.record(pid, tenant.id, "api_calls", 1000, idempotency_key="big-1", enforce=True)
except AxentraApiError as e:
    if e.code == "quota_exceeded":
        ...                                        # e.status == 429, e.retry_after, e.request_id
ax.close()                                         # or use `with AxentraClient(...) as ax:`
```

Async: the same API with `await`, `async for` and `async with`:

```python
from axentra_client import AsyncAxentraClient

async with AsyncAxentraClient("https://api.example.com") as ax:
    await ax.auth.login_password("me@example.com", "password")
    async for msg in ax.notify.iter_messages(pid, tenant_id=tid):
        ...
    async with ax.files.stream(pid, tid, fid) as resp:
        async for chunk in resp.aiter_bytes():
            ...
    await ax.auth.logout()
```

## Authentication

| Way | How | Notes |
|---|---|---|
| API key | `AxentraClient(url, api_key="axk_...")` | Machines. Product-scoped, optionally tenant-scoped, explicit permissions |
| Password login | `ax.auth.login_password(email, password)` | Reads the session token from the response's `Set-Cookie` and sends it as `Authorization: Bearer` from then on. No CSRF is needed for bearer sessions. `ax.auth.logout()` ends the session and forgets the token |
| Existing session token | `AxentraClient(url, session_token=...)` | E.g. a CLI that stored the token |
| First run | `ax.auth.setup(setup_token, email, password)` | Registers the first platform admin and logs in |

The client keeps **no cookie jar** (a stored cookie would switch the server into cookie + CSRF
mode); it authenticates with bearer tokens only. `ax.token` / `ax.set_token(...)` read and change
the credentials. Every request carries
`Axentra-Client: axentra-client-python/<version>; api=<major.minor>`.

## Resources

| Attribute | Methods |
|---|---|
| (client) | `meta()`, `check_compatibility()`, `request()`, `request_json()`, `stream()` |
| `auth` | `login_password`, `setup`, `session`, `sessions`, `logout` |
| `me` | `get(tenants=)` (`all`, `memberships` or `none`), `update` |
| `products` | `list`, `get`, `create`, `update(version=)` |
| `tenants` | `list` (page), `iter`, `get`, `create`, `update(version=)`, `delete` |
| `operators` (product members) | `list`, `add`, `change`, `remove` |
| `members` (tenant members) | `list`, `add`, `change`, `remove` |
| `invitations` | `list`, `create` (returns the one-time `token`), `revoke`, `accept` |
| `roles` | `list`, `permissions(include_retired=)` (built-in and product-defined catalog of a product), `all_permissions` (built-in catalog), `declare_permission`, `retire_permission`, `create`, `update(version=)`, `delete` |
| `api_keys` | `list`, `get`, `create` (returns the `secret` once), `revoke`, `rotate` |
| `records` | `list` (page), `iter`, `get`, `create`, `replace(version=)`, `delete(version=)` |
| `files` | `upload` (bytes, file object or path), `get`, `list`, `iter`, `update`, `delete`, `download`, `download_to`, `stream`, `download_url` |
| `usage` | `record(idempotency_key=)`, `record_batch`, `reserve(idempotency_key=)`, `reservation`, `commit`, `release`, `events`, `iter_events`, `summary`, `quotas`, `set_quota`, `delete_quota`, `meters`, `create_meter` |
| `billing` | `plans`, `tenant_plans`, `create_plan`, `subscriptions`, `subscription`, `checkout`, `subscribe`, `change_plan`, `cancel`, `resume`, `entitlements` |
| `notify` | `send(idempotency_key=)`, `messages`, `iter_messages`, `message`, `templates`, `template`, `create_template`, `update_template(version=)`, `delete_template(version=)`, `preview_template`, `preview_draft`, `preferences`, `set_preferences(version=)`, `inbox(unread_only=)`, `unread_count`, `mark_read(message_ids=None)` (the caller's own) |
| `audit` | `list`, `iter`, `get` |
| `events` | `publish(idempotency_key=)`, `list` (page; `type` exact or `prefix.*`), `iter`, `get`, `stream(types=, last_event_id=)` (server-sent events as `StreamMessage {id, event, data}`) |
| `jobs` | `enqueue(idempotency_key=)`, `list` (page), `iter`, `get`, `retry`, `cancel`, `stats`, `kinds` (what the caller may enqueue), `stream(last_event_id=)` (job status changes) |
| `schedules` | `create` (`interval_seconds` or `cron`), `list` (page), `iter`, `get`, `update(version=)`, `delete(version=)` |
| `webhooks` | `create` and `rotate_secret` (return the signing `secret` once), `list` (page), `iter`, `get`, `update(version=)`, `delete(version=)`, `test`, `deliveries`, `iter_deliveries`, `delivery`, `redeliver` |
| `search` | `index` (add or replace a document), `index_batch` (up to 100, all or nothing), `query` (page; `kinds=`, `metadata=`), `iter`, `document`, `remove`, `remove_kind`, `kinds` |
| `users` | `list` (page; all users or `product_id=`), `iter`, `get`, `update` (status, platform role), `memberships`, `sessions`, `revoke_sessions`, `create_external`, `identities`, `link_identity`, `unlink_identity` |
| `product_invitations` | `list`, `create` (returns the one-time `token`), `revoke`, `accept` |

Models (`axentra_client.models`) are pydantic v2 models. Following the API conventions they
**never reject what they do not know**: unknown fields are kept (`model_extra`), enum-like fields
are plain `str`, so a newer server minor does not break an older client. Usage quantities and
limits are `Decimal`. `version` arguments send `If-Match`; a stale version raises
`AxentraApiError(412, "precondition_failed")`.

`Idempotency-Key`: `usage.record` always sends one. Pass your own stable key (request id, order
id) so that retries are safe; without one a random key is generated and the call is not safe to
retry. `notify.send`, `events.publish` and `jobs.enqueue` send one only when you pass it; a key
reused with a different request raises `AxentraApiError(409)`.

## Errors

Every non-2xx answer raises `AxentraApiError` with `status`, `code` (stable machine-readable code
from the RFC 9457 body, else derived from the status), `title`, `detail`, `request_id` (body or
`X-Request-ID` header), `errors` (`[{loc, msg}]` for `validation_failed`), `retry_after` (429) and
the raw `problem`. Transport errors are httpx exceptions (`httpx.TransportError`), unwrapped.
`IncompatibleApiError` (`reason`, `server`, `required`) comes from `check_compatibility()`.
Both derive from `AxentraError`.

## Endpoints without a typed method

New endpoints are reachable at once through the generic methods, with the same authentication
and error mapping:

```python
stats = ax.request_json("GET", f"/v1/products/{pid}/notify/stats")
with ax.stream("GET", f"/v1/products/{pid}/exports/{eid}/content") as resp: ...
```

## How the SDK is maintained

The Python SDK is **hand-maintained** (an ergonomic, resource-oriented API is worth more here
than a mechanical one-method-per-operation mirror) and kept honest by **contract tests against
the live API**:

- `src/axentra_client/_async/client.py` is the single source. The sync client
  `_sync/client.py` is generated from it with `python scripts/unasync.py` (textual async -> sync
  transformation); a unit test fails when it is stale.
- `tests/unit` (httpx `MockTransport`) also checks that every path the client calls exists in the
  committed `openapi/axentra-v1.json` and that `API_VERSION` equals the contract's `info.version`.
- `tests/integration` runs every resource against a real Axentra app (the server package is
  imported **only in these tests**), served by uvicorn on a free port, on a fresh PostgreSQL
  database owned by a non-superuser role (RLS enforced).
- `tests/e2e` runs against a separately started `axentra serve` (`scripts/sdk-e2e.sh`).

Adding an endpoint: add a method to the resource class in `_async/client.py` (model in
`models.py` if needed), run `python scripts/unasync.py`, add an integration test, and bump
`API_VERSION` when the client starts to depend on a newer API minor.

```bash
cd sdk/python
pip install -e "../..[server]" -e ".[test]"
python scripts/unasync.py
ruff check src tests scripts && ruff format --check src tests scripts && mypy
AXENTRA_TEST_DATABASE_URL=postgresql://postgres:pg@127.0.0.1:5432/postgres pytest -ra
```

## Limitations

- Covers the resources in the table above, not every operation (no OIDC browser flow, meters
  update/delete, plan update/delete, storage quotas, notify stats and mailbox). Use `request_json`
  for those until typed methods are added.
- `events.stream()` / `jobs.stream()` end when the server closes the stream
  (`events.sse_max_seconds`); reconnect with the last message's `id` as `last_event_id`. Close an
  unfinished stream (`.close()` / `await .aclose()` on the iterator) to release the connection.
- No automatic retries or rate-limit backoff (use idempotency keys and `retry_after`).
- `files.upload` in the async client reads a given file object synchronously while sending.
- Not yet published to PyPI.
