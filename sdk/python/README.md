# axentra-client

A small, typed Python client for the [Axentra](../../README.md) HTTP API, with a synchronous
(`AxentraClient`) and an asynchronous (`AsyncAxentraClient`) flavour. It is a **pure HTTP
client**: it depends only on `httpx` and `pydantic` and never imports the `axentra` server
package.

- Python >= 3.11
- Written against Axentra API **1.0** (`axentra_client.API_VERSION`)
- Status: alpha, not yet published to PyPI. Install from the repository:
  `pip install ./sdk/python`

Full guide: [docs/sdk/PYTHON.md](../../docs/sdk/PYTHON.md).

## Quick start

```python
from axentra_client import AxentraClient, AxentraApiError

with AxentraClient("https://api.example.com", api_key="axk_...") as ax:
    ax.check_compatibility()  # refuses an incompatible server clearly

    tenant = ax.tenants.create("prd_...", slug="acme", name="Acme")
    note = ax.records.create("prd_...", tenant.id, "notes", {"title": "Hello"})
    ax.records.replace("prd_...", tenant.id, "notes", note.id, {"title": "Hi"}, version=note.version)

    for rec in ax.records.iter("prd_...", tenant.id, "notes", page_size=100):
        print(rec.id, rec.data)

    result = ax.usage.record("prd_...", tenant.id, "api_calls", 1, idempotency_key="req-123")
    print(result.replayed, result.quota.remaining)

    try:
        ax.tenants.get("prd_...", "ten_unknown")
    except AxentraApiError as e:
        print(e.status, e.code, e.request_id)  # 404 not_found req_...
```

Async:

```python
from axentra_client import AsyncAxentraClient

async with AsyncAxentraClient("https://api.example.com") as ax:
    await ax.auth.login_password("me@example.com", "secret")  # session token as bearer
    me = await ax.me.get()
    async for event in ax.audit.iter(product_id="prd_..."):
        ...
    await ax.auth.logout()
```

## Coverage

meta + compatibility check, auth (password login, setup, session, logout, password reset,
email verification), me, products,
tenants, operators (product members), members (tenant members), invitations, roles, API keys,
records (CRUD + iterator), files (multipart upload, streamed download), usage (record and batch record with
idempotency key, events, summary, quotas, meters), billing (plans, subscription, entitlements),
notify (send, messages, templates and previews, the caller's preferences and inbox), audit, events (publish
with idempotency key, list, iterator, live stream), jobs (enqueue, list, retry, cancel, stats, the
kinds the caller may enqueue, live stream), schedules (interval or cron), webhooks (endpoints, secret
rotation, test, deliveries, redeliver), search (index, batch index, query with kind and metadata
filters, kinds, remove, remove a kind), usage reservations, billing checkout, the users admin with
external identities, product invitations and permission declarations. Anything else:
`client.request(method, path, ...)` / `client.request_json(...)`, which apply the same authentication and error mapping.

## Development

```bash
pip install -e "../..[dev]" -e ".[test]"          # from sdk/python; the server is a TEST dependency
python scripts/unasync.py                         # regenerate the sync client after editing _async/
AXENTRA_TEST_DATABASE_URL=postgresql://postgres:pg@127.0.0.1:5432/postgres pytest
ruff check src tests && mypy
```

Tests: `tests/unit` (httpx.MockTransport, no server), `tests/integration` (a real in-process
Axentra app served by uvicorn on a free port, PostgreSQL required; skipped without
`AXENTRA_TEST_DATABASE_URL`), `tests/e2e` (a running server, used by `scripts/sdk-e2e.sh`).
