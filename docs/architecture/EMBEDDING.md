# Embedding Axentra as a library

This page is for product backends that import Axentra (`axentra.platform.Axentra`) into their own
process and web framework instead of, or next to, running `axentra serve`. The general rules
(services authorize, `Principal.system()` is all-powerful, sync API, one pool per process) are in
[OVERVIEW](OVERVIEW.md#library-vs-http-usage). Axentra stays product-agnostic: everything below is
generic. A product with its own PostgreSQL server profile, such as Nodestro
([migration plan](../integrations/NODESTRO_MIGRATION_PLAN.md)), is one example consumer.

## Construction

```python
from axentra import load_settings
from axentra.config.secrets import Keyring
from axentra.platform import Axentra

settings = load_settings(None, environ=host_environ, **overrides)
ax = Axentra(settings, keyring=Keyring.parse(host_config.master_keys))  # keyring: optional
ax.start()
...
ax.close()
```

- `keyring=`: the host loads the master keys from its own validated configuration (environment
  mapping, file, secret store) and passes them. Axentra then neither resolves
  `security.master_keys_ref` nor writes a development keyring file, and production does not
  require `master_keys_ref` (every other production check stays, including the refusal of inline
  `security.master_keys`).
- `database=`: a prepared `axentra.data.Database` (default: built from `settings.database`).

## Error mapping

Every Axentra error is an `axentra.core.errors.AxentraError` with a stable `code` and HTTP
`status`. A host with its own web layer maps any exception with
`axentra.core.errors.problem_details(exc)`, which returns a framework-independent `ProblemInfo`:

| Field | Meaning |
| --- | --- |
| `status`, `code`, `title` | From the error class (`404`, `not_found`, `Not found`) |
| `detail` | Client-safe text, redacted (tokens, keys, URLs with passwords removed) |
| `extra` | Additional problem members, e.g. `{"reason": "email_not_verified"}` or quota numbers |
| `headers` | Response headers, e.g. `Retry-After` for `429` (default 60 s, or the error's `retry_after`) |
| `internal` | `True` for 5xx and for non-Axentra exceptions: log the original exception; the problem itself is the generic `500 internal` without details |
| `body(request_id=...)` | The `application/problem+json` body exactly as the Axentra HTTP API renders it |

Axentra's own FastAPI handlers use the same function, so both stay identical. Example for any
framework:

```python
from axentra.core.errors import problem_details

def on_error(exc):
    info = problem_details(exc)
    if info.internal:
        log.exception("internal error", exc_info=exc)
    return Response(json.dumps(info.body(request_id=rid)), status=info.status,
                    headers={"Content-Type": "application/problem+json", **info.headers})
```

## Joining the host's transaction

The host may have its own psycopg connection to the **same database** and want Axentra writes to
commit or roll back together with its own changes. The connection must be inside a transaction
block (`conn.info.transaction_status` is `INTRANS`): `with conn.transaction():`, an explicit
`BEGIN` on an `autocommit=True` connection, or the implicit transaction of a non-autocommit
connection after its first statement. Anything else is refused with `ConfigurationError`.
Axentra never commits or rolls back the host transaction. Rows are returned as dicts regardless
of the connection's row factory.

**Whole services: `ax.db.joined(conn)`.** While the block is active, every Axentra transaction
opened **on the calling thread** (so every service call made from it, including authorization
reads) runs on `conn` inside a savepoint instead of on a pooled connection; other threads keep
using the pool.

```python
conn.execute("BEGIN")                      # host connection, autocommit=True, tuple rows
with ax.db.joined(conn):
    tenant = ax.tenancy.create_tenant(principal, product_id, slug="acme", name="Acme")
    ax.tenancy.set_member(principal, product_id, tenant.id, role="member", user_id=uid)
    conn.execute("INSERT INTO host_projects ...")
conn.execute("COMMIT")                     # or ROLLBACK: then none of it exists
```

- An Axentra error inside rolls back only to its savepoint and propagates; the host transaction
  and the host's earlier writes stay intact and usable.
- Each Axentra transaction sets its scope (`axentra.scope`, `axentra.product_id`,
  `axentra.tenant_id`) with `set_config(..., true)` and restores the enclosing scope (or the
  host's own values) when it ends.
- `read_only=True` is ignored: `SET TRANSACTION READ ONLY` cannot be issued mid-transaction.
- Services see the host's uncommitted changes. Work handed to other threads or processes (job
  workers, webhook delivery, notification dispatch) sees the rows only after the host commits.
- Use `READ COMMITTED` (the PostgreSQL default) for the host transaction: idempotency races
  (usage events, notifications) re-read the winning row after a conflict.

**Low-level: `axentra.data.join(conn, scope)`.** Yields a `Tx` on the host connection in the given
scope (no savepoint) for the APIs that take a transaction: `AuditLog.record(tx, ...)`,
`UsageService.record_in(tx, ...)`, `RecordStore` and similar. The previous scope values are
restored when the block ends.

```python
from axentra.data import DbScope, join

with conn.transaction(), join(conn, DbScope.tenant(product_id, tenant_id)) as tx:
    ax.audit.record(tx, principal, "projects.run.start", target_type="run", target_id=run_id,
                    product_id=product_id, tenant_id=tenant_id)
    ax.usage.record_in(tx, principal, product_id, tenant_id, "runs", 1, idempotency_key=run_id)
```

`UsageService.record_in` has the same validation and idempotency as `record` (a replayed key
returns the stored event and adds nothing; `enforce=True` behaves like `check_and_record`). It
refuses a transaction whose scope does not cover the product and tenant. Authorization is read on
a pooled connection (committed state) unless the call runs inside `ax.db.joined(...)`.

RLS applies to the host connection only if its role is subject to it (not a superuser, no
`BYPASSRLS`); services still filter explicitly either way.

## Migrations and the schema gate

- Register the product's namespace (`ax.register_migrations(...)`) and run `ax.migrate()` once
  per deployment. `ax.migrate(before_apply=backup)` calls `backup(pending)` under the migration
  lock when something is pending; if it raises, nothing is applied.
- `ax.migrate()` refuses when the database holds versions of a registered namespace that the code
  does not know (the schema is newer than the code); `allow_newer=True` overrides.
- `ax.schema_status()` reports applied, pending and unknown versions per namespace;
  `ax.require_current_schema(namespaces)` raises `SchemaNotCurrent` (a serving gate). With
  `database.require_current_schema = true`, `ax.start()` runs the gate and `/v1/health/ready`
  reports it.
- Non-transactional steps: files marked `-- axentra:no-transaction`. Details in
  [DATA](DATA.md#migrations-and-namespaces).

## Version checks

The package version is dynamic (hatch reads `src/axentra/_version.py`), so `pyproject.toml` has no
static `project.version`. Supported ways to read it:

- at runtime: `axentra.__version__`, or `importlib.metadata.version("axentra")` for the installed
  distribution;
- from the command line: `axentra --version`;
- over HTTP: `GET /v1/meta` (`version` and `api_version`).

Pin a compatible range in the host's dependencies (`axentra>=0.y,<0.(y+1)` before 1.0) and compare
`axentra.API_VERSION` when the host also serves Axentra's HTTP API
([VERSIONING](VERSIONING.md)).
