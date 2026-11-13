# Guide: building a product on Axentra

This guide walks through a product backend on Axentra, step by step. Every snippet comes from
the tested example [examples/taskboard](../../examples/taskboard/), a multi-tenant project and
task SaaS. Read [PRODUCT_TABLES.md](PRODUCT_TABLES.md) for the rules of product tables, and
[DEPLOYMENT_MODELS.md](../architecture/DEPLOYMENT_MODELS.md) for single- vs multi-product.

## 0. Choose the integration style

| | Library (in-process) | HTTP (separate server) |
|---|---|---|
| Your backend | Python, imports `axentra.platform.Axentra` | Any language, calls `/v1/...` |
| Your own tables | Yes, same database, RLS-protected | No (use records, or your own database) |
| Auth in your routes | `axentra.api.context.resolve_principal` | Forward the session cookie, bearer token or API key |
| Example | `examples/taskboard` | `examples/single-product`, `examples/multi-product` |

The library style can still serve the full Axentra API. Taskboard mounts it under `/axentra`,
so login, sessions, members, invitations, roles, API keys and audit need no code of your own.
Axentra Studio can manage the product through that API.

## 1. Install

```bash
pip install -r requirements/tabrion.txt "axentra[server]"  # library + FastAPI pieces; add [oidc], [s3], [otel] as needed
```

Tabrion, which Axentra requires, is not on a package index: `requirements/tabrion.txt` (from the Axentra commit you
install, pip 25.0 or newer) says where it comes from. In this repository:
`pip install -r requirements/tabrion.txt -e ".[dev]" && pip install -e examples/taskboard`.

## 2. Configure

Axentra reads one settings object from a TOML file (`AXENTRA_CONFIG`) and `AXENTRA__SECTION__KEY`
variables ([CONFIGURATION.md](../operations/CONFIGURATION.md)). For a product with its own
installation, use single-product mode:

```toml
environment = "production"
mode = "single"

[product]
slug = "taskboard"
name = "Taskboard"

[database]
url_ref = "env:AXENTRA_DATABASE_URL"     # runtime role: no superuser, no BYPASSRLS

[security]
public_url = "https://taskboard.example.com/axentra"   # include the mount prefix
allowed_origins = ["https://taskboard.example.com"]   # your frontend origin
master_keys_ref = "env:AXENTRA_MASTER_KEYS"

[billing]
provider = "manual"   # or "stripe"
```

In multi-product mode the same backend runs as one product of a shared installation. It then
looks up its product by `product.slug` (see `resolve_product_id` in `taskboard/app.py`).

## 3. Migrations: your own namespace

Put plain SQL files `NNNN_name.sql` in your package and register them under your namespace:

```python
from axentra.data.migrations import load_directory

def taskboard_migrations():
    return load_directory("taskboard", Path(__file__).parent / "migrations")

ax = Axentra.from_settings(load_settings())
ax.register_migrations(taskboard_migrations())
ax.migrate()          # Axentra's namespace first, then "taskboard"; checksummed, advisory-locked
```

Run this in your deployment step as the schema owner (`python -m taskboard migrate`, the
`migrate` service in `deploy/compose/docker-compose.taskboard.yml`). The plain `axentra migrate`
command does not know your namespace.

Each tenant-owned table needs `product_id`, `tenant_id` and a foreign key to
`axentra_tenants (product_id, id) ON DELETE CASCADE`, plus `ENABLE` **and** `FORCE ROW LEVEL
SECURITY` with the scope policy:

```sql
CREATE POLICY scope ON taskboard_tasks
    USING (axentra_scope_allows(product_id, tenant_id))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id));
```

Tables with product-level rows (nullable `tenant_id`) use `axentra_scope_allows_write` in
`WITH CHECK` instead, so tenant code cannot write them (see `PRODUCT_TABLES.md`, rule 3).

Taskboard adds a composite foreign key `(product_id, tenant_id, project_id) -> taskboard_projects`.
A task can therefore never point at another tenant's project, whatever the application code does.

## 4. Authentication

Mount the Axentra API and reuse its principal resolution in your routes:

```python
from axentra.api.app import create_app
from axentra.api.context import CurrentPrincipal          # Depends(resolve_principal)
from axentra.api.problems import axentra_error_handler

app = FastAPI(lifespan=...)                     # lifespan: ax.start() ... ax.close()
app.state.axentra = ax                          # resolve_principal finds Axentra here
app.add_exception_handler(AxentraError, axentra_error_handler)
app.include_router(router)                      # your /api routes
app.mount("/axentra", create_app(axentra=ax, start=False))

@router.get("/api/workspaces/{tenant_id}/projects")
def list_projects(tenant_id: str, principal: CurrentPrincipal, svc: Svc): ...
```

- Browsers log in with `POST /axentra/v1/auth/login/password`. The `Path=/` session cookie also
  authenticates `/api`. Unsafe methods need the `X-Axentra-CSRF` header (the `csrf_token` from the
  login response).
- SDKs and CLIs send the session token as `Authorization: Bearer`. Integrations use API keys
  (`axk_...`), created by product operators and confined to the product or one tenant.
- Keep a route-protection check like Axentra's. `taskboard.app.check_routes` refuses to start if
  a route neither depends on `resolve_principal` nor is listed as public. Walk the routes with
  `axentra.api.app.iter_api_routes`, because newer FastAPI versions keep included routers as
  wrapper objects.
- Signup is your product's decision. Taskboard's public `POST /api/signup` throttles per IP
  (`ax.identity.hit`, an atomic per-minute counter). It creates the tenant first, so a taken slug fails
  before an account exists. It then calls `ax.identity.create_user`, adds the owner membership and
  subscribes the free plan, and deletes the tenant again if a later step fails.

## 5. Authorization

Every service method takes the principal first and asks Axentra before touching data:

```python
def get_task(self, principal, tenant_id, task_id):
    self.ax.authz.require(principal, "records:read", self.product_id, tenant_id)   # 404 / 403
    with self.ax.db.transaction(DbScope.tenant(self.product_id, tenant_id), read_only=True) as tx:
        row = tx.one("SELECT * FROM taskboard_tasks WHERE id = %s AND product_id = %s AND tenant_id = %s",
                     (task_id, self.product_id, tenant_id))
    if row is None:
        raise NotFound("task not found")
    return Task.model_validate(row)
```

- `require` raises `NotFound` for callers without any relation to the tenant (no existence oracle)
  and `Forbidden` for related callers without the permission.
- Product tables can reuse `records:read`/`records:write`, or the product declares its own
  permissions (see below). Taskboard reuses the built-in ones and lets `members:manage`
  (workspace owner/admin) change the plan.
- Own permissions: register them once per process, before or after `ax.start()`:

  ```python
  from axentra.access import ProductPermission

  ax.permissions.register("taskboard", [   # product slug or id
      ProductPermission("taskboard.tasks:assign", "tenant", "Assign tasks to members",
                        default_roles=("member",)),
      ProductPermission("taskboard.boards:read", "tenant", "View boards"),
      ProductPermission("taskboard.reports:export", "product", "Export product reports"),
  ])
  ax.authz.require(principal, "taskboard.tasks:assign", product_id, tenant_id)
  ```

  Names are `<namespace>.<resource>:<action>` (use the product slug as namespace). Owners and
  admins hold them automatically (tenant owners/admins the tenant-scoped ones), viewer/support
  roles the read-like ones, `member`/`viewer` what `default_roles` lists; custom roles and API
  keys made in Studio can carry them. A permission that a later registration no longer lists is
  retired and grants nothing anymore. Rules: docs/architecture/SECURITY_MODEL.md,
  "Product-defined permissions".
- When the product, not the user, decides an action is allowed (for example creating the
  workspace at signup, or recording usage), act as `Principal.system("taskboard")` *after*
  checking the user. Never pass a system principal for something the user asked for without such a check.
- Use the narrowest `DbScope` (tenant for tenant data). RLS is the second line of defense if a
  `WHERE` is ever forgotten.

## 6. Audit

Write audit events in the same transaction as the change:

```python
with self.ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
    tx.execute("DELETE FROM taskboard_tasks WHERE id = %s", (task_id,))
    self.ax.audit.record(tx, principal, "taskboard.task.delete", target_type="task", target_id=task_id,
                         product_id=pid, tenant_id=tid, details={"title": row["title"]})
```

The events appear in `GET /axentra/v1/audit` (product operators with `audit:read`) and in Studio.
Details are redacted by Axentra (keys that look like secrets).

## 7. Usage metering and plan limits

Define a meter and plans once (idempotent bootstrap at startup):

```python
ax.usage.create_meter(SYSTEM, pid, key="tasks_created", aggregation="sum", reset_period="month",
                      default_limit=50, default_enforcement="hard")
ax.billing.create_plan(SYSTEM, pid, key="free", name="Free", entitlements={"limit.tasks_created": 50})
ax.billing.create_plan(SYSTEM, pid, key="pro", name="Pro",
                       prices=[{"amount_minor": 900, "currency": "EUR", "interval": "month"}],
                       entitlements={"limit.tasks_created": None})          # null = unlimited
ax.billing.create_subscription(SYSTEM, pid, tenant_id, plan="free")        # at signup
```

The effective limit is the first match of tenant quota override, plan entitlement
`limit.<meter>`, and the meter's default. To meter an action without over- or under-counting
under concurrency, reserve first, then do the work, then commit:

```python
res = ax.usage.reserve(SYSTEM, pid, tid, "tasks_created", 1, ttl_seconds=60)   # QuotaExceeded -> 429
try:
    insert_task(...)
except BaseException:
    ax.usage.release_reservation(SYSTEM, pid, tid, res.id)
    raise
ax.usage.commit_reservation(SYSTEM, pid, tid, res.id)
```

The 429 response is Axentra's problem document (`code: quota_exceeded`, `meter`, `limit`, `used`,
`Retry-After`). Plan changes go through `ax.billing.change_plan` (manual provider) or
`ax.billing.create_checkout` (Stripe). Your backend decides who may buy what.

## 8. Files

```python
info = ax.storage.upload(principal, pid, tid, stream, name=filename, content_type=ctype,
                         metadata={"taskboard.task_id": task_id})     # files:write, quotas, sniffing
page = ax.storage.list(principal, pid, tid, metadata={"taskboard.task_id": task_id})
info, chunks = ax.storage.open(principal, pid, tid, file_id)          # files:read
```

For HTTP uploads use `axentra.api.multipart.parse_upload` (streaming, size limit enforced while
reading). Authorize before reading the body.

## 9. Tests

Reuse the repository's fixtures (`tests/conftest.py`). They create a fresh database per session
and a non-superuser role, so RLS is enforced as in production. Taskboard's
`examples/taskboard/tests/conftest.py` shows how: truncate, `register_migrations` + `migrate`,
`start`, build the app with `start=False`, then drive it with `TestClient`. Cover at least: two
tenants isolated over HTTP **and** directly in SQL (unscoped connection sees nothing; `WITH CHECK`
refuses foreign rows), permission denial per role and API key, quotas (including concurrency),
and audit events of destructive actions.

## 10. Deploy

- Two database roles: an owner that runs migrations and an application role without
  superuser/BYPASSRLS (`deploy/compose/initdb/01-roles.sql`). Default privileges make your tables
  usable by the application role.
- A one-shot migration job before the app (`migrate` service), then the app.
- [deploy/compose/docker-compose.taskboard.yml](../../deploy/compose/docker-compose.taskboard.yml)
  runs Taskboard with its own PostgreSQL in single-product mode. The image comes from
  `examples/taskboard/Dockerfile`.
- Schedule the periodic jobs Axentra does not run by itself:
  `ax.usage.sweep_expired_reservations()`, `ax.billing.advance_periods()` (manual provider),
  `axentra storage purge`, `axentra maintenance purge`.
- Production checklist: [DEPLOYMENT.md](../operations/DEPLOYMENT.md).

To provision products, operators and keys over HTTP (and to prove their isolation), see
`examples/single-product/provision.py` and `examples/multi-product/provision.py`.
