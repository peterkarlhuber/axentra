# Guide: adding relational product tables

Records are fine for document-like data. For core domain data (deals, invoices, bookings) a
product defines its own tables in its own **migration namespace**, protected by the same
row-level security as Axentra's tables. The example below is real: the SQL file is
[examples/crm/migrations/0001_deals.sql](examples/crm/migrations/0001_deals.sql) and
`tests/integration/test_product_tables_guide.py` runs it against PostgreSQL with a non-superuser
role and checks isolation and cascading deletes.

## 1. Rules

1. Prefix every table, index and function with your namespace (`crm_`). Never alter `axentra_*`
   objects.
2. Tenant-owned tables have `product_id` and `tenant_id`, both `NOT NULL`, and
   `FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE`.
   Product-level tables have `product_id` with a foreign key to `axentra_products (id)`.
3. `ENABLE` **and** `FORCE ROW LEVEL SECURITY`, plus the `scope` policy with
   `axentra_scope_allows(product_id, tenant_id)` in `USING` and `WITH CHECK`.
4. Index `(product_id, tenant_id, ...)` first: every query filters by them.
5. Ids from `axentra.core.ids.new_id("<prefix>")` (2-4 lowercase letters), a `version` column if
   rows are edited concurrently.
6. Never edit a migration after it was applied anywhere; add `0002_...`.

## 2. The migration

`migrations/0001_deals.sql`:

```sql
CREATE TABLE crm_deals (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    stage text NOT NULL DEFAULT 'open' CHECK (stage IN ('open', 'won', 'lost')),
    amount_cents bigint NOT NULL DEFAULT 0 CHECK (amount_cents >= 0),
    version integer NOT NULL DEFAULT 1,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX crm_deals_list ON crm_deals (product_id, tenant_id, id);
CREATE INDEX crm_deals_stage ON crm_deals (product_id, tenant_id, stage);

ALTER TABLE crm_deals ENABLE ROW LEVEL SECURITY;
ALTER TABLE crm_deals FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON crm_deals
    USING (axentra_scope_allows(product_id, tenant_id))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id));
```

Data migrations (backfills) run as the owner role, and `FORCE` applies RLS to it as well: start
such a migration with `SELECT set_config('axentra.scope', 'platform', true);` or the statements
see no rows.

## 3. Register and run the migrations

```python
from pathlib import Path

from axentra.config import load_settings
from axentra.data.migrations import load_directory
from axentra.platform import Axentra

ax = Axentra.from_settings(load_settings())
ax.register_migrations(load_directory("crm", Path(__file__).parent / "migrations"))
ax.migrate()   # Axentra's namespace first, then "crm"; idempotent, checksummed, advisory-locked
ax.start()
```

Run `ax.migrate()` from your product's deployment step (a one-shot job, like the `migrate`
service in the compose files). `axentra migrate` alone does not know your namespace.

## 4. Use the table with authorization, scope and audit

```python
from axentra.core.context import Principal
from axentra.core.errors import NotFound, PreconditionFailed
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import DbScope


def create_deal(principal: Principal, product_id: str, tenant_id: str, title: str, amount_cents: int) -> str:
    ax.authz.require(principal, "records:write", product_id, tenant_id)   # 404/403 as usual
    deal_id = new_id("deal")
    with ax.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
        tx.execute(
            "INSERT INTO crm_deals (id, product_id, tenant_id, title, amount_cents, created_by)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (deal_id, product_id, tenant_id, title, amount_cents, principal.actor.id),
        )
        ax.audit.record(
            tx, principal, "crm.deal.create", target_type="deal", target_id=deal_id,
            product_id=product_id, tenant_id=tenant_id, details={"title": title},
        )
    return deal_id


def list_deals(principal: Principal, product_id: str, tenant_id: str, *, limit: int | None = None,
               cursor: str | None = None) -> Page[dict]:
    ax.authz.require(principal, "records:read", product_id, tenant_id)
    limit = clamp_limit(limit)
    after = decode_cursor(cursor)
    sql = "SELECT * FROM crm_deals WHERE product_id = %s AND tenant_id = %s"
    params: list = [product_id, tenant_id]
    if after:
        sql += " AND id > %s"
        params.append(after[0])
    params.append(limit + 1)
    with ax.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
        rows = tx.all(sql + " ORDER BY id LIMIT %s", params)
    items = rows[:limit]
    return Page[dict](items=items, next_cursor=encode_cursor([items[-1]["id"]]) if len(rows) > limit else None)


def rename_deal(principal: Principal, product_id: str, tenant_id: str, deal_id: str, title: str,
                if_match: int | None) -> None:
    ax.authz.require(principal, "records:write", product_id, tenant_id)
    with ax.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
        row = tx.one("SELECT version FROM crm_deals WHERE id = %s AND tenant_id = %s FOR UPDATE",
                     (deal_id, tenant_id))
        if row is None:
            raise NotFound("deal not found")
        if if_match is not None and row["version"] != if_match:
            raise PreconditionFailed("the deal was changed by someone else")
        tx.execute("UPDATE crm_deals SET title = %s, version = version + 1, updated_at = now() WHERE id = %s",
                   (title, deal_id))
        ax.audit.record(tx, principal, "crm.deal.rename", target_type="deal", target_id=deal_id,
                        product_id=product_id, tenant_id=tenant_id)
```

Notes:

- Keep the explicit `WHERE product_id/tenant_id` even though RLS would filter: RLS is the second
  line of defense, and the explicit filter lets PostgreSQL use the index.
- Always pick the narrowest scope (`tenant` for tenant data). `DbScope.platform()` disables the
  protection for that transaction.
- The permission catalog is fixed in this version, so product tables reuse `records:read` and
  `records:write` (or other existing permissions). Product-defined permissions are on the
  [TODO list](../TODO.md).
- Grants: with the compose roles (`deploy/compose/initdb/01-roles.sql`), tables created by the
  owner role are automatically usable by the application role (default privileges). On other
  setups, grant `SELECT, INSERT, UPDATE, DELETE` on your tables to the application role.
- Deleting a tenant through Axentra cascades to your rows via the foreign key.
