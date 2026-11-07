# Data: records, product tables, migrations, pagination, concurrency

## Two ways to store product data

| | Records (`axentra_records`) | Own product tables |
|---|---|---|
| What | Tenant-owned JSON documents in named collections | Relational tables a product defines in its own migration namespace |
| Use for | Settings-like data, prototypes, small document data, data a generic UI (Studio) should list | Core domain data with relations, constraints, aggregates, heavy queries |
| Schema | None (JSON object, at most 256 KiB); collection name `^[a-z][a-z0-9_]{0,62}$` | Your SQL |
| Access | `ax.records` (authorized: `records:read` / `records:write`) and `/v1/.../records/{collection}` | Your code via `ax.db.transaction(DbScope.tenant(...))` after `ax.authz.require(...)` |
| Filtering | JSON containment on top-level fields (`?where[field]=value`, `data @> ...`, GIN index) | Any SQL |
| Sorting | `id`, `created_at`, `updated_at` (prefix `-` for descending) | Any |
| Isolation | Forced RLS (tenant scope) | Forced RLS if you follow the template |
| Concurrency | `version` + `If-Match` | Your choice; the template uses `version` |

Records are not a general document database: there are no secondary indexes per field, no
partial updates (`PUT` replaces `data`), and only record deletion writes an audit event.
For anything beyond that, use a product table: [guides/PRODUCT_TABLES.md](../guides/PRODUCT_TABLES.md).

## RLS template for product tables

Every product or tenant table carries `product_id` (and `tenant_id` when tenant-owned), a
foreign key to `axentra_tenants (product_id, id)` (or `axentra_products (id)`) with
`ON DELETE CASCADE`, and the scope policy:

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON <t>
    USING (axentra_scope_allows(product_id, tenant_id))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id));
```

For product-level tables (no tenant), use `axentra_scope_allows(product_id, NULL)`; such rows are
also visible in tenant scope of the same product (see
[SECURITY_MODEL](SECURITY_MODEL.md#row-level-security-design)).

## Migrations and namespaces

- Plain SQL files `NNNN_name.sql`, grouped by **namespace**. Axentra's own files live in
  `axentra/data/sql/` (namespace `axentra`, reserved). Products register theirs
  (`ax.register_migrations(load_directory("crm", path))`), and `ax.migrate()` applies Axentra's
  first, then each product namespace in registration order.
- Applied migrations are recorded in `axentra_schema_migrations (namespace, version, name,
  checksum, applied_at)`. A changed file that was already applied stops the run
  ("changed after it was applied"): never edit an applied migration, add a new one.
- Each migration runs in its own transaction (except `-- axentra:no-transaction` files, below); concurrent runners (several containers starting at
  once) serialize on a PostgreSQL advisory lock.
- Forward only. Rolling back means restoring a backup taken before the migration
  ([BACKUP_RESTORE](../operations/BACKUP_RESTORE.md)); write migrations so that the previous
  release still works with the new schema where possible (expand, then contract).
- Migrations may run with a separate owner connection (`database.migration_url_ref`, or
  `migration_url` outside production); the API should run as a role without DDL rights
  ([DEPLOYMENT](../operations/DEPLOYMENT.md)).
- `axentra migrate` (CLI) applies Axentra's namespace and every discovered product namespace:
  sources listed in `database.extra_migrations` (`"crm.schema:migrations"`, a list of `Migration`
  or a callable returning one, e.g. `lambda: package_migrations("crm", "crm.sql")`) in the listed
  order, then entry points of the group `axentra.migrations` of installed packages (by entry point
  name; off with `database.migration_entry_points = false`). `ax.migrate()` additionally applies
  migrations passed to `register_migrations`. The same migration registered twice is applied
  once; two different migrations claiming one `namespace:version` are refused.
- **Schema newer than code.** `MigrationRunner.check(namespaces=None)` (CLI
  `axentra migrate --check [--namespace NS]`, exit code 3 when not current) reports per namespace
  the applied versions, the pending ones (code newer than schema), the **unknown** ones (applied in
  the database but not in the code: the schema is newer than the code, e.g. after rolling back the
  application) and changed checksums. `migrate()` refuses with a `ConfigurationError` while a
  namespace the code registers has unknown versions (`allow_newer=True` / `--allow-newer`
  overrides) and refuses changed checksums before applying anything. Namespaces recorded in the
  database that this process does not register at all (another product's schema in a shared
  database) are listed with `registered: false` and never block, unless named explicitly.
- **Pre-migration hook.** `migrate(before_apply=fn)` (also `ax.migrate(before_apply=fn)`) calls
  `fn(pending)` once, under the migration advisory lock, only when something is pending, e.g. to
  take a backup. If it raises, nothing is applied and the error propagates.
- **Serving gate.** `MigrationRunner.require_current(namespaces)` / `ax.require_current_schema()`
  raise `SchemaNotCurrent` (`503`, code `schema_not_current`) on pending, unknown or changed
  migrations. With `database.require_current_schema = true` (default false), `Axentra.start()`
  runs the gate (through the application pool, which needs `SELECT` on
  `axentra_schema_migrations`) and `/v1/health/ready` reports a `schema` check.
- **Non-transactional steps.** A file whose leading comment lines contain
  `-- axentra:no-transaction` runs outside a transaction, statement by statement in autocommit
  mode (for `CREATE INDEX CONCURRENTLY`, or `ALTER TYPE ... ADD VALUE` before PostgreSQL 12), and
  is recorded after its last statement. It cannot be rolled back halfway: make every statement
  re-runnable (`IF NOT EXISTS`, `CREATE OR REPLACE`). Statements are split at top-level
  semicolons (quotes, dollar quotes and comments are respected).
  An interrupted `CREATE INDEX CONCURRENTLY` leaves an `INVALID` index that `IF NOT EXISTS` would
  keep: find it with `SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid`, drop it
  (`DROP INDEX CONCURRENTLY ...`) and run `axentra migrate` again. Axentra's own `0014` (time-sort
  indexes of `axentra_records`) is such a migration. Runners wait for the migration lock by
  polling (`pg_try_advisory_lock`), so a waiting runner holds no snapshot that a concurrent index
  build of the lock holder would wait for.
- **Timeouts.** `-- axentra:lock-timeout=<duration>` and `-- axentra:statement-timeout=<duration>`
  in a file's leading comment lines (a PostgreSQL duration: `250ms`, `5s`, `2min`) set
  `lock_timeout` / `statement_timeout` for that migration only; `database.migration_lock_timeout_ms`
  and `database.migration_statement_timeout_ms` (default `0`, off) are the defaults for all. A
  migration that hits the lock timeout (for example an `ALTER TABLE` behind a long-running
  transaction) fails without being recorded instead of queueing every query of the table behind
  its lock request; run `axentra migrate` again later. An invalid duration is refused when the
  migration is registered.
- **Dry run.** `axentra migrate --dry-run` (`MigrationRunner.plan()` + `render_plan()`) prints the
  SQL of the pending migrations in apply order, with their timeouts and `BEGIN`/`COMMIT` for
  transactional ones, after the same refusals as `migrate` (changed or unknown applied
  migrations; `--allow-newer` applies here too). Nothing is applied and no lock is taken.
- Backups: `pg_dump` must run as a superuser or a dedicated backup role with `BYPASSRLS`
  (`pg_read_all_data`); forced RLS makes dumps as the owner or the application role fail
  ([BACKUP_RESTORE](../operations/BACKUP_RESTORE.md#database-backup)).

## Identifiers

Opaque prefixed ids (`ten_01jbx3k7d2h9q8w5v4c3b2a1z0`): a 2-4 letter prefix plus 26 characters of
Crockford base32 encoding a 48-bit millisecond timestamp and 80 random bits (ULID layout). They
sort roughly by creation time, which keeps B-tree indexes compact and keyset pagination cheap.
Clients must not parse them ([ADR 0008](../adr/0008-ids-and-pagination.md)).

## Pagination and filtering

- Keyset (cursor) pagination: `?limit=` (1-200, default 50) and `?cursor=`; responses are
  `{"items": [...], "next_cursor": "..." | null}`. The cursor is an opaque, URL-safe base64 JSON
  list of the last row's sort key and id; a malformed or tampered cursor gives `400 invalid_cursor`
  (`decode_cursor(cursor, shape)` checks the number and types of the values before any SQL).
  Cursors carry no authority: the next page is authorized and scoped like the first.
- Services fetch `limit + 1` rows to know whether a next page exists; there are no total counts
  (counting is expensive and leaks information). Use `/overview` or collection statistics.
- Sorting is restricted to documented fields; ties are broken by `id`, so pages are stable.
- Filters are plain query parameters documented per endpoint. Free-text `q` filters use `ILIKE`
  with `%` and `_` escaped.

## Concurrency

- **Optimistic concurrency** for edited resources with a `version` column (products, tenants,
  roles, records): `If-Match: <version>` on `PUT/PATCH/DELETE`; a mismatch returns `412
  precondition_failed`. Without `If-Match` the last write wins. Each update increments `version`.
- Updates lock the row (`SELECT ... FOR UPDATE`) inside the transaction, compare the version and
  write; two concurrent writers with the same `If-Match` cannot both succeed.
- Invariants that span rows (last platform admin, last owner) are checked inside the same
  transaction as the change.
- Audit events are written in the same transaction as the change they describe.
- `statement_timeout` (`database.statement_timeout_ms`, default 30 s) bounds every statement.
