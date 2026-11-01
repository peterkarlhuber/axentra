# ADR 0003: PostgreSQL with psycopg 3 and raw parameterized SQL

Status: accepted (Phase 0)

## Context

Axentra relies on PostgreSQL features: row-level security, transaction-local settings, `jsonb`
with GIN indexes, advisory locks, `FOR UPDATE`, composite foreign keys. An ORM would hide or fight
several of them, and its session and identity map complicate the explicit scope per transaction.
Nodestro already uses psycopg 3 with raw SQL, which makes a later migration simpler.

## Decision

- PostgreSQL only (15+, 16 recommended). No database abstraction for other engines.
- psycopg 3 with `psycopg_pool.ConnectionPool`, `dict_row` rows, autocommit off, a per-connection
  `statement_timeout` and a connection check.
- Plain SQL with bound parameters (`%s`) everywhere. Identifiers are never built from input;
  where SQL is assembled (sort order, optional filters) the pieces come from fixed allow-lists.
- Migrations are plain SQL files ([DATA](../architecture/DATA.md#migrations-and-namespaces)).
- Pydantic models at the service boundary, built from rows.

## Consequences

- Queries are visible and reviewable, and RLS, locks and JSON operators are used directly.
- No automatic schema generation; every schema change is a reviewed migration.
- Product code that uses `ax.db` must follow the same parameterization rule; ruff's `S` rules help
  (S608 is disabled because SQL strings are composed from constants).
