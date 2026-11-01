# ADR 0005: Forced row-level security with per-transaction scope

Status: accepted (Phase 0)

## Context

A single missing `WHERE tenant_id = ...` leaks data between tenants (or products). Service code is
reviewed and tested, but a second, independent line of defense in the database is cheap.

## Decision

- Every product or tenant table has `product_id` (+ `tenant_id`), `ENABLE` and `FORCE ROW LEVEL
  SECURITY`, and one policy using `axentra_scope_allows(product_id, tenant_id)`.
- Every transaction declares a `DbScope` (`platform`, `product`, `tenant`), written with
  `set_config(..., true)` (transaction-local) at the start of the transaction.
- No scope means no rows.
- The application connects with a role that is neither superuser nor `BYPASSRLS`; `Axentra.start()`
  verifies this and refuses to start in production otherwise (unless explicitly overridden).
- Tests run as a non-superuser owner role so the policies are exercised.

## Consequences

- Services must pick the narrowest scope; platform scope disables the protection.
- Global tables (users, sessions) are not covered; see
  [SECURITY_MODEL](../architecture/SECURITY_MODEL.md#limits-of-row-level-security).
- Product tables must follow the same template ([guide](../guides/PRODUCT_TABLES.md)).
- A small overhead per query (a STABLE SQL function in the policy) is accepted.
