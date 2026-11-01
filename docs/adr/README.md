# Architecture decision records

Short records of decisions that shape Axentra: context, decision, consequences. A superseded
decision stays in place with a link to the one that replaces it.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith-single-package.md) | One installable package with internal modules and extras | accepted |
| [0002](0002-python-versions.md) | Python >= 3.11; CI on 3.11, 3.12, 3.13 | accepted |
| [0003](0003-postgres-psycopg-raw-sql.md) | PostgreSQL, psycopg 3 with pool, parameterized SQL, no ORM | accepted |
| [0004](0004-sync-core.md) | Synchronous services; FastAPI runs them in its thread pool | accepted |
| [0005](0005-row-level-security.md) | Forced row-level security with per-transaction scope | accepted |
| [0006](0006-sessions-and-csrf.md) | Server-side sessions, cookie + CSRF header + origin check | accepted |
| [0007](0007-api-keys.md) | Product-scoped API keys with explicit permissions, hash-only | accepted |
| [0008](0008-ids-and-pagination.md) | Prefixed ULID-style ids; keyset cursor pagination | accepted |
| [0009](0009-errors-rfc9457.md) | RFC 9457 problem details with stable codes | accepted |
| [0010](0010-single-and-multi-product.md) | Single- and multi-product mode in one code base | accepted |
| [0011](0011-keyring-rotation.md) | Versioned AES-256-GCM keyring with rotation | accepted |
| [0012](0012-studio-separation.md) | Studio is a separate client, only via HTTP/OpenAPI | accepted |
