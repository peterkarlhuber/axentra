# ADR 0004: Synchronous core

Status: accepted (Phase 0)

## Context

Most work in Axentra is short PostgreSQL transactions plus CPU-bound hashing (Argon2id). An async
core would force async on every library user, double the API surface (sync wrappers) and make the
explicit transaction scope harder to reason about. FastAPI runs `def` endpoints in a thread pool.

## Decision

Services and the database layer are synchronous (psycopg sync connections and pool). Routes are
plain `def` functions, executed by FastAPI/Starlette in the worker thread pool. Concurrency comes
from the thread pool and from running several API processes.

## Consequences

- Library users call services directly from scripts, workers or sync frameworks; async
  applications call them through `run_in_threadpool`/`asyncio.to_thread`.
- Throughput per process is bounded by the thread pool and `database.pool_max`; scale with
  processes or replicas.
- Long-lived connections (server-sent events, planned for Phase 2) need an async path of their
  own and must not hold a pooled connection while idle.
