# Source of the golden snapshots

The snapshots in this directory are the "before" picture of the Tabrion adoption (TABRION QA-13, QA-25). They were
written from the old code, before any TABRION MIG-AXE step:

- commit: `ea7aa9f8e0af493f1ce70fc06e49cc975cf8795a` (master, "Merge PR #62: TB-031 DETAIL redaction port")
- tool: `python -m tests.evidence.snapshots --url <superuser URL> write`
- server: PostgreSQL 16; CI compares them on PostgreSQL 15, 16 and 17 (`tests/integration/test_rollback_snapshots.py`)

| File | What it holds | Evidence for |
|---|---|---|
| `catalog.json` | Row-level security per table, policies, the runtime role's privileges after `grant_runtime_role` | AX-I-6 (MIG-T-AXE-6), MIG-AXE-6 |
| `roles.json` | Role decision table, eight variants (`inspect_role`, `grant_runtime_role`, `role_info`, `check_role`) | AX-I-5 (MIG-T-AXE-5), MIG-AXE-6 |
| `problems.json` | Problem details of every error class, HTTP error answers, OpenAPI `Problem` schemas | AX-I-7 (MIG-T-AXE-7), MIG-AXE-3 |
| `settings.json` | `SHOW` extract per kind of connection (owned pool, read-only, `on_pool`, `joined`, `join`, leader lock, ping) | AX-I-1..4, MIG-AXE-4, MIG-AXE-5 |
| `schema.json` | Schema dump from the catalog (columns, constraints, indexes, triggers, functions, applied migrations) | every step: no schema change (document 11, section 3) |

A pull request that changes a snapshot on purpose (a new migration, or a step whose plan allows the change) rewrites
the file with the tool and says why; the diff is part of the review. A rollback (revert pull request) is verified by
the same files: after the revert, `check` must report "snapshots identical" again.
