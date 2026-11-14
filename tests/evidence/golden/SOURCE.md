# Source of the golden snapshots

The snapshots in this directory are the "before" picture of the Tabrion adoption (TABRION QA-13, QA-25). They were
written from the old code, before any TABRION MIG-AXE step:

- commit: `ea7aa9f8e0af493f1ce70fc06e49cc975cf8795a` (master, "Merge PR #62: TB-031 DETAIL redaction port")
- tool: `python -m tests.evidence.snapshots --url <superuser URL> write`
- `catalog.json` was rewritten from the same commit with the review fix round's tool (ACL entries and memberships
  added, M-1 of `qa-13-25-review.md`); the other four files were byte-identical in that run
- server: PostgreSQL 16; CI compares them on PostgreSQL 15, 16 and 17 (`tests/integration/test_rollback_snapshots.py`)

| File | What it holds | Evidence for |
|---|---|---|
| `catalog.json` | Row-level security per table, policies, the runtime role's privileges after `grant_runtime_role`, every ACL entry of the schema's objects (`relacl`, `attacl`, `proacl`, `nspacl`, `datacl`: grantor, grantee incl. `PUBLIC`, privilege, grant option; owners' implicit entries left out), memberships of the owner and runtime roles | AX-I-6 (MIG-T-AXE-6), MIG-AXE-6 |
| `roles.json` | Role decision table, eight variants (`inspect_role`, `grant_runtime_role`, `role_info`, `check_role`) | AX-I-5 (MIG-T-AXE-5), MIG-AXE-6 |
| `problems.json` | Problem details of every error class, HTTP error answers, OpenAPI `Problem` schemas | AX-I-7 (MIG-T-AXE-7), MIG-AXE-3 |
| `settings.json` | `SHOW` extract per kind of connection (owned pool, read-only, `on_pool`, `joined`, `join`, leader lock, ping) | AX-I-1..4, MIG-AXE-4, MIG-AXE-5 |
| `statements.json` | Statements of every migration file (Axentra and the Taskboard example) and of the splitter test vectors, written with Axentra's own `split_statements` at master `b91e05a` (before TABRION MIG-AXE-2; a one-off script, not the snapshot tool) | MIG-AXE-2 (G-AX-7), `tests/unit/test_split_statements_golden.py` |
| `schema.json` | Schema dump from the catalog (columns, constraints, indexes, triggers, functions, applied migrations) | every step: no schema change (document 11, section 3) |

Changes since then, each rewritten with the tool and explained in its pull request:

- TABRION MIG-AXE-6: `roles.json` (`--only roles write`). Tabrion's role check counts every role a role can become
  (contract I-20; Peter's decision to adopt it, as for MIG-NOD-5). A superuser is a member of every role, also of the
  `BYPASSRLS` ones, so the `superuser` variant now reports `bypass_rls: true` in `inspect_role`, `role_info` and
  `check_role` (4 lines). Every decision and error class is unchanged; `catalog.json` (the grants) is identical. The
  security review of #87 extended the `check_role` refusal of a superuser or `BYPASSRLS` role with "also through role
  membership; see `axentra db inspect-role`" (6 lines of `message`).
- I5 (identity link method): `schema.json` (`--only schema write`). Migration 15 `identity_link_method` adds
  `axentra_user_identities.linked_by` (`unknown`, `email`, `explicit`, `signup`; default `unknown`) and its check
  constraint, so an identity linked by verified email stops working once the user holds a platform role, until an
  administrator confirms the link. The other four files are identical.

A pull request that changes a snapshot on purpose (a new migration, or a step whose plan allows the change) rewrites
the file with the tool and says why; the diff is part of the review. A rollback (revert pull request) is verified by
the same files: after the revert, `check` must report "snapshots identical" again.

No timing is stored here: a benchmark result is valid only as an interleaved A/B run of the old and the new code
on one idle machine (`python -m tests.evidence.bench_transactions ab`, review `qa-13-25-review.md` M-5).
