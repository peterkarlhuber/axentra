# Compatibility matrix: Axentra and Axentra Studio

Combinations of Axentra (backend) and Axentra Studio (admin UI) that were tested together. A
combination is listed only after Studio's contract check ran against that Axentra commit's
`openapi/axentra-v1.json` **and** Studio's end-to-end suite ran against a running server of that
commit. Rules: [architecture/VERSIONING.md](architecture/VERSIONING.md). Studio keeps the mirror
of this table in its own `docs/COMPATIBILITY.md`.

| Axentra version | Axentra commit | API version | Studio version | Studio commit | Studio `REQUIRED_API` | Tested on | Result | Evidence |
|---|---|---|---|---|---|---|---|---|
| 0.1.0.dev0 | `a2ca72a7270d51942824b19ce84e154e99346984` (PR #8 head; same tree as `master` `537484f`) | 1.0 | 0.1.0 | `0aed4fce5dc2e4dc3c662d5fdcd066611077c4da` (Studio PR #2 merge) | 1.0 | 2026-11-02 | pass: contract identical; e2e 180 passed, 0 failed | Studio CI on PR #2: contract job 125053499893, e2e job 125053499801 |
| 0.1.0.dev0 | `7511a37ce0876c13e5a9c861e3b9e31b6401d99c` (`master`, PR #9 merge) | 1.0 | 0.1.0 | `ee7d9f2a9007a1f570d800b2d77e584ddfe6a5cb` (Studio PR #3 merge, Studio `master`) | 1.0 | 2026-11-02 | pass: contract identical; e2e 186 passed, 0 failed | Studio CI on PR #3: contract job 125058075510, e2e job 125058075685 |
| 0.1.0.dev0 | `7511a37ce0876c13e5a9c861e3b9e31b6401d99c` (`master`, PR #9 merge) | 1.0 | 0.1.0 | `4d2df1aed0756abc9b6fcf884f28f3c1e8b9a3f6` (Studio PR #4 merge) | 1.0 | 2026-11-02 | pass: contract identical; e2e multi 188 passed / 10 skipped, single 196 passed / 2 skipped, 0 failed | Studio CI on PR #4: run 41383014581, contract job 125077688112, e2e jobs 125077688055 (multi), 125077688056 (single) |

Notes:

- The e2e suite is Playwright (Chromium; desktop and 360 px projects) against PostgreSQL 16, the
  backend installed as `axentra[server]` from the pinned checkout, and a worker. The backend runs in
  **multi-product mode** up to Studio PR #3; since Studio PR #4 the e2e job is a matrix over both
  modes (`mode = "multi"` and `mode = "single"`). Skips are only the other mode's blocks of
  `e2e/single-product.spec.ts`.
- Axentra `f80429f` (search module) adds two backend-only paths; Studio still pins `7511a37`, so
  that combination is not listed yet (Studio TODO: re-pin).
- The CI runs belong to the Studio pull requests, i.e. to the merge of the PR head into the
  then-current Studio `master`, which is the content of the listed merge commit.

## How a row is added

1. Studio pins one backend commit in `api/BACKEND_REF` (a full, pushed Axentra SHA) and vendors
   that commit's contract as `api/openapi.json` (`npm run api:sync -- --sha <sha>`, which also writes
   `api/SOURCE` and the generated types).
2. Studio CI checks out `peterkarlhuber/axentra` at `BACKEND_REF` and runs two jobs:
   - **contract** (`npm run api:check -- --backend .backend`): `api/openapi.json` is byte-identical
     to the backend's `openapi/axentra-v1.json`, and `api/SOURCE` and the generated types match;
   - **e2e**: installs the backend from that checkout, runs its `axentra openapi export --check`,
     starts it with a worker (`scripts/e2e-backend.sh`) and runs every Playwright spec.
3. When both jobs pass, a row is added here (and in Studio's mirror table) with both commits, the
   API version, Studio's `REQUIRED_API`, the date, the counts and the CI job ids.
4. Rows are never edited after the fact. A failed combination is recorded with result `fail` and
   the reason, so the history stays complete.

Nothing on the Axentra side triggers Studio's jobs: a new Axentra commit is covered only when
Studio moves its pin (see [TODO.md](TODO.md)).
