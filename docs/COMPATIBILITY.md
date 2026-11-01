# Compatibility matrix: Axentra and Axentra Studio

Combinations of Axentra (backend) and Axentra Studio (admin UI) that were tested together. A
combination is listed only after Studio's contract tests ran against that Axentra commit's
`openapi/axentra-v1.json` and Studio was exercised against a running server of that commit.
Rules: [architecture/VERSIONING.md](architecture/VERSIONING.md).

| Axentra version | Axentra commit | API version | Studio version | Studio commit | Studio `REQUIRED_API` | Tested on | Result | Notes |
|---|---|---|---|---|---|---|---|---|
| 0.1.0.dev0 | to be filled at merge | 1.0 | 0.1.0 | to be filled at merge | 1.0 | - | pending | Phase 1 foundation (backend PR #1) |
