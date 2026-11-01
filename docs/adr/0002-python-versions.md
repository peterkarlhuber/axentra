# ADR 0002: Supported Python versions

Status: accepted (Phase 0)

## Context

- Python 3.10 reaches end of life in October 2026.
- Nodestro, the most likely first large consumer, declares `requires-python >= 3.10`, but tests on
  3.10 and 3.13 and ships 3.13 (server image and release workflow). Its MCP integration already needs 3.11.
- Axentra uses 3.11 features: `enum.StrEnum`, `datetime.UTC`, `tomllib` (standard library TOML
  parsing) and modern typing.

## Decision

`requires-python = ">=3.11"`. CI tests 3.11, 3.12 and 3.13 (each with a different PostgreSQL
major: 15, 16, 17). The container image uses `python:3.13-slim`. ruff and mypy target 3.11.

## Consequences

- A Nodestro migration onto Axentra requires dropping Python 3.10 there, which is end of life
  anyway and already excluded by its MCP dependency.
- New Python releases are added to the CI matrix when the dependencies support them; the oldest
  version is dropped after its end of life, as a minor release with a changelog note.
