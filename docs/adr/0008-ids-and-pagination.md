# ADR 0008: Prefixed time-ordered ids and keyset pagination

Status: accepted (Phase 0)

## Context

Ids appear in URLs, logs and support tickets. Sequential integers leak volume and invite
enumeration; random UUIDs fragment B-tree indexes and are hard to recognize. Offset pagination is
slow on large tables and unstable under concurrent inserts.

## Decision

- Ids are `<prefix>_<26 chars>`: a 2-4 letter type prefix (`prd`, `ten`, `usr`, `key`, `rec`, ...)
  and Crockford base32 of a 48-bit millisecond timestamp plus 80 random bits (ULID layout),
  stored as `text`. Clients treat them as opaque.
- Lists use keyset pagination with an opaque cursor (base64 JSON of the last sort key and id),
  `limit` 1-200 (default 50), `{"items", "next_cursor"}` responses, and no total counts.

## Consequences

- Ids reveal their approximate creation time (accepted).
- No "jump to page N"; UIs page forward with cursors.
- Sort fields are restricted to indexed, documented columns.
