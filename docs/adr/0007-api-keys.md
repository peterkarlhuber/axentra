# ADR 0007: Product-scoped API keys with explicit permissions

Status: accepted (Phase 0)

## Context

Machines (product backends, integrations, CI) need credentials that are not tied to a person,
can be limited to what they need, and can be rotated without downtime.

## Decision

- Format `axk_<id>_<secret>`; the id is public and indexed, the 256-bit secret is stored only as a
  SHA-256 hash and compared in constant time. The full key is shown once.
- A key belongs to one product, optionally one tenant, and carries an explicit permission list.
  Keys never hold platform permissions.
- The creator must hold every permission given to the key (no escalation).
- Rotation creates a replacement and revokes the old key immediately or after a grace period of
  up to 7 days. Revocation and expiry are checked on every request.

## Consequences

- Keys cannot administer the installation (create products, manage users).
- Tenant-bound keys are the default recommendation for per-customer integrations.
- A leaked key is limited to its product/tenant and permissions until revoked.
