# ADR 0010: Single- and multi-product mode in one code base

Status: accepted (Phase 0). Details: [DEPLOYMENT_MODELS](../architecture/DEPLOYMENT_MODELS.md).

## Context

Some installations serve one SaaS product, others several. Two code bases or schemas would
diverge.

## Decision

A `mode` setting (`single` | `multi`). Both use the same schema, API paths and authorization. In
single mode the product is created from configuration on first start and product creation and
archiving are refused (`mode_not_supported`); `GET /v1/meta` reports the mode and, in single mode,
the product.

## Consequences

- Clients always address `/v1/products/{product_id}/...`; in single mode they take the id from
  `/v1/meta`.
- Single to multi is a configuration change without data migration.
- Studio adapts its navigation to the mode reported by the server.
