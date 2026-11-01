# Deployment models: single-product and multi-product

Status: accepted (Phase 0). Summary in [ADR 0010](../adr/0010-single-and-multi-product.md).

## Context

Axentra is meant both for a team that builds one SaaS product and for an operator who runs
several products on shared infrastructure. Both need the same tenancy model (products contain
tenants, tenants contain members and data) and the same API, but differ in who may create
products and how much product management the UI should show.

## Decision

One code base, one schema and one API with a `mode` setting:

| | `single` | `multi` |
|---|---|---|
| Products | Exactly one, created on first start from `[product]` (slug, name); idempotent on restart | Any number, created by platform admins (`POST /v1/products`) |
| Create / archive / restore products | Refused with `409 mode_not_supported` | Platform admins (`products:create`, `products:archive`) |
| `GET /v1/meta` | `mode: "single"`, `product: {...}` | `mode: "multi"`, `product: null` |
| API paths | The same `/v1/products/{product_id}/...` paths; clients take the id from `/v1/meta` | Same |
| Data model and RLS | Identical | Identical |

Single-product mode refuses to start if the database already contains other products and none
has the configured slug (`ModeNotSupported`), so a multi-product database is not silently
reinterpreted. Moving from single to multi is a configuration change (`mode = "multi"`); the
existing product stays. Moving back is possible only while exactly one product exists and its
slug is configured.

## Consequences

- Product code and SDKs always pass a `product_id`; there is no "implicit product" path. This
  keeps one contract for both modes.
- A single-product installation can grow into a multi-product one without a data migration.
- Isolation between products in multi mode rests on the same authorization rules and RLS
  policies as isolation between tenants; see [SECURITY_MODEL](SECURITY_MODEL.md).
- Users are global in both modes: one account can work in several products.

## Axentra Studio in each mode

Studio reads `GET /v1/meta` at startup and adapts to `mode`. Intended behavior (Studio implements
it incrementally; see the Studio repository for the current state):

- **single**: Studio opens directly in the configured product (`meta.product`) and hides product
  creation, archiving and the product switcher. Operators manage tenants, users, roles, keys,
  records, audit and settings of that product.
- **multi**: Studio shows a product list and switcher; platform admins see create, archive and
  restore; product operators see only the products they belong to (`GET /v1/products`).

Studio adapts its navigation, but every permission decision is made by the API; a hidden button
is never the only protection.

## Configuration examples

Complete files: [deploy/config/single.toml](../../deploy/config/single.toml),
[deploy/config/multi.toml](../../deploy/config/multi.toml).

```toml
# single-product
environment = "production"
mode = "single"

[product]
slug = "crm"
name = "Acme CRM"

[database]
url_ref = "env:AXENTRA_DATABASE_URL"

[security]
public_url = "https://api.crm.example.com"
allowed_origins = ["https://app.crm.example.com", "https://studio.crm.example.com"]
master_keys_ref = "file:/run/secrets/axentra_keyring"
```

```toml
# multi-product
environment = "production"
mode = "multi"

[database]
url_ref = "env:AXENTRA_DATABASE_URL"
pool_max = 20

[security]
public_url = "https://api.example.com"
allowed_origins = ["https://studio.example.com", "https://crm.example.com", "https://books.example.com"]
master_keys_ref = "file:/run/secrets/axentra_keyring"
```

Compose stacks for both: `deploy/compose/docker-compose.single.yml` and
`deploy/compose/docker-compose.multi.yml` ([DEPLOYMENT](../operations/DEPLOYMENT.md)).
