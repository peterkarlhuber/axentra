# API v1 endpoint catalog (Phase 1)

The OpenAPI document `openapi/axentra-v1.json` is authoritative; this catalog is the design
summary. Permission names in brackets.

## Meta and health (public)
- `GET /v1/meta` -> `{name, version, api_version, mode: "single"|"multi", modules[], product|null, auth: {password: bool, oidc: [{id, name}]}, setup_required: bool}`
- `GET /v1/health/live`, `GET /v1/health/ready`

## Auth
- `POST /v1/auth/setup` `{setup_token, email, name, password}` -> first platform admin (token printed by `axentra admin setup-token`)
- `POST /v1/auth/login/password` `{email, password}` -> `Session`
- `GET /v1/auth/oidc/{provider}/start?return_to=/path` -> 302; `GET /v1/auth/oidc/{provider}/callback`
- `GET /v1/auth/session` -> `{user, csrf_token, expires_at, platform_role|null}`
- `POST /v1/auth/logout`
- `GET /v1/auth/sessions` (own), `DELETE /v1/auth/sessions/{session_id}` (own)

## Me
- `GET /v1/me` -> `{user, platform_role, products: [{product, role, permissions[], tenants: [{tenant, role, permissions[]}]}]}`
- `PATCH /v1/me` `{name?, locale?, preferences?}`; `POST /v1/me/password` `{current_password, new_password}`

## Products
- `GET /v1/products` (visible to caller), `POST /v1/products` [platform admin, multi mode only]
- `GET /v1/products/{pid}`, `PATCH /v1/products/{pid}` `{name?, description?, settings?}` [product:manage]
- `POST /v1/products/{pid}/archive`, `POST /v1/products/{pid}/restore` [platform admin, multi]
- `GET /v1/products/{pid}/overview` -> counts (tenants, users, keys, audit last 24h) [product:read]
- `GET/POST /v1/products/{pid}/members`, `PATCH/DELETE /v1/products/{pid}/members/{user_id}` [product_members:*]

## Tenants
- `GET/POST /v1/products/{pid}/tenants` [tenants:read / tenants:create]
- `GET/PATCH/DELETE /v1/products/{pid}/tenants/{tid}` [tenants:read / tenants:update / tenants:delete]
- `GET/POST /v1/products/{pid}/tenants/{tid}/members`, `PATCH/DELETE .../members/{user_id}` [members:read / members:manage]
- `GET/POST /v1/products/{pid}/tenants/{tid}/invitations`, `DELETE .../invitations/{inv_id}` [members:manage]
- `POST /v1/invitations/accept` `{token}` (authenticated user)

## Users
- `GET /v1/users?q=&status=` platform admin: all users; product admin: users of the product (`?product_id=`) [users:read]
- `GET /v1/users/{uid}`, `PATCH /v1/users/{uid}` `{status: active|disabled}` [users:manage]
- `GET /v1/users/{uid}/sessions`, `POST /v1/users/{uid}/sessions/revoke` [users:manage]

## Access
- `GET /v1/permissions` -> permission catalog `{name, scope, description}`
- `GET /v1/products/{pid}/roles` (built-in + custom), `POST`, `PATCH/DELETE /v1/products/{pid}/roles/{role_id}` [roles:manage]
- `GET/POST /v1/products/{pid}/api-keys`, `GET .../{kid}`, `POST .../{kid}/rotate`, `POST .../{kid}/revoke` [api_keys:manage]

## Data (records)
- `GET /v1/products/{pid}/collections` -> collection stats [records:read]
- `GET/POST /v1/products/{pid}/tenants/{tid}/records/{collection}` (filter `?where[field]=value`, `sort`, pagination) [records:read/write]
- `GET/PUT/DELETE /v1/products/{pid}/tenants/{tid}/records/{collection}/{rid}` (`If-Match`)

## Audit and settings
- `GET /v1/audit?product_id=&tenant_id=&action=&actor_id=&since=&until=&q=` [audit:read]
- `GET /v1/audit/{event_id}`
- `GET /v1/settings` (effective non-secret configuration) [platform admin or product admin read-only]
