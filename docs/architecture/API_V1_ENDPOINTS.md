# API v1 endpoint catalog (Phase 1)

The OpenAPI document `openapi/axentra-v1.json` is authoritative; this catalog is the design
summary. Permission names in brackets.

## Meta and health (public)
- `GET /v1/meta` -> `{name, version, api_version, mode: "single"|"multi", modules[], product|null, auth: {password: bool, oidc: [{id, name}]}, setup_required: bool}`
- `GET /v1/health/live`, `GET /v1/health/ready`

## Auth
- `POST /v1/auth/setup` `{setup_token, email, name, password}` -> first platform admin (token printed by `axentra admin setup-token`)
- `POST /v1/auth/login/password` `{email, password}` -> `Session`
- `GET /v1/auth/oidc/{provider}/start?return_to=/path|<allowed origin URL>&invitation=<token>` -> 302 to the IdP; `GET /v1/auth/oidc/{provider}/callback?code&state` -> 302 to return_to (session cookie) or to the login page with `?login_error=<code>` (see docs/modules/IDENTITY.md)
- `GET /v1/auth/session` -> `{user, csrf_token, expires_at, platform_role|null}`
- `POST /v1/auth/logout`
- `GET /v1/auth/sessions` (own), `DELETE /v1/auth/sessions/{session_id}` (own)

## Me
- `GET /v1/me` -> `{user, platform_role, products: [{product, role, permissions[], tenants: [{tenant, role, permissions[]}]}]}`
- `PATCH /v1/me` `{name?, locale?, preferences?}`; `POST /v1/me/password` `{current_password, new_password}`
  (users without a password: only within `security.fresh_login_minutes` of the login, else `403`
  `reauthentication_required`; never with `security.first_password = "disabled"`)

## Products
- `GET /v1/products` (visible to caller), `POST /v1/products` [platform admin, multi mode only]
- `GET /v1/products/{pid}`, `PATCH /v1/products/{pid}` `{name?, description?, settings?}` [product:manage]
- `POST /v1/products/{pid}/archive`, `POST /v1/products/{pid}/restore` [platform admin, multi]
- `GET /v1/products/{pid}/overview` -> counts (tenants, users, keys, audit last 24h) [product:read]
- `GET/POST /v1/products/{pid}/members`, `PATCH/DELETE /v1/products/{pid}/members/{user_id}` [product_members:*]
  (role ceiling: `403` for roles above the caller's permissions or the owner rank; `404` for users
  not visible to the caller, see SECURITY_MODEL.md rules 8-9)

## Tenants
- `GET/POST /v1/products/{pid}/tenants` [tenants:read / tenants:create]
- `GET/PATCH/DELETE /v1/products/{pid}/tenants/{tid}` [tenants:read / tenants:update / tenants:delete]
- `GET/POST /v1/products/{pid}/tenants/{tid}/members`, `PATCH/DELETE .../members/{user_id}` [members:read / members:manage]
  - Role ceiling: `403` when the role to assign, or the member's current role, has permissions the
    caller lacks, or is `tenant_owner` and the caller is neither a tenant owner nor a product
    operator. `DELETE`/`PATCH` of a non-member: `404`.
  - `POST` by email/user id resolves only users visible to the caller (platform admin: all;
    `product_users:read`: users of the product; otherwise members of this tenant). Others get
    `404` "user not found; invite them by email instead", the same as unknown users: use invitations.
- `GET/POST /v1/products/{pid}/tenants/{tid}/invitations`, `DELETE .../invitations/{inv_id}` [members:manage] (role ceiling as above)
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
- `GET /v1/audit/{event_id}` (`404` both for unknown events and for events the caller may not read)
- `GET /v1/settings` (effective non-secret configuration) [platform admin or product admin read-only]
