# TypeScript SDK (`@axentra/sdk`)

A thin, fully typed client for the Axentra HTTP API. Location: `sdk/typescript`. Status: alpha,
`private` in `package.json` (not published to npm yet).

- **Types are generated** from the committed contract `openapi/axentra-v1.json` with
  [openapi-typescript](https://openapi-ts.dev) (exact pinned versions) into `src/schema.d.ts`.
  Every path, parameter, request body and response of the API is typed; nothing is hand-written
  per endpoint.
- **Requests** go through [openapi-fetch](https://openapi-ts.dev/openapi-fetch/) (its only
  runtime dependency) with a small layer on top: authentication, CSRF in cookie mode,
  RFC 9457 problem details as `AxentraApiError`, the API version check, cursor pagination and
  `Idempotency-Key` helpers.
- ESM only, `.d.ts` included, Node >= 20 or any modern browser (uses `fetch`, `Request`,
  `crypto.randomUUID`).

## Install and build

```bash
cd sdk/typescript
npm ci
npm run build          # tsc -> dist/ (ESM + .d.ts); src/schema.d.ts is copied to dist/
```

Until the package is published, depend on it by path (`"@axentra/sdk": "file:../axentra/sdk/typescript"`)
or pack it (`npm pack`).

## Usage

```ts
import {
  AxentraApiError,
  createAxentraClient,
  idempotencyKey,
  type Schema,
} from '@axentra/sdk';

const ax = createAxentraClient({ baseUrl: 'https://api.example.com', apiKey: process.env.AXENTRA_KEY });
await ax.checkCompatibility(); // throws IncompatibleApiError with a clear message

const product_id = 'prd_...';
const tenant: Schema<'Tenant'> = await ax.POST('/v1/products/{product_id}/tenants', {
  params: { path: { product_id } },
  body: { name: 'Acme', slug: 'acme' },
});

// Every 2xx resolves to the typed body (204 -> undefined); everything else throws.
try {
  await ax.GET('/v1/products/{product_id}/tenants/{tenant_id}', {
    params: { path: { product_id, tenant_id: 'ten_unknown' } },
  });
} catch (e) {
  if (e instanceof AxentraApiError) console.log(e.status, e.code, e.detail, e.requestId, e.errors);
}

// Cursor pagination: lazily iterates all items.
for await (const t of ax.paginate((cursor) =>
  ax.GET('/v1/products/{product_id}/tenants', {
    params: { path: { product_id }, query: { cursor, limit: 100 } },
  }),
)) {
  console.log(t.slug);
}

// Idempotent usage recording: reuse YOUR key on retries.
await ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/usage/events', {
  params: { path: { product_id, tenant_id: tenant.id }, header: idempotencyKey(`order-${orderId}`) },
  body: { meter: 'api_calls', quantity: 1 },
});

// Optimistic concurrency: If-Match is a typed header parameter where the API accepts it.
await ax.PUT('/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}/{record_id}', {
  params: { path: { product_id, tenant_id: tenant.id, collection: 'notes', record_id }, header: { 'If-Match': '3' } },
  body: { title: 'changed' },
});
```

Files (multipart upload, binary download):

```ts
const form = new FormData();
form.set('file', new Blob([bytes], { type: 'text/plain' }), 'hello.txt');
const info = await ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/files', {
  params: { path: { product_id, tenant_id } },
  body: { file: '' },            // satisfies the type; the serializer sends the FormData
  bodySerializer: () => form,
});
const data = await ax.GET('/v1/products/{product_id}/tenants/{tenant_id}/files/{file_id}/content', {
  params: { path: { product_id, tenant_id, file_id: info.id } },
  parseAs: 'arrayBuffer',        // or 'stream' / 'blob'
});
```

## Options of `createAxentraClient`

| Option | Default | Meaning |
|---|---|---|
| `baseUrl` | required | API origin without `/v1` (paths include it) |
| `apiKey` | none | `axk_...`, sent as `Authorization: Bearer` |
| `sessionToken` | none | A user session token, sent as `Authorization: Bearer` (no CSRF needed) |
| `credentials` | `'include'` in cookie mode, `'omit'` with a bearer | `fetch` credentials mode |
| `csrf` | on in cookie mode, off with a bearer | Send `X-Axentra-CSRF` on unsafe methods |
| `fetch` | `globalThis.fetch` | Custom fetch (receives a `Request`): tests, SSR, proxies |
| `headers` | none | Extra headers for every request |

**Cookie mode** (no `apiKey`/`sessionToken`; browsers, e.g. a product frontend on an
`allowed_origins` origin): the HttpOnly session cookie is sent by the browser. Before the first
unsafe request (`POST/PUT/PATCH/DELETE`) the client fetches `GET /v1/auth/session` once
(concurrent requests share that lookup), keeps `csrf_token` in memory only and sends it as
`X-Axentra-CSRF`. The token is also taken from the `POST /v1/auth/login/password` and
`/v1/auth/setup` responses and forgotten on logout or a `401`. `ax.csrf.refresh()` re-reads it,
`ax.csrf.set(token)` sets it explicitly. `ax.setAuth({ apiKey } | { sessionToken } | null)`
switches credentials at runtime.

Every request carries `Axentra-Client: axentra-sdk-ts/<version>; api=<major.minor>`.

## Errors

`AxentraApiError` fields: `status`, `code` (stable machine-readable code from the problem body; for
non-problem bodies derived from the status), `title`, `detail`, `requestId` (body `request_id`,
else the `X-Request-ID` header), `errors` (`[{loc, msg}]` for `validation_failed`), `retryAfter`
(seconds, for 429) and the raw `problem`. Network failures are not wrapped: the `fetch` error
propagates unchanged.

`ax.raw` is the underlying openapi-fetch client (same auth, CSRF and headers) when you want
`{ data, error, response }` instead of exceptions.

## API version check

`GENERATED_API_VERSION` (from `info.version` of the contract, written by the generator) is the
version this build requires. `checkCompatibility()` calls `GET /v1/meta` and throws
`IncompatibleApiError` (`reason`: `major_mismatch` | `minor_too_low` | `unparseable`) unless the
server's major is equal and its minor is at least the SDK's. A newer server minor is fine. Call it
once at startup. `assertCompatible(value)` applies the same rule to a value you already have.

## Scripts

| Script | What it does |
|---|---|
| `npm run generate` | Regenerates `src/schema.d.ts` and `src/generated.ts` from `../../openapi/axentra-v1.json` |
| `npm run generate:check` | Fails when the committed generated files are stale (CI job `sdk-typescript`) |
| `npm run typecheck` | `tsc --noEmit` over sources and tests (includes compile-time type assertions) |
| `npm test` | vitest unit tests with a mocked `fetch` |
| `npm run test:e2e` | Contract tests against a live server (skipped unless `AXENTRA_SDK_E2E_URL` is set) |
| `npm run build` | `dist/` (ESM + `.d.ts`) |

**When the API changes** (for example when a new module adds endpoints): regenerate the OpenAPI
in the repository root (`axentra openapi export`), then `npm run generate` in `sdk/typescript`
and commit both. New endpoints are immediately available, typed, through `ax.GET/POST/...`;
the SDK has no per-endpoint code. CI fails while `src/schema.d.ts` is stale. If the API minor was
bumped, the regenerated SDK requires that minor from the server.

## Contract tests against a real server

`scripts/sdk-e2e.sh` (repository root) creates a temporary PostgreSQL database with a
non-superuser role, migrates it, starts `axentra serve` on a free port, bootstraps a platform
admin through `POST /v1/auth/setup`, creates a product, a tenant and an API key, and runs both SDK
e2e suites:

```bash
AXENTRA_TEST_DATABASE_URL=postgresql://postgres:pg@127.0.0.1:5432/postgres scripts/sdk-e2e.sh
SDK_E2E_ONLY=ts scripts/sdk-e2e.sh      # only the TypeScript suite
```

Against your own server: set `AXENTRA_SDK_E2E_URL` and either `AXENTRA_SDK_E2E_API_KEY` +
`AXENTRA_SDK_E2E_PRODUCT_ID` (+ optional `AXENTRA_SDK_E2E_TENANT_ID`,
`AXENTRA_SDK_E2E_ADMIN_EMAIL`/`_PASSWORD` for the cookie + CSRF test) or a fresh
`AXENTRA_SDK_E2E_SETUP_TOKEN` (the suite then bootstraps everything itself), and run
`npm run test:e2e`. The suites create data; do not point them at production.

## Limitations

- No automatic retries (deliberately: only idempotent operations should be retried; use
  `idempotencyKey()` and retry yourself).
- Multipart uploads need the `bodySerializer` shown above (the generated body type for
  `multipart/form-data` describes the fields, not a `FormData`).
- A `403` because of a stale CSRF token is not retried automatically; call `ax.csrf.refresh()`.
- Problem responses are not described in the OpenAPI document yet: it lists only FastAPI's
  default `422 HTTPValidationError` (`{detail: [...]}`), while the server really answers every
  error, including 422, with `application/problem+json`. `ax.raw`'s `error` type is therefore
  inaccurate; use the thrown `AxentraApiError` (it parses the real body). A server-side fix
  (documenting the problem schema per operation) is listed in docs/TODO.md.
- In Node, cookie mode needs a `fetch` with a cookie jar (the e2e suite has a minimal one); use
  an API key or a session token there instead.
