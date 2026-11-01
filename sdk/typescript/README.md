# @axentra/sdk

Typed TypeScript client for the Axentra HTTP API. The types are **generated** from the committed
OpenAPI contract (`../../openapi/axentra-v1.json`) with openapi-typescript; requests go through
openapi-fetch with a thin layer for authentication, CSRF, errors, the API version check,
pagination and idempotency keys. Status: alpha, private (not published yet).

```ts
import { createAxentraClient, AxentraApiError, idempotencyKey } from '@axentra/sdk';

const ax = createAxentraClient({ baseUrl: 'https://api.example.com', apiKey: 'axk_...' });
await ax.checkCompatibility();

const page = await ax.GET('/v1/products/{product_id}/tenants', {
  params: { path: { product_id: 'prd_...' }, query: { limit: 50 } },
});

for await (const tenant of ax.paginate((cursor) =>
  ax.GET('/v1/products/{product_id}/tenants', { params: { path: { product_id: 'prd_...' }, query: { cursor } } }),
)) {
  console.log(tenant.slug);
}
```

- Auth: `apiKey` or `sessionToken` (bearer), or cookie mode (browsers) with an automatic
  `X-Axentra-CSRF` header read once from `GET /v1/auth/session`.
- Errors: every non-2xx throws `AxentraApiError { status, code, detail, requestId, errors }`.
- `checkCompatibility()` throws `IncompatibleApiError` when the server's API major differs or its
  minor is lower than the one this SDK was generated for (`GENERATED_API_VERSION`).
- `paginate(fn)` / `collectAll(fn)` for cursor lists, `idempotencyKey(key?)` for `Idempotency-Key`.

## Scripts

```bash
npm ci
npm run generate         # regenerate src/schema.d.ts + src/generated.ts from the committed OpenAPI
npm run generate:check   # CI: fail when the generated files are stale
npm run typecheck
npm test                 # unit tests (mocked fetch)
npm run build            # dist/ (ESM + .d.ts)
npm run test:e2e         # against a live server; see ../../scripts/sdk-e2e.sh
```

Full guide: [docs/sdk/TYPESCRIPT.md](../../docs/sdk/TYPESCRIPT.md).
