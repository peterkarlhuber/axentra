/**
 * Shared setup for the contract tests against a REAL Axentra server.
 *
 * Environment (the suite is skipped when AXENTRA_SDK_E2E_URL is unset):
 *   AXENTRA_SDK_E2E_URL             server origin, e.g. http://127.0.0.1:8123
 *   AXENTRA_SDK_E2E_API_KEY         product-wide API key (axk_...)       } either these
 *   AXENTRA_SDK_E2E_PRODUCT_ID      product of that key                  } (scripts/sdk-e2e.sh
 *   AXENTRA_SDK_E2E_TENANT_ID       optional; a tenant is created if unset  sets all of them)
 *   AXENTRA_SDK_E2E_SETUP_TOKEN     or: a first-run setup token; the suite then bootstraps an
 *                                   admin, a product, a tenant and an API key itself
 *   AXENTRA_SDK_E2E_ADMIN_EMAIL / AXENTRA_SDK_E2E_ADMIN_PASSWORD
 *                                   optional; enables the cookie + CSRF tests
 */
import { createAxentraClient, type AxentraClient, type FetchLike } from '../../src/index.js';

export const E2E_URL = process.env.AXENTRA_SDK_E2E_URL ?? '';
export const enabled = E2E_URL !== '' && Boolean(process.env.AXENTRA_SDK_E2E_API_KEY || process.env.AXENTRA_SDK_E2E_SETUP_TOKEN);

export interface E2EContext {
  url: string;
  ax: AxentraClient;
  apiKey: string;
  productId: string;
  tenantId: string;
  admin: { email: string; password: string } | null;
}

/** A fetch with a tiny cookie jar, so Node behaves like a browser for cookie-mode tests. */
export function cookieFetch(): FetchLike & { jar: Map<string, string> } {
  const jar = new Map<string, string>();
  const fn = (async (req: Request) => {
    if (jar.size > 0) {
      const headers = new Headers(req.headers);
      headers.set('cookie', [...jar].map(([k, v]) => `${k}=${v}`).join('; '));
      req = new Request(req, { headers });
    }
    const res = await fetch(req);
    for (const line of res.headers.getSetCookie()) {
      const [pair = '', ...attrs] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a)) || value === '' || value === '""';
      if (expired) jar.delete(name);
      else jar.set(name, value);
    }
    return res;
  }) as FetchLike & { jar: Map<string, string> };
  fn.jar = jar;
  return fn;
}

const ALL_PRODUCT_AND_TENANT = [
  'product:read',
  'tenants:read',
  'tenants:create',
  'tenants:update',
  'tenants:delete',
  'roles:read',
  'api_keys:read',
  'audit:read',
  'collections:read',
  'usage:manage',
  'billing:manage',
  'notify:manage',
  'tenant:read',
  'members:read',
  'records:read',
  'records:write',
  'files:read',
  'files:write',
  'usage:read',
  'usage:record',
  'billing:read',
  'notify:send',
];

async function bootstrap(url: string, setupToken: string): Promise<Omit<E2EContext, 'ax'>> {
  const admin = { email: `sdk-e2e-${Date.now()}@example.com`, password: 'sdk e2e password 123' };
  const jarFetch = cookieFetch();
  const browser = createAxentraClient({ baseUrl: url, fetch: jarFetch });
  await browser.POST('/v1/auth/setup', {
    body: { setup_token: setupToken, email: admin.email, name: 'SDK e2e', password: admin.password },
  });
  const product = await browser.POST('/v1/products', {
    body: { name: 'SDK e2e', slug: `sdk-e2e-${Date.now().toString(36)}` },
  });
  const tenant = await browser.POST('/v1/products/{product_id}/tenants', {
    params: { path: { product_id: product.id } },
    body: { name: 'Main', slug: 'main' },
  });
  const key = await browser.POST('/v1/products/{product_id}/api-keys', {
    params: { path: { product_id: product.id } },
    body: { name: 'sdk-e2e', permissions: ALL_PRODUCT_AND_TENANT },
  });
  return { url, apiKey: key.secret, productId: product.id, tenantId: tenant.id, admin };
}

let cached: Promise<E2EContext> | null = null;

export function e2eContext(): Promise<E2EContext> {
  cached ??= (async () => {
    const url = E2E_URL.replace(/\/+$/, '');
    const env = process.env;
    const admin =
      env.AXENTRA_SDK_E2E_ADMIN_EMAIL && env.AXENTRA_SDK_E2E_ADMIN_PASSWORD
        ? { email: env.AXENTRA_SDK_E2E_ADMIN_EMAIL, password: env.AXENTRA_SDK_E2E_ADMIN_PASSWORD }
        : null;
    let base: Omit<E2EContext, 'ax'>;
    if (env.AXENTRA_SDK_E2E_API_KEY && env.AXENTRA_SDK_E2E_PRODUCT_ID) {
      base = {
        url,
        apiKey: env.AXENTRA_SDK_E2E_API_KEY,
        productId: env.AXENTRA_SDK_E2E_PRODUCT_ID,
        tenantId: env.AXENTRA_SDK_E2E_TENANT_ID ?? '',
        admin,
      };
    } else if (env.AXENTRA_SDK_E2E_SETUP_TOKEN) {
      base = await bootstrap(url, env.AXENTRA_SDK_E2E_SETUP_TOKEN);
    } else {
      throw new Error('set AXENTRA_SDK_E2E_API_KEY + AXENTRA_SDK_E2E_PRODUCT_ID, or AXENTRA_SDK_E2E_SETUP_TOKEN');
    }
    const ax = createAxentraClient({ baseUrl: url, apiKey: base.apiKey });
    if (!base.tenantId) {
      const t = await ax.POST('/v1/products/{product_id}/tenants', {
        params: { path: { product_id: base.productId } },
        body: { name: 'TS e2e', slug: `ts-e2e-${Date.now().toString(36)}` },
      });
      base.tenantId = t.id;
    }
    return { ...base, ax };
  })();
  return cached;
}
