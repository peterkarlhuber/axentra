import { beforeAll, describe, expect, it } from 'vitest';
import {
  AxentraApiError,
  collectAll,
  createAxentraClient,
  idempotencyKey,
  REQUIRED_API_VERSION,
} from '../../src/index.js';
import { cookieFetch, e2eContext, enabled, type E2EContext } from './context.js';

const run = Date.now().toString(36);

describe.skipIf(!enabled)('contract against a live Axentra server', () => {
  let ctx: E2EContext;
  const scope = () => ({ product_id: ctx.productId, tenant_id: ctx.tenantId });

  beforeAll(async () => {
    ctx = await e2eContext();
  });

  it('is compatible with the server', async () => {
    const meta = await ctx.ax.checkCompatibility();
    expect(meta.name).toBe('axentra');
    expect(meta.server_api.major).toBe(REQUIRED_API_VERSION.major);
    expect(meta.server_api.minor).toBeGreaterThanOrEqual(REQUIRED_API_VERSION.minor);
  });

  it('authenticates with the API key', async () => {
    const me = await ctx.ax.GET('/v1/me');
    expect(me.actor_kind).toBe('api_key');
    expect(me.user).toBeNull();
  });

  it('maps problem responses to AxentraApiError (404, 401, 422)', async () => {
    const notFound = await ctx.ax
      .GET('/v1/products/{product_id}', { params: { path: { product_id: 'prd_doesnotexist' } } })
      .catch((e: unknown) => e);
    expect(notFound).toBeInstanceOf(AxentraApiError);
    expect(notFound).toMatchObject({ status: 404, code: 'not_found' });
    expect((notFound as AxentraApiError).requestId).toMatch(/\S+/);

    const anon = createAxentraClient({ baseUrl: ctx.url, csrf: false });
    await expect(anon.GET('/v1/me')).rejects.toMatchObject({ status: 401, code: 'unauthenticated' });

    const invalid = (await ctx.ax
      .POST('/v1/products/{product_id}/tenants', {
        params: { path: { product_id: ctx.productId } },
        body: { name: 'x', slug: 'NOT A SLUG' },
      })
      .catch((e: unknown) => e)) as AxentraApiError;
    expect(invalid.status).toBe(422);
    expect(invalid.code).toBe('validation_failed');
  });

  it('paginates tenants with the cursor helper', async () => {
    for (const i of [1, 2, 3]) {
      await ctx.ax.POST('/v1/products/{product_id}/tenants', {
        params: { path: { product_id: ctx.productId } },
        body: { name: `Page ${i}`, slug: `page-${run}-${i}` },
      });
    }
    const all = await collectAll((cursor) =>
      ctx.ax.GET('/v1/products/{product_id}/tenants', {
        params: { path: { product_id: ctx.productId }, query: { limit: 1, cursor } },
      }),
    );
    const slugs = all.map((t) => t.slug);
    for (const i of [1, 2, 3]) expect(slugs).toContain(`page-${run}-${i}`);
    expect(new Set(all.map((t) => t.id)).size).toBe(all.length);
  });

  it('records: create, read, replace with If-Match, 412 on a stale version, delete', async () => {
    const path = { ...scope(), collection: 'sdk_notes' };
    const rec = await ctx.ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}', {
      params: { path },
      body: { title: 'hello', n: 1 },
    });
    expect(rec.version).toBe(1);
    const p = { ...path, record_id: rec.id };
    const got = await ctx.ax.GET('/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}/{record_id}', {
      params: { path: p },
    });
    expect(got.data).toMatchObject({ title: 'hello', n: 1 });
    const replaced = await ctx.ax.PUT(
      '/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}/{record_id}',
      { params: { path: p, header: { 'If-Match': '1' } }, body: { title: 'changed', n: 2 } },
    );
    expect(replaced.version).toBe(2);
    await expect(
      ctx.ax.PUT('/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}/{record_id}', {
        params: { path: p, header: { 'If-Match': '1' } },
        body: { title: 'stale' },
      }),
    ).rejects.toMatchObject({ status: 412, code: 'precondition_failed' });

    for (const n of [3, 4, 5]) {
      await ctx.ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}', {
        params: { path },
        body: { title: `bulk ${n}`, n },
      });
    }
    const items = await collectAll((cursor) =>
      ctx.ax.GET('/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}', {
        params: { path, query: { limit: 2, cursor } },
      }),
    );
    expect(items.length).toBe(4);

    const deleted = await ctx.ax.DELETE(
      '/v1/products/{product_id}/tenants/{tenant_id}/records/{collection}/{record_id}',
      { params: { path: p } },
    );
    expect(deleted).toBeUndefined();
  });

  it('usage: idempotent recording replays with the same key', async () => {
    await ctx.ax.POST('/v1/products/{product_id}/usage/meters', {
      params: { path: { product_id: ctx.productId } },
      body: { key: `ts_calls_${run}`, unit: 'calls' },
    });
    const header = idempotencyKey(`ts-${run}`);
    const send = () =>
      ctx.ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/usage/events', {
        params: { path: scope(), header },
        body: { meter: `ts_calls_${run}`, quantity: 2 },
      });
    const first = await send();
    const second = await send();
    expect(first.replayed).toBe(false);
    expect(second.replayed).toBe(true);
    expect(second.event.id).toBe(first.event.id);
    const summary = await ctx.ax.GET('/v1/products/{product_id}/tenants/{tenant_id}/usage/summary', {
      params: { path: scope() },
    });
    expect(summary.find((m) => m.meter === `ts_calls_${run}`)?.value).toBe(2);
  });

  it('files: multipart upload and binary download', async () => {
    const content = new TextEncoder().encode(`hello from the TS SDK ${run}`);
    const form = new FormData();
    form.set('file', new Blob([content], { type: 'text/plain' }), 'hello.txt');
    const info = await ctx.ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/files', {
      params: { path: scope() },
      body: { file: '' },
      bodySerializer: () => form,
    });
    expect(info.size).toBe(content.length);
    const downloaded = await ctx.ax.GET('/v1/products/{product_id}/tenants/{tenant_id}/files/{file_id}/content', {
      params: { path: { ...scope(), file_id: info.id } },
      parseAs: 'arrayBuffer',
    });
    expect(new Uint8Array(downloaded as ArrayBuffer)).toEqual(content);
  });

  it(
    'cookie mode: login, automatic CSRF header, refused without it',
    async (test) => {
      // Needs admin credentials: from the env, or from the suite's own setup-token bootstrap.
      if (!ctx.admin) return test.skip();
      const admin = ctx.admin;
      const jarFetch = cookieFetch();
      const browser = createAxentraClient({ baseUrl: ctx.url, fetch: jarFetch });
      const session = await browser.POST('/v1/auth/login/password', {
        body: { email: admin.email, password: admin.password },
      });
      expect(browser.csrf.token).toBe(session.csrf_token);
      expect(jarFetch.jar.size).toBeGreaterThan(0);

      // A fresh client sharing the cookie jar has no token yet: it fetches /v1/auth/session once.
      const second = createAxentraClient({ baseUrl: ctx.url, fetch: jarFetch });
      const user = await second.PATCH('/v1/me', { body: { name: `SDK ${run}` } });
      expect(user.name).toBe(`SDK ${run}`);
      expect(second.csrf.token).toBe(session.csrf_token);

      const noCsrf = createAxentraClient({ baseUrl: ctx.url, fetch: jarFetch, csrf: false });
      await expect(noCsrf.PATCH('/v1/me', { body: { name: 'x' } })).rejects.toMatchObject({
        status: 403,
        code: 'forbidden',
      });

      await browser.POST('/v1/auth/logout');
      expect(browser.csrf.token).toBeNull();
      await expect(second.GET('/v1/me')).rejects.toMatchObject({ status: 401 });
    },
  );
});
