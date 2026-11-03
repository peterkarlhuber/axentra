import fs from 'node:fs';
import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  AxentraApiError,
  CLIENT_HEADER,
  CSRF_HEADER,
  collectAll,
  createAxentraClient,
  GENERATED_API_VERSION,
  IncompatibleApiError,
  idempotencyKey,
  newIdempotencyKey,
  paginate,
  REQUIRED_API_VERSION,
  SDK_VERSION,
  type Schema,
} from '../src/index.js';

const BASE = 'http://api.test';

interface Recorded {
  method: string;
  url: string;
  headers: Headers;
  credentials: RequestCredentials;
  body: string;
}

type Handler = (req: Request, body: string) => Response | Promise<Response>;

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function problem(status: number, code: string, extra: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({
      type: `urn:axentra:problem:${code}`,
      title: code,
      status,
      code,
      detail: `detail for ${code}`,
      request_id: 'req_abc',
      ...extra,
    }),
    { status, headers: { 'content-type': 'application/problem+json' } },
  );
}

function mockFetch(handler: Handler) {
  const calls: Recorded[] = [];
  const fetch = async (req: Request) => {
    const body = req.body ? await req.clone().text() : '';
    calls.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      credentials: req.credentials,
      body,
    });
    return handler(req, body);
  };
  return { fetch, calls };
}

const session = (csrf: string) => ({
  user: { id: 'usr_1', email: 'a@example.com' },
  session_id: 'ses_1',
  csrf_token: csrf,
  expires_at: '2026-11-02T00:00:00Z',
  platform_role: null,
});

const tenant = (id: string) => ({ id, name: id, slug: id, product_id: 'prd_1', status: 'active', version: 1 });

describe('authentication', () => {
  it('sends the API key as a bearer token and never fetches a CSRF token', async () => {
    const { fetch, calls } = mockFetch(() => json(tenant('ten_1'), 201));
    const ax = createAxentraClient({ baseUrl: `${BASE}/`, apiKey: 'axk_k1_secret', fetch });
    const created = await ax.POST('/v1/products/{product_id}/tenants', {
      params: { path: { product_id: 'prd_1' } },
      body: { name: 'Acme', slug: 'acme' },
    });
    expect(created.id).toBe('ten_1');
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toBe(`${BASE}/v1/products/prd_1/tenants`);
    expect(call.headers.get('authorization')).toBe('Bearer axk_k1_secret');
    expect(call.headers.get('axentra-client')).toBe(CLIENT_HEADER);
    expect(call.headers.get(CSRF_HEADER)).toBeNull();
    expect(call.credentials).toBe('omit');
    expect(JSON.parse(call.body)).toEqual({ name: 'Acme', slug: 'acme' });
  });

  it('sends a session token as a bearer token', async () => {
    const { fetch, calls } = mockFetch(() => json({ actor_kind: 'user' }));
    const ax = createAxentraClient({ baseUrl: BASE, sessionToken: 'tok_123', fetch });
    await ax.GET('/v1/me');
    expect(calls[0]!.headers.get('authorization')).toBe('Bearer tok_123');
  });

  it('setAuth switches between bearer and cookie mode', async () => {
    const { fetch, calls } = mockFetch(() => json({ actor_kind: 'user' }));
    const ax = createAxentraClient({ baseUrl: BASE, fetch });
    await ax.GET('/v1/me');
    ax.setAuth({ apiKey: 'axk_x_y' });
    await ax.GET('/v1/me');
    ax.setAuth(null);
    await ax.GET('/v1/me');
    expect(calls.map((c) => c.headers.get('authorization'))).toEqual([null, 'Bearer axk_x_y', null]);
    expect(calls.map((c) => c.credentials)).toEqual(['include', 'omit', 'include']);
  });
});

describe('cookie mode CSRF', () => {
  it('fetches /v1/auth/session once and sends X-Axentra-CSRF on unsafe methods only', async () => {
    const { fetch, calls } = mockFetch((req) => {
      if (req.url.endsWith('/v1/auth/session')) return json(session('csrf-1'));
      if (req.method === 'GET') return json({ items: [], next_cursor: null });
      if (req.method === 'DELETE') return new Response(null, { status: 204 });
      return json(tenant('ten_1'), 201);
    });
    const ax = createAxentraClient({ baseUrl: BASE, fetch });
    await ax.GET('/v1/products/{product_id}/tenants', { params: { path: { product_id: 'prd_1' } } });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers.get(CSRF_HEADER)).toBeNull();
    expect(calls[0]!.credentials).toBe('include');

    // Two concurrent unsafe requests share one session lookup.
    await Promise.all([
      ax.POST('/v1/products/{product_id}/tenants', {
        params: { path: { product_id: 'prd_1' } },
        body: { name: 'A', slug: 'a' },
      }),
      ax.DELETE('/v1/products/{product_id}/tenants/{tenant_id}', {
        params: { path: { product_id: 'prd_1', tenant_id: 'ten_1' } },
      }),
    ]);
    const sessionCalls = calls.filter((c) => c.url.endsWith('/v1/auth/session'));
    expect(sessionCalls).toHaveLength(1);
    expect(sessionCalls[0]!.credentials).toBe('include');
    const unsafe = calls.filter((c) => c.method === 'POST' || c.method === 'DELETE');
    expect(unsafe.map((c) => c.headers.get(CSRF_HEADER))).toEqual(['csrf-1', 'csrf-1']);
    expect(ax.csrf.token).toBe('csrf-1');
  });

  it('takes the token from the login response and forgets it on logout', async () => {
    let n = 0;
    const { fetch, calls } = mockFetch((req) => {
      if (req.url.endsWith('/v1/auth/login/password')) return json(session('from-login'));
      if (req.url.endsWith('/v1/auth/logout')) return new Response(null, { status: 204 });
      if (req.url.endsWith('/v1/auth/session')) return json(session(`fresh-${++n}`));
      return json({ id: 'usr_1' });
    });
    const ax = createAxentraClient({ baseUrl: BASE, fetch });
    await ax.POST('/v1/auth/login/password', { body: { email: 'a@example.com', password: 'pw' } });
    expect(calls[0]!.headers.get(CSRF_HEADER)).toBeNull();
    expect(ax.csrf.token).toBe('from-login');
    await ax.PATCH('/v1/me', { body: { name: 'New' } });
    expect(calls[1]!.headers.get(CSRF_HEADER)).toBe('from-login');
    await ax.POST('/v1/auth/logout');
    expect(ax.csrf.token).toBeNull();
    expect(calls.some((c) => c.url.endsWith('/v1/auth/session'))).toBe(false); // the login token sufficed
  });

  it('sends no header when there is no session (the server answers 401) and can refresh', async () => {
    let loggedIn = false;
    const { fetch, calls } = mockFetch((req) => {
      if (req.url.endsWith('/v1/auth/session'))
        return loggedIn ? json(session('later')) : problem(401, 'unauthenticated');
      return problem(401, 'unauthenticated');
    });
    const ax = createAxentraClient({ baseUrl: BASE, fetch });
    await expect(ax.PATCH('/v1/me', { body: { name: 'x' } })).rejects.toMatchObject({
      status: 401,
      code: 'unauthenticated',
    });
    expect(calls.at(-1)!.headers.get(CSRF_HEADER)).toBeNull();
    loggedIn = true;
    expect(await ax.csrf.refresh()).toBe('later');
  });

  it('can be disabled explicitly', async () => {
    const { fetch, calls } = mockFetch(() => json({ id: 'usr_1' }));
    const ax = createAxentraClient({ baseUrl: BASE, fetch, csrf: false, credentials: 'same-origin' });
    await ax.PATCH('/v1/me', { body: { name: 'x' } });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.credentials).toBe('same-origin');
  });
});

describe('errors', () => {
  it('maps problem+json to AxentraApiError', async () => {
    const { fetch } = mockFetch(() =>
      problem(422, 'validation_failed', { errors: [{ loc: ['body', 'slug'], msg: 'bad slug' }] }),
    );
    const ax = createAxentraClient({ baseUrl: BASE, apiKey: 'axk_a_b', fetch });
    const err = await ax
      .POST('/v1/products', { body: { name: 'x', slug: '!' } })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AxentraApiError);
    const e = err as AxentraApiError;
    expect(e.status).toBe(422);
    expect(e.code).toBe('validation_failed');
    expect(e.detail).toBe('detail for validation_failed');
    expect(e.requestId).toBe('req_abc');
    expect(e.errors).toEqual([{ loc: ['body', 'slug'], msg: 'bad slug' }]);
    expect(e.message).toContain('422 validation_failed');
  });

  it('handles non-problem error bodies and takes the request id from the header', async () => {
    const { fetch } = mockFetch(
      () => new Response('upstream broke', { status: 502, headers: { 'x-request-id': 'req_hdr' } }),
    );
    const ax = createAxentraClient({ baseUrl: BASE, apiKey: 'axk_a_b', fetch });
    const e = (await ax.GET('/v1/meta').catch((x: unknown) => x)) as AxentraApiError;
    expect(e).toBeInstanceOf(AxentraApiError);
    expect(e.status).toBe(502);
    expect(e.code).toBe('internal');
    expect(e.detail).toBe('upstream broke');
    expect(e.requestId).toBe('req_hdr');
  });

  it('exposes Retry-After for 429', async () => {
    const { fetch } = mockFetch(() => {
      const r = problem(429, 'quota_exceeded');
      r.headers.set('retry-after', '60');
      return r;
    });
    const ax = createAxentraClient({ baseUrl: BASE, apiKey: 'axk_a_b', fetch });
    const e = (await ax
      .POST('/v1/products/{product_id}/tenants/{tenant_id}/usage/events', {
        params: { path: { product_id: 'p', tenant_id: 't' }, header: idempotencyKey('k1') },
        body: { meter: 'm', quantity: 1 },
      })
      .catch((x: unknown) => x)) as AxentraApiError;
    expect(e.code).toBe('quota_exceeded');
    expect(e.retryAfter).toBe(60);
  });

  it('raw keeps openapi-fetch semantics', async () => {
    const { fetch } = mockFetch(() => problem(404, 'not_found'));
    const ax = createAxentraClient({ baseUrl: BASE, apiKey: 'axk_a_b', fetch });
    const res = await ax.raw.GET('/v1/products/{product_id}', { params: { path: { product_id: 'prd_x' } } });
    expect(res.response.status).toBe(404);
    expect(res.data).toBeUndefined();
    expect(res.error).toMatchObject({ code: 'not_found' });
  });

  it('204 resolves to undefined', async () => {
    const { fetch } = mockFetch(() => new Response(null, { status: 204 }));
    const ax = createAxentraClient({ baseUrl: BASE, apiKey: 'axk_a_b', fetch });
    const out = await ax.DELETE('/v1/products/{product_id}/roles/{role_id}', {
      params: { path: { product_id: 'p', role_id: 'r' } },
    });
    expect(out).toBeUndefined();
  });
});

describe('checkCompatibility', () => {
  const meta = (major: unknown, minor: unknown) =>
    json({
      name: 'axentra',
      version: '0.1.0',
      api_version: { major, minor },
      mode: 'multi',
      environment: 'test',
      modules: [],
      product: null,
      auth: { password: true, oidc: [] },
      setup_required: false,
    });

  const run = (major: unknown, minor: unknown) => {
    const { fetch } = mockFetch(() => meta(major, minor));
    return createAxentraClient({ baseUrl: BASE, fetch }).checkCompatibility();
  };

  it('accepts the generated version and newer minors', async () => {
    const { major, minor } = REQUIRED_API_VERSION;
    expect((await run(major, minor)).server_api).toEqual({ major, minor });
    expect((await run(major, minor + 3)).server_api).toEqual({ major, minor: minor + 3 });
  });

  it('rejects another major, a lower minor and garbage', async () => {
    const { major, minor } = REQUIRED_API_VERSION;
    await expect(run(major + 1, 0)).rejects.toMatchObject({ reason: 'major_mismatch' });
    await expect(run(major, 'x')).rejects.toMatchObject({ reason: 'unparseable' });
    const e = await run(major, minor - 1).catch((x: unknown) => x);
    if (minor > 0) expect(e).toMatchObject({ reason: 'minor_too_low' });
    const err = (await run(major + 1, 0).catch((x: unknown) => x)) as IncompatibleApiError;
    expect(err).toBeInstanceOf(IncompatibleApiError);
    expect(err.message).toMatch(/Incompatible Axentra API/);
    expect(err.required).toEqual(REQUIRED_API_VERSION);
  });

  it('the generated version matches the committed OpenAPI contract', () => {
    const spec = JSON.parse(fs.readFileSync(new URL('../../../openapi/axentra-v1.json', import.meta.url), 'utf8'));
    expect(`${GENERATED_API_VERSION.major}.${GENERATED_API_VERSION.minor}`).toBe(spec.info.version);
  });
});

describe('pagination', () => {
  it('follows next_cursor until it is null', async () => {
    const pages: Record<string, { items: unknown[]; next_cursor: string | null }> = {
      '': { items: [tenant('t1'), tenant('t2')], next_cursor: 'c2' },
      c2: { items: [tenant('t3')], next_cursor: 'c3' },
      c3: { items: [], next_cursor: null },
    };
    const { fetch, calls } = mockFetch((req) => {
      const cursor = new URL(req.url).searchParams.get('cursor') ?? '';
      return json(pages[cursor]);
    });
    const ax = createAxentraClient({ baseUrl: BASE, apiKey: 'axk_a_b', fetch });
    const ids: string[] = [];
    for await (const t of ax.paginate((cursor) =>
      ax.GET('/v1/products/{product_id}/tenants', {
        params: { path: { product_id: 'prd_1' }, query: { cursor, limit: 2 } },
      }),
    )) {
      expectTypeOf(t).toEqualTypeOf<Schema<'Tenant'>>();
      ids.push(t.id);
    }
    expect(ids).toEqual(['t1', 't2', 't3']);
    expect(calls.map((c) => new URL(c.url).search)).toEqual(['?limit=2', '?cursor=c2&limit=2', '?cursor=c3&limit=2']);
  });

  it('honours maxPages, stops on repeated cursors and collects', async () => {
    const loop = async () => ({ items: [1], next_cursor: 'same' });
    expect(await collectAll(loop, { maxPages: 1 })).toEqual([1]);
    await expect(collectAll(loop)).rejects.toThrow(/twice/);
    const it = paginate(async () => ({ items: [], next_cursor: null }));
    expect((await it.next()).done).toBe(true);
  });
});

describe('idempotency', () => {
  it('builds the header parameter and sends it', async () => {
    const { fetch, calls } = mockFetch(() => json({ replayed: false }, 201));
    const ax = createAxentraClient({ baseUrl: BASE, apiKey: 'axk_a_b', fetch });
    await ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/usage/events', {
      params: { path: { product_id: 'p', tenant_id: 't' }, header: idempotencyKey('order-42') },
      body: { meter: 'api_calls', quantity: 1 },
    });
    expect(calls[0]!.headers.get('idempotency-key')).toBe('order-42');
    expect(newIdempotencyKey()).not.toBe(newIdempotencyKey());
    expect(idempotencyKey()['Idempotency-Key']).toMatch(/^[0-9a-f-]{36}$/);
    expect(() => idempotencyKey('')).toThrow(RangeError);
    expect(() => idempotencyKey('x'.repeat(201))).toThrow(RangeError);
  });
});

describe('package', () => {
  it('SDK_VERSION matches package.json', () => {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    expect(SDK_VERSION).toBe(pkg.version);
    expect(CLIENT_HEADER).toBe(`axentra-sdk-ts/${pkg.version}; api=${REQUIRED_API_VERSION.major}.${REQUIRED_API_VERSION.minor}`);
  });

  it('typed responses: data is non-optional and 204 is undefined', async () => {
    const { fetch } = mockFetch((req) =>
      req.method === 'DELETE' ? new Response(null, { status: 204 }) : json({ api_version: { major: 1, minor: 0 } }),
    );
    const ax = createAxentraClient({ baseUrl: BASE, fetch });
    const meta = await ax.GET('/v1/meta');
    expectTypeOf(meta).toEqualTypeOf<Schema<'Meta'>>();
    const deleted = await ax.DELETE('/v1/products/{product_id}/roles/{role_id}', {
      params: { path: { product_id: 'p', role_id: 'r' } },
    });
    expectTypeOf(deleted).toEqualTypeOf<undefined>();
  });
});
