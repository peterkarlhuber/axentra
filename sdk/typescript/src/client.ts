import createClient, {
  type Client,
  type FetchResponse,
  type MaybeOptionalInit,
  type Middleware,
} from 'openapi-fetch';
import type { HttpMethod, MediaType, PathsWithMethod } from 'openapi-typescript-helpers';
import { assertCompatible, REQUIRED_API_VERSION, type ApiVersion } from './compat.js';
import { toApiError } from './errors.js';
import { paginate, type CursorPage, type PaginateOptions } from './pagination.js';
import type { components, paths } from './schema.js';
import { SDK_VERSION } from './version.js';

export type Meta = components['schemas']['Meta'];
export type SessionInfo = components['schemas']['SessionInfo'];

export const CSRF_HEADER = 'X-Axentra-CSRF';
/** `Axentra-Client` header value sent with every request (API_CONVENTIONS "Base path and versioning"). */
export const CLIENT_HEADER = `axentra-sdk-ts/${SDK_VERSION}; api=${REQUIRED_API_VERSION.major}.${REQUIRED_API_VERSION.minor}`;

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

export type FetchLike = (input: Request) => Promise<Response>;

export interface AxentraClientOptions {
  /** API origin, e.g. `https://api.example.com` (no `/v1`; paths include it). */
  baseUrl: string;
  /** Machine authentication: `axk_<id>_<secret>`, sent as `Authorization: Bearer`. */
  apiKey?: string;
  /** A user session token (from a login), sent as `Authorization: Bearer`. No CSRF needed. */
  sessionToken?: string;
  /**
   * `fetch` credentials mode. Default: `'include'` in cookie mode (no apiKey/sessionToken) so
   * the browser sends the HttpOnly session cookie cross-origin; `'omit'` with a bearer token.
   */
  credentials?: RequestCredentials;
  /**
   * Send `X-Axentra-CSRF` on unsafe methods. Default: on in cookie mode, off with a bearer
   * token. The token is read once from `GET /v1/auth/session` (or the login/setup response)
   * and kept in memory only.
   */
  csrf?: boolean;
  /** Custom fetch (tests, SSR, proxies). Receives a `Request`. */
  fetch?: FetchLike;
  /** Extra headers for every request. */
  headers?: Record<string, string>;
}

type InitParam<Init> = keyof Init extends never
  ? [(Init & { [key: string]: unknown })?]
  : {} extends Init
    ? [(Init & { [key: string]: unknown })?]
    : [Init & { [key: string]: unknown }];

type SuccessBranch<T, Init> =
  T extends Record<string | number, any> ? Extract<FetchResponse<T, Init, MediaType>, { data: unknown }> : never;

type SuccessData<T, Init> = [SuccessBranch<T, Init>['data']] extends [never]
  ? void
  : SuccessBranch<T, Init>['data'];

/**
 * Like an openapi-fetch method, but resolves to the response data and throws
 * `AxentraApiError` for every non-2xx answer.
 */
export type DataMethod<Method extends HttpMethod> = <
  Path extends PathsWithMethod<paths, Method>,
  Init extends MaybeOptionalInit<paths[Path], Method>,
>(
  url: Path,
  ...init: InitParam<Init>
) => Promise<SuccessData<paths[Path][Method], Init>>;

export type AuthOptions = { apiKey: string } | { sessionToken: string } | null;

export interface AxentraClient {
  GET: DataMethod<'get'>;
  POST: DataMethod<'post'>;
  PUT: DataMethod<'put'>;
  PATCH: DataMethod<'patch'>;
  DELETE: DataMethod<'delete'>;
  /**
   * The underlying openapi-fetch client (same auth, CSRF and headers), for callers that want
   * `{ data, error, response }` instead of exceptions, or the raw `Response` (`parseAs: 'stream'`).
   */
  raw: Client<paths>;
  /**
   * `GET /v1/meta` and the version rule: throws `IncompatibleApiError` when the server's major
   * differs or its minor is lower than the one this SDK was generated for. Returns the meta.
   */
  checkCompatibility(): Promise<Meta & { server_api: ApiVersion }>;
  /** Iterate all items of a cursor-paginated endpoint (see `paginate`). */
  paginate<T>(
    fetchPage: (cursor: string | undefined) => Promise<CursorPage<T>>,
    options?: PaginateOptions,
  ): AsyncGenerator<T, void, undefined>;
  /** Switch credentials at runtime (e.g. after a login). `null` returns to cookie mode. */
  setAuth(auth: AuthOptions): void;
  /** CSRF token handling in cookie mode. */
  csrf: {
    /** The token currently held in memory (or null). */
    readonly token: string | null;
    /** Forget the token and fetch it again from `GET /v1/auth/session`. */
    refresh(): Promise<string | null>;
    /** Set the token explicitly (e.g. from a login response handled elsewhere). */
    set(token: string | null): void;
  };
}

const CSRF_SOURCES = new Set(['/v1/auth/login/password', '/v1/auth/setup']);

export function createAxentraClient(options: AxentraClientOptions): AxentraClient {
  const baseUrl = options.baseUrl.replace(/\/+$/, '');
  const fetchImpl: FetchLike = options.fetch ?? ((req) => globalThis.fetch(req));
  let bearer: string | null = options.apiKey ?? options.sessionToken ?? null;
  let csrfToken: string | null = null;
  let csrfPending: Promise<string | null> | null = null;

  const cookieMode = () => bearer === null;
  const credentials = (): RequestCredentials =>
    options.credentials ?? (cookieMode() ? 'include' : 'omit');
  const csrfEnabled = () => options.csrf ?? cookieMode();

  async function fetchCsrf(): Promise<string | null> {
    const response = await fetchImpl(
      new Request(`${baseUrl}/v1/auth/session`, {
        method: 'GET',
        credentials: credentials(),
        headers: { Accept: 'application/json', 'Axentra-Client': CLIENT_HEADER, ...options.headers },
      }),
    );
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      return null;
    }
    const body = (await response.json()) as Partial<SessionInfo>;
    return typeof body.csrf_token === 'string' ? body.csrf_token : null;
  }

  function ensureCsrf(): Promise<string | null> {
    if (csrfToken) return Promise.resolve(csrfToken);
    csrfPending ??= fetchCsrf()
      .then((token) => {
        csrfToken = token;
        return token;
      })
      .finally(() => {
        csrfPending = null;
      });
    return csrfPending;
  }

  const middleware: Middleware = {
    async onRequest({ request, schemaPath }) {
      request.headers.set('Axentra-Client', CLIENT_HEADER);
      if (bearer !== null) request.headers.set('Authorization', `Bearer ${bearer}`);
      if (
        csrfEnabled() &&
        !SAFE_METHODS.has(request.method.toUpperCase()) &&
        !CSRF_SOURCES.has(schemaPath) &&
        !request.headers.has(CSRF_HEADER)
      ) {
        const token = await ensureCsrf();
        if (token) request.headers.set(CSRF_HEADER, token);
      }
      return request;
    },
    async onResponse({ response, schemaPath }) {
      if (CSRF_SOURCES.has(schemaPath) && response.ok) {
        const body = (await response
          .clone()
          .json()
          .catch(() => null)) as Partial<SessionInfo> | null;
        if (body && typeof body.csrf_token === 'string') csrfToken = body.csrf_token;
      } else if (schemaPath === '/v1/auth/logout' && response.ok) {
        csrfToken = null;
      } else if (response.status === 401) {
        csrfToken = null;
      }
      return response;
    },
  };

  const raw = createClient<paths>({
    baseUrl,
    fetch: fetchImpl,
    credentials: credentials(),
    headers: { Accept: 'application/json', ...options.headers },
  });
  raw.use(middleware);

  function dataMethod<M extends HttpMethod>(method: M): DataMethod<M> {
    return (async (url: string, init?: Record<string, unknown>) => {
      // credentials follow the current auth mode (setAuth); `raw` keeps the initial mode.
      const withCredentials = { credentials: credentials(), ...init };
      const result = (await raw.request(method as never, url as never, withCredentials as never)) as {
        data?: unknown;
        error?: unknown;
        response: Response;
      };
      if (result.error !== undefined || !result.response.ok) {
        throw await toApiError(result.response, result.error);
      }
      return result.response.status === 204 ? undefined : result.data;
    }) as unknown as DataMethod<M>;
  }

  const client: AxentraClient = {
    GET: dataMethod('get'),
    POST: dataMethod('post'),
    PUT: dataMethod('put'),
    PATCH: dataMethod('patch'),
    DELETE: dataMethod('delete'),
    raw,
    async checkCompatibility() {
      const meta = await client.GET('/v1/meta');
      const server = assertCompatible(meta.api_version);
      return { ...meta, server_api: server };
    },
    paginate: (fetchPage, opts) => paginate(fetchPage, opts),
    setAuth(auth) {
      bearer = auth === null ? null : 'apiKey' in auth ? auth.apiKey : auth.sessionToken;
      csrfToken = null;
    },
    csrf: {
      get token() {
        return csrfToken;
      },
      async refresh() {
        csrfToken = null;
        return ensureCsrf();
      },
      set(token) {
        csrfToken = token;
      },
    },
  };
  return client;
}
