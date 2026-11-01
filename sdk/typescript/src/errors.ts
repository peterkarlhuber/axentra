/** One entry of `errors` in a `validation_failed` problem. */
export interface ProblemFieldError {
  loc: (string | number)[];
  msg: string;
}

/** RFC 9457 problem details as Axentra returns them (`application/problem+json`). */
export interface Problem {
  type?: string;
  title?: string;
  status?: number;
  code?: string;
  detail?: string;
  request_id?: string | null;
  errors?: ProblemFieldError[];
  [extra: string]: unknown;
}

/**
 * A non-2xx answer from the Axentra API. `code` is the stable, machine-readable error code
 * (`validation_failed`, `unauthenticated`, `forbidden`, `not_found`, `conflict`,
 * `precondition_failed`, `rate_limited`, `quota_exceeded`, `mode_not_supported`, `internal`, ...).
 * Treat unknown codes like their HTTP status.
 */
export class AxentraApiError extends Error {
  override readonly name = 'AxentraApiError';
  readonly status: number;
  readonly code: string;
  readonly title: string;
  readonly detail: string;
  readonly requestId: string | null;
  readonly errors: ProblemFieldError[];
  /** The parsed problem body (or `{}` when the body was not a problem document). */
  readonly problem: Problem;
  /** `Retry-After` in seconds for 429 answers, when the server sent it. */
  readonly retryAfter: number | null;

  constructor(init: {
    status: number;
    code: string;
    title?: string;
    detail?: string;
    requestId?: string | null;
    errors?: ProblemFieldError[];
    problem?: Problem;
    retryAfter?: number | null;
  }) {
    const detail = init.detail ?? '';
    super(`${init.status} ${init.code}${detail ? `: ${detail}` : ''}`);
    this.status = init.status;
    this.code = init.code;
    this.title = init.title ?? '';
    this.detail = detail;
    this.requestId = init.requestId ?? null;
    this.errors = init.errors ?? [];
    this.problem = init.problem ?? {};
    this.retryAfter = init.retryAfter ?? null;
  }
}

/** Thrown by `checkCompatibility()` when the server's API version cannot serve this SDK build. */
export class IncompatibleApiError extends Error {
  override readonly name = 'IncompatibleApiError';
  readonly reason: 'major_mismatch' | 'minor_too_low' | 'unparseable';
  readonly server: { major: number; minor: number } | null;
  readonly required: { major: number; minor: number };

  constructor(
    reason: IncompatibleApiError['reason'],
    server: IncompatibleApiError['server'],
    required: IncompatibleApiError['required'],
  ) {
    const want = `${required.major}.${required.minor}`;
    const got = server ? `${server.major}.${server.minor}` : 'an unreadable version';
    const why =
      reason === 'major_mismatch'
        ? `the server speaks API ${got}, but this SDK needs major version ${required.major}`
        : reason === 'minor_too_low'
          ? `the server speaks API ${got}, but this SDK needs at least ${want}; upgrade the server or use an older SDK`
          : `the server reported ${got}; expected api_version {major, minor}`;
    super(`Incompatible Axentra API: ${why}.`);
    this.reason = reason;
    this.server = server;
    this.required = required;
  }
}

const STATUS_CODES: Record<number, string> = {
  400: 'bad_request',
  401: 'unauthenticated',
  403: 'forbidden',
  404: 'not_found',
  409: 'conflict',
  412: 'precondition_failed',
  413: 'payload_too_large',
  422: 'validation_failed',
  429: 'rate_limited',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Builds an `AxentraApiError` from a failed response. `body` is what was already read from the
 * response (openapi-fetch parses JSON and falls back to text); when omitted the body is read here.
 */
export async function toApiError(response: Response, body?: unknown): Promise<AxentraApiError> {
  let parsed: unknown = body;
  if (parsed === undefined && !response.bodyUsed) {
    const text = await response.text().catch(() => '');
    try {
      parsed = text ? JSON.parse(text) : undefined;
    } catch {
      parsed = text;
    }
  }
  const problem: Problem = isRecord(parsed) ? (parsed as Problem) : {};
  const retry = response.headers.get('retry-after');
  const retryAfter = retry !== null && /^\d+$/.test(retry) ? Number(retry) : null;
  const code =
    typeof problem.code === 'string' && problem.code
      ? problem.code
      : (STATUS_CODES[response.status] ?? (response.status >= 500 ? 'internal' : 'error'));
  const detail =
    typeof problem.detail === 'string'
      ? problem.detail
      : typeof parsed === 'string'
        ? parsed.slice(0, 500)
        : response.statusText;
  return new AxentraApiError({
    status: response.status,
    code,
    title: typeof problem.title === 'string' ? problem.title : response.statusText,
    detail,
    requestId:
      (typeof problem.request_id === 'string' ? problem.request_id : null) ??
      response.headers.get('x-request-id'),
    errors: Array.isArray(problem.errors) ? problem.errors : [],
    problem,
    retryAfter,
  });
}
