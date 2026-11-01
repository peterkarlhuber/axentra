export {
  CLIENT_HEADER,
  CSRF_HEADER,
  createAxentraClient,
  type AuthOptions,
  type AxentraClient,
  type AxentraClientOptions,
  type DataMethod,
  type FetchLike,
  type Meta,
  type SessionInfo,
} from './client.js';
export { assertCompatible, REQUIRED_API_VERSION, type ApiVersion } from './compat.js';
export {
  AxentraApiError,
  IncompatibleApiError,
  toApiError,
  type Problem,
  type ProblemFieldError,
} from './errors.js';
export { GENERATED_API_VERSION, GENERATED_FROM_SHA256 } from './generated.js';
export { IDEMPOTENCY_KEY_MAX_LENGTH, idempotencyKey, newIdempotencyKey } from './idempotency.js';
export { collectAll, paginate, type CursorPage, type PaginateOptions } from './pagination.js';
export type { components, operations, paths } from './schema.js';
export { SDK_VERSION } from './version.js';

import type { components } from './schema.js';
/** Shorthand for a component schema type: `Schema<'Tenant'>`. */
export type Schema<Name extends keyof components['schemas']> = components['schemas'][Name];
