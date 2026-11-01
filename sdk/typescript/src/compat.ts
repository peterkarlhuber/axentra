import { IncompatibleApiError } from './errors.js';
import { GENERATED_API_VERSION } from './generated.js';

export interface ApiVersion {
  major: number;
  minor: number;
}

/** The API version this SDK build requires (= the version it was generated for). */
export const REQUIRED_API_VERSION: ApiVersion = { ...GENERATED_API_VERSION };

/**
 * Applies the rule from API_CONVENTIONS "Base path and versioning": the server's major must
 * equal the SDK's, and its minor must be at least the SDK's. A newer server minor is fine.
 * Throws `IncompatibleApiError`; returns the parsed server version otherwise.
 */
export function assertCompatible(value: unknown, required: ApiVersion = REQUIRED_API_VERSION): ApiVersion {
  const v = value as { major?: unknown; minor?: unknown } | null | undefined;
  if (!v || !Number.isInteger(v.major) || !Number.isInteger(v.minor)) {
    throw new IncompatibleApiError('unparseable', null, required);
  }
  const server = { major: v.major as number, minor: v.minor as number };
  if (server.major !== required.major) throw new IncompatibleApiError('major_mismatch', server, required);
  if (server.minor < required.minor) throw new IncompatibleApiError('minor_too_low', server, required);
  return server;
}
