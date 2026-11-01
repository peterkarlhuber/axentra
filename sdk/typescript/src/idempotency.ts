/** Maximum length the server accepts for `Idempotency-Key` (see the usage/notify endpoints). */
export const IDEMPOTENCY_KEY_MAX_LENGTH = 200;

/** A new random idempotency key (UUID v4). Persist it with the operation if you may retry later. */
export function newIdempotencyKey(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * The `Idempotency-Key` header parameter for endpoints that accept one (usage events and
 * reservations, notify send). Pass your own key to make retries of the SAME logical operation
 * safe; omit it to get a fresh one.
 *
 * ```ts
 * await ax.POST('/v1/products/{product_id}/tenants/{tenant_id}/usage/events', {
 *   params: { path: { product_id, tenant_id }, header: idempotencyKey(orderId) },
 *   body: { meter: 'api_calls', quantity: 1 },
 * });
 * ```
 */
export function idempotencyKey(key: string = newIdempotencyKey()): { 'Idempotency-Key': string } {
  if (!key || key.length > IDEMPOTENCY_KEY_MAX_LENGTH) {
    throw new RangeError(`Idempotency-Key must be 1..${IDEMPOTENCY_KEY_MAX_LENGTH} characters`);
  }
  return { 'Idempotency-Key': key };
}
