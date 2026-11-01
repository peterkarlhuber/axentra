/** A cursor page as every Axentra list endpoint with `limit`/`cursor` returns it. */
export interface CursorPage<T> {
  items: T[];
  next_cursor?: string | null;
}

export interface PaginateOptions {
  /** Stop after this many pages (default: no limit). */
  maxPages?: number;
}

/**
 * Iterates all items of a cursor-paginated endpoint. `fetchPage` receives the cursor to send
 * (`undefined` for the first page) and returns one page:
 *
 * ```ts
 * for await (const tenant of paginate((cursor) =>
 *   ax.GET('/v1/products/{product_id}/tenants', {
 *     params: { path: { product_id }, query: { cursor, limit: 100 } },
 *   }),
 * )) { ... }
 * ```
 *
 * Pages are fetched lazily, one at a time. A server that returns the same cursor twice stops
 * the iteration with an error instead of looping forever.
 */
export async function* paginate<T>(
  fetchPage: (cursor: string | undefined) => Promise<CursorPage<T>>,
  options: PaginateOptions = {},
): AsyncGenerator<T, void, undefined> {
  let cursor: string | undefined;
  const seen = new Set<string>();
  for (let page = 0; options.maxPages === undefined || page < options.maxPages; page += 1) {
    const result = await fetchPage(cursor);
    yield* result.items;
    const next = result.next_cursor ?? undefined;
    if (!next) return;
    if (seen.has(next)) throw new Error(`paginate: the server returned cursor ${next} twice`);
    seen.add(next);
    cursor = next;
  }
}

/** Collects all items of `paginate(fetchPage)` into an array (convenient for small lists). */
export async function collectAll<T>(
  fetchPage: (cursor: string | undefined) => Promise<CursorPage<T>>,
  options: PaginateOptions = {},
): Promise<T[]> {
  const out: T[] = [];
  for await (const item of paginate(fetchPage, options)) out.push(item);
  return out;
}
