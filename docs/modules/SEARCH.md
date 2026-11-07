# Search module (`axentra.search`)

A tenant-scoped full-text index for product data. Products push the searchable text of their
objects into the index (an invoice, a contact, a ticket); users query it with ranking and
highlighted snippets. The default adapter uses PostgreSQL full-text search, so the module needs
no extra service or dependency. The interface is a small protocol, so another engine can replace it.

The index is a **derived copy**. The product stays the source of truth and keeps the index in
sync (upsert on create/change, delete on removal). Axentra does not read product tables or records
by itself.

## Concepts

| Concept | Description |
|---|---|
| **Document** | One indexed object in one tenant: `kind` (`^[a-z][a-z0-9_.-]{0,62}$`, e.g. `invoice`), `ref_id` (the product's id of the object, `^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,199}$`), `title` (at most 1000 characters), `body` (plain text, at most `search.max_body_chars`), `metadata` (JSON object, at most 16 KB, returned with hits, **not searched**), `language`, `version`, `created_by`/`updated_by`, timestamps. Ids are `sdoc_...`. |
| **Identity** | `(product, tenant, kind, ref_id)` is unique. Upserting the same key replaces the document (`version` + 1). The same kind and ref id in another tenant or product is a different document. |
| **Product namespace** | Every document carries its `product_id` and `tenant_id`. Products never see each other's documents, even when they use the same kinds and ref ids. |
| **Search vector** | A generated `tsvector` column: `title` with weight A, `body` with weight B, in the document's text search configuration. GIN index. |
| **Language** | `search.language` (default `simple`: lower-casing, no stemming, no stop words, language independent). Any PostgreSQL text search configuration works, e.g. `english` or `german` (stemming, stop words). Each document stores the configuration it was indexed with; queries use the configured one. After changing the setting, re-index (upsert) existing documents. Until then, they match only on tokens that both configurations produce the same way. |
| **Query** | Web search syntax (`websearch_to_tsquery`): all words must match; `"quoted phrase"`; `or`; `-word` excludes. User input is never parsed as raw `tsquery` operators, so it cannot cause a syntax error. A query without searchable words (e.g. only punctuation, or only stop words) returns no hits. With `match=prefix` (search as you type) the text is split into terms of letters and digits (at most 8; operators and quotes are plain text); every term must match, and terms of two or more characters also match longer words that start with them (`inv` finds `invoice`). |
| **Ranking** | `ts_rank` (title matches outweigh body matches; more occurrences rank higher), then newest `updated_at`, then id. |
| **Highlights** | `title_highlight` (the whole title) and `body_highlight` (up to two fragments separated by ` ... `) from `ts_headline`. They are **HTML-escaped text** in which only the matches are wrapped in `<mark>...</mark>`, so a client may render them as HTML. All other fields (e.g. `title`) are raw text. |
| **Adapter** | `SearchAdapter` protocol (`upsert`, `get`, `delete`, `query`). `PostgresSearchAdapter` is the default. |

## Library usage

```python
from axentra.core.context import Principal

# Index from product code (e.g. after saving an invoice, in a job handler, or in a record hook).
# A user/API key principal needs search:index; trusted in-process code can use a system principal.
indexer = Principal.system("invoice-indexer")
result = ax.search.upsert(
    indexer, pid, tid, "invoice", invoice.id,
    title=f"Invoice {invoice.number} for {invoice.customer}",
    body=invoice.notes,
    metadata={"number": invoice.number, "total": str(invoice.total)},
)
result.created, result.document.version

ax.search.delete(indexer, pid, tid, "invoice", invoice.id)       # NotFound if not indexed

# Query as the calling user (needs search:query in that tenant):
page = ax.search.query(principal, pid, tid, "roadmap -draft", kinds=["invoice", "note"], limit=20)
for hit in page.items:
    hit.kind, hit.ref_id, hit.rank, hit.title_highlight, hit.body_highlight, hit.metadata
more = ax.search.query(principal, pid, tid, "roadmap -draft", cursor=page.next_cursor)

# Another engine: implement axentra.search.SearchAdapter and install it at startup.
ax.search.set_adapter(MyEngineAdapter(...))
```

`ax.search` is `None` when the module `search` is disabled (`modules` setting).

Search results are only as fresh as the product's index writes. When a document must disappear
together with its source object, delete it in the same code path; when it must stay consistent even
if the process dies in between, index from a job (module `events`) that retries.

## HTTP endpoints

All paths are under `/v1/products/{product_id}/tenants/{tenant_id}/search`. Errors are
`application/problem+json`. A foreign product or tenant returns `404`.

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `?q&kind&match&limit&cursor` | `search:query` | `Page[SearchHit]`. `q` 1..500 characters, required. `kind` repeatable (at most 20). `match` `words` (default) or `prefix` (search as you type). `limit` 1..200, default 20 |
| GET | `/kinds` | `search:query` | `[{kind, count}]`: the kinds indexed in the tenant with their document counts, in kind order (at most 500), for a kind picker. An adapter without `kinds()` answers `409` |
| GET | `/documents/{kind}/{ref_id}` | `search:query` | `SearchDocument` |
| PUT | `/documents/{kind}/{ref_id}` `{title, body, metadata}` | `search:index` | `201 SearchDocument` when created, `200` when replaced. `413` when the body is too long, `422` on invalid input (e.g. neither title nor body) |
| DELETE | `/documents/{kind}/{ref_id}` | `search:index` | `204`, `404` when not indexed |

Response shapes:

- `SearchHit`: `{id, kind, ref_id, title, metadata, rank, title_highlight, body_highlight, updated_at}`
  (no `body`; fetch the document or the source object for it).
- `SearchDocument`: `{id, product_id, tenant_id, kind, ref_id, title, body, metadata, language,
  version, created_by, updated_by, created_at, updated_at}`.

Paging: `next_cursor` encodes the position in the ranked result. Pages are not a snapshot. When
the index changes between two requests, a hit can move to another page, so it can be seen twice or
not at all. Paging stops at position `search.max_offset` (default 1000; a cursor beyond it gets
`422`). Refine the query instead of paging deeper.

### Permissions and role defaults

Both permissions are tenant permissions (catalog in `axentra.access.permissions`):

| Role | `search:query` | `search:index` |
|---|---|---|
| `tenant_owner`, `tenant_admin` | yes | yes |
| `member`, `viewer` | yes | no |
| `product_owner`, `product_admin` (every tenant) | yes | yes |
| `product_support`, `product_viewer` (every tenant) | yes | no |
| `platform_admin` | yes | yes |
| `platform_viewer` | yes | no |
| API keys | only if listed | only if listed |

Members cannot write to the index by default: index entries are shown to everyone with
`search:query` in the tenant, so a forged entry could mislead other users. Products index with an
API key (`search:index`, optionally bound to one tenant), with a system principal in process, or
grant `search:index` through a custom role.

## Guarantees

- **Tenant isolation in two layers.** Every query and write filters by product and tenant, and runs
  in a tenant-scoped transaction on a table with `FORCE ROW LEVEL SECURITY`
  (`axentra_scope_allows(product_id, tenant_id)`). A query that forgot its filter still sees only
  that tenant's rows (tested with direct SQL under another tenant's scope).
- **Atomic audit.** With the PostgreSQL adapter, the audit event (`search.document.upsert` /
  `search.document.delete`, details `{kind, ref_id, version}`) commits in the same transaction as
  the index write.
- **One document per key under concurrency.** Upserts use `INSERT ... ON CONFLICT DO UPDATE`;
  concurrent upserts of one key create it once and the last commit wins (tested with 10 parallel
  writers).
- **Cascades.** Deleting a tenant or product deletes its documents (foreign key `ON DELETE CASCADE`).
- **Last writer wins.** There is no `If-Match` on index writes: the index mirrors the product's data,
  and the product orders its own writes.

## Security notes

- Highlights are HTML-escaped on the server. The highlighter's delimiters are private-use
  characters (U+E000/U+E001) that are stripped from indexed text, so a document cannot inject
  markup or fake `<mark>` tags. NUL characters are stripped as well.
- `q` is passed to `websearch_to_tsquery` as a bound parameter (`match=prefix`: split on every
  character that is not a letter or digit, so only letters and digits reach `to_tsquery`, quoted); `search.language` must match
  `^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$` and is checked against PostgreSQL on first use (an unknown
  configuration is a server configuration error, reported as `500 internal` without details).
- The audit trail never contains title, body or metadata. Do not put secrets into indexed text or
  metadata: everyone with `search:query` in the tenant can read them through hits and documents.
- Index writes are audited by default; `search.audit_index_writes = false` turns this off for
  high-volume indexing (the documents still record `created_by`/`updated_by`).
- Input limits: title 1000 characters, body `search.max_body_chars` (default 100 000), metadata
  16 KB, query 500 characters, at most 20 kinds, page size at most 200, paging depth
  `search.max_offset`.
- Cost bounds (reads need only `search:query`): a query ranks at most `search.max_candidates`
  matching documents (default 10 000; a very common term in a larger tenant ranks only that many
  matches, taken in index order, not the best ones), runs with `search.statement_timeout_ms`
  (default 5 s; a cancelled query answers `422 validation_failed` with `reason`
  `query_too_expensive`), and `GET .../search` is charged to the per-credential heavy-read budget
  `security.heavy_rate_limit_per_minute` (default 120, `429 rate_limited` with `Retry-After`).

## Configuration (`[search]`)

| Key | Default | Meaning |
|---|---|---|
| `language` | `"simple"` | PostgreSQL text search configuration for indexing and queries |
| `max_body_chars` | `100000` | Longest accepted body (1000..1000000) |
| `max_offset` | `1000` | Deepest result position reachable by paging (0..100000) |
| `max_candidates` | `10000` | Most matching documents ranked per query (100..10000000); beyond it, only that many matches in index order are ranked |
| `statement_timeout_ms` | `5000` | Longest a query may run (100..600000); slower ones are cancelled with `422` (`reason` `query_too_expensive`) |
| `audit_index_writes` | `true` | Audit every index upsert and delete |

## Limitations / TODO

- **No vector or semantic search.** Only lexical full-text search. A vector adapter (e.g. pgvector)
  would implement the same protocol plus an embedding step; see [TODO](../TODO.md).
- **No external adapters shipped.** Only `PostgresSearchAdapter` exists. An external engine
  (OpenSearch, Meilisearch, ...) cannot share Axentra's transaction, so its audit event would follow
  the write instead of being atomic with it.
- **No fuzzy matching and no accent folding** (`unaccent` and `pg_trgm` are not used): `café`
  does not match `cafe` with the `simple` configuration, and a typo finds nothing. Both need
  PostgreSQL extensions, and `unaccent` in the generated `tsvector` needs an immutable wrapper
  function and a rebuild of the index; an operator would have to install the extensions (Axentra's
  migrations never create extensions). Prefix matching (`match=prefix`) needs neither.
- **One language per installation.** There is no per-document or per-tenant language; changing it
  requires re-indexing.
- **Tenant scope only.** There is no product-wide search across tenants, and no per-document access
  control inside a tenant: everyone with `search:query` sees every document of the tenant. Products
  that need finer visibility must index only what all those users may see, or filter hits
  themselves.
- **No bulk API and no reindex job.** Documents are written one at a time; there is no "delete all
  of a kind" endpoint.
- **Paging is offset based** (not a snapshot) and bounded by `search.max_offset`.
- `metadata` is returned but not searchable or filterable.
- The Python SDK (`axentra-client`) has typed methods (`client.search`); the TypeScript SDK types
  are generated and include the search endpoints.
