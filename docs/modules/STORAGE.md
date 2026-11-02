# Storage module (`storage`)

Generic file management for products and tenants: upload, download, metadata, per-tenant quotas,
short-lived signed download URLs, expiry and purge. The module has no knowledge of what files mean
to a product (no agent, knowledge or document semantics); products attach meaning through their
own tables or through the free-form `metadata` labels.

Code: `src/axentra/storage/` (service, backends, safety, tokens, models), HTTP layer
`src/axentra/api/routes/storage.py` and `src/axentra/api/multipart.py`, migrations
`src/axentra/data/sql/0003_storage.sql` and `0008_product_permissions.sql` (`stored_inert`,
`original_content_type`).

## Concepts

- **File**: belongs to one product and one tenant. Metadata lives in `axentra_files`
  (`id` `fil_...`, `name`, `content_type`, `stored_inert`, `original_content_type`, `size`,
  `sha256`, `metadata`, `status`, `version`,
  `created_by`, `created_at`, `updated_at`, `expires_at`, `deleted_at`, plus the internal
  `storage_key`, `backend` and `object_deleted_at`). Files are immutable: to change the content,
  upload a new file. `name` and `metadata` can be edited (optimistic concurrency via `version`).
- **Status**: `pending` (bytes are being written), `active`, `deleted`. Only active, unexpired files
  are visible; a file whose `expires_at` passed disappears for readers immediately, even before the
  purge removes it.
- **Storage key**: `<product_id>/<tenant_id>/<file_id>`, derived only from ids, never from user
  input. Display names are sanitized (last path segment, no control/reserved characters, NFC, at
  most 255 bytes) but are never used as paths.
- **Metadata**: a flat JSON object of user labels (string, number, boolean or null values; at most
  64 keys matching `^[A-Za-z0-9_.:-]{1,64}$`, values up to 1024 characters, 8 KiB in total).
  The list endpoint filters by containment.
- **Quotas and usage**: `axentra_storage_usage` counts bytes and files of active files per tenant.
  `axentra_storage_quotas` holds optional per-tenant overrides. The effective quota is resolved per
  field: tenant override, else product settings (`settings.storage.quota_bytes` /
  `settings.storage.quota_files` on the product), else the installation default
  (`storage.default_quota_bytes` / `storage.default_quota_files`), else unlimited.
  Lowering a quota below current usage is allowed; it only blocks further uploads.
- **Backends**: `StorageBackend` interface (`put` stream, `get` stream, `delete`, `exists`,
  `list_keys`, optional `presigned_url`, `cleanup_temporary`) with `LocalBackend` and `S3Backend`.
  The backend is created lazily on first use. The backend name is recorded per file.

## Configuration (`[storage]`)

| key | default | meaning |
| --- | --- | --- |
| `backend` | `local` | `local` or `s3` |
| `local_path` | `./var/storage` | root directory of the local backend (created with mode 0700) |
| `s3_bucket`, `s3_region`, `s3_endpoint_url` | | S3 or S3-compatible service |
| `s3_access_key_ref`, `s3_secret_key_ref` | | secret references (`env:`/`file:`); empty: boto3's default credential chain |
| `s3_prefix` | `""` | key prefix inside the bucket |
| `s3_server_side_encryption` | none | `AES256` or `aws:kms` |
| `s3_presigned_downloads` | `false` | `download-url` returns a presigned S3 URL instead of an Axentra URL |
| `max_file_bytes` | 50 MiB | hard per-file limit, enforced while streaming |
| `allowed_content_types` | `[]` | allow-list (`image/png`, `image/*`); empty: everything except the blocked types |
| `store_blocked_as_inert` | `false` | installation default of the content-type policy: store blocked (executable/HTML/SVG/script) uploads as inert `application/octet-stream` instead of refusing them; products override it (see "Content-type policy") |
| `signed_url_ttl_seconds` | 300 | maximum (and default) lifetime of download URLs |
| `default_quota_bytes`, `default_quota_files` | none | installation-wide tenant default |
| `pending_upload_timeout_seconds` | 3600 | after this, a still-pending upload counts as abandoned |

The S3 backend needs the optional extra: `pip install 'axentra[s3]'` (boto3 is imported lazily).

## Library usage

```python
from axentra import load_settings
from axentra.platform import Axentra

ax = Axentra.from_settings(load_settings())
ax.start()
principal = ax.api_keys.authenticate(token)

with open("invoice.pdf", "rb") as fh:
    info = ax.storage.upload(principal, product_id, tenant_id, fh, name="invoice.pdf",
                             content_type="application/pdf", metadata={"kind": "invoice"})

info, chunks = ax.storage.open(principal, product_id, tenant_id, info.id)
for chunk in chunks:
    ...

url = ax.storage.create_download_url(principal, product_id, tenant_id, info.id, ttl_seconds=60)
ax.storage.set_quota(principal, product_id, tenant_id, quota_bytes=10 * 2**30, quota_files=None)
ax.storage.delete(principal, product_id, tenant_id, info.id)

report = ax.storage.purge()      # run periodically, or `axentra storage purge`
```

`upload` accepts bytes, a binary file object or any iterable of byte chunks.

## HTTP endpoints

All paths are under `/v1`. `F = /products/{product_id}/tenants/{tenant_id}/files`.

| method and path | permission | response |
| --- | --- | --- |
| `POST F` (multipart: `file`, optional `name`, `metadata` JSON, `expires_at` RFC 3339) | `files:write` | 201 `FileInfo` |
| `GET F?q=&content_type=&metadata=&created_by=&sort=&limit=&cursor=` | `files:read` | `{items: FileInfo[], next_cursor}` |
| `GET F/{file_id}` | `files:read` | `FileInfo`, `ETag: "<version>"` |
| `GET F/{file_id}/content` | `files:read` | bytes (streamed, attachment) |
| `PATCH F/{file_id}` `{name?, metadata?}`, `If-Match` | `files:write` | `FileInfo` |
| `DELETE F/{file_id}`, `If-Match` | `files:write` | 204 |
| `POST F/{file_id}/download-url` `{ttl_seconds?}` | `files:read` | `DownloadUrl` |
| `GET /files/download/{token}` | public (the token is the credential) | bytes (streamed, attachment) |
| `GET /products/{product_id}/storage/usage?limit=&cursor=` | `collections:read` | `ProductStorageUsage` |
| `GET /products/{product_id}/storage/policy` | `product:read` | `StoragePolicy` |
| `PUT /products/{product_id}/storage/policy` `{blocked_types, blocked_extensions, blocked_content_types, inert_extensions}`, `If-Match` (product version) | `product:manage` | `StoragePolicy` |
| `GET /products/{product_id}/tenants/{tenant_id}/storage/usage` | `files:read` | `TenantStorageUsage` |
| `PUT /products/{product_id}/tenants/{tenant_id}/storage/quota` `{quota_bytes, quota_files}`, `If-Match` | `tenants:update` | `TenantStorageUsage` |

Shapes:

- `FileInfo`: `{id, product_id, tenant_id, name, content_type, stored_inert,
  original_content_type, size, sha256, metadata, status, version, created_by, created_at,
  updated_at, expires_at}`. `stored_inert` marks a blocked file kept as an opaque attachment;
  `original_content_type` is then its declared type (else the sniffed one), for display only.
- `StoragePolicy`: `{product_id, blocked_types, blocked_types_source, installation_blocked_types,
  blocked_extensions, blocked_content_types, inert_extensions, builtin_blocked_extensions,
  builtin_blocked_content_types, allowed_content_types, product_version}` (the effective policy,
  see "Content-type policy").
- `DownloadUrl`: `{url, path, expires_at, kind}`; `kind` is `signed` (Axentra URL, `path` is
  `/v1/files/download/{token}`, `url` is `security.public_url` + path) or `presigned` (S3, `path`
  is null).
- `TenantStorageUsage`: `{product_id, tenant_id, bytes_used, files_used, quota_bytes, quota_files,
  quota_bytes_override, quota_files_override, quota_version}`; quotas are effective values (null:
  unlimited), `*_override` the tenant's own values (null: inherited), `quota_version` (0 when no
  override exists) for `If-Match` on `PUT .../quota`.
- `ProductStorageUsage`: `{product_id, bytes_used, files_used, default_quota_bytes,
  default_quota_files, tenants: TenantStorageUsage[], next_cursor}` (tenants paginated by id).

Sorting: `created_at`, `name`, `size`, prefixed with `-` for descending (default `-created_at`).
`content_type` filters by exact type or `type/*`.

Errors: 401 unauthenticated, 403 missing permission, 404 foreign scope / unknown / deleted / expired
file and every invalid download token (expired, tampered, wrong scope, deleted file, suspended
tenant: no oracle), 412 `If-Match` mismatch, 413 `payload_too_large`, 415 `unsupported_media_type`,
422 validation, 429 `quota_exceeded`.

Why `collections:read` for product usage: `product:read` is also granted to plain tenant members
(so they can pick a tenant), which would reveal other tenants' usage. `collections:read` is held
only by product-level roles (owner, admin, support, viewer) and platform roles; tenant members see
their own tenant's usage through the tenant endpoint.

Audit events (same transaction as the change): `storage.file.upload`, `storage.file.update`,
`storage.file.delete`, `storage.file.expire` (system actor, from the purge), `storage.quota.update`
(old and new values), `storage.policy.update` (old and new policy keys). Upload events of inert
files carry `stored_inert` and `original_content_type`. Downloads are not audited.

## Content-type policy

Executable, HTML, XHTML, SVG, script and PHP files are *blocked*: by declared type
(`safety.BLOCKED_TYPES`), by file name extension (`safety.BLOCKED_EXTENSIONS`: `html`, `js`, `sh`,
`php`, `ps1`, `bat`, `exe`, `svg`, ...) or by sniffed content (PE/ELF/Mach-O, HTML, SVG, and any
file that starts with a `#!` shebang). One rule decides for all three reasons, per product
(`axentra.storage.policy`), stored in the product's settings next to the quota defaults:

```json
{"storage": {
  "quota_files": 10000,
  "blocked_types": "store_inert",
  "blocked_extensions": ["py", "rb"],
  "blocked_content_types": ["text/x-ruby"],
  "inert_extensions": ["html", "sh"]
}}
```

| key | default | meaning |
| --- | --- | --- |
| `blocked_types` | installation (`storage.store_blocked_as_inert`: `store_inert` if true, else `refuse`) | `refuse`: blocked uploads get `415`. `store_inert`: they are stored as `application/octet-stream` with `stored_inert = true` |
| `blocked_extensions` | `[]` | extensions blocked in addition to the built-in list (lowercase, without dot; tighten only) |
| `blocked_content_types` | `[]` | content types blocked in addition to the built-in list (tighten only) |
| `inert_extensions` | `[]` | blocked extensions accepted as inert even under `refuse`; the decision uses the file's extension, also when the file is blocked by its content (a shebang script named `run.sh` with `sh` listed is stored inert, the same content named `run.txt` is refused) |

- The built-in blocklist cannot be shortened; a product can only block more or keep blocked files
  inert instead of refusing them. A blocked file is never stored or served with its real type:
  downloads (direct and signed URLs) are attachments with `nosniff`, a sandboxing CSP and
  `application/octet-stream`. `original_content_type` is informational.
- Renaming a file (`PATCH`) to a blocked extension follows the same policy: refused, or the file
  becomes inert (`content_type` turns to `application/octet-stream`, the old type moves to
  `original_content_type`).
- `storage.allowed_content_types` (installation) still applies to the resulting type, so an
  allow-list without `application/octet-stream` refuses inert files.
- `PUT .../storage/policy` replaces the four keys (other `settings.storage` keys such as quotas
  are kept; `blocked_types: null` inherits the installation default). `PATCH /products/{id}` with
  `settings.storage` validates the same keys (`422` for unknown modes, malformed extensions or
  types, more than 100 entries).
- A product's policy never affects another product. Library callers read the effective policy
  with `ax.storage.content_policy(product_id)`.

## Guarantees

- **Size limit while streaming.** The HTTP layer parses `multipart/form-data` itself, chunk by
  chunk, and stops reading as soon as the file part exceeds `max_file_bytes` (or the other fields
  exceed 64 KiB). `Content-Length` is only used to refuse obviously oversized requests early. The
  service enforces the limit again while writing to the backend, for library callers.
  Authorization (`files:write`) is checked before the body is read.
- **Exact quotas under concurrency.** The final check locks the tenant's usage row
  (`SELECT ... FOR UPDATE`) and compares the real size; concurrent uploads serialize on that row.
  A pre-check before streaming refuses uploads when the quota is already exhausted and cuts off a
  stream once it exceeds the remaining bytes, but an upload that loses the race is only refused
  after its bytes were written (they are deleted again).
- **Crash safety.** A `pending` row is committed before any byte is written; a crash leaves either a
  pending row (discarded by the purge after `pending_upload_timeout_seconds`) or nothing. The local
  backend writes a temp file (`O_CREAT|O_EXCL`, mode 0600) in the target directory, `fsync`s it,
  renames it atomically and `fsync`s the directory. The S3 backend uses a single `PutObject` below
  8 MiB and a multipart upload above, aborting the multipart upload when the stream fails.
- **SHA-256** is computed while streaming and stored; it is the download `ETag`.
- **Counters** change in the same transaction as the file status, so they are exact as long as
  rows are changed only through the service (a tenant deletion cascades all three tables).
- **Purge** is idempotent and safe to run concurrently with traffic and with other purges.

## Security notes

- Every file endpoint authorizes through the authorizer and runs in a tenant-scoped transaction;
  all three tables have forced row-level security. Foreign product/tenant ids yield 404.
- Keys are validated by every backend (`[A-Za-z0-9_-]` segments, no dots), so there is no path
  traversal. The local backend additionally refuses paths that resolve outside its root (symlinked
  directories) and opens files with `O_NOFOLLOW`.
- Content types: the declared type is a hint. The first 512 bytes are sniffed (PE/ELF/Mach-O,
  shebang, HTML, SVG, XML, PNG, JPEG, GIF, WebP, PDF, ZIP, GZIP). Executable, HTML, XHTML, SVG and
  script types are refused at upload by declared type, by sniffed content and by file name
  extension, unless the product's content-type policy (see above) keeps them as inert
  `application/octet-stream` attachments (never with their real type). A sniffed type replaces
  the declared one when that is missing, generic or of another
  top-level type. `allowed_content_types` is applied to the resulting type.
- Downloads are always `Content-Disposition: attachment` (ASCII fallback plus RFC 5987
  `filename*`), `X-Content-Type-Options: nosniff`, `Cache-Control: private, no-store`,
  `Content-Security-Policy: default-src 'none'; sandbox`, and a `Content-Type` that falls back to
  `application/octet-stream` for anything HTML/XML/SVG/script-like.
- Signed download tokens: `d1.<kid>.<payload>.<mac>`, HMAC-SHA256 with a key derived by HKDF from
  the keyring key `kid` (purpose-bound, never the raw key). The payload holds file, product,
  tenant and expiry. Verification checks the MAC (constant time), expiry, that the product and
  tenant are active and that the file is still active in exactly that scope. Tokens survive key
  rotation as long as the old key stays in the keyring. A token is a bearer credential for one
  file until it expires; it cannot be revoked individually (deleting the file revokes it). The
  `Referrer-Policy: no-referrer` header keeps tokens out of referrers.
- Presigned S3 URLs (opt-in) are verified by S3 only: they bypass the product/tenant status
  check and work until they expire as long as the object exists (deleting the file deletes the
  object, which ends them; with bucket versioning see below).
- File names and sizes appear in audit details; avoid putting secrets into file names or metadata.

### What "secure deletion" means here

`DELETE` marks the file deleted (it is invisible at once), releases its quota and then deletes the
object in the backend; if that fails, the purge retries until the backend confirms. Orphaned
objects (no pending/active row, e.g. after a tenant was deleted) are removed by the purge's
backend scan. This is **logical deletion at the storage API level**, nothing more:

- The local backend unlinks the file. The bytes stay on the disk until the file system reuses the
  blocks; on SSDs (wear leveling, TRIM) and copy-on-write file systems, overwriting would not
  reliably destroy them either, so no overwrite is attempted. Use full-disk encryption if
  deleted data must be unrecoverable from the medium.
- On S3 with versioning enabled, `DeleteObject` only adds a delete marker; earlier versions remain
  until a lifecycle rule expires them. Replication, backups and provider-internal redundancy are
  outside Axentra's control. Configure bucket lifecycle rules (noncurrent version expiration,
  incomplete multipart upload abort) to match your retention policy.
- Database backups and the audit trail keep the metadata (name, size, sha256) of deleted files.
  Deleted metadata rows are removed by the purge after `retain_deleted_days` (default 30).

## Operations

Run `axentra storage purge` periodically (cron, a scheduled job; e.g. every 15 minutes). It
expires files, discards abandoned uploads, retries failed object deletions, deletes orphaned
objects and old temp files, and removes old deleted rows. `--no-orphans` skips the backend scan
(useful for very large buckets; run it less often). The orphan scan only considers keys of the
form `prd_.../ten_.../fil_...`, but the bucket/prefix or directory **must be dedicated** to one
Axentra installation, because objects of another installation using the same layout would look
orphaned.

## Limitations and TODOs

- The HTTP upload spools the file part to a temporary file (memory up to 1 MiB, then disk) before
  the service streams it to the backend, so large uploads are written twice locally.
- No resumable or direct-to-S3 (presigned PUT) uploads, no range requests, no deduplication by
  hash, no malware scanning hook, no archive inspection.
- Quota usage counts expired files until the purge has run.
- Content sniffing covers a small set of signatures; it is a safety net, not a format validator.
- Changing `storage.backend` does not migrate existing objects; files remember their backend name,
  but are always read from the currently configured backend.
- The purge scans the whole backend for orphans; for very large buckets prefer S3 inventory based
  tooling.
