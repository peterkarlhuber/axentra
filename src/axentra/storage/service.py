"""Generic file storage: authorized upload, download, metadata, quotas, signed URLs and purge.

Upload protocol (crash safe, quota exact under concurrency):

1. Authorize ``files:write``, validate name/metadata/expiry, sniff the first bytes, check the
   content type policy, and refuse early if the tenant quota is already exhausted.
2. Insert a ``pending`` metadata row (own transaction) *before* any byte is written, so an
   interrupted upload always leaves a row the purge can find.
3. Stream the bytes into the backend under ``<product_id>/<tenant_id>/<file_id>``, counting and
   hashing (SHA-256) on the way; the size limit (and the remaining byte quota) is enforced while
   streaming, never from a declared length.
4. In one transaction: lock the tenant's usage row (``SELECT ... FOR UPDATE``), re-check the
   quota with the real size, add to the counters, activate the file and write the audit event.
   Concurrent uploads of one tenant serialize on that row lock, so the quota cannot be overshot.
   If the quota check fails the object is deleted again and ``QuotaExceeded`` is raised.
"""

from __future__ import annotations

import builtins
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
import hashlib
import json
import logging
import re
import threading
from typing import IO, Any, Literal

from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.config.secrets import Keyring
from axentra.config.settings import Settings
from axentra.core.clock import utcnow
from axentra.core.context import Principal
from axentra.core.errors import (
    Conflict,
    NotFound,
    PayloadTooLarge,
    PreconditionFailed,
    QuotaExceeded,
    UnsupportedMediaType,
    ValidationFailed,
)
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.storage import safety
from axentra.storage.backends import CHUNK_SIZE, StorageBackend, backend_from_settings
from axentra.storage.models import (
    DownloadUrl,
    FileInfo,
    ProductStorageUsage,
    PurgeReport,
    TenantStorageUsage,
)
from axentra.storage.tokens import DownloadClaims, DownloadSigner

logger = logging.getLogger(__name__)

MAX_METADATA_BYTES = 8 * 1024
MAX_METADATA_KEYS = 64
MAX_METADATA_VALUE = 1024
_META_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_OBJECT_KEY = re.compile(r"^prd_[0-9a-z]{26}/ten_[0-9a-z]{26}/fil_[0-9a-z]{26}$")
_VISIBLE = "status = 'active' AND (expires_at IS NULL OR expires_at > now())"
_SORTS = {"created_at": "created_at", "name": "name", "size": "size"}
_CAST = {"created_at": "timestamptz", "name": "text", "size": "bigint"}
SYSTEM = Principal.system("storage.purge")

Source = bytes | bytearray | memoryview | IO[bytes] | Iterable[bytes]


def check_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """User labels: a flat JSON object of scalars, at most 64 keys and 8 KiB."""
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise ValidationFailed("metadata must be a JSON object")
    if len(metadata) > MAX_METADATA_KEYS:
        raise ValidationFailed(f"metadata may hold at most {MAX_METADATA_KEYS} keys")
    for key, value in metadata.items():
        if not isinstance(key, str) or not _META_KEY.match(key):
            raise ValidationFailed("metadata keys must match ^[A-Za-z0-9_.:-]{1,64}$")
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValidationFailed("metadata values must be strings, numbers, booleans or null")
        if isinstance(value, str) and len(value) > MAX_METADATA_VALUE:
            raise ValidationFailed(f"metadata values may be at most {MAX_METADATA_VALUE} characters")
    if len(json.dumps(metadata, separators=(",", ":")).encode()) > MAX_METADATA_BYTES:
        raise ValidationFailed(f"metadata may be at most {MAX_METADATA_BYTES} bytes")
    return metadata


def _chunks(data: Source) -> Iterator[bytes]:
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
        for i in range(0, len(raw), CHUNK_SIZE):
            yield raw[i : i + CHUNK_SIZE]
        return
    read = getattr(data, "read", None)
    if callable(read):
        while True:
            block = read(CHUNK_SIZE)
            if not block:
                return
            yield bytes(block)
    else:
        for block in data:
            if block:
                yield bytes(block)


def _peek(chunks: Iterator[bytes], n: int) -> tuple[bytes, Iterator[bytes]]:
    taken: list[bytes] = []
    size = 0
    for chunk in chunks:
        taken.append(chunk)
        size += len(chunk)
        if size >= n:
            break

    def chained() -> Iterator[bytes]:
        yield from taken
        yield from chunks

    return b"".join(taken)[:n], chained()


class _Meter:
    """Counts and hashes a stream, enforcing the file size limit and the remaining byte quota."""

    def __init__(self, chunks: Iterator[bytes], *, max_bytes: int, quota_remaining: int | None) -> None:
        self._chunks = chunks
        self.max_bytes = max_bytes
        self.quota_remaining = quota_remaining
        self.size = 0
        self._hash = hashlib.sha256()

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._chunks:
            self.size += len(chunk)
            if self.size > self.max_bytes:
                raise PayloadTooLarge(f"files may be at most {self.max_bytes} bytes")
            if self.quota_remaining is not None and self.size > self.quota_remaining:
                raise QuotaExceeded("the tenant's storage quota (bytes) is exhausted")
            self._hash.update(chunk)
            yield chunk

    @property
    def sha256(self) -> str:
        return self._hash.hexdigest()


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


class StorageService:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        authz: Authorizer,
        audit: AuditLog,
        keyring: Keyring,
        *,
        backend: StorageBackend | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.cfg = settings.storage
        self.authz = authz
        self.audit = audit
        self.signer = DownloadSigner(keyring)
        self._backend = backend
        self._lock = threading.Lock()

    @property
    def backend(self) -> StorageBackend:
        """Created on first use, so importing/configuring never touches the disk or the network."""
        if self._backend is None:
            with self._lock:
                if self._backend is None:
                    self._backend = backend_from_settings(self.cfg)
        return self._backend

    @backend.setter
    def backend(self, value: StorageBackend) -> None:
        self._backend = value

    @property
    def max_file_bytes(self) -> int:
        return self.cfg.max_file_bytes

    # -- quotas ------------------------------------------------------------------------------

    def _product_defaults(self, tx: Tx, product_id: str) -> tuple[int | None, int | None]:
        row = tx.one("SELECT settings -> 'storage' AS s FROM axentra_products WHERE id = %s", (product_id,))
        s = row["s"] if row and isinstance(row["s"], dict) else {}
        qb = _int_or_none(s.get("quota_bytes"))
        qf = _int_or_none(s.get("quota_files"))
        return (
            qb if qb is not None else self.cfg.default_quota_bytes,
            qf if qf is not None else self.cfg.default_quota_files,
        )

    def _quota_row(self, tx: Tx, product_id: str, tenant_id: str) -> Row | None:
        return tx.one(
            "SELECT quota_bytes, quota_files, version FROM axentra_storage_quotas"
            " WHERE product_id = %s AND tenant_id = %s",
            (product_id, tenant_id),
        )

    def _effective_quota(self, tx: Tx, product_id: str, tenant_id: str) -> tuple[int | None, int | None]:
        dbytes, dfiles = self._product_defaults(tx, product_id)
        q = self._quota_row(tx, product_id, tenant_id)
        qb = q["quota_bytes"] if q and q["quota_bytes"] is not None else dbytes
        qf = q["quota_files"] if q and q["quota_files"] is not None else dfiles
        return qb, qf

    def _usage(self, tx: Tx, product_id: str, tenant_id: str, *, lock: bool = False) -> Row:
        if lock:
            tx.execute(
                "INSERT INTO axentra_storage_usage (product_id, tenant_id) VALUES (%s, %s)"
                " ON CONFLICT DO NOTHING",
                (product_id, tenant_id),
            )
        row = tx.one(
            "SELECT bytes_used, files_used FROM axentra_storage_usage WHERE product_id = %s AND tenant_id = %s"
            + (" FOR UPDATE" if lock else ""),
            (product_id, tenant_id),
        )
        return row or {"bytes_used": 0, "files_used": 0}

    # -- upload --------------------------------------------------------------------------------

    def upload(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        data: Source,
        *,
        name: str,
        content_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        expires_at: datetime | None = None,
    ) -> FileInfo:
        self.authz.require(principal, "files:write", product_id, tenant_id)
        clean_name = safety.sanitize_name(name)
        meta = check_metadata(metadata)
        if expires_at is not None:
            if expires_at.tzinfo is None:
                raise ValidationFailed("expires_at must include a time zone")
            if expires_at <= utcnow():
                raise ValidationFailed("expires_at must be in the future")
        declared = safety.normalize_content_type(content_type)
        inert = self.cfg.store_blocked_as_inert
        blocked = safety.is_blocked(declared) or safety.extension(clean_name) in safety.BLOCKED_EXTENSIONS
        if blocked and not inert:
            raise UnsupportedMediaType("executable, HTML, SVG and script files are not accepted")
        head, stream = _peek(_chunks(data), safety.SNIFF_BYTES)
        sniffed = safety.sniff(head)
        if safety.is_blocked(sniffed):
            if not inert:
                raise UnsupportedMediaType("executable, HTML, SVG and script files are not accepted")
            blocked = True
        # storage.store_blocked_as_inert: risky files are kept as opaque bytes, never as their real type.
        ctype = safety.OCTET_STREAM if blocked else safety.choose_content_type(declared, sniffed)
        if not safety.type_allowed(ctype, self.cfg.allowed_content_types):
            raise UnsupportedMediaType(f"content type {ctype} is not allowed")
        if not head:
            raise ValidationFailed("empty files are not accepted")

        file_id = new_id("fil")
        key = f"{product_id}/{tenant_id}/{file_id}"
        scope = DbScope.tenant(product_id, tenant_id)
        with self.db.transaction(scope) as tx:
            usage = self._usage(tx, product_id, tenant_id)
            qb, qf = self._effective_quota(tx, product_id, tenant_id)
            if qf is not None and usage["files_used"] + 1 > qf:
                raise QuotaExceeded("the tenant's storage quota (files) is exhausted")
            if qb is not None and usage["bytes_used"] >= qb:
                raise QuotaExceeded("the tenant's storage quota (bytes) is exhausted")
            tx.execute(
                "INSERT INTO axentra_files (id, product_id, tenant_id, name, content_type, storage_key, backend,"
                " metadata, status, created_by, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s)",
                (
                    file_id,
                    product_id,
                    tenant_id,
                    clean_name,
                    ctype,
                    key,
                    self.backend.name,
                    Jsonb(meta),
                    principal.actor.id,
                    expires_at,
                ),
            )
        remaining = None if qb is None else qb - usage["bytes_used"]
        meter = _Meter(stream, max_bytes=self.max_file_bytes, quota_remaining=remaining)
        try:
            self.backend.put(key, meter, content_type=ctype)
        except BaseException:
            self._abandon(product_id, tenant_id, file_id, key)
            raise

        over = False
        try:
            with self.db.transaction(scope) as tx:
                usage = self._usage(tx, product_id, tenant_id, lock=True)
                qb, qf = self._effective_quota(tx, product_id, tenant_id)
                if (qf is not None and usage["files_used"] + 1 > qf) or (
                    qb is not None and usage["bytes_used"] + meter.size > qb
                ):
                    over = True
                else:
                    row = tx.one(
                        "UPDATE axentra_files SET status = 'active', size = %s, sha256 = %s, updated_at = now()"
                        " WHERE id = %s AND status = 'pending' RETURNING *",
                        (meter.size, meter.sha256, file_id),
                    )
                    if row is None:
                        raise Conflict("the upload took too long and was discarded; retry")
                    tx.execute(
                        "UPDATE axentra_storage_usage SET bytes_used = bytes_used + %s,"
                        " files_used = files_used + 1, updated_at = now() WHERE product_id = %s AND tenant_id = %s",
                        (meter.size, product_id, tenant_id),
                    )
                    self.audit.record(
                        tx,
                        principal,
                        "storage.file.upload",
                        target_type="file",
                        target_id=file_id,
                        product_id=product_id,
                        tenant_id=tenant_id,
                        details={
                            "name": clean_name,
                            "size": meter.size,
                            "content_type": ctype,
                            "sha256": meter.sha256,
                        },
                    )
        except BaseException:
            self._abandon(product_id, tenant_id, file_id, key)
            raise
        if over:
            self._abandon(product_id, tenant_id, file_id, key)
            raise QuotaExceeded("the tenant's storage quota is exhausted")
        return FileInfo.model_validate(row)

    def _abandon(self, product_id: str, tenant_id: str, file_id: str, key: str) -> None:
        """Remove the object of a failed upload; keep a 'deleted' row for the purge if that fails."""
        try:
            self.backend.delete(key)
            gone = True
        except Exception:
            logger.warning("could not delete the object of a failed upload %s", file_id, exc_info=True)
            gone = False
        try:
            with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
                if gone:
                    tx.execute("DELETE FROM axentra_files WHERE id = %s AND status = 'pending'", (file_id,))
                else:
                    tx.execute(
                        "UPDATE axentra_files SET status = 'deleted', deleted_at = now() WHERE id = %s"
                        " AND status = 'pending'",
                        (file_id,),
                    )
        except Exception:
            logger.warning("could not clean up the pending row of %s (purge will)", file_id, exc_info=True)

    # -- read ----------------------------------------------------------------------------------

    def _visible(self, tx: Tx, product_id: str, tenant_id: str, file_id: str, *, lock: bool = False) -> Row:
        row = tx.one(
            f"SELECT * FROM axentra_files WHERE id = %s AND product_id = %s AND tenant_id = %s AND {_VISIBLE}"
            + (" FOR UPDATE" if lock else ""),
            (file_id, product_id, tenant_id),
        )
        if row is None:
            raise NotFound("file not found")
        return row

    def get(self, principal: Principal, product_id: str, tenant_id: str, file_id: str) -> FileInfo:
        self.authz.require(principal, "files:read", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            return FileInfo.model_validate(self._visible(tx, product_id, tenant_id, file_id))

    def list(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        q: str | None = None,
        content_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        created_by: str | None = None,
        sort: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[FileInfo]:
        self.authz.require(principal, "files:read", product_id, tenant_id)
        limit = clamp_limit(limit)
        clauses = ["product_id = %s", "tenant_id = %s", _VISIBLE]
        params: builtins.list[Any] = [product_id, tenant_id]
        if q:
            clauses.append("name ILIKE %s")
            params.append("%" + q.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%")
        if content_type:
            ct = content_type.strip().lower()
            if ct.endswith("/*"):
                clauses.append("content_type LIKE %s")
                params.append(ct[:-1].replace("%", r"\%").replace("_", r"\_") + "%")
            else:
                clauses.append("content_type = %s")
                params.append(ct)
        if metadata:
            clauses.append("metadata @> %s")
            params.append(Jsonb(check_metadata(metadata)))
        if created_by:
            clauses.append("created_by = %s")
            params.append(created_by)
        sort = sort or "-created_at"
        desc = sort.startswith("-")
        field = _SORTS.get(sort.lstrip("-"))
        if field is None:
            raise ValidationFailed("sort must be created_at, name or size (prefix - for descending)")
        after = decode_cursor(cursor)
        op = "<" if desc else ">"
        if after:
            if len(after) != 2:
                raise ValidationFailed("invalid cursor")
            clauses.append(f"({field}, id) {op} (%s::{_CAST[field]}, %s)")
            params += [after[0], after[1]]
        direction = "DESC" if desc else "ASC"
        params.append(limit + 1)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(
                f"SELECT * FROM axentra_files WHERE {' AND '.join(clauses)}"
                f" ORDER BY {field} {direction}, id {direction} LIMIT %s",
                params,
            )
        items = [FileInfo.model_validate(r) for r in rows[:limit]]
        nxt = None
        if len(rows) > limit:
            last = items[-1]
            value = getattr(last, field)
            nxt = encode_cursor([value.isoformat() if isinstance(value, datetime) else value, last.id])
        return Page[FileInfo](items=items, next_cursor=nxt)

    def open(
        self, principal: Principal, product_id: str, tenant_id: str, file_id: str
    ) -> tuple[FileInfo, Iterator[bytes]]:
        """Metadata plus a byte stream of the content (``files:read``)."""
        info = self.get(principal, product_id, tenant_id, file_id)
        return info, self._stream(info)

    def _stream(self, info: FileInfo) -> Iterator[bytes]:
        key = f"{info.product_id}/{info.tenant_id}/{info.id}"
        try:
            return self.backend.get(key)
        except NotFound:
            logger.error("storage object of active file %s is missing", info.id)
            raise NotFound("file content not found") from None

    # -- update / delete -----------------------------------------------------------------------

    def update(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        file_id: str,
        *,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
        if_match: int | None = None,
    ) -> FileInfo:
        self.authz.require(principal, "files:write", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            row = self._visible(tx, product_id, tenant_id, file_id, lock=True)
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the file was changed by someone else")
            changes: dict[str, Any] = {}
            if name is not None:
                clean = safety.sanitize_name(name)
                if (
                    safety.extension(clean) in safety.BLOCKED_EXTENSIONS
                    and not self.cfg.store_blocked_as_inert
                ):
                    raise UnsupportedMediaType("this file name extension is not accepted")
                if clean != row["name"]:
                    changes["name"] = clean
            if metadata is not None:
                changes["metadata"] = Jsonb(check_metadata(metadata))
            if changes:
                sets = ", ".join(f"{k} = %s" for k in changes)
                row = tx.one_or_404(
                    f"UPDATE axentra_files SET {sets}, version = version + 1, updated_at = now()"
                    " WHERE id = %s RETURNING *",
                    [*changes.values(), file_id],
                )
                self.audit.record(
                    tx,
                    principal,
                    "storage.file.update",
                    target_type="file",
                    target_id=file_id,
                    product_id=product_id,
                    tenant_id=tenant_id,
                    details={"fields": sorted(changes)},
                )
        return FileInfo.model_validate(row)

    def delete(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        file_id: str,
        *,
        if_match: int | None = None,
    ) -> None:
        """Mark the file deleted (it disappears at once), then delete the object from the backend."""
        self.authz.require(principal, "files:write", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            row = self._visible(tx, product_id, tenant_id, file_id, lock=True)
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the file was changed by someone else")
            self._mark_deleted(tx, row)
            self.audit.record(
                tx,
                principal,
                "storage.file.delete",
                target_type="file",
                target_id=file_id,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"name": row["name"], "size": row["size"]},
            )
        self._delete_object(row)

    def _mark_deleted(self, tx: Tx, row: Row) -> None:
        tx.execute(
            "UPDATE axentra_files SET status = 'deleted', deleted_at = now(), version = version + 1,"
            " updated_at = now() WHERE id = %s",
            (row["id"],),
        )
        if row["status"] == "active":
            tx.execute(
                "UPDATE axentra_storage_usage SET bytes_used = GREATEST(bytes_used - %s, 0),"
                " files_used = GREATEST(files_used - 1, 0), updated_at = now()"
                " WHERE product_id = %s AND tenant_id = %s",
                (row["size"], row["product_id"], row["tenant_id"]),
            )

    def _delete_object(self, row: Row) -> bool:
        try:
            self.backend.delete(row["storage_key"])
        except Exception:
            logger.warning(
                "deleting the object of file %s failed; the purge retries", row["id"], exc_info=True
            )
            return False
        with self.db.transaction(DbScope.tenant(row["product_id"], row["tenant_id"])) as tx:
            tx.execute("UPDATE axentra_files SET object_deleted_at = now() WHERE id = %s", (row["id"],))
        return True

    # -- signed download URLs ------------------------------------------------------------------

    def create_download_url(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        file_id: str,
        *,
        ttl_seconds: int | None = None,
    ) -> DownloadUrl:
        info = self.get(principal, product_id, tenant_id, file_id)
        max_ttl = self.cfg.signed_url_ttl_seconds
        ttl = max_ttl if ttl_seconds is None else ttl_seconds
        if ttl < 1 or ttl > max_ttl:
            raise ValidationFailed(f"ttl_seconds must be between 1 and {max_ttl}")
        if info.expires_at is not None:
            ttl = max(1, min(ttl, int((info.expires_at - utcnow()).total_seconds())))
        expires = utcnow().replace(microsecond=0) + timedelta(seconds=ttl)
        if self.cfg.s3_presigned_downloads:
            url = self.backend.presigned_url(
                f"{product_id}/{tenant_id}/{file_id}",
                ttl_seconds=ttl,
                filename_header=safety.content_disposition(info.name),
                content_type=safety.served_content_type(info.content_type),
            )
            if url is not None:
                return DownloadUrl(url=url, path=None, expires_at=expires, kind="presigned")
        token = self.signer.sign(DownloadClaims(file_id, product_id, tenant_id, int(expires.timestamp())))
        path = f"/v1/files/download/{token}"
        base = self.settings.security.public_url.rstrip("/")
        return DownloadUrl(url=base + path, path=path, expires_at=expires, kind="signed")

    def open_signed(self, token: str) -> tuple[FileInfo, Iterator[bytes]]:
        """Resolve a signed download token (no principal: the token is the credential)."""
        claims = self.signer.verify(token)
        with self.db.transaction(DbScope.tenant(claims.product_id, claims.tenant_id), read_only=True) as tx:
            scope = tx.one(
                "SELECT p.status AS product_status, t.status AS tenant_status FROM axentra_tenants t"
                " JOIN axentra_products p ON p.id = t.product_id WHERE t.id = %s AND t.product_id = %s",
                (claims.tenant_id, claims.product_id),
            )
            if scope is None or scope["product_status"] != "active" or scope["tenant_status"] != "active":
                raise NotFound("download link not found or expired")
            try:
                row = self._visible(tx, claims.product_id, claims.tenant_id, claims.file_id)
            except NotFound:
                raise NotFound("download link not found or expired") from None
        info = FileInfo.model_validate(row)
        return info, self._stream(info)

    # -- usage and quotas ----------------------------------------------------------------------

    def _tenant_usage(
        self, row: Row, defaults: tuple[int | None, int | None], product_id: str
    ) -> TenantStorageUsage:
        ob, of = row.get("quota_bytes"), row.get("quota_files")
        return TenantStorageUsage(
            product_id=product_id,
            tenant_id=row["tenant_id"],
            bytes_used=row["bytes_used"] or 0,
            files_used=row["files_used"] or 0,
            quota_bytes=ob if ob is not None else defaults[0],
            quota_files=of if of is not None else defaults[1],
            quota_bytes_override=ob,
            quota_files_override=of,
            quota_version=row.get("quota_version") or 0,
        )

    _USAGE_SQL = (
        "SELECT t.id AS tenant_id, COALESCE(u.bytes_used, 0) AS bytes_used, COALESCE(u.files_used, 0) AS files_used,"
        " q.quota_bytes, q.quota_files, COALESCE(q.version, 0) AS quota_version FROM axentra_tenants t"
        " LEFT JOIN axentra_storage_usage u ON u.product_id = t.product_id AND u.tenant_id = t.id"
        " LEFT JOIN axentra_storage_quotas q ON q.product_id = t.product_id AND q.tenant_id = t.id"
    )

    def tenant_usage(self, principal: Principal, product_id: str, tenant_id: str) -> TenantStorageUsage:
        self.authz.require(principal, "files:read", product_id, tenant_id)
        return self._read_tenant_usage(product_id, tenant_id)

    def _read_tenant_usage(self, product_id: str, tenant_id: str) -> TenantStorageUsage:
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            defaults = self._product_defaults(tx, product_id)
            row = tx.one_or_404(
                self._USAGE_SQL + " WHERE t.product_id = %s AND t.id = %s",
                (product_id, tenant_id),
                what="tenant",
            )
        return self._tenant_usage(row, defaults, product_id)

    def product_usage(
        self, principal: Principal, product_id: str, *, limit: int | None = None, cursor: str | None = None
    ) -> ProductStorageUsage:
        """Totals and per-tenant usage (``collections:read``: product operators only)."""
        self.authz.require(principal, "collections:read", product_id)
        limit = clamp_limit(limit)
        after = decode_cursor(cursor)
        params: builtins.list[Any] = [product_id]
        where = "t.product_id = %s"
        if after:
            where += " AND t.id > %s"
            params.append(str(after[0]))
        params.append(limit + 1)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            defaults = self._product_defaults(tx, product_id)
            totals = tx.one_or_404(
                "SELECT COALESCE(sum(bytes_used), 0)::bigint AS b, COALESCE(sum(files_used), 0)::bigint AS f"
                " FROM axentra_storage_usage WHERE product_id = %s",
                (product_id,),
            )
            rows = tx.all(self._USAGE_SQL + f" WHERE {where} ORDER BY t.id LIMIT %s", params)
        tenants = [self._tenant_usage(r, defaults, product_id) for r in rows[:limit]]
        nxt = encode_cursor([tenants[-1].tenant_id]) if len(rows) > limit else None
        return ProductStorageUsage(
            product_id=product_id,
            bytes_used=totals["b"],
            files_used=totals["f"],
            default_quota_bytes=defaults[0],
            default_quota_files=defaults[1],
            tenants=tenants,
            next_cursor=nxt,
        )

    def set_quota(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        quota_bytes: int | None,
        quota_files: int | None,
        if_match: int | None = None,
    ) -> TenantStorageUsage:
        """Set (or with None: clear, i.e. inherit) the tenant's quota overrides (``tenants:update``)."""
        self.authz.require(principal, "tenants:update", product_id, tenant_id)
        for value in (quota_bytes, quota_files):
            if value is not None and (isinstance(value, bool) or value < 0):
                raise ValidationFailed("quotas must be non-negative integers or null")
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            tx.one_or_404(
                "SELECT id FROM axentra_tenants WHERE id = %s AND product_id = %s FOR UPDATE",
                (tenant_id, product_id),
                what="tenant",
            )
            old = self._quota_row(tx, product_id, tenant_id)
            version = old["version"] if old else 0
            if if_match is not None and version != if_match:
                raise PreconditionFailed("the quota was changed by someone else")
            tx.execute(
                "INSERT INTO axentra_storage_quotas (product_id, tenant_id, quota_bytes, quota_files, updated_by)"
                " VALUES (%s, %s, %s, %s, %s) ON CONFLICT (product_id, tenant_id) DO UPDATE SET"
                " quota_bytes = EXCLUDED.quota_bytes, quota_files = EXCLUDED.quota_files,"
                " updated_by = EXCLUDED.updated_by, version = axentra_storage_quotas.version + 1,"
                " updated_at = now()",
                (product_id, tenant_id, quota_bytes, quota_files, principal.actor.id),
            )
            self.audit.record(
                tx,
                principal,
                "storage.quota.update",
                target_type="tenant",
                target_id=tenant_id,
                product_id=product_id,
                tenant_id=tenant_id,
                details={
                    "old": {"quota_bytes": old["quota_bytes"], "quota_files": old["quota_files"]}
                    if old
                    else None,
                    "new": {"quota_bytes": quota_bytes, "quota_files": quota_files},
                },
            )
        return self._read_tenant_usage(product_id, tenant_id)

    # -- purge ---------------------------------------------------------------------------------

    def purge(
        self,
        *,
        batch_size: int = 500,
        orphans: bool = True,
        retain_deleted_days: int = 30,
        now: datetime | None = None,
    ) -> PurgeReport:
        """Housekeeping, safe to run repeatedly and concurrently with traffic (e.g. every few minutes).

        1. Expire active files whose ``expires_at`` passed (usage released, audit ``storage.file.expire``).
        2. Discard uploads still ``pending`` after ``storage.pending_upload_timeout_seconds``.
        3. Retry object deletion for deleted files whose object was not confirmed deleted.
        4. With ``orphans``: delete backend objects with an Axentra file key and no pending/active
           row (e.g. after a tenant or product was deleted, or after a crash). The bucket/prefix or
           local directory must be dedicated to this installation.
        5. Remove leftover temp files of interrupted local writes and deleted rows older than
           ``retain_deleted_days``.
        """
        now = now or utcnow()
        report = PurgeReport()
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            expired = tx.all(
                "SELECT * FROM axentra_files WHERE status = 'active' AND expires_at <= %s ORDER BY expires_at LIMIT %s",
                (now, batch_size),
            )
        for row in expired:
            if self._expire(row, now):
                report.expired += 1
                if self._delete_object(row):
                    report.objects_deleted += 1
                else:
                    report.errors += 1

        stale_before = now - timedelta(seconds=self.cfg.pending_upload_timeout_seconds)
        with self.db.transaction(DbScope.platform()) as tx:
            stale = tx.all(
                "UPDATE axentra_files SET status = 'deleted', deleted_at = now() WHERE id IN"
                " (SELECT id FROM axentra_files WHERE status = 'pending' AND created_at < %s LIMIT %s"
                " FOR UPDATE SKIP LOCKED) RETURNING *",
                (stale_before, batch_size),
            )
        report.abandoned_pending = len(stale)

        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            undeleted = tx.all(
                "SELECT * FROM axentra_files WHERE status = 'deleted' AND object_deleted_at IS NULL"
                " ORDER BY deleted_at LIMIT %s",
                (batch_size,),
            )
        for row in undeleted:
            if self._delete_object(row):
                report.objects_deleted += 1
            else:
                report.errors += 1

        if orphans:
            o, e = self._purge_orphans(batch_size)
            report.orphans_deleted += o
            report.errors += e
        try:
            report.temp_files_removed = self.backend.cleanup_temporary(
                self.cfg.pending_upload_timeout_seconds
            )
        except Exception:
            logger.warning("temp file cleanup failed", exc_info=True)
            report.errors += 1
        with self.db.transaction(DbScope.platform()) as tx:
            report.rows_removed = tx.execute(
                "DELETE FROM axentra_files WHERE status = 'deleted' AND object_deleted_at IS NOT NULL"
                " AND deleted_at < %s",
                (now - timedelta(days=retain_deleted_days),),
            )
        if any(report.model_dump().values()):
            logger.info("storage purge: %s", report.model_dump())
        return report

    def _expire(self, row: Row, now: datetime) -> bool:
        with self.db.transaction(DbScope.tenant(row["product_id"], row["tenant_id"])) as tx:
            current = tx.one(
                "SELECT * FROM axentra_files WHERE id = %s AND status = 'active' AND expires_at <= %s FOR UPDATE",
                (row["id"], now),
            )
            if current is None:
                return False
            self._mark_deleted(tx, current)
            self.audit.record(
                tx,
                SYSTEM,
                "storage.file.expire",
                target_type="file",
                target_id=row["id"],
                product_id=row["product_id"],
                tenant_id=row["tenant_id"],
                details={"name": current["name"], "size": current["size"]},
            )
        return True

    def _purge_orphans(self, batch_size: int) -> tuple[int, int]:
        deleted = errors = 0
        batch: builtins.list[str] = []

        def flush() -> None:
            nonlocal deleted, errors
            with self.db.transaction(DbScope.platform(), read_only=True) as tx:
                known = {
                    r["storage_key"]
                    for r in tx.all(
                        "SELECT storage_key FROM axentra_files WHERE storage_key = ANY(%s)"
                        " AND status IN ('pending', 'active')",
                        (batch,),
                    )
                }
            for key in batch:
                if key in known:
                    continue
                try:
                    self.backend.delete(key)
                    deleted += 1
                except Exception:
                    logger.warning("could not delete orphaned object %s", key, exc_info=True)
                    errors += 1
            batch.clear()

        for key in self.backend.list_keys():
            if not _OBJECT_KEY.match(key):
                continue
            batch.append(key)
            if len(batch) >= batch_size:
                flush()
        if batch:
            flush()
        return deleted, errors


SortField = Literal["created_at", "-created_at", "name", "-name", "size", "-size"]
