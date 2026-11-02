"""Declaring, mirroring, listing and retiring product-defined permissions.

Two ways to declare (see :mod:`axentra.access.product_permissions` for the semantics):

- **In process** (embedding products): ``ax.permissions.register(product, [...])`` keeps the
  definitions in a process registry; :meth:`ProductPermissionService.sync` (called by
  :meth:`~axentra.platform.Axentra.start`, and at once by ``register`` after start) mirrors them
  into ``axentra_product_permissions``. Code-declared rows the registration no longer lists are
  retired, never deleted. The last process that synchronizes wins, so run the same registration in
  every process of a product (API, workers), or use versioned access definitions
  (:mod:`axentra.access.definitions`): a product managed by those is skipped here.
- **Over HTTP** (products that do not embed Axentra): ``PUT``/``DELETE
  /v1/products/{product_id}/permissions/{name}`` with ``permissions:manage``. Rows registered by
  code cannot be changed or retired over HTTP (``409``); code takes over rows declared over HTTP.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
import logging
import threading

from axentra.access.authorizer import Authorizer
from axentra.access.definitions import lock_product
from axentra.access.models import PermissionInfo
from axentra.access.product_permissions import (
    MAX_PERMISSIONS_PER_PRODUCT,
    ProductPermission,
    ProductPermissionRecord,
    check_definition,
    check_definitions,
    load_records,
)
from axentra.access.roles import permission_catalog
from axentra.audit.log import AuditLog
from axentra.core.context import Principal
from axentra.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from axentra.data.database import Database, DbScope, Tx

logger = logging.getLogger(__name__)

#: Any of these lets a principal read a product's permission catalog (role and key editors).
CATALOG_READERS = frozenset({"roles:read", "api_keys:read", "permissions:manage"})


@dataclass
class SyncReport:
    """What :meth:`ProductPermissionService.sync` changed for one registered product."""

    product: str
    product_id: str | None
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    reactivated: list[str] = field(default_factory=list)
    retired: list[str] = field(default_factory=list)
    skipped: bool = False
    """The product does not exist (yet); nothing was written."""

    @property
    def changed(self) -> bool:
        return bool(self.added or self.updated or self.reactivated or self.retired)


def info(record: ProductPermissionRecord) -> PermissionInfo:
    p = record.permission
    return PermissionInfo(
        name=p.name,
        scope=p.scope,
        description=p.description,
        source="product",
        read_like=p.is_read_like,
        default_roles=list(p.default_roles),
        declared_by=record.declared_by,
        retired_at=record.retired_at,
    )


def _same(row: dict[str, object], p: ProductPermission) -> bool:
    return (
        row["scope"] == p.scope
        and row["description"] == p.description
        and bool(row["read_like"]) == p.is_read_like
        and sorted(row["default_roles"] or []) == list(p.default_roles)  # type: ignore[call-overload]
    )


class ProductPermissionService:
    def __init__(self, db: Database, authz: Authorizer, audit: AuditLog) -> None:
        self.db = db
        self.authz = authz
        self.audit = audit
        self._registry: dict[str, tuple[ProductPermission, ...]] = {}
        self._lock = threading.Lock()
        self._live = False

    # -- in-process registration ---------------------------------------------------------------

    def register(self, product: str, permissions: Iterable[ProductPermission]) -> None:
        """Declare the complete set of permissions of ``product`` (its id or slug).

        Replaces an earlier registration of the same product in this process. Mirrored into the
        database by :meth:`sync` (at once when called after ``Axentra.start()``). An empty list
        retires every permission this product registered from code before."""
        if not product or not isinstance(product, str):
            raise ValidationFailed("product must be a product id or slug")
        checked = check_definitions(permissions)
        with self._lock:
            self._registry[product] = checked
            live = self._live
        if live:
            self.sync(product)

    def registered(self) -> dict[str, tuple[ProductPermission, ...]]:
        with self._lock:
            return dict(self._registry)

    def sync(self, product: str | None = None) -> list[SyncReport]:
        """Mirror registered definitions into the database (all products, or one)."""
        with self._lock:
            items = [(k, v) for k, v in self._registry.items() if product is None or k == product]
            self._live = True
        return [self._sync_one(key, perms) for key, perms in items]

    def _sync_one(self, key: str, perms: tuple[ProductPermission, ...]) -> SyncReport:
        report = SyncReport(product=key, product_id=None)
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT id FROM axentra_products WHERE id = %s OR slug = %s ORDER BY (id = %s) DESC LIMIT 1",
                (key, key, key),
            )
            if row is None:
                logger.warning("product permissions registered for unknown product %r; not synchronized", key)
                report.skipped = True
                return report
            pid = row["id"]
            report.product_id = pid
            self._lock_product(tx, pid)
            if tx.one("SELECT 1 FROM axentra_access_definitions WHERE product_id = %s", (pid,)):
                # Versioned definitions (axentra.access.definitions) own this product's permissions: an
                # unversioned registration must never overwrite them ("last start wins").
                logger.warning(
                    "product %r is managed by versioned access definitions; the in-process registration is ignored",
                    key,
                )
                report.skipped = True
                return report
            existing = {
                r["name"]: r
                for r in tx.all("SELECT * FROM axentra_product_permissions WHERE product_id = %s", (pid,))
            }
            for p in perms:
                old = existing.get(p.name)
                if old is None:
                    report.added.append(p.name)
                elif old["retired_at"] is not None:
                    report.reactivated.append(p.name)
                elif old["declared_by"] != "code" or not _same(old, p):
                    report.updated.append(p.name)
                else:
                    continue
                self._upsert(tx, pid, p, "code")
            declared = {p.name for p in perms}
            for name, old in existing.items():
                if old["declared_by"] == "code" and old["retired_at"] is None and name not in declared:
                    tx.execute(
                        "UPDATE axentra_product_permissions SET retired_at = now(), updated_at = now(),"
                        " version = version + 1 WHERE product_id = %s AND name = %s",
                        (pid, name),
                    )
                    report.retired.append(name)
            if report.changed:
                self.audit.record(
                    tx,
                    Principal.system("permissions.sync"),
                    "access.permission.sync",
                    target_type="product",
                    target_id=pid,
                    product_id=pid,
                    details={
                        "added": report.added,
                        "updated": report.updated,
                        "reactivated": report.reactivated,
                        "retired": report.retired,
                    },
                )
        return report

    @staticmethod
    def _lock_product(tx: Tx, product_id: str) -> None:
        """Serialize declarations of one product (concurrent starts, API calls, versioned definitions)."""
        lock_product(tx, product_id)

    @staticmethod
    def _upsert(tx: Tx, product_id: str, p: ProductPermission, declared_by: str) -> None:
        tx.execute(
            "INSERT INTO axentra_product_permissions (product_id, name, scope, description, read_like,"
            " default_roles, declared_by) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (product_id, name) DO UPDATE SET scope = EXCLUDED.scope,"
            " description = EXCLUDED.description, read_like = EXCLUDED.read_like,"
            " default_roles = EXCLUDED.default_roles, declared_by = EXCLUDED.declared_by,"
            " retired_at = NULL, updated_at = now(), version = axentra_product_permissions.version + 1",
            (product_id, p.name, p.scope, p.description, p.is_read_like, list(p.default_roles), declared_by),
        )

    # -- catalog ---------------------------------------------------------------------------------

    def catalog(
        self, principal: Principal, product_id: str, *, include_retired: bool = False
    ) -> list[PermissionInfo]:
        """Every permission that can be granted in the product: built-in product and tenant
        permissions, then the product's own (``roles:read``, ``api_keys:read`` or
        ``permissions:manage``)."""
        grant = self.authz.grant(principal, product_id)
        if not grant.permissions & CATALOG_READERS:
            raise Forbidden("missing permission roles:read")
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            records = load_records(tx, product_id, include_retired=include_retired)
        return permission_catalog(include_platform=False) + [info(r) for r in records]

    def records(self, product_id: str, *, include_retired: bool = False) -> list[ProductPermissionRecord]:
        """Stored definitions of a product (trusted in-process callers; no authorization)."""
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            return load_records(tx, product_id, include_retired=include_retired)

    # -- HTTP declaration --------------------------------------------------------------------------

    def declare(self, principal: Principal, product_id: str, permission: ProductPermission) -> PermissionInfo:
        """Create, change or re-activate a permission declared over the API (``permissions:manage``)."""
        self.authz.require(principal, "permissions:manage", product_id)
        p = check_definition(permission)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            self._lock_product(tx, product_id)
            old = tx.one(
                "SELECT * FROM axentra_product_permissions WHERE product_id = %s AND name = %s",
                (product_id, p.name),
            )
            if old is not None and old["declared_by"] == "code":
                raise Conflict("this permission is registered by the product's code; change it there")
            if old is None:
                count = tx.scalar(
                    "SELECT count(*) FROM axentra_product_permissions WHERE product_id = %s", (product_id,)
                )
                if count >= MAX_PERMISSIONS_PER_PRODUCT:
                    raise ValidationFailed(
                        f"a product may declare at most {MAX_PERMISSIONS_PER_PRODUCT} permissions"
                    )
            if old is None or old["retired_at"] is not None or not _same(old, p):
                self._upsert(tx, product_id, p, "api")
                self.audit.record(
                    tx,
                    principal,
                    "access.permission.declare",
                    target_type="permission",
                    target_id=p.name,
                    product_id=product_id,
                    details={
                        "scope": p.scope,
                        "default_roles": list(p.default_roles),
                        "read_like": p.is_read_like,
                        "created": old is None,
                        "reactivated": old is not None and old["retired_at"] is not None,
                    },
                )
            records = [r for r in load_records(tx, product_id) if r.permission.name == p.name]
        return info(records[0])

    def retire(self, principal: Principal, product_id: str, name: str) -> None:
        """Retire a permission declared over the API (``permissions:manage``). Idempotent."""
        self.authz.require(principal, "permissions:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            self._lock_product(tx, product_id)
            old = tx.one(
                "SELECT declared_by, retired_at FROM axentra_product_permissions WHERE product_id = %s AND name = %s",
                (product_id, name),
            )
            if old is None:
                raise NotFound("permission not found")
            if old["declared_by"] == "code":
                raise Conflict("this permission is registered by the product's code; remove it there")
            if old["retired_at"] is not None:
                return
            tx.execute(
                "UPDATE axentra_product_permissions SET retired_at = now(), updated_at = now(),"
                " version = version + 1 WHERE product_id = %s AND name = %s",
                (product_id, name),
            )
            self.audit.record(
                tx,
                principal,
                "access.permission.retire",
                target_type="permission",
                target_id=name,
                product_id=product_id,
            )
