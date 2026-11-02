"""Versioned access definitions: an embedding product's permissions and roles, applied deterministically.

Registering permissions and roles at every start (``ax.permissions.register`` plus creating roles) lets the last
process that starts win: during a rolling deployment an old process can undo what a new one wrote. An
:class:`AccessDefinitions` set carries a **revision** (a whole number the product raises whenever the content
changes) and is identified by a **content hash** (SHA-256 of its canonical form, the revision excluded).
:meth:`AccessDefinitionService.apply` stores both per product (``axentra_access_definitions``) and decides:

- **no row yet** or a **newer revision**: the definitions are applied (permissions declared, re-activated or
  retired; managed roles created or updated) and the change is audited (``access.definitions.apply``);
- the **same revision and content**: nothing is written (``unchanged``; the normal start);
- an **older revision**: nothing is written and a warning is logged (``stale``): an old process never downgrades;
- the **same revision with other content**: refused with ``409`` and audited as denied (``conflict``): two builds
  disagree about what one revision means, which is a release error.

Concurrent applications for one product are serialized by the advisory lock that also serializes
:class:`~axentra.access.product_permission_service.ProductPermissionService` (one transaction, one lock), so two
processes starting at once apply a revision once. A product managed this way is skipped by the unversioned
in-process registration (``ax.permissions.register`` / ``sync``), and the roles it manages cannot be changed or
deleted over the API (``409``): code owns them, like code-declared permissions.

Roles that a newer revision no longer lists are **released**, not deleted (members may still hold them): they keep
their permissions and become ordinary custom roles again. Permissions no longer listed are retired (never deleted;
see :mod:`axentra.access.product_permissions`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
import hashlib
import json
import logging
import re
from typing import Any, Literal

from axentra.access.permissions import BUILTIN_ROLES
from axentra.access.product_permissions import ProductPermission, check_definitions
from axentra.audit.log import AuditLog
from axentra.core.context import Principal
from axentra.core.errors import Conflict, NotFound, ValidationFailed
from axentra.core.ids import new_id
from axentra.data.database import Database, DbScope, Tx

logger = logging.getLogger(__name__)

_ROLE_KEY = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
MAX_ROLES = 100

Outcome = Literal["applied", "unchanged", "stale"]


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    """A custom role an embedding product defines in code."""

    key: str
    name: str
    scope: Literal["product", "tenant"]
    permissions: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True, slots=True)
class AccessDefinitions:
    """The complete permission and role definitions of one product at one revision."""

    revision: int
    permissions: tuple[ProductPermission, ...] = ()
    roles: tuple[RoleDefinition, ...] = ()

    def normalized(self) -> AccessDefinitions:
        """The definitions validated (``422`` on errors) and in canonical order."""
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise ValidationFailed("revision must be a whole number of at least 1")
        permissions = tuple(sorted(check_definitions(self.permissions), key=lambda p: p.name))
        roles: list[RoleDefinition] = []
        for role in self.roles:
            if not isinstance(role.key, str) or not _ROLE_KEY.fullmatch(role.key):
                raise ValidationFailed(
                    f"role key {role.key!r} must be 2-41 lowercase letters, digits or underscores"
                )
            if role.key in BUILTIN_ROLES:
                raise ValidationFailed(f"role key {role.key!r} belongs to a built-in role")
            if role.scope not in ("product", "tenant"):
                raise ValidationFailed(f"role {role.key}: scope must be product or tenant")
            name = (role.name or "").strip()
            if not name or len(name) > 200:
                raise ValidationFailed(f"role {role.key}: name must be 1-200 characters")
            roles.append(
                RoleDefinition(
                    key=role.key,
                    name=name,
                    scope=role.scope,
                    permissions=tuple(sorted(set(role.permissions))),
                    description=(role.description or "").strip(),
                )
            )
        keys = [r.key for r in roles]
        duplicates = sorted({k for k in keys if keys.count(k) > 1})
        if duplicates:
            raise ValidationFailed(f"duplicate roles: {', '.join(duplicates)}")
        if len(roles) > MAX_ROLES:
            raise ValidationFailed(f"at most {MAX_ROLES} roles")
        return AccessDefinitions(self.revision, permissions, tuple(sorted(roles, key=lambda r: r.key)))

    def canonical(self) -> str:
        """The canonical JSON of the content (the revision is not part of it)."""
        n = self.normalized()
        return json.dumps(
            {
                "permissions": [
                    {
                        "name": p.name,
                        "scope": p.scope,
                        "description": p.description,
                        "default_roles": list(p.default_roles),
                        "read_like": p.is_read_like,
                    }
                    for p in n.permissions
                ],
                "roles": [
                    {
                        "key": r.key,
                        "name": r.name,
                        "scope": r.scope,
                        "permissions": list(r.permissions),
                        "description": r.description,
                    }
                    for r in n.roles
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredDefinitions:
    """What ``axentra_access_definitions`` holds for a product."""

    product_id: str
    revision: int
    content_hash: str
    roles: tuple[str, ...]
    applied_by: str
    applied_at: Any


@dataclass
class ApplyResult:
    """What :meth:`AccessDefinitionService.apply` did."""

    product_id: str
    outcome: Outcome
    revision: int
    content_hash: str
    stored_revision: int | None
    permissions: dict[str, list[str]] = field(
        default_factory=lambda: {"added": [], "updated": [], "reactivated": [], "retired": []}
    )
    roles: dict[str, list[str]] = field(
        default_factory=lambda: {"created": [], "updated": [], "released": []}
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "outcome": self.outcome,
            "revision": self.revision,
            "content_hash": self.content_hash,
            "stored_revision": self.stored_revision,
            "permissions": {k: list(v) for k, v in self.permissions.items()},
            "roles": {k: list(v) for k, v in self.roles.items()},
        }


def lock_product(tx: Tx, product_id: str) -> None:
    """The advisory lock that serializes every change to a product's permission and role definitions."""
    tx.execute("SELECT pg_advisory_xact_lock(hashtext('axentra.product_permissions:' || %s))", (product_id,))


def managed_roles(tx: Tx, product_id: str) -> frozenset[str]:
    """Role keys of the product that its access definitions manage (empty: none)."""
    row = tx.one("SELECT roles FROM axentra_access_definitions WHERE product_id = %s", (product_id,))
    return frozenset(row["roles"] or ()) if row else frozenset()


class AccessDefinitionService:
    """``ax.access_definitions``: apply, inspect and compare versioned access definitions (see the module docs)."""

    def __init__(self, db: Database, audit: AuditLog) -> None:
        self.db = db
        self.audit = audit

    @staticmethod
    def _product(tx: Tx, product: str) -> str:
        row = tx.one(
            "SELECT id FROM axentra_products WHERE id = %s OR slug = %s ORDER BY (id = %s) DESC LIMIT 1",
            (product, product, product),
        )
        if row is None:
            raise NotFound("product not found")
        return str(row["id"])

    def current(self, product: str) -> StoredDefinitions | None:
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            pid = self._product(tx, product)
            row = tx.one("SELECT * FROM axentra_access_definitions WHERE product_id = %s", (pid,))
        if row is None:
            return None
        return StoredDefinitions(
            product_id=pid,
            revision=int(row["revision"]),
            content_hash=row["content_hash"],
            roles=tuple(row["roles"] or ()),
            applied_by=row["applied_by"],
            applied_at=row["applied_at"],
        )

    def apply(self, product: str, definitions: AccessDefinitions, *, applied_by: str = "") -> ApplyResult:
        """Apply ``definitions`` to ``product`` (id or slug) if their revision is newer (see the module docs).

        Raises ``NotFound`` for an unknown product, ``ValidationFailed`` for invalid definitions and ``Conflict``
        when the stored revision equals this one but its content differs."""
        n = definitions.normalized()
        digest = n.content_hash
        applied_by = (applied_by or "")[:200]
        with self.db.transaction(DbScope.platform()) as tx:
            pid = self._product(tx, product)
            lock_product(tx, pid)
            row = tx.one(
                "SELECT revision, content_hash, roles FROM axentra_access_definitions WHERE product_id = %s FOR UPDATE",
                (pid,),
            )
            stored = int(row["revision"]) if row else None
            result = ApplyResult(
                product_id=pid,
                outcome="applied",
                revision=n.revision,
                content_hash=digest,
                stored_revision=stored,
            )
            conflict = False
            if row is not None and stored is not None:
                if n.revision == stored and row["content_hash"] == digest:
                    result.outcome = "unchanged"
                    return result
                if n.revision < stored:
                    result.outcome = "stale"
                    logger.warning(
                        "access definitions of product %s: revision %s is older than the stored revision %s;"
                        " not applied (an older process never downgrades)",
                        pid,
                        n.revision,
                        stored,
                    )
                    return result
                conflict = n.revision == stored
            if not conflict:
                previous_roles = frozenset(row["roles"] or ()) if row else frozenset()
                self._apply_permissions(tx, pid, n.permissions, result)
                self._apply_roles(tx, pid, n.roles, previous_roles, result)
                tx.execute(
                    "INSERT INTO axentra_access_definitions (product_id, revision, content_hash, roles, applied_by)"
                    " VALUES (%s, %s, %s, %s, %s) ON CONFLICT (product_id) DO UPDATE SET"
                    " revision = EXCLUDED.revision, content_hash = EXCLUDED.content_hash, roles = EXCLUDED.roles,"
                    " applied_by = EXCLUDED.applied_by, applied_at = now(),"
                    " version = axentra_access_definitions.version + 1",
                    (pid, n.revision, digest, [r.key for r in n.roles], applied_by),
                )
                self.audit.record(
                    tx,
                    Principal.system("access.definitions"),
                    "access.definitions.apply",
                    target_type="product",
                    target_id=pid,
                    product_id=pid,
                    details={
                        "revision": n.revision,
                        "previous_revision": stored,
                        "content_hash": digest,
                        "applied_by": applied_by,
                        "permissions": result.permissions,
                        "roles": result.roles,
                    },
                )
                return result
        # Same revision, other content: refused outside the (rolled back) transaction and audited as denied.
        self.audit.record_standalone(
            Principal.system("access.definitions"),
            "access.definitions.apply",
            target_type="product",
            target_id=pid,
            product_id=pid,
            outcome="denied",
            details={
                "revision": n.revision,
                "content_hash": digest,
                "applied_by": applied_by,
                "reason": "conflict",
            },
        )
        logger.error(
            "access definitions of product %s: revision %s is stored with other content; refused",
            pid,
            n.revision,
        )
        raise Conflict(
            f"revision {n.revision} of the access definitions is stored with other content; raise the revision"
        )

    # -- applying ----------------------------------------------------------------------------------------

    @staticmethod
    def _apply_permissions(
        tx: Tx, pid: str, permissions: tuple[ProductPermission, ...], result: ApplyResult
    ) -> None:
        from axentra.access.product_permission_service import ProductPermissionService, _same

        existing = {
            r["name"]: r
            for r in tx.all("SELECT * FROM axentra_product_permissions WHERE product_id = %s", (pid,))
        }
        for p in permissions:
            old = existing.get(p.name)
            if old is None:
                result.permissions["added"].append(p.name)
            elif old["retired_at"] is not None:
                result.permissions["reactivated"].append(p.name)
            elif old["declared_by"] != "code" or not _same(old, p):
                result.permissions["updated"].append(p.name)
            else:
                continue
            ProductPermissionService._upsert(tx, pid, p, "code")
        declared = {p.name for p in permissions}
        for name, old in existing.items():
            if old["declared_by"] == "code" and old["retired_at"] is None and name not in declared:
                tx.execute(
                    "UPDATE axentra_product_permissions SET retired_at = now(), updated_at = now(),"
                    " version = version + 1 WHERE product_id = %s AND name = %s",
                    (pid, name),
                )
                result.permissions["retired"].append(name)

    @staticmethod
    def _apply_roles(
        tx: Tx, pid: str, roles: tuple[RoleDefinition, ...], previous: frozenset[str], result: ApplyResult
    ) -> None:
        from axentra.access.roles import RoleService

        existing = {r["key"]: r for r in tx.all("SELECT * FROM axentra_roles WHERE product_id = %s", (pid,))}
        for role in roles:
            perms = RoleService._check(tx, pid, role.scope, list(role.permissions))
            old = existing.get(role.key)
            if old is None:
                tx.execute(
                    "INSERT INTO axentra_roles (id, product_id, key, name, description, scope, permissions)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (new_id("rol"), pid, role.key, role.name, role.description, role.scope, perms),
                )
                result.roles["created"].append(role.key)
                continue
            if old["scope"] != role.scope:
                # A role's scope never changes in place: members hold it with the meaning of its scope.
                raise ValidationFailed(f"role {role.key} exists with scope {old['scope']}; use another key")
            if (old["name"], old["description"], sorted(old["permissions"])) == (
                role.name,
                role.description,
                perms,
            ):
                continue
            tx.execute(
                "UPDATE axentra_roles SET name = %s, description = %s, permissions = %s, version = version + 1,"
                " updated_at = now() WHERE id = %s",
                (role.name, role.description, perms, old["id"]),
            )
            result.roles["updated"].append(role.key)
        listed = {r.key for r in roles}
        result.roles["released"] = sorted(k for k in previous if k not in listed and k in existing)

    # -- comparing -----------------------------------------------------------------------------------------

    def drift(self, product: str, definitions: AccessDefinitions) -> list[str]:
        """How the stored state differs from ``definitions`` (empty: it matches); for reconciliation reports."""
        n = definitions.normalized()
        problems: list[str] = []
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            pid = self._product(tx, product)
            row = tx.one(
                "SELECT revision, content_hash FROM axentra_access_definitions WHERE product_id = %s", (pid,)
            )
            perms = {
                r["name"]: r
                for r in tx.all(
                    "SELECT * FROM axentra_product_permissions WHERE product_id = %s AND retired_at IS NULL",
                    (pid,),
                )
            }
            roles = {r["key"]: r for r in tx.all("SELECT * FROM axentra_roles WHERE product_id = %s", (pid,))}
        from axentra.access.product_permission_service import _same

        if row is None:
            problems.append("no access definitions applied")
        elif int(row["revision"]) != n.revision or row["content_hash"] != n.content_hash:
            problems.append(f"stored revision {row['revision']} differs from revision {n.revision}")
        for p in n.permissions:
            if p.name not in perms:
                problems.append(f"permission {p.name}: missing or retired")
            elif not _same(perms[p.name], p):
                problems.append(f"permission {p.name}: definition differs")
        for r in n.roles:
            stored_role = roles.get(r.key)
            if stored_role is None:
                problems.append(f"role {r.key}: missing")
            elif sorted(stored_role["permissions"]) != list(r.permissions) or stored_role["scope"] != r.scope:
                problems.append(f"role {r.key}: permissions differ")
        return problems


def definitions(
    revision: int, permissions: Iterable[ProductPermission] = (), roles: Iterable[RoleDefinition] = ()
) -> AccessDefinitions:
    """Shorthand for :class:`AccessDefinitions` from any iterables."""
    return AccessDefinitions(revision, tuple(permissions), tuple(roles))


__all__ = [
    "AccessDefinitionService",
    "AccessDefinitions",
    "ApplyResult",
    "RoleDefinition",
    "StoredDefinitions",
    "definitions",
    "lock_product",
    "managed_roles",
]
