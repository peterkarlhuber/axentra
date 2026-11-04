"""API keys for machines and integrations.

A key looks like ``axk_<26 char id body>_<43 char secret>``. It is shown once when created or
rotated; the database keeps its id, the SHA-256 hash of the secret, the product it belongs to,
an optional tenant binding, an explicit permission list and an optional expiry. Keys never hold
platform permissions. Rotation creates a replacement key and revokes the old one, optionally
after a grace period so deployments can switch over.

Keys created by keys (a principal holding ``api_keys:manage`` through an API key):

- hold at most the creating key's permissions (as for every creator);
- never outlive it: without ``expires_at`` the child inherits the parent's expiry, and a later
  ``expires_at`` is refused (``422``);
- are revoked together with it: revoking a key also revokes, at once, every active key that was
  created by it (recursively). Rotation does not cascade (the replacement takes over the role of
  the old key).

Every key is bounded at request time by what its creator holds *now* in the same scope
(:class:`~axentra.access.authorizer.Authorizer`): a removed, demoted or disabled creator takes the
key's rights along without revoking it (``403 api_key_creator_lost_access``).

Adapted in concept from nodestro-api ``api_keys.py``/``serving.py`` (MIT, see
docs/architecture/NODESTRO_REUSE.md): hash-only storage, constant-time comparison, ``last_used_at``
written at most once a minute.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import re
from typing import Any

from axentra.access.authorizer import Authorizer
from axentra.access.models import ApiKey, NewApiKey
from axentra.access.permissions import is_product_permission_name, validate_permissions
from axentra.access.product_permissions import load_catalog
from axentra.audit.log import AuditLog
from axentra.core.clock import utcnow
from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import Forbidden, NotFound, Unauthenticated, ValidationFailed
from axentra.core.ids import new_id, new_token
from axentra.data.database import Database, DbScope
from axentra.identity.tokens import hash_token, token_matches

_KEY_RE = re.compile(r"^axk_([0-9a-hjkmnp-tv-z]{26})_([A-Za-z0-9_-]{32,64})$")
_LAST_USED_RESOLUTION = timedelta(seconds=60)


def _status(row: dict[str, Any]) -> str:
    if row["revoked_at"] and row["revoked_at"] <= utcnow():
        return "revoked"
    if row["expires_at"] and row["expires_at"] <= utcnow():
        return "expired"
    return "active"


def _model(row: dict[str, Any]) -> ApiKey:
    body = row["id"].split("_", 1)[1]
    return ApiKey.model_validate({**row, "prefix": f"axk_{body}_", "status": _status(row)})


class ApiKeyService:
    def __init__(self, db: Database, authz: Authorizer, audit: AuditLog) -> None:
        self.db = db
        self.authz = authz
        self.audit = audit

    def list_keys(
        self, principal: Principal, product_id: str, *, include_revoked: bool = True
    ) -> list[ApiKey]:
        self.authz.require(principal, "api_keys:read", product_id)
        sql = "SELECT * FROM axentra_api_keys WHERE product_id = %s"
        if not include_revoked:
            sql += " AND revoked_at IS NULL"
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(sql + " ORDER BY created_at DESC LIMIT 1000", (product_id,))
        return [_model(r) for r in rows]

    def get_key(self, principal: Principal, product_id: str, key_id: str) -> ApiKey:
        self.authz.require(principal, "api_keys:read", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_api_keys WHERE id = %s AND product_id = %s",
                (key_id, product_id),
                what="API key",
            )
        return _model(row)

    def create_key(
        self,
        principal: Principal,
        product_id: str,
        *,
        name: str,
        permissions: list[str],
        tenant_id: str | None = None,
        expires_at: datetime | None = None,
        _replaces: str | None = None,
    ) -> NewApiKey:
        grant = self.authz.require(principal, "api_keys:manage", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            catalog = load_catalog(tx, product_id)
        # Built-in names and the product's own active permissions (never another product's).
        perms = validate_permissions(permissions, product_permissions=catalog.scopes)
        if not perms:
            raise ValidationFailed("an API key needs at least one permission")
        # No privilege escalation: a caller can only hand out permissions it holds itself.
        missing = sorted(perms - grant.permissions)
        if missing:
            raise Forbidden(f"you cannot grant permissions you do not hold: {', '.join(missing)}")
        if not name.strip() or len(name) > 200:
            raise ValidationFailed("name must be 1-200 characters")
        if expires_at is not None and expires_at <= utcnow():
            raise ValidationFailed("expires_at must be in the future")
        if principal.actor.kind is ActorKind.API_KEY:
            # A derived key never outlives the key that creates it.
            with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
                parent_expiry = tx.scalar(
                    "SELECT expires_at FROM axentra_api_keys WHERE id = %s AND product_id = %s",
                    (principal.actor.id, product_id),
                )
            if parent_expiry is not None:
                if expires_at is None:
                    expires_at = parent_expiry
                elif expires_at > parent_expiry:
                    raise ValidationFailed("expires_at must not be later than the expiry of the creating key")
        key_id = new_id("key")
        secret = new_token()
        full = f"axk_{key_id.split('_', 1)[1]}_{secret}"
        scope = DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)
        with self.db.transaction(scope) as tx:
            if tenant_id and not tx.one(
                "SELECT 1 FROM axentra_tenants WHERE id = %s AND product_id = %s", (tenant_id, product_id)
            ):
                raise NotFound("tenant not found")
            tx.execute(
                "INSERT INTO axentra_api_keys (id, product_id, tenant_id, name, secret_hash, permissions,"
                " created_by, expires_at, replaces) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    key_id,
                    product_id,
                    tenant_id,
                    name.strip(),
                    hash_token(secret),
                    sorted(perms),
                    principal.actor.id,
                    expires_at,
                    _replaces,
                ),
            )
            self.audit.record(
                tx,
                principal,
                "access.api_key.create",
                target_type="api_key",
                target_id=key_id,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"name": name, "permissions": sorted(perms), "replaces": _replaces},
            )
            row = tx.one_or_404("SELECT * FROM axentra_api_keys WHERE id = %s", (key_id,))
        return NewApiKey(key=_model(row), secret=full)

    def rotate_key(
        self, principal: Principal, product_id: str, key_id: str, *, grace_seconds: int = 0
    ) -> NewApiKey:
        if not 0 <= grace_seconds <= 7 * 86400:
            raise ValidationFailed("grace_seconds must be between 0 and 604800")
        old = self.get_key(principal, product_id, key_id)
        if old.status != "active":
            raise ValidationFailed("only active keys can be rotated")
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            active = load_catalog(tx, product_id).names
        # Retired product permissions have no effect on the old key either; the replacement does
        # not carry them (so rotating never fails because a product retired a permission).
        dropped = sorted(p for p in old.permissions if is_product_permission_name(p) and p not in active)
        new = self.create_key(
            principal,
            product_id,
            name=old.name,
            permissions=[p for p in old.permissions if p not in dropped],
            tenant_id=old.tenant_id,
            expires_at=old.expires_at,
            _replaces=key_id,
        )
        with self.db.transaction(DbScope.product(product_id)) as tx:
            tx.execute(
                "UPDATE axentra_api_keys SET revoked_at = now() + make_interval(secs => %s) WHERE id = %s"
                " AND revoked_at IS NULL",
                (grace_seconds, key_id),
            )
            self.audit.record(
                tx,
                principal,
                "access.api_key.rotate",
                target_type="api_key",
                target_id=key_id,
                product_id=product_id,
                details={"replacement": new.key.id, "grace_seconds": grace_seconds}
                | ({"dropped_permissions": dropped} if dropped else {}),
            )
        return new

    def revoke_key(self, principal: Principal, product_id: str, key_id: str) -> ApiKey:
        self.authz.require(principal, "api_keys:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_api_keys WHERE id = %s AND product_id = %s FOR UPDATE",
                (key_id, product_id),
                what="API key",
            )
            if row["revoked_at"] is None or row["revoked_at"] > utcnow():
                tx.execute("UPDATE axentra_api_keys SET revoked_at = now() WHERE id = %s", (key_id,))
                # Cascade: keys created by this key (and by those, recursively) are revoked too.
                children = tx.all(
                    "WITH RECURSIVE d(id) AS (SELECT id FROM axentra_api_keys WHERE product_id = %(p)s"
                    " AND created_by = %(k)s UNION SELECT k.id FROM axentra_api_keys k JOIN d ON k.created_by = d.id"
                    " WHERE k.product_id = %(p)s)"
                    " UPDATE axentra_api_keys SET revoked_at = now() WHERE id IN (SELECT id FROM d)"
                    " AND (revoked_at IS NULL OR revoked_at > now()) RETURNING id",
                    {"p": product_id, "k": key_id},
                )
                self.audit.record(
                    tx,
                    principal,
                    "access.api_key.revoke",
                    target_type="api_key",
                    target_id=key_id,
                    product_id=product_id,
                    tenant_id=row["tenant_id"],
                    details={"cascaded": sorted(r["id"] for r in children)} if children else None,
                )
            row = tx.one_or_404("SELECT * FROM axentra_api_keys WHERE id = %s", (key_id,))
        return _model(row)

    def authenticate(self, token: str, *, request_id: str | None = None, ip: str | None = None) -> Principal:
        m = _KEY_RE.match(token)
        if not m:
            raise Unauthenticated("invalid API key")
        key_id = "key_" + m.group(1)
        now = utcnow()
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT k.*, p.status AS product_status FROM axentra_api_keys k"
                " JOIN axentra_products p ON p.id = k.product_id WHERE k.id = %s",
                (key_id,),
            )
            if (
                row is None
                or not token_matches(m.group(2), row["secret_hash"])
                or (row["revoked_at"] and row["revoked_at"] <= now)
                or (row["expires_at"] and row["expires_at"] <= now)
            ):
                raise Unauthenticated("invalid API key")
            if row["last_used_at"] is None or now - row["last_used_at"] > _LAST_USED_RESOLUTION:
                tx.execute("UPDATE axentra_api_keys SET last_used_at = now() WHERE id = %s", (key_id,))
        return Principal(
            actor=Actor(ActorKind.API_KEY, key_id, row["name"]),
            api_key_product_id=row["product_id"],
            api_key_tenant_id=row["tenant_id"],
            api_key_permissions=frozenset(row["permissions"]),
            request_id=request_id,
            ip=ip,
        )
