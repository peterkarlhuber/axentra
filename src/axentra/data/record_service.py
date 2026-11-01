"""Authorized access to tenant records (permission checks on top of :class:`RecordStore`)."""

from __future__ import annotations

import builtins
from typing import Any

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.core.context import Principal
from axentra.core.pagination import Page
from axentra.data.database import Database, DbScope
from axentra.data.records import CollectionStats, Record, RecordStore


class RecordService:
    def __init__(self, db: Database, authz: Authorizer, audit: AuditLog) -> None:
        self.store = RecordStore(db)
        self.db = db
        self.authz = authz
        self.audit = audit

    def collections(self, principal: Principal, product_id: str) -> builtins.list[CollectionStats]:
        self.authz.require(principal, "collections:read", product_id)
        return self.store.collections(product_id)

    def list(
        self, principal: Principal, product_id: str, tenant_id: str, collection: str, **kw: Any
    ) -> Page[Record]:
        self.authz.require(principal, "records:read", product_id, tenant_id)
        return self.store.list(product_id, tenant_id, collection, **kw)

    def get(
        self, principal: Principal, product_id: str, tenant_id: str, collection: str, record_id: str
    ) -> Record:
        self.authz.require(principal, "records:read", product_id, tenant_id)
        return self.store.get(product_id, tenant_id, collection, record_id)

    def create(
        self, principal: Principal, product_id: str, tenant_id: str, collection: str, data: dict[str, Any]
    ) -> Record:
        self.authz.require(principal, "records:write", product_id, tenant_id)
        return self.store.create(product_id, tenant_id, collection, data, actor=principal.actor.id)

    def replace(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        collection: str,
        record_id: str,
        data: dict[str, Any],
        if_match: int | None = None,
    ) -> Record:
        self.authz.require(principal, "records:write", product_id, tenant_id)
        return self.store.replace(
            product_id, tenant_id, collection, record_id, data, actor=principal.actor.id, if_match=if_match
        )

    def delete(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        collection: str,
        record_id: str,
        if_match: int | None = None,
    ) -> None:
        self.authz.require(principal, "records:write", product_id, tenant_id)
        self.store.delete(product_id, tenant_id, collection, record_id, if_match=if_match)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            self.audit.record(
                tx,
                principal,
                "data.record.delete",
                target_type="record",
                target_id=record_id,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"collection": collection},
            )
