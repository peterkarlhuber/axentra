"""Authorized access to tenant records (permission checks on top of :class:`RecordStore`)."""

from __future__ import annotations

import builtins
from typing import Any

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.core.context import Principal
from axentra.core.pagination import Page
from axentra.data.database import Database, Tx
from axentra.data.records import CollectionStats, Record, RecordHook, RecordStore


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
        return self.store.create(
            product_id,
            tenant_id,
            collection,
            data,
            actor=principal.actor.id,
            hook=self._audit(principal, "data.record.create"),
        )

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
            product_id,
            tenant_id,
            collection,
            record_id,
            data,
            actor=principal.actor.id,
            if_match=if_match,
            hook=self._audit(principal, "data.record.replace"),
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

        def audit(tx: Tx) -> None:
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

        self.store.delete(product_id, tenant_id, collection, record_id, if_match=if_match, hook=audit)

    def _audit(self, principal: Principal, action: str) -> RecordHook:
        """Audit event in the write transaction; the record data itself is never copied into it."""

        def hook(tx: Tx, record: Record) -> None:
            self.audit.record(
                tx,
                principal,
                action,
                target_type="record",
                target_id=record.id,
                product_id=record.product_id,
                tenant_id=record.tenant_id,
                details={"collection": record.collection, "version": record.version},
            )

        return hook
