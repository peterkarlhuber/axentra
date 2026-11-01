"""All API routers; each belongs to a module that can be disabled in the settings."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter

from axentra.api.routes import (
    access,
    audit,
    auth,
    billing,
    events,
    meta,
    notify,
    observability,
    products,
    records,
    storage,
    tenants,
    usage,
    users,
)


@dataclass(frozen=True)
class ModuleRouter:
    router: APIRouter
    module: str | None


ROUTERS: list[ModuleRouter] = [
    ModuleRouter(meta.router, None),
    ModuleRouter(auth.router, "identity"),
    ModuleRouter(users.router, "identity"),
    ModuleRouter(products.router, "tenancy"),
    ModuleRouter(tenants.router, "tenancy"),
    ModuleRouter(access.router, "access"),
    ModuleRouter(records.router, "data"),
    ModuleRouter(audit.router, "audit"),
    ModuleRouter(storage.router, "storage"),
    ModuleRouter(notify.router, "notify"),
    ModuleRouter(observability.router, None),
    ModuleRouter(usage.router, "usage"),
    ModuleRouter(billing.router, "billing"),
    ModuleRouter(events.router, "events"),
]
