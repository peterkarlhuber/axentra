from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, Limit
from axentra.audit.log import AuditEvent
from axentra.core.errors import NotFound
from axentra.core.pagination import Page
from axentra.data.database import DbScope

router = APIRouter(prefix="/v1", tags=["audit"])


class EffectiveSettings(BaseModel):
    environment: str
    mode: str
    modules: list[str]
    public_url: str
    allowed_origins: list[str]
    trusted_proxies: list[str]
    session_ttl_hours: int
    session_idle_minutes: int
    password_login: bool
    password_min_length: int
    login_rate_per_minute: int
    limits: dict[str, Any] = Field(default_factory=dict)
    """Request limits: max_body_bytes, rate_limit_per_minute, rate_limit_ip_per_minute, rate_limit_burst, api_docs."""
    oidc_providers: list[dict[str, Any]]
    storage: dict[str, Any]
    notify: dict[str, Any]
    billing: dict[str, Any]
    observability: dict[str, Any]
    encryption_key_ids: list[str]
    active_encryption_key: str
    features: dict[str, bool]


@router.get("/audit", response_model=Page[AuditEvent], summary="Audit events (filters combine with AND)")
def list_audit(
    principal: CurrentPrincipal,
    ax: Ax,
    product_id: str | None = None,
    tenant_id: str | None = None,
    action: str | None = Query(None, max_length=100, description="Exact action or prefix ending in *"),
    actor_id: str | None = None,
    outcome: Literal["success", "denied", "failure"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = Query(None, max_length=200),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[AuditEvent]:
    if product_id:
        ax.authz.require(principal, "audit:read", product_id)
        scope = DbScope.product(product_id)
        return ax.audit.list(
            scope,
            product_id=product_id,
            tenant_id=tenant_id,
            action=action,
            actor_id=actor_id,
            outcome=outcome,
            since=since,
            until=until,
            q=q,
            limit=limit,
            cursor=cursor,
        )
    ax.authz.require(principal, "platform:audit")
    return ax.audit.list(
        DbScope.platform(),
        tenant_id=tenant_id,
        action=action,
        actor_id=actor_id,
        outcome=outcome,
        since=since,
        until=until,
        q=q,
        limit=limit,
        cursor=cursor,
    )


@router.get("/audit/{event_id}", response_model=AuditEvent)
def get_audit(event_id: str, principal: CurrentPrincipal, ax: Ax) -> AuditEvent:
    # Same 404 for "does not exist" and "not yours to read" (no existence oracle for event ids).
    event = ax.audit.get(DbScope.platform(), event_id)
    if event.product_id is None:
        if not ax.authz.has(principal, "platform:audit"):
            raise NotFound("audit event not found")
    elif not ax.authz.has(principal, "audit:read", event.product_id):
        raise NotFound("audit event not found")
    return event


@router.get("/settings", response_model=EffectiveSettings, summary="Effective non-secret configuration")
def effective_settings(principal: CurrentPrincipal, ax: Ax) -> EffectiveSettings:
    allowed = ax.authz.has(principal, "platform:settings") or any(
        ax.authz.has(principal, "product:manage", p.id) for p in ax.tenancy.list_products(principal)
    )
    if not allowed:
        ax.authz.require(principal, "platform:settings")
    s = ax.settings
    return EffectiveSettings(
        environment=s.environment.value,
        mode=s.mode.value,
        modules=s.modules,
        public_url=s.security.public_url,
        allowed_origins=s.security.allowed_origins,
        trusted_proxies=s.security.trusted_proxies,
        session_ttl_hours=s.security.session_ttl_hours,
        session_idle_minutes=s.security.session_idle_minutes,
        password_login=s.security.password_login,
        password_min_length=s.security.password_min_length,
        login_rate_per_minute=s.security.login_rate_per_minute,
        limits={
            "max_body_bytes": s.security.max_body_bytes,
            "rate_limit_per_minute": s.security.rate_limit_per_minute,
            "rate_limit_ip_per_minute": s.security.rate_limit_ip_per_minute,
            "rate_limit_burst": s.security.rate_limit_burst,
            "api_docs": s.api_docs_mode,
        },
        oidc_providers=[
            {
                "id": p.id,
                "name": p.name,
                "issuer": p.issuer,
                "allow_signup": p.allow_signup,
                "allowed_email_domains": p.allowed_email_domains,
                "link_by_verified_email": p.link_by_verified_email,
                "allow_signup_without_email": p.allow_signup_without_email,
            }
            for p in s.oidc
        ],
        storage={
            "backend": s.storage.backend,
            "max_file_bytes": s.storage.max_file_bytes,
            "allowed_content_types": s.storage.allowed_content_types,
            "store_blocked_as_inert": s.storage.store_blocked_as_inert,
            "s3_bucket": s.storage.s3_bucket,
            "s3_region": s.storage.s3_region,
        },
        notify={
            "provider": s.notify.provider,
            "sender": s.notify.sender,
            # The installation-wide base of invitation links (a product's own setting still wins).
            "invitation_accept_url": s.invitation_accept_base,
        },
        billing={"provider": s.billing.provider, "live_payments": s.billing.live_payments},
        observability={
            "log_level": s.observability.log_level,
            "otel_enabled": s.observability.otel_enabled,
            "audit_retention_days": s.observability.audit_retention_days,
            "job_retention_days": s.observability.job_retention_days,
        },
        encryption_key_ids=ax.keyring.kids,
        active_encryption_key=ax.keyring.active_kid,
        features=s.features,
    )
