from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Header, Query, Response
from pydantic import BaseModel, Field, model_validator

from axentra.api.context import Ax, CurrentPrincipal
from axentra.api.routes.common import Cursor, IfMatch, Limit, parse_if_match
from axentra.core.errors import ModuleDisabled
from axentra.core.pagination import Page
from axentra.notify.models import (
    DeliveryStats,
    MailboxEntry,
    Message,
    MessageStatus,
    Preferences,
    RenderedContent,
    Template,
    TemplateVariant,
)
from axentra.notify.service import NotifyService
from axentra.platform import Axentra

router = APIRouter(prefix="/v1/products/{product_id}", tags=["notify"])
N = "/notify"


def _svc(ax: Axentra) -> NotifyService:
    if ax.notify is None:
        raise ModuleDisabled("the notify module is not enabled")
    return ax.notify


class TemplateCreate(BaseModel):
    key: str = Field(min_length=2, max_length=63, pattern=r"^[a-z][a-z0-9_.-]{1,62}$")
    channel: Literal["email", "sms", "push", "inbox"] = "email"
    category: str = Field(default="transactional", max_length=41)
    name: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=2000)
    variables: list[str] = Field(default_factory=list, max_length=50)
    sample_data: dict[str, Any] = Field(default_factory=dict)
    variants: dict[str, TemplateVariant] = Field(min_length=1, max_length=20)
    sensitive: bool = False


class TemplateUpdate(BaseModel):
    channel: Literal["email", "sms", "push", "inbox"] | None = None
    category: str | None = Field(default=None, max_length=41)
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    variables: list[str] | None = Field(default=None, max_length=50)
    sample_data: dict[str, Any] | None = None
    variants: dict[str, TemplateVariant] | None = Field(default=None, min_length=1, max_length=20)
    sensitive: bool | None = None


class PreviewRequest(BaseModel):
    locale: str | None = Field(default=None, max_length=20)
    variables: dict[str, Any] = Field(default_factory=dict)
    """Values that override the template's sample data."""


class DraftPreviewRequest(BaseModel):
    variables: list[str] = Field(default_factory=list, max_length=50)
    sample_data: dict[str, Any] = Field(default_factory=dict)
    variants: dict[str, TemplateVariant] = Field(min_length=1, max_length=20)
    locale: str | None = Field(default=None, max_length=20)
    values: dict[str, Any] = Field(default_factory=dict)


class Recipient(BaseModel):
    user_id: str | None = Field(default=None, max_length=64)
    email: str | None = Field(default=None, max_length=320)

    @model_validator(mode="after")
    def _one(self) -> Recipient:
        if (self.user_id is None) == (self.email is None):
            raise ValueError("give exactly one of user_id or email")
        return self


class SendRequest(BaseModel):
    template_key: str = Field(min_length=2, max_length=63)
    to: Recipient
    variables: dict[str, Any] = Field(default_factory=dict)
    locale: str | None = Field(default=None, max_length=20)


class PreferencesUpdate(BaseModel):
    opted_out: list[str] = Field(default_factory=list, max_length=50)


def _template_dict(body: BaseModel) -> dict[str, Any]:
    return body.model_dump(exclude_unset=True)


# -- templates ------------------------------------------------------------------------------------


@router.get(
    N + "/templates",
    response_model=list[Template],
    summary="Notification templates (incl. built-in defaults)",
)
def list_templates(product_id: str, principal: CurrentPrincipal, ax: Ax) -> list[Template]:
    return _svc(ax).list_templates(principal, product_id)


@router.post(N + "/templates", response_model=Template, status_code=201, summary="Create a template")
def create_template(product_id: str, body: TemplateCreate, principal: CurrentPrincipal, ax: Ax) -> Template:
    data = _template_dict(body)
    key = data.pop("key")
    return _svc(ax).create_template(principal, product_id, key=key, **data)


@router.post(
    N + "/templates/preview",
    response_model=RenderedContent,
    summary="Validate and render an unsaved template",
)
def preview_draft(
    product_id: str, body: DraftPreviewRequest, principal: CurrentPrincipal, ax: Ax
) -> RenderedContent:
    return _svc(ax).preview_draft(
        principal,
        product_id,
        variants={k: v.model_dump() for k, v in body.variants.items()},
        variables=body.variables,
        sample_data=body.sample_data,
        locale=body.locale,
        values=body.values,
    )


@router.get(N + "/templates/{key}", response_model=Template)
def get_template(
    product_id: str, key: str, principal: CurrentPrincipal, ax: Ax, response: Response
) -> Template:
    t = _svc(ax).get_template(principal, product_id, key)
    response.headers["ETag"] = f'"{t.version}"'
    return t


@router.patch(
    N + "/templates/{key}", response_model=Template, summary="Change a template (If-Match: version)"
)
def update_template(
    product_id: str,
    key: str,
    body: TemplateUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    if_match: IfMatch = None,
) -> Template:
    return _svc(ax).update_template(
        principal, product_id, key, _template_dict(body), if_match=parse_if_match(if_match)
    )


@router.delete(
    N + "/templates/{key}", status_code=204, summary="Delete a template (restores a built-in default)"
)
def delete_template(
    product_id: str, key: str, principal: CurrentPrincipal, ax: Ax, if_match: IfMatch = None
) -> Response:
    _svc(ax).delete_template(principal, product_id, key, if_match=parse_if_match(if_match))
    return Response(status_code=204)


@router.post(
    N + "/templates/{key}/preview",
    response_model=RenderedContent,
    summary="Render a template with its sample data (overridable)",
)
def preview_template(
    product_id: str, key: str, body: PreviewRequest, principal: CurrentPrincipal, ax: Ax
) -> RenderedContent:
    return _svc(ax).preview(principal, product_id, key, locale=body.locale, variables=body.variables)


# -- sending & messages ---------------------------------------------------------------------------


@router.post(
    "/tenants/{tenant_id}/notify/send",
    response_model=Message,
    status_code=202,
    summary="Render and enqueue a notification (asynchronous delivery)",
    responses={
        200: {"model": Message, "description": "Replay of an earlier request with the same Idempotency-Key"}
    },
)
def send(
    product_id: str,
    tenant_id: str,
    body: SendRequest,
    principal: CurrentPrincipal,
    ax: Ax,
    response: Response,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", max_length=200),
) -> Message:
    result = _svc(ax).send(
        principal,
        product_id,
        tenant_id,
        template_key=body.template_key,
        to_user_id=body.to.user_id,
        to_email=body.to.email,
        variables=body.variables,
        locale=body.locale,
        idempotency_key=idempotency_key,
    )
    if result.replayed:
        response.status_code = 200
        response.headers["Idempotent-Replayed"] = "true"
    return result.message


@router.get(
    N + "/messages",
    response_model=Page[Message],
    summary="Outbox messages (notify:manage; or notify:send with tenant_id)",
)
def list_messages(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    tenant_id: str | None = None,
    status: MessageStatus | None = None,
    template_key: str | None = Query(None, max_length=63),
    recipient: str | None = Query(None, max_length=320),
    since: datetime | None = None,
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Message]:
    return _svc(ax).list_messages(
        principal,
        product_id,
        tenant_id=tenant_id,
        status=status,
        template_key=template_key,
        recipient=recipient,
        since=since,
        limit=limit,
        cursor=cursor,
    )


@router.get(
    N + "/messages/{message_id}", response_model=Message, summary="One message, with content if available"
)
def get_message(product_id: str, message_id: str, principal: CurrentPrincipal, ax: Ax) -> Message:
    return _svc(ax).get_message(principal, product_id, message_id)


@router.post(
    N + "/messages/{message_id}/retry", response_model=Message, summary="Queue a failed message again"
)
def retry_message(product_id: str, message_id: str, principal: CurrentPrincipal, ax: Ax) -> Message:
    return _svc(ax).retry_message(principal, product_id, message_id)


@router.get(
    N + "/mailbox",
    response_model=Page[MailboxEntry],
    summary="Messages 'delivered' by the local development provider",
)
def mailbox(
    product_id: str,
    principal: CurrentPrincipal,
    ax: Ax,
    recipient: str | None = Query(None, max_length=320),
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[MailboxEntry]:
    return _svc(ax).list_mailbox(principal, product_id, recipient=recipient, limit=limit, cursor=cursor)


@router.get(N + "/stats", response_model=DeliveryStats, summary="Delivery statistics for dashboards")
def stats(
    product_id: str, principal: CurrentPrincipal, ax: Ax, tenant_id: str | None = None
) -> DeliveryStats:
    return _svc(ax).stats(principal, product_id, tenant_id)


# -- preferences ----------------------------------------------------------------------------------


@router.get(N + "/preferences/me", response_model=Preferences, summary="My notification preferences")
def get_my_preferences(
    product_id: str, principal: CurrentPrincipal, ax: Ax, response: Response, tenant_id: str | None = None
) -> Preferences:
    p = _svc(ax).get_preferences(principal, product_id, tenant_id)
    response.headers["ETag"] = f'"{p.version}"'
    return p


@router.put(
    N + "/preferences/me", response_model=Preferences, summary="Replace my opt-outs (If-Match: version)"
)
def put_my_preferences(
    product_id: str,
    body: PreferencesUpdate,
    principal: CurrentPrincipal,
    ax: Ax,
    tenant_id: str | None = None,
    if_match: IfMatch = None,
) -> Preferences:
    return _svc(ax).set_preferences(
        principal, product_id, tenant_id, opted_out=body.opted_out, if_match=parse_if_match(if_match)
    )
