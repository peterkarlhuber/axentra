from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Channel = Literal["email", "sms", "push"]
MessageStatus = Literal["queued", "sending", "sent", "failed", "suppressed"]
ContentState = Literal["available", "redacted", "purged", "none"]

#: Categories a user can never opt out of.
LOCKED_CATEGORIES: frozenset[str] = frozenset({"transactional", "security"})


class TemplateVariant(BaseModel):
    subject: str = Field(min_length=1, max_length=500)
    text: str = Field(min_length=1, max_length=100_000)
    html: str | None = Field(default=None, max_length=200_000)


class Template(BaseModel):
    id: str | None
    """``None`` for a built-in default that the product has not overridden."""
    product_id: str
    key: str
    channel: Channel
    category: str
    name: str
    description: str
    variables: list[str]
    sample_data: dict[str, Any]
    variants: dict[str, TemplateVariant]
    sensitive: bool
    """Rendered content of sensitive messages (e.g. invitation links) is never returned by the API
    and is erased as soon as the message was sent."""
    version: int
    builtin: bool
    system_only: bool = False
    """Only Axentra itself sends this template (e.g. ``invitation``); ``POST .../notify/send``
    refuses it, so callers can never choose its variables (such as the accept link)."""
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RenderedContent(BaseModel):
    locale: str
    subject: str
    text: str
    html: str | None


class MessageContent(BaseModel):
    subject: str
    text: str
    html: str | None


class Message(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    template_key: str
    template_version: int
    channel: Channel
    category: str
    recipient: str
    recipient_user_id: str | None
    locale: str
    status: MessageStatus
    attempts: int
    max_attempts: int
    next_attempt_at: datetime | None
    last_error: str | None
    provider: str | None
    provider_message_id: str | None
    idempotency_key: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    sent_at: datetime | None
    subject: str | None = None
    """The rendered subject while content is available (``None`` if redacted or purged)."""
    content_state: ContentState
    content: MessageContent | None = None
    """Only on single-message reads."""


class MailboxEntry(BaseModel):
    id: str
    product_id: str
    tenant_id: str | None
    message_id: str
    sender: str
    recipient: str
    subject: str
    text: str
    html: str | None
    provider_message_id: str
    created_at: datetime


class Preferences(BaseModel):
    product_id: str
    tenant_id: str | None
    user_id: str
    opted_out: list[str]
    available_categories: list[str]
    """Categories used by the product's templates that the user may opt out of."""
    locked_categories: list[str]
    version: int


class StatusCounts(BaseModel):
    queued: int = 0
    sending: int = 0
    sent: int = 0
    failed: int = 0
    suppressed: int = 0


class DeliveryStats(BaseModel):
    product_id: str
    tenant_id: str | None
    provider: str
    total: StatusCounts
    last_24h: StatusCounts
    oldest_queued_at: datetime | None
    attempts_24h: int
    """Delivery attempts made for messages created in the last 24 hours."""


class SendResult(BaseModel):
    message: Message
    replayed: bool = False
