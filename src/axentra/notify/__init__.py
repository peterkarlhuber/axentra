"""Notifications: templates, an encrypted outbox, providers (local, SMTP), preferences, dispatcher."""

from axentra.notify.dispatcher import DispatchResult, NotifyDispatcher
from axentra.notify.providers import (
    LocalProvider,
    NotificationProvider,
    OutgoingMessage,
    ProviderError,
    SmtpProvider,
)
from axentra.notify.service import NotifyService

__all__ = [
    "DispatchResult",
    "LocalProvider",
    "NotificationProvider",
    "NotifyDispatcher",
    "NotifyService",
    "OutgoingMessage",
    "ProviderError",
    "SmtpProvider",
]
