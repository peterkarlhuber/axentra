"""Delivery providers behind one small protocol.

Only the ``email`` channel is implemented. SMS and push are planned as further adapters with the
same shape (``send(OutgoingMessage) -> provider message id``); they do not exist yet and the API
rejects templates for those channels.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, parseaddr
import ipaddress
import logging
import smtplib
import ssl
from typing import Protocol, runtime_checkable

from axentra.config.secrets import SecretBox, resolve_secret
from axentra.config.settings import NotifySettings
from axentra.core.errors import ConfigurationError
from axentra.core.ids import new_id
from axentra.data.database import Database, DbScope

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    message_id: str
    product_id: str
    tenant_id: str | None
    channel: str
    sender: str
    recipient: str
    subject: str
    text: str
    html: str | None


class ProviderError(Exception):
    """A delivery failure. ``permanent`` failures (e.g. recipient rejected) are not retried."""

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


@runtime_checkable
class NotificationProvider(Protocol):
    name: str

    def send(self, message: OutgoingMessage) -> str:
        """Deliver one message; return the provider's message id or raise :class:`ProviderError`."""
        ...

    def check(self) -> bool:
        """Configuration sanity check without network calls (readiness)."""
        ...


def _msgid(sender: str, message_id: str) -> str:
    domain = parseaddr(sender)[1].rpartition("@")[2] or "axentra.local"
    return make_msgid(idstring=message_id.replace("_", "-"), domain=domain)


def build_email(message: OutgoingMessage, msgid: str) -> EmailMessage:
    em = EmailMessage()
    em["Subject"] = message.subject
    em["From"] = message.sender
    em["To"] = message.recipient
    em["Message-ID"] = msgid
    em["Auto-Submitted"] = "auto-generated"
    em.set_content(message.text)
    if message.html:
        em.add_alternative(message.html, subtype="html")
    return em


class LocalProvider:
    """Development/test provider: never sends; "delivers" into ``axentra_notify_mailbox``.

    The mailbox is readable through ``GET /v1/products/{id}/notify/mailbox`` while
    ``notify.provider = "local"``. Content is encrypted at rest like the outbox.
    """

    name = "local"

    def __init__(self, db: Database, secrets: SecretBox) -> None:
        self.db = db
        self.secrets = secrets

    def send(self, message: OutgoingMessage) -> str:
        if message.channel != "email":
            raise ProviderError(f"channel {message.channel} is not supported", permanent=True)
        mid = new_id("mbx")
        msgid = _msgid(message.sender, message.message_id)
        build_email(message, msgid)  # same validation as real delivery (header injection etc.)
        ctx = f"axentra_notify_mailbox|{mid}"
        scope = (
            DbScope.tenant(message.product_id, message.tenant_id)
            if message.tenant_id
            else DbScope.product(message.product_id)
        )
        with self.db.transaction(scope) as tx:
            tx.execute(
                "INSERT INTO axentra_notify_mailbox (id, product_id, tenant_id, message_id, sender, recipient,"
                " subject_enc, body_text_enc, body_html_enc, provider_message_id)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    mid,
                    message.product_id,
                    message.tenant_id,
                    message.message_id,
                    message.sender,
                    message.recipient,
                    self.secrets.encrypt(message.subject, ctx + "|subject"),
                    self.secrets.encrypt(message.text, ctx + "|text"),
                    self.secrets.encrypt(message.html, ctx + "|html") if message.html else None,
                    msgid,
                ),
            )
        return msgid

    def check(self) -> bool:
        return True


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class SmtpProvider:
    """SMTP submission with STARTTLS (``smtplib``); the password comes from ``smtp_password_ref``."""

    name = "smtp"

    def __init__(
        self, settings: NotifySettings, *, production: bool, ssl_context: ssl.SSLContext | None = None
    ) -> None:
        self.settings = settings
        if not settings.smtp_host:
            raise ConfigurationError("notify.smtp_host is required for the smtp provider")
        if production and not settings.smtp_starttls and not _is_loopback(settings.smtp_host):
            raise ConfigurationError("notify.smtp_starttls must be enabled in production (non-loopback host)")
        self._password: str | None = None
        if settings.smtp_username:
            if not settings.smtp_password_ref:
                raise ConfigurationError("notify.smtp_password_ref is required with smtp_username")
            self._password = resolve_secret(settings.smtp_password_ref)
        if ssl_context is not None:
            self._ssl = ssl_context
        else:
            self._ssl = ssl.create_default_context(cafile=settings.smtp_ca_file)

    def check(self) -> bool:
        return bool(self.settings.smtp_host) and (
            not self.settings.smtp_username or self._password is not None
        )

    def send(self, message: OutgoingMessage) -> str:
        if message.channel != "email":
            raise ProviderError(f"channel {message.channel} is not supported", permanent=True)
        s = self.settings
        msgid = _msgid(message.sender, message.message_id)
        em = build_email(message, msgid)
        envelope_from = parseaddr(message.sender)[1] or message.sender
        try:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds) as smtp:
                smtp.ehlo()
                if s.smtp_starttls:
                    smtp.starttls(context=self._ssl)
                    smtp.ehlo()
                if s.smtp_username and self._password is not None:
                    smtp.login(s.smtp_username, self._password)
                refused = smtp.send_message(em, from_addr=envelope_from, to_addrs=[message.recipient])
        except smtplib.SMTPRecipientsRefused as exc:
            codes = [c for c, _ in exc.recipients.values()]
            raise ProviderError(
                f"recipient refused ({', '.join(map(str, codes))})", permanent=all(c >= 500 for c in codes)
            ) from None
        except smtplib.SMTPAuthenticationError as exc:
            # A configuration problem, not a property of the message: retry later.
            raise ProviderError(f"smtp authentication failed ({exc.smtp_code})") from None
        except smtplib.SMTPResponseException as exc:
            text = exc.smtp_error.decode(errors="replace") if isinstance(exc.smtp_error, bytes) else ""
            raise ProviderError(
                f"smtp error {exc.smtp_code}: {text[:200]}", permanent=exc.smtp_code >= 500
            ) from None
        except (TimeoutError, smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise ProviderError(f"smtp connection failed: {type(exc).__name__}: {exc}"[:300]) from None
        if refused:
            raise ProviderError("recipient refused", permanent=True)
        return msgid


def provider_from_settings(
    settings: NotifySettings, db: Database, secrets: SecretBox, *, production: bool
) -> NotificationProvider:
    if settings.provider == "smtp":
        return SmtpProvider(settings, production=production)
    if production:
        logger.warning("notify.provider is 'local' in production: notifications are not delivered")
    return LocalProvider(db, secrets)


def sender_address(settings: NotifySettings) -> str:
    name, addr = parseaddr(settings.sender)
    if not addr or "@" not in addr:
        raise ConfigurationError("notify.sender must be an email address, e.g. 'Name <no-reply@example.com>'")
    return formataddr((name, addr)) if name else addr
