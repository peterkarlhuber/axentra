"""Notifications: templates, the outbox, preferences, the local mailbox and delivery stats.

Sending is asynchronous: :meth:`NotifyService.send` renders the template, applies the recipient's
preferences and stores a ``queued`` message in the same transaction as its audit event; the
:class:`~axentra.notify.dispatcher.NotifyDispatcher` delivers it later (at-least-once).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import hashlib
import json
import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from psycopg import errors as pg_errors
from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.config.secrets import SecretBox
from axentra.config.settings import Settings
from axentra.core.context import ActorKind, Principal
from axentra.core.errors import (
    ConfigurationError,
    Conflict,
    Forbidden,
    ModeNotSupported,
    NotFound,
    PreconditionFailed,
    ValidationFailed,
)
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.identity.service import normalize_email
from axentra.notify.builtin import BUILTIN_TEMPLATES, INVITATION
from axentra.notify.models import (
    LOCKED_CATEGORIES,
    DeliveryStats,
    MailboxEntry,
    Message,
    MessageContent,
    Preferences,
    RenderedContent,
    SendResult,
    StatusCounts,
    Template,
    TemplateVariant,
)
from axentra.notify.providers import NotificationProvider, provider_from_settings, sender_address
from axentra.notify.render import check_variables, placeholders, render_variant

if TYPE_CHECKING:
    from axentra.notify.dispatcher import NotifyDispatcher
    from axentra.observability.metrics import MetricsRegistry
    from axentra.tenancy.models import NewInvitation

logger = logging.getLogger(__name__)

_KEY = re.compile(r"^[a-z][a-z0-9_.-]{1,62}$")
_CATEGORY = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_LOCALE = re.compile(r"^[a-z]{2,3}(-[a-z0-9]{2,8})?$")
_VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_IDEMPOTENCY_KEY = re.compile(r"^[\x21-\x7e]{1,200}$")
MAX_LOCALES = 20
MAX_OPT_OUTS = 50
_TEMPLATE_FIELDS = (
    "channel",
    "category",
    "name",
    "description",
    "variables",
    "sample_data",
    "variants",
    "sensitive",
)


def _ctx(table: str, row_id: str, field: str) -> str:
    return f"{table}|{row_id}|{field}"


def _like(q: str) -> str:
    return q.replace("%", r"\%").replace("_", r"\_")


class NotifyService:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        authz: Authorizer,
        audit: AuditLog,
        secrets: SecretBox,
        *,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.authz = authz
        self.audit = audit
        self.secrets = secrets
        self.metrics = metrics
        self._provider: NotificationProvider | None = None
        self._enqueued = (
            metrics.counter(
                "axentra_notify_messages_enqueued_total", "Notification messages enqueued", ("status",)
            )
            if metrics
            else None
        )

    # -- provider / dispatcher -------------------------------------------------------------------

    @property
    def provider(self) -> NotificationProvider:
        if self._provider is None:
            self._provider = provider_from_settings(
                self.settings.notify, self.db, self.secrets, production=self.settings.is_production
            )
        return self._provider

    def set_provider(self, provider: NotificationProvider) -> None:
        """Replace the delivery provider (tests, custom adapters)."""
        self._provider = provider

    def dispatcher(self, **kwargs: Any) -> NotifyDispatcher:
        """A dispatcher bound to this service's provider; call ``run_once(batch)`` from any worker."""
        from axentra.notify.dispatcher import NotifyDispatcher

        return NotifyDispatcher(
            self.db, self.secrets, self.provider, self.settings.notify, metrics=self.metrics, **kwargs
        )

    def check_config(self) -> bool:
        """Readiness: the provider configuration is complete (no network calls)."""
        try:
            sender_address(self.settings.notify)
            return bool(self.provider.check())
        except ConfigurationError as exc:
            logger.warning("notify provider configuration is invalid: %s", exc)
            return False

    # -- templates -------------------------------------------------------------------------------

    @staticmethod
    def _validate_template(data: dict[str, Any]) -> dict[str, Any]:
        if data["channel"] != "email":
            raise ValidationFailed(
                f"the {data['channel']} channel is not available yet; only email is supported"
            )
        if not _CATEGORY.match(data["category"]):
            raise ValidationFailed("category must be 2-41 lowercase letters, digits or underscores")
        variables = list(data["variables"])
        if len(variables) > 50 or len(set(variables)) != len(variables):
            raise ValidationFailed("variables must be unique (at most 50)")
        for v in variables:
            if not _VAR.match(v):
                raise ValidationFailed(f"invalid variable name {v!r}")
        variants_in = data["variants"]
        if not variants_in or len(variants_in) > MAX_LOCALES:
            raise ValidationFailed(f"a template needs 1-{MAX_LOCALES} locale variants")
        variants: dict[str, dict[str, Any]] = {}
        for loc, var in variants_in.items():
            loc_n = loc.strip().replace("_", "-").lower()
            if not _LOCALE.match(loc_n):
                raise ValidationFailed(f"invalid locale {loc!r} (e.g. en, de, de-at)")
            v = TemplateVariant.model_validate(var).model_dump()
            used: list[str] = []
            for part in ("subject", "text", "html"):
                if v.get(part):
                    used += placeholders(v[part])
            undeclared = sorted(set(used) - set(variables))
            if undeclared:
                raise ValidationFailed(
                    f"variant {loc_n} uses undeclared variables: {', '.join(undeclared)}",
                    extra={"undeclared": undeclared},
                )
            variants[loc_n] = v
        if "en" not in variants:
            raise ValidationFailed("a template needs an 'en' variant (the fallback locale)")
        sample = check_variables(data["sample_data"] or {})
        return {**data, "variables": variables, "variants": variants, "sample_data": sample}

    @staticmethod
    def _template(row: Row, *, builtin: bool = False) -> Template:
        return Template.model_validate({**row, "builtin": builtin})

    @staticmethod
    def _builtin(product_id: str, key: str) -> Template | None:
        spec = BUILTIN_TEMPLATES.get(key)
        if spec is None:
            return None
        return Template.model_validate(
            {**spec, "id": None, "product_id": product_id, "key": key, "version": 0, "builtin": True}
        )

    def _load_template(self, tx: Tx, product_id: str, key: str) -> Template | None:
        row = tx.one(
            "SELECT * FROM axentra_notify_templates WHERE product_id = %s AND key = %s", (product_id, key)
        )
        if row is not None:
            return self._template(row)
        return self._builtin(product_id, key)

    def list_templates(self, principal: Principal, product_id: str) -> list[Template]:
        self.authz.require(principal, "notify:manage", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT * FROM axentra_notify_templates WHERE product_id = %s ORDER BY key LIMIT 1000",
                (product_id,),
            )
        items = [self._template(r) for r in rows]
        have = {t.key for t in items}
        for key in BUILTIN_TEMPLATES:
            if key not in have:
                b = self._builtin(product_id, key)
                if b is not None:
                    items.append(b)
        return sorted(items, key=lambda t: t.key)

    def get_template(self, principal: Principal, product_id: str, key: str) -> Template:
        self.authz.require(principal, "notify:manage", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            t = self._load_template(tx, product_id, key)
        if t is None:
            raise NotFound("template not found")
        return t

    def create_template(
        self,
        principal: Principal,
        product_id: str,
        *,
        key: str,
        variants: dict[str, Any],
        channel: str = "email",
        category: str = "transactional",
        name: str = "",
        description: str = "",
        variables: list[str] | None = None,
        sample_data: dict[str, Any] | None = None,
        sensitive: bool = False,
    ) -> Template:
        self.authz.require(principal, "notify:manage", product_id)
        if not _KEY.match(key):
            raise ValidationFailed("key must be 2-63 lowercase letters, digits, '.', '_' or '-'")
        data = self._validate_template(
            {
                "channel": channel,
                "category": category,
                "name": name,
                "description": description,
                "variables": variables or [],
                "sample_data": sample_data or {},
                "variants": variants,
                "sensitive": sensitive,
            }
        )
        tid = new_id("tpl")
        try:
            with self.db.transaction(DbScope.product(product_id)) as tx:
                tx.execute(
                    "INSERT INTO axentra_notify_templates (id, product_id, key, channel, category, name, description,"
                    " variables, sample_data, variants, sensitive, created_by, updated_by)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        tid,
                        product_id,
                        key,
                        data["channel"],
                        data["category"],
                        data["name"],
                        data["description"],
                        data["variables"],
                        Jsonb(data["sample_data"]),
                        Jsonb(data["variants"]),
                        data["sensitive"],
                        principal.actor.id,
                        principal.actor.id,
                    ),
                )
                self.audit.record(
                    tx,
                    principal,
                    "notify.template.create",
                    target_type="notify_template",
                    target_id=tid,
                    product_id=product_id,
                    details={"key": key, "locales": sorted(data["variants"])},
                )
                row = tx.one_or_404("SELECT * FROM axentra_notify_templates WHERE id = %s", (tid,))
        except pg_errors.UniqueViolation:
            raise Conflict("a template with this key exists") from None
        return self._template(row)

    def update_template(
        self,
        principal: Principal,
        product_id: str,
        key: str,
        changes: dict[str, Any],
        *,
        if_match: int | None = None,
    ) -> Template:
        self.authz.require(principal, "notify:manage", product_id)
        unknown = set(changes) - set(_TEMPLATE_FIELDS)
        if unknown:
            raise ValidationFailed(f"unknown template fields: {', '.join(sorted(unknown))}")
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one(
                "SELECT * FROM axentra_notify_templates WHERE product_id = %s AND key = %s FOR UPDATE",
                (product_id, key),
            )
            if row is None:
                raise NotFound(
                    "template not found"
                    + (
                        " (built-in defaults are overridden by creating a template with this key)"
                        if key in BUILTIN_TEMPLATES
                        else ""
                    )
                )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the template was changed by someone else")
            merged = {f: row[f] for f in _TEMPLATE_FIELDS}
            merged.update({k: v for k, v in changes.items() if v is not None})
            data = self._validate_template(merged)
            tx.execute(
                "UPDATE axentra_notify_templates SET channel = %s, category = %s, name = %s, description = %s,"
                " variables = %s, sample_data = %s, variants = %s, sensitive = %s, updated_by = %s,"
                " version = version + 1, updated_at = now() WHERE id = %s",
                (
                    data["channel"],
                    data["category"],
                    data["name"],
                    data["description"],
                    data["variables"],
                    Jsonb(data["sample_data"]),
                    Jsonb(data["variants"]),
                    data["sensitive"],
                    principal.actor.id,
                    row["id"],
                ),
            )
            self.audit.record(
                tx,
                principal,
                "notify.template.update",
                target_type="notify_template",
                target_id=row["id"],
                product_id=product_id,
                details={"key": key, "fields": sorted(k for k, v in changes.items() if v is not None)},
            )
            row = tx.one_or_404("SELECT * FROM axentra_notify_templates WHERE id = %s", (row["id"],))
        return self._template(row)

    def delete_template(
        self, principal: Principal, product_id: str, key: str, *, if_match: int | None = None
    ) -> None:
        self.authz.require(principal, "notify:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one(
                "SELECT id, version FROM axentra_notify_templates WHERE product_id = %s AND key = %s FOR UPDATE",
                (product_id, key),
            )
            if row is None:
                raise NotFound("template not found")
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the template was changed by someone else")
            tx.execute("DELETE FROM axentra_notify_templates WHERE id = %s", (row["id"],))
            self.audit.record(
                tx,
                principal,
                "notify.template.delete",
                target_type="notify_template",
                target_id=row["id"],
                product_id=product_id,
                details={"key": key},
            )

    @staticmethod
    def _preview(template: Template, locale: str | None, variables: dict[str, Any] | None) -> RenderedContent:
        values = {**template.sample_data, **check_variables(variables or {})}
        r = render_variant({k: v.model_dump() for k, v in template.variants.items()}, locale, values)
        return RenderedContent(locale=r.locale, subject=r.subject, text=r.text, html=r.html)

    def preview(
        self,
        principal: Principal,
        product_id: str,
        key: str,
        *,
        locale: str | None = None,
        variables: dict[str, Any] | None = None,
    ) -> RenderedContent:
        """Render a stored (or built-in) template with its sample data, overridden by ``variables``."""
        return self._preview(self.get_template(principal, product_id, key), locale, variables)

    def preview_draft(
        self,
        principal: Principal,
        product_id: str,
        *,
        variants: dict[str, Any],
        variables: list[str] | None = None,
        sample_data: dict[str, Any] | None = None,
        locale: str | None = None,
        values: dict[str, Any] | None = None,
    ) -> RenderedContent:
        """Validate and render an unsaved template (editor preview)."""
        self.authz.require(principal, "notify:manage", product_id)
        data = self._validate_template(
            {
                "channel": "email",
                "category": "transactional",
                "name": "",
                "description": "",
                "variables": variables or [],
                "sample_data": sample_data or {},
                "variants": variants,
                "sensitive": False,
            }
        )
        tpl = Template.model_validate(
            {**data, "id": None, "product_id": product_id, "key": "draft", "version": 0, "builtin": False}
        )
        return self._preview(tpl, locale, values)

    # -- messages ----------------------------------------------------------------------------------

    def _message(self, row: Row, *, with_content: bool = False) -> Message:
        mid = row["id"]
        if row["subject_enc"] is None:
            state = "purged" if row["content_purged_at"] else "none"
        elif row["sensitive"]:
            state = "redacted"
        else:
            state = "available"
        subject: str | None = None
        content: MessageContent | None = None
        if state == "available":
            try:
                subject = self.secrets.decrypt(
                    row["subject_enc"], _ctx("axentra_notify_messages", mid, "subject")
                )
                if with_content:
                    content = MessageContent(
                        subject=subject,
                        text=self.secrets.decrypt(
                            row["body_text_enc"], _ctx("axentra_notify_messages", mid, "text")
                        ),
                        html=self.secrets.decrypt(
                            row["body_html_enc"], _ctx("axentra_notify_messages", mid, "html")
                        )
                        if row["body_html_enc"]
                        else None,
                    )
            except (ValueError, ConfigurationError):
                # e.g. the encryption key was removed from the keyring.
                state, subject, content = "purged", None, None
            except Exception:
                logger.warning("cannot decrypt notification message %s", mid)
                state, subject, content = "purged", None, None
        return Message.model_validate(
            {
                **row,
                "next_attempt_at": row["next_attempt_at"] if row["status"] == "queued" else None,
                "subject": subject,
                "content_state": state,
                "content": content,
            }
        )

    @staticmethod
    def _request_hash(payload: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    def send(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        template_key: str,
        to_user_id: str | None = None,
        to_email: str | None = None,
        variables: dict[str, Any] | None = None,
        locale: str | None = None,
        idempotency_key: str | None = None,
    ) -> SendResult:
        """Render and enqueue one notification for a tenant (permission ``notify:send``)."""
        self.authz.require(principal, "notify:send", product_id, tenant_id)
        return self._enqueue(
            principal,
            product_id,
            tenant_id,
            template_key=template_key,
            to_user_id=to_user_id,
            to_email=to_email,
            variables=variables,
            locale=locale,
            idempotency_key=idempotency_key,
            restrict_users=True,
        )

    def enqueue_system(
        self,
        product_id: str,
        tenant_id: str | None,
        *,
        template_key: str,
        to_user_id: str | None = None,
        to_email: str | None = None,
        variables: dict[str, Any] | None = None,
        locale: str | None = None,
        idempotency_key: str | None = None,
        fallback_locale: str | None = None,
        reason: str = "notify",
    ) -> SendResult:
        """Enqueue from trusted in-process code (hooks, job handlers); no permission check."""
        return self._enqueue(
            Principal.system(reason),
            product_id,
            tenant_id,
            template_key=template_key,
            to_user_id=to_user_id,
            to_email=to_email,
            variables=variables,
            locale=locale,
            idempotency_key=idempotency_key,
            restrict_users=False,
            fallback_locale=fallback_locale,
        )

    def _enqueue(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str | None,
        *,
        template_key: str,
        to_user_id: str | None,
        to_email: str | None,
        variables: dict[str, Any] | None,
        locale: str | None,
        idempotency_key: str | None,
        restrict_users: bool,
        fallback_locale: str | None = None,
    ) -> SendResult:
        if (to_user_id is None) == (to_email is None):
            raise ValidationFailed("give exactly one recipient: user_id or email")
        if idempotency_key is not None and not _IDEMPOTENCY_KEY.match(idempotency_key):
            raise ValidationFailed("Idempotency-Key must be 1-200 printable ASCII characters")
        if locale is not None and (
            len(locale) > 20 or not re.fullmatch(r"[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8})?", locale)
        ):
            raise ValidationFailed("invalid locale")
        values = check_variables(variables or {})
        email = normalize_email(to_email) if to_email is not None else None
        if email is not None and any(c in email for c in "\r\n<>,;\"'()"):
            raise ValidationFailed("invalid email address")
        request_hash = self._request_hash(
            {
                "tenant_id": tenant_id,
                "template_key": template_key,
                "to_user_id": to_user_id,
                "to_email": email,
                "variables": values,
                "locale": locale,
            }
        )
        if idempotency_key is not None:
            replay = self._replay(product_id, tenant_id, idempotency_key, request_hash)
            if replay is not None:
                return replay
        scope = DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)
        mid = new_id("msg")
        try:
            with self.db.transaction(scope) as tx:
                template = self._load_template(tx, product_id, template_key)
                if template is None:
                    raise NotFound("template not found")
                if template.channel != "email":
                    raise ValidationFailed("only email templates can be sent")
                user_locale: str | None = None
                user_id: str | None = None
                if to_user_id is not None:
                    user = tx.one(
                        "SELECT id, email, locale, status FROM axentra_users WHERE id = %s", (to_user_id,)
                    )
                    if (
                        user is not None
                        and restrict_users
                        and not self._user_in_scope(tx, product_id, tenant_id, to_user_id)
                    ):
                        user = None
                    if user is None:
                        raise NotFound("recipient not found")
                    if user["status"] != "active":
                        raise ValidationFailed("the recipient user is disabled")
                    email, user_locale, user_id = user["email"], user["locale"], user["id"]
                    lookup_user = user_id
                else:
                    found = tx.one(
                        "SELECT id, locale FROM axentra_users WHERE lower(email) = lower(%s)", (email,)
                    )
                    lookup_user = found["id"] if found else None
                    user_locale = found["locale"] if found else None
                assert email is not None
                rendered = render_variant(
                    {k: v.model_dump() for k, v in template.variants.items()},
                    locale or user_locale or fallback_locale,
                    values,
                )
                suppressed = False
                if lookup_user is not None and template.category not in LOCKED_CATEGORIES:
                    suppressed = bool(
                        tx.scalar(
                            "SELECT EXISTS (SELECT 1 FROM axentra_notify_preferences WHERE product_id = %s"
                            " AND user_id = %s AND (tenant_id IS NULL OR tenant_id = %s) AND %s = ANY(opted_out))",
                            (product_id, lookup_user, tenant_id, template.category),
                        )
                    )
                status = "suppressed" if suppressed else "queued"
                enc = (
                    (None, None, None)
                    if suppressed
                    else (
                        self.secrets.encrypt(
                            rendered.subject, _ctx("axentra_notify_messages", mid, "subject")
                        ),
                        self.secrets.encrypt(rendered.text, _ctx("axentra_notify_messages", mid, "text")),
                        self.secrets.encrypt(rendered.html, _ctx("axentra_notify_messages", mid, "html"))
                        if rendered.html
                        else None,
                    )
                )
                tx.execute(
                    "INSERT INTO axentra_notify_messages (id, product_id, tenant_id, template_key, template_version,"
                    " channel, category, recipient, recipient_user_id, locale, subject_enc, body_text_enc,"
                    " body_html_enc, sensitive, status, max_attempts, idempotency_key, request_hash, created_by,"
                    " last_error) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                    " %s, %s)",
                    (
                        mid,
                        product_id,
                        tenant_id,
                        template.key,
                        template.version,
                        template.channel,
                        template.category,
                        email,
                        user_id,
                        rendered.locale,
                        *enc,
                        template.sensitive,
                        status,
                        self.settings.notify.max_attempts,
                        idempotency_key,
                        request_hash,
                        principal.actor.id,
                        f"recipient opted out of category {template.category}" if suppressed else None,
                    ),
                )
                self.audit.record(
                    tx,
                    principal,
                    "notify.message.enqueue",
                    target_type="notify_message",
                    target_id=mid,
                    product_id=product_id,
                    tenant_id=tenant_id,
                    details={"template_key": template.key, "status": status, "category": template.category},
                )
                row = tx.one_or_404("SELECT * FROM axentra_notify_messages WHERE id = %s", (mid,))
        except pg_errors.UniqueViolation:
            # A concurrent request with the same Idempotency-Key won the race.
            if idempotency_key is None:
                raise
            replay = self._replay(product_id, tenant_id, idempotency_key, request_hash)
            if replay is None:
                raise Conflict("Idempotency-Key conflict") from None
            return replay
        if self._enqueued is not None:
            self._enqueued.inc(status=status)
        return SendResult(message=self._message(row), replayed=False)

    def _replay(
        self, product_id: str, tenant_id: str | None, key: str, request_hash: str
    ) -> SendResult | None:
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one(
                "SELECT * FROM axentra_notify_messages WHERE product_id = %s AND idempotency_key = %s",
                (product_id, key),
            )
        if row is None:
            return None
        if row["request_hash"] != request_hash or row["tenant_id"] != tenant_id:
            raise Conflict("the Idempotency-Key was already used for a different request")
        return SendResult(message=self._message(row), replayed=True)

    @staticmethod
    def _user_in_scope(tx: Tx, product_id: str, tenant_id: str | None, user_id: str) -> bool:
        if tenant_id and tx.one(
            "SELECT 1 FROM axentra_memberships WHERE product_id = %s AND tenant_id = %s AND user_id = %s",
            (product_id, tenant_id, user_id),
        ):
            return True
        return bool(
            tx.one(
                "SELECT 1 FROM axentra_product_members WHERE product_id = %s AND user_id = %s",
                (product_id, user_id),
            )
        )

    def _authorize_message_access(self, principal: Principal, product_id: str, tenant_id: str | None) -> None:
        if self.authz.has(principal, "notify:manage", product_id):
            return
        if tenant_id is not None and self.authz.has(principal, "notify:send", product_id, tenant_id):
            return
        self.authz.grant(principal, product_id)  # NotFound for unrelated callers
        raise NotFound("message not found")

    def list_messages(
        self,
        principal: Principal,
        product_id: str,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        template_key: str | None = None,
        recipient: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Message]:
        """All messages (``notify:manage``) or those of one tenant (``notify:manage`` or ``notify:send``)."""
        if tenant_id is None or self.authz.has(principal, "notify:manage", product_id):
            self.authz.require(principal, "notify:manage", product_id)
        else:
            self.authz.require(principal, "notify:send", product_id, tenant_id)
        limit = clamp_limit(limit)
        where = ["product_id = %s"]
        params: list[Any] = [product_id]
        if tenant_id:
            where.append("tenant_id = %s")
            params.append(tenant_id)
        if status:
            where.append("status = %s")
            params.append(status)
        if template_key:
            where.append("template_key = %s")
            params.append(template_key)
        if recipient:
            where.append("lower(recipient) = lower(%s)")
            params.append(recipient.strip())
        if since:
            where.append("created_at >= %s")
            params.append(since)
        after = decode_cursor(cursor)
        if after:
            where.append("(created_at, id) < (%s::timestamptz, %s)")
            params += [after[0], after[1]]
        params.append(limit + 1)
        scope = DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)
        with self.db.transaction(scope, read_only=True) as tx:
            rows = tx.all(
                "SELECT * FROM axentra_notify_messages WHERE "
                + " AND ".join(where)
                + " ORDER BY created_at DESC, id DESC LIMIT %s",
                params,
            )
        items = [self._message(r) for r in rows[:limit]]
        nxt = encode_cursor([items[-1].created_at.isoformat(), items[-1].id]) if len(rows) > limit else None
        return Page[Message](items=items, next_cursor=nxt)

    def _get_row(self, principal: Principal, product_id: str, message_id: str) -> Row:
        self.authz.grant(principal, product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one(
                "SELECT * FROM axentra_notify_messages WHERE id = %s AND product_id = %s",
                (message_id, product_id),
            )
        if row is None:
            raise NotFound("message not found")
        self._authorize_message_access(principal, product_id, row["tenant_id"])
        return row

    def get_message(self, principal: Principal, product_id: str, message_id: str) -> Message:
        return self._message(self._get_row(principal, product_id, message_id), with_content=True)

    def retry_message(self, principal: Principal, product_id: str, message_id: str) -> Message:
        row = self._get_row(principal, product_id, message_id)
        scope = (
            DbScope.tenant(product_id, row["tenant_id"]) if row["tenant_id"] else DbScope.product(product_id)
        )
        with self.db.transaction(scope) as tx:
            cur = tx.one(
                "SELECT status, subject_enc FROM axentra_notify_messages WHERE id = %s FOR UPDATE",
                (message_id,),
            )
            if cur is None:
                raise NotFound("message not found")
            if cur["status"] != "failed":
                raise Conflict("only failed messages can be retried")
            if cur["subject_enc"] is None:
                raise Conflict("the message content was erased (retention); send it again")
            tx.execute(
                "UPDATE axentra_notify_messages SET status = 'queued', attempts = 0, next_attempt_at = now(),"
                " lease_until = NULL, claim_token = NULL, updated_at = now() WHERE id = %s",
                (message_id,),
            )
            self.audit.record(
                tx,
                principal,
                "notify.message.retry",
                target_type="notify_message",
                target_id=message_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
            )
            new = tx.one_or_404("SELECT * FROM axentra_notify_messages WHERE id = %s", (message_id,))
        return self._message(new, with_content=True)

    # -- local mailbox ------------------------------------------------------------------------------

    def list_mailbox(
        self,
        principal: Principal,
        product_id: str,
        *,
        recipient: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[MailboxEntry]:
        self.authz.require(principal, "notify:manage", product_id)
        if self.settings.notify.provider != "local":
            raise ModeNotSupported("the mailbox exists only with notify.provider = 'local'")
        limit = clamp_limit(limit)
        where = ["product_id = %s"]
        params: list[Any] = [product_id]
        if recipient:
            where.append("lower(recipient) = lower(%s)")
            params.append(recipient.strip())
        after = decode_cursor(cursor)
        if after:
            where.append("(created_at, id) < (%s::timestamptz, %s)")
            params += [after[0], after[1]]
        params.append(limit + 1)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT * FROM axentra_notify_mailbox WHERE "
                + " AND ".join(where)
                + " ORDER BY created_at DESC, id DESC LIMIT %s",
                params,
            )
        items = []
        for r in rows[:limit]:
            ctx = f"axentra_notify_mailbox|{r['id']}"
            try:
                items.append(
                    MailboxEntry.model_validate(
                        {
                            **r,
                            "subject": self.secrets.decrypt(r["subject_enc"], ctx + "|subject"),
                            "text": self.secrets.decrypt(r["body_text_enc"], ctx + "|text"),
                            "html": self.secrets.decrypt(r["body_html_enc"], ctx + "|html")
                            if r["body_html_enc"]
                            else None,
                        }
                    )
                )
            except Exception:
                logger.warning("cannot decrypt mailbox entry %s", r["id"])
        nxt = (
            encode_cursor([rows[limit - 1]["created_at"].isoformat(), rows[limit - 1]["id"]])
            if len(rows) > limit
            else None
        )
        return Page[MailboxEntry](items=items, next_cursor=nxt)

    # -- preferences ------------------------------------------------------------------------------

    def _pref_user(self, principal: Principal, product_id: str, tenant_id: str | None) -> str:
        if tenant_id is None:
            self.authz.grant(principal, product_id)  # any relation to the product
        else:
            self.authz.require(principal, "notify:preferences", product_id, tenant_id)
        if principal.actor.kind is not ActorKind.USER or principal.user_id is None:
            raise Forbidden("only users have notification preferences")
        return principal.user_id

    def _categories(self, tx: Tx, product_id: str) -> list[str]:
        cats = {
            r["category"]
            for r in tx.all(
                "SELECT DISTINCT category FROM axentra_notify_templates WHERE product_id = %s", (product_id,)
            )
        }
        cats |= {str(t["category"]) for t in BUILTIN_TEMPLATES.values()}
        return sorted(cats - LOCKED_CATEGORIES)

    def _prefs_row(
        self, tx: Tx, product_id: str, tenant_id: str | None, user_id: str, *, lock: bool = False
    ) -> Row | None:
        return tx.one(
            "SELECT * FROM axentra_notify_preferences WHERE product_id = %s AND user_id = %s"
            " AND coalesce(tenant_id, '') = %s" + (" FOR UPDATE" if lock else ""),
            (product_id, user_id, tenant_id or ""),
        )

    def get_preferences(
        self, principal: Principal, product_id: str, tenant_id: str | None = None
    ) -> Preferences:
        user_id = self._pref_user(principal, product_id, tenant_id)
        scope = DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)
        with self.db.transaction(scope, read_only=True) as tx:
            row = self._prefs_row(tx, product_id, tenant_id, user_id)
            cats = self._categories(tx, product_id)
        return Preferences(
            product_id=product_id,
            tenant_id=tenant_id,
            user_id=user_id,
            opted_out=sorted(row["opted_out"]) if row else [],
            available_categories=cats,
            locked_categories=sorted(LOCKED_CATEGORIES),
            version=row["version"] if row else 0,
        )

    def set_preferences(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str | None,
        *,
        opted_out: list[str],
        if_match: int | None = None,
    ) -> Preferences:
        user_id = self._pref_user(principal, product_id, tenant_id)
        cats = sorted(set(opted_out))
        if len(cats) > MAX_OPT_OUTS:
            raise ValidationFailed(f"at most {MAX_OPT_OUTS} categories")
        for c in cats:
            if not _CATEGORY.match(c):
                raise ValidationFailed(f"invalid category {c!r}")
        locked = sorted(set(cats) & LOCKED_CATEGORIES)
        if locked:
            raise ValidationFailed(f"these categories cannot be opted out of: {', '.join(locked)}")
        scope = DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)
        with self.db.transaction(scope) as tx:
            row = self._prefs_row(tx, product_id, tenant_id, user_id, lock=True)
            current = row["version"] if row else 0
            if if_match is not None and current != if_match:
                raise PreconditionFailed("the preferences were changed elsewhere")
            if row is None:
                try:
                    with tx.conn.transaction():
                        tx.execute(
                            "INSERT INTO axentra_notify_preferences (id, product_id, tenant_id, user_id, opted_out)"
                            " VALUES (%s, %s, %s, %s, %s)",
                            (new_id("npf"), product_id, tenant_id, user_id, cats),
                        )
                except pg_errors.UniqueViolation:
                    raise PreconditionFailed("the preferences were changed elsewhere") from None
            else:
                tx.execute(
                    "UPDATE axentra_notify_preferences SET opted_out = %s, version = version + 1, updated_at = now()"
                    " WHERE id = %s",
                    (cats, row["id"]),
                )
            self.audit.record(
                tx,
                principal,
                "notify.preferences.update",
                target_type="user",
                target_id=user_id,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"opted_out": cats},
            )
        return self.get_preferences(principal, product_id, tenant_id)

    # -- stats & retention -----------------------------------------------------------------------

    def stats(self, principal: Principal, product_id: str, tenant_id: str | None = None) -> DeliveryStats:
        self.authz.require(principal, "notify:manage", product_id)
        cond = "product_id = %s" + (" AND tenant_id = %s" if tenant_id else "")
        params: list[Any] = [product_id] + ([tenant_id] if tenant_id else [])
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                f"SELECT status, count(*) AS n, count(*) FILTER (WHERE created_at > now() - interval '24 hours')"
                f" AS n24, coalesce(sum(attempts) FILTER (WHERE created_at > now() - interval '24 hours'), 0)"
                f" AS a24 FROM axentra_notify_messages WHERE {cond} GROUP BY status",
                params,
            )
            oldest = tx.scalar(
                f"SELECT min(created_at) FROM axentra_notify_messages WHERE {cond} AND status = 'queued'",
                params,
            )
        total = StatusCounts(**{r["status"]: r["n"] for r in rows})
        last = StatusCounts(**{r["status"]: r["n24"] for r in rows})
        return DeliveryStats(
            product_id=product_id,
            tenant_id=tenant_id,
            provider=self.settings.notify.provider,
            total=total,
            last_24h=last,
            oldest_queued_at=oldest,
            attempts_24h=int(sum(r["a24"] for r in rows)),
        )

    def purge_retention(self) -> dict[str, int]:
        """Erase old rendered content and mailbox entries; delete old finished messages."""
        n = self.settings.notify
        with self.db.transaction(DbScope.platform()) as tx:
            erased = tx.execute(
                "UPDATE axentra_notify_messages SET subject_enc = NULL, body_text_enc = NULL, body_html_enc = NULL,"
                " content_purged_at = now(), updated_at = now() WHERE subject_enc IS NOT NULL"
                " AND status IN ('sent', 'failed', 'suppressed') AND created_at < now() - make_interval(days => %s)",
                (n.content_retention_days,),
            )
            deleted = tx.execute(
                "DELETE FROM axentra_notify_messages WHERE status IN ('sent', 'failed', 'suppressed')"
                " AND created_at < now() - make_interval(days => %s)",
                (n.message_retention_days,),
            )
            mailbox = tx.execute(
                "DELETE FROM axentra_notify_mailbox WHERE created_at < now() - make_interval(days => %s)",
                (n.content_retention_days,),
            )
        return {"content_erased": erased, "messages_deleted": deleted, "mailbox_deleted": mailbox}

    # -- invitation hook -----------------------------------------------------------------------------

    def invitation_accept_url(self, product_settings: dict[str, Any], token: str) -> str:
        base = product_settings.get("invitation_accept_url")
        if not isinstance(base, str) or not base.startswith(("https://", "http://")):
            base = self.settings.security.public_url.rstrip("/") + "/accept-invitation"
        tok = quote(token, safe="")
        if "{token}" in base:
            return base.replace("{token}", tok)
        return base + ("&" if "?" in base else "?") + "token=" + tok

    def on_invitation(self, result: NewInvitation) -> None:
        """Called by the API after an invitation was created: enqueue the invitation email.

        Never raises (the invitation exists either way) and never logs the token or the link.
        Sets ``result.accept_url`` so the inviter can share the link manually.
        """
        inv = result.invitation
        try:
            with self.db.transaction(DbScope.tenant(inv.product_id, inv.tenant_id), read_only=True) as tx:
                product = tx.one_or_404(
                    "SELECT name, settings FROM axentra_products WHERE id = %s", (inv.product_id,)
                )
                tenant = tx.one_or_404("SELECT name FROM axentra_tenants WHERE id = %s", (inv.tenant_id,))
                inviter = (
                    tx.one("SELECT name, email FROM axentra_users WHERE id = %s", (inv.invited_by,))
                    if inv.invited_by
                    else None
                )
            settings = product["settings"] or {}
            url = self.invitation_accept_url(settings, result.token)
            result.accept_url = url
            default_locale = settings.get("default_locale")
            self.enqueue_system(
                inv.product_id,
                inv.tenant_id,
                template_key=INVITATION,
                to_email=inv.email,
                variables={
                    "product_name": product["name"],
                    "tenant_name": tenant["name"],
                    "inviter_name": (inviter["name"] or inviter["email"]) if inviter else product["name"],
                    "role": inv.role,
                    "accept_url": url,
                    "expires_at": inv.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
                },
                fallback_locale=default_locale
                if isinstance(default_locale, str) and len(default_locale) <= 20
                else None,
                idempotency_key=f"invitation:{inv.id}",
                reason="invitation",
            )
        except Exception as exc:
            logger.warning(
                "could not enqueue the invitation email for invitation %s (%s)", inv.id, type(exc).__name__
            )


InvitationHook = Callable[["NewInvitation"], None]
