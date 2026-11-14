"""Outgoing webhooks: endpoints, signed deliveries with retries through the job queue.

Signature: every request carries ``Axentra-Signature: t=<unix ts>,v1=<hex>`` where ``<hex>`` is
``HMAC-SHA256(secret, "<ts>.<raw body>")``. During a rotation grace period a second ``v1=`` value
signed with the previous secret follows. Receivers verify with :func:`verify_signature` (or the
same few lines in any language), reject timestamps older than a few minutes and deduplicate by
``Axentra-Event-Id`` / the ``id`` field: delivery is at-least-once.
"""

from __future__ import annotations

import builtins
from datetime import timedelta
import hashlib
import hmac
import json
import logging
import random
import time
from typing import TYPE_CHECKING, Any

from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.config.secrets import SecretBox
from axentra.config.settings import EventsSettings, Settings
from axentra.core.clock import utcnow
from axentra.core.context import Principal
from axentra.core.errors import Conflict, NotFound, PreconditionFailed, ValidationFailed
from axentra.core.ids import new_id, new_token
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.core.redaction import redact_text
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.events.events import EventService, check_pattern, type_matches
from axentra.events.http_client import HttpResult, TargetRefused, TargetUnresolvable, parse_target, post_json
from axentra.events.jobs import (
    SKIPPED_PREFIX,
    JobQueue,
    PermanentJobError,
    RetryJob,
    backoff_delay,
    job_scope,
)
from axentra.events.models import Delivery, Event, Job, NewWebhookSecret, WebhookEndpoint

if TYPE_CHECKING:
    from axentra.events.worker import JobContext

logger = logging.getLogger(__name__)

DELIVER_KIND = "axentra.webhook.deliver"
#: Time a delivery job may take beyond ``webhook_timeout_seconds`` before its lease is no longer renewed.
DELIVERY_RUNTIME_MARGIN_SECONDS = 30.0
SIGNATURE_HEADER = "Axentra-Signature"
PING_TYPE = "axentra.ping"
MAX_EVENT_TYPES = 50
MAX_GRACE_SECONDS = 7 * 86400
#: ``last_error`` of a delivery dropped because the endpoint's creator lost ``webhooks:manage``.
CREATOR_LOST_ACCESS = "endpoint creator no longer has access"


def webhook_retry_delay(attempt: int, events: EventsSettings, *, rng: random.Random | None = None) -> float:
    """Seconds to wait after failed attempt ``attempt`` (1-based) before the next delivery attempt.

    Webhooks use their own schedule (``events.webhook_backoff_base_seconds`` doubling per attempt,
    capped at ``events.webhook_backoff_max_seconds``, with the job queue's "equal jitter"), not the
    short job backoff: a receiver that is down for a while must not lose its events after minutes.
    """
    return backoff_delay(
        attempt, events.webhook_backoff_base_seconds, events.webhook_backoff_max_seconds, rng=rng
    )


def sign(secret: str, timestamp: int, body: bytes) -> str:
    msg = str(timestamp).encode() + b"." + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def signature_header(secrets: builtins.list[str], timestamp: int, body: bytes) -> str:
    return ",".join([f"t={timestamp}"] + [f"v1={sign(s, timestamp, body)}" for s in secrets])


def verify_signature(
    secret: str, header: str, body: bytes, *, tolerance_seconds: int = 300, now: float | None = None
) -> bool:
    """Receiver side: check an ``Axentra-Signature`` header against the raw request body."""
    ts: int | None = None
    sigs: list[str] = []
    for part in header.split(","):
        k, _, v = part.strip().partition("=")
        if k == "t" and v.isdigit():
            ts = int(v)
        elif k == "v1":
            sigs.append(v)
    if ts is None or not sigs:
        return False
    if abs((now if now is not None else time.time()) - ts) > tolerance_seconds:
        return False
    expected = sign(secret, ts, body)
    return any(hmac.compare_digest(expected, s) for s in sigs)


def _context(endpoint_id: str) -> str:
    return f"axentra_webhook_endpoints:{endpoint_id}:secret"


def _endpoint(row: Row) -> WebhookEndpoint:
    data = dict(row)
    data["has_previous_secret"] = bool(
        row.get("previous_secret_enc")
        and row.get("previous_secret_expires_at")
        and row["previous_secret_expires_at"] > utcnow()
    )
    return WebhookEndpoint.model_validate(data)


def _delivery(row: Row) -> Delivery:
    return Delivery.model_validate(row)


def envelope(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "type": event.type,
        "product_id": event.product_id,
        "tenant_id": event.tenant_id,
        "occurred_at": event.occurred_at.isoformat(),
        "data": event.data,
    }


class WebhookService:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        authz: Authorizer,
        audit: AuditLog,
        secrets: SecretBox,
        queue: JobQueue,
        events: EventService,
    ) -> None:
        self.db = db
        self.settings = settings
        self.authz = authz
        self.audit = audit
        self.secrets = secrets
        self.queue = queue
        events.fanouts.append(self._fan_out)
        # One attempt is bounded by webhook_timeout_seconds (http_client); the margin covers the
        # database work around it. Past that, a hung delivery stops holding its lease.
        events.jobs.register(
            DELIVER_KIND,
            self._deliver_job,
            max_runtime_seconds=settings.events.webhook_timeout_seconds + DELIVERY_RUNTIME_MARGIN_SECONDS,
        )
        events.jobs.on_skip(DELIVER_KIND, self._skipped)

    # -- validation ----------------------------------------------------------------------------

    def _check_url(self, url: str) -> str:
        parse_target(url, self.settings.events, production=self.settings.is_production)
        return url.strip()

    @staticmethod
    def _check_types(types: builtins.list[str]) -> builtins.list[str]:
        if not isinstance(types, list) or not 1 <= len(types) <= MAX_EVENT_TYPES:
            raise ValidationFailed(f"event_types needs 1-{MAX_EVENT_TYPES} type patterns (use ['*'] for all)")
        return sorted({check_pattern(t) for t in types})

    # -- CRUD ----------------------------------------------------------------------------------

    def _load(self, principal: Principal, product_id: str, endpoint_id: str, perm: str) -> Row:
        self.authz.require(principal, perm, product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            return tx.one_or_404(
                "SELECT * FROM axentra_webhook_endpoints WHERE id = %s AND product_id = %s",
                (endpoint_id, product_id),
                what="webhook",
            )

    def create(
        self,
        principal: Principal,
        product_id: str,
        *,
        url: str,
        event_types: builtins.list[str],
        description: str = "",
        tenant_id: str | None = None,
        enabled: bool = True,
    ) -> NewWebhookSecret:
        self.authz.require(principal, "webhooks:manage", product_id)
        url = self._check_url(url)
        types = self._check_types(event_types)
        if len(description) > 1000:
            raise ValidationFailed("description must be at most 1000 characters")
        wid = new_id("whk")
        secret = "whsec_" + new_token(32)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            if tenant_id and not tx.one(
                "SELECT 1 FROM axentra_tenants WHERE id = %s AND product_id = %s", (tenant_id, product_id)
            ):
                raise NotFound("tenant not found")
            tx.execute(
                "INSERT INTO axentra_webhook_endpoints (id, product_id, tenant_id, url, description, event_types,"
                " enabled, secret_enc, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    wid,
                    product_id,
                    tenant_id,
                    url,
                    description,
                    types,
                    enabled,
                    self.secrets.encrypt(secret, _context(wid)),
                    principal.actor.id,
                ),
            )
            self.audit.record(
                tx,
                principal,
                "events.webhook.create",
                target_type="webhook",
                target_id=wid,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"url": redact_text(url), "event_types": types},
            )
            row = tx.one_or_404("SELECT * FROM axentra_webhook_endpoints WHERE id = %s", (wid,))
        return NewWebhookSecret(endpoint=_endpoint(row), secret=secret)

    def _listed(self, row: Row, access: dict[str | None, bool] | None = None) -> WebhookEndpoint:
        """:func:`_endpoint` with the creator's current access (:meth:`creator_has_access`);
        ``access`` caches it per creator within one listing."""
        access = {} if access is None else access
        creator = row["created_by"]
        if creator not in access:
            access[creator] = self.creator_has_access(row["product_id"], creator)
        ep = _endpoint(row)
        ep.creator_has_access = access[creator]
        return ep

    def get(self, principal: Principal, product_id: str, endpoint_id: str) -> WebhookEndpoint:
        return self._listed(self._load(principal, product_id, endpoint_id, "webhooks:read"))

    def list(
        self, principal: Principal, product_id: str, *, limit: int | None = None, cursor: str | None = None
    ) -> Page[WebhookEndpoint]:
        self.authz.require(principal, "webhooks:read", product_id)
        n = clamp_limit(limit)
        after = decode_cursor(cursor, ("str",))
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                "SELECT * FROM axentra_webhook_endpoints WHERE product_id = %s AND id > %s ORDER BY id LIMIT %s",
                (product_id, after[0] if after else "", n + 1),
            )
        access: dict[str | None, bool] = {}
        items = [self._listed(r, access) for r in rows[:n]]
        return Page[WebhookEndpoint](
            items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > n and items else None
        )

    def update(
        self,
        principal: Principal,
        product_id: str,
        endpoint_id: str,
        *,
        changes: dict[str, Any],
        if_match: int | None = None,
    ) -> WebhookEndpoint:
        self.authz.require(principal, "webhooks:manage", product_id)
        allowed = {"url", "event_types", "description", "enabled"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValidationFailed(f"unknown fields: {', '.join(sorted(unknown))}")
        if "url" in changes:
            changes["url"] = self._check_url(changes["url"])
        if "event_types" in changes:
            changes["event_types"] = self._check_types(changes["event_types"])
        if "description" in changes and len(changes["description"]) > 1000:
            raise ValidationFailed("description must be at most 1000 characters")
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_webhook_endpoints WHERE id = %s AND product_id = %s FOR UPDATE",
                (endpoint_id, product_id),
                what="webhook",
            )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the webhook was changed by someone else")
            merged = {k: changes.get(k, row[k]) for k in allowed}
            tx.execute(
                "UPDATE axentra_webhook_endpoints SET url = %s, event_types = %s, description = %s, enabled = %s,"
                " version = version + 1, updated_at = now() WHERE id = %s",
                (
                    merged["url"],
                    merged["event_types"],
                    merged["description"],
                    bool(merged["enabled"]),
                    endpoint_id,
                ),
            )
            self.audit.record(
                tx,
                principal,
                "events.webhook.update",
                target_type="webhook",
                target_id=endpoint_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
                details={"fields": sorted(changes)},
            )
            out = tx.one_or_404("SELECT * FROM axentra_webhook_endpoints WHERE id = %s", (endpoint_id,))
        return self._listed(out)

    def delete(
        self, principal: Principal, product_id: str, endpoint_id: str, *, if_match: int | None = None
    ) -> None:
        self.authz.require(principal, "webhooks:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_webhook_endpoints WHERE id = %s AND product_id = %s FOR UPDATE",
                (endpoint_id, product_id),
                what="webhook",
            )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the webhook was changed by someone else")
            tx.execute("DELETE FROM axentra_webhook_endpoints WHERE id = %s", (endpoint_id,))
            self.audit.record(
                tx,
                principal,
                "events.webhook.delete",
                target_type="webhook",
                target_id=endpoint_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
            )

    def rotate_secret(
        self, principal: Principal, product_id: str, endpoint_id: str, *, grace_seconds: int = 0
    ) -> NewWebhookSecret:
        """New signing secret (shown once). During ``grace_seconds`` requests carry a second
        signature made with the previous secret."""
        self.authz.require(principal, "webhooks:manage", product_id)
        if not 0 <= grace_seconds <= MAX_GRACE_SECONDS:
            raise ValidationFailed(f"grace_seconds must be between 0 and {MAX_GRACE_SECONDS}")
        secret = "whsec_" + new_token(32)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_webhook_endpoints WHERE id = %s AND product_id = %s FOR UPDATE",
                (endpoint_id, product_id),
                what="webhook",
            )
            prev = row["secret_enc"] if grace_seconds else None
            prev_until = utcnow() + timedelta(seconds=grace_seconds) if grace_seconds else None
            tx.execute(
                "UPDATE axentra_webhook_endpoints SET secret_enc = %s, previous_secret_enc = %s,"
                " previous_secret_expires_at = %s, version = version + 1, updated_at = now() WHERE id = %s",
                (self.secrets.encrypt(secret, _context(endpoint_id)), prev, prev_until, endpoint_id),
            )
            self.audit.record(
                tx,
                principal,
                "events.webhook.rotate_secret",
                target_type="webhook",
                target_id=endpoint_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
                details={"grace_seconds": grace_seconds},
            )
            out = tx.one_or_404("SELECT * FROM axentra_webhook_endpoints WHERE id = %s", (endpoint_id,))
        return NewWebhookSecret(endpoint=_endpoint(out), secret=secret)

    # -- deliveries ----------------------------------------------------------------------------

    def list_deliveries(
        self,
        principal: Principal,
        product_id: str,
        endpoint_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Delivery]:
        self._load(principal, product_id, endpoint_id, "webhooks:read")
        if status is not None and status not in ("pending", "succeeded", "failed", "dead"):
            raise ValidationFailed("status must be pending, succeeded, failed or dead")
        n = clamp_limit(limit)
        sql = "SELECT * FROM axentra_webhook_deliveries WHERE product_id = %s AND endpoint_id = %s"
        params: builtins.list[Any] = [product_id, endpoint_id]
        if status:
            sql += " AND status = %s"
            params.append(status)
        after = decode_cursor(cursor, ("str",))
        if after:
            sql += " AND id < %s"
            params.append(after[0])
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(n + 1)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [_delivery(r) for r in rows[:n]]
        return Page[Delivery](
            items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > n and items else None
        )

    def get_delivery(
        self, principal: Principal, product_id: str, endpoint_id: str, delivery_id: str
    ) -> Delivery:
        self._load(principal, product_id, endpoint_id, "webhooks:read")
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_webhook_deliveries WHERE id = %s AND endpoint_id = %s AND product_id = %s",
                (delivery_id, endpoint_id, product_id),
                what="delivery",
            )
        return _delivery(row)

    def redeliver(
        self, principal: Principal, product_id: str, endpoint_id: str, delivery_id: str
    ) -> Delivery:
        """Queue the delivery again (a new job with a fresh attempt budget)."""
        self._load(principal, product_id, endpoint_id, "webhooks:manage")
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_webhook_deliveries WHERE id = %s AND endpoint_id = %s AND product_id = %s"
                " FOR UPDATE",
                (delivery_id, endpoint_id, product_id),
                what="delivery",
            )
            if row["job_id"]:
                active = tx.one(
                    "SELECT status FROM axentra_jobs WHERE id = %s AND status IN ('queued', 'running')",
                    (row["job_id"],),
                )
                if active:
                    raise Conflict("the delivery is already queued or in progress")
            job, _ = self.queue.enqueue_in_tx(
                tx,
                product_id,
                row["tenant_id"],
                DELIVER_KIND,
                {"delivery_id": delivery_id},
                max_attempts=self.settings.events.webhook_max_attempts,
                created_by=principal.actor.id,
            )
            tx.execute(
                "UPDATE axentra_webhook_deliveries SET status = 'pending', next_attempt_at = NULL, job_id = %s,"
                " updated_at = now() WHERE id = %s",
                (job.id, delivery_id),
            )
            self.audit.record(
                tx,
                principal,
                "events.webhook.redeliver",
                target_type="delivery",
                target_id=delivery_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
                details={"endpoint_id": endpoint_id},
            )
            out = tx.one_or_404("SELECT * FROM axentra_webhook_deliveries WHERE id = %s", (delivery_id,))
        return _delivery(out)

    def test(self, principal: Principal, product_id: str, endpoint_id: str) -> Delivery:
        """Send a signed ``axentra.ping`` now (synchronously, no retries) and record the delivery."""
        row = self._load(principal, product_id, endpoint_id, "webhooks:manage")
        did = new_id("dlv")
        payload = {
            "id": did,
            "type": PING_TYPE,
            "product_id": product_id,
            "tenant_id": row["tenant_id"],
            "occurred_at": utcnow().isoformat(),
            "data": {"endpoint_id": endpoint_id},
        }
        with self.db.transaction(DbScope.product(product_id)) as tx:
            tx.execute(
                "INSERT INTO axentra_webhook_deliveries (id, product_id, tenant_id, endpoint_id, event_id, event_type,"
                " payload) VALUES (%s, %s, %s, %s, NULL, %s, %s)",
                (did, product_id, row["tenant_id"], endpoint_id, PING_TYPE, Jsonb(payload)),
            )
            self.audit.record(
                tx,
                principal,
                "events.webhook.test",
                target_type="webhook",
                target_id=endpoint_id,
                product_id=product_id,
                tenant_id=row["tenant_id"],
            )
        result, error = self._send(row, did, payload)
        self._record(DbScope.product(product_id), did, result, error, final=True)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            out = tx.one_or_404("SELECT * FROM axentra_webhook_deliveries WHERE id = %s", (did,))
        return _delivery(out)

    # -- fan-out and delivery (workers) --------------------------------------------------------

    def creator_has_access(self, product_id: str, created_by: str | None) -> bool:
        """Whether the endpoint's creator could still create it: ``webhooks:manage`` in the product,
        held *now* (an API key creator is bounded by its own creator, see the authorizer). An
        endpoint whose creator lost it (removed, demoted, disabled, revoked) delivers nothing, like
        that creator's API keys. Endpoints created in process by a system caller are not bounded."""
        creator = self.authz.actor_principal(created_by)
        if creator is None:
            return True
        return self.authz.has(creator, "webhooks:manage", product_id)

    def _fan_out(self, tx: Tx, event: Event) -> None:
        if event.type.startswith("axentra."):
            return
        rows = tx.all(
            "SELECT * FROM axentra_webhook_endpoints WHERE product_id = %s AND enabled"
            " AND (tenant_id IS NULL OR tenant_id = %s) ORDER BY id",
            (event.product_id, event.tenant_id),
        )
        access: dict[str | None, bool] = {}
        for ep in rows:
            if not type_matches(event.type, ep["event_types"]):
                continue
            creator = ep["created_by"]
            if creator not in access:
                access[creator] = self.creator_has_access(event.product_id, creator)
            if not access[creator]:
                continue
            did = new_id("dlv")
            inserted = tx.one(
                "INSERT INTO axentra_webhook_deliveries (id, product_id, tenant_id, endpoint_id, event_id, event_type,"
                " payload) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (endpoint_id, event_id) WHERE event_id IS NOT NULL DO NOTHING RETURNING id",
                (
                    did,
                    event.product_id,
                    event.tenant_id,
                    ep["id"],
                    event.id,
                    event.type,
                    Jsonb(envelope(event)),
                ),
            )
            if inserted is None:
                continue
            job, _ = self.queue.enqueue_in_tx(
                tx,
                event.product_id,
                event.tenant_id,
                DELIVER_KIND,
                {"delivery_id": did},
                max_attempts=self.settings.events.webhook_max_attempts,
                idempotency_key=f"delivery:{did}",
            )
            tx.execute("UPDATE axentra_webhook_deliveries SET job_id = %s WHERE id = %s", (job.id, did))

    def _secrets_of(self, ep: Row) -> builtins.list[str]:
        out = [self.secrets.decrypt(ep["secret_enc"], _context(ep["id"]))]
        if (
            ep.get("previous_secret_enc")
            and ep.get("previous_secret_expires_at")
            and ep["previous_secret_expires_at"] > utcnow()
        ):
            out.append(self.secrets.decrypt(ep["previous_secret_enc"], _context(ep["id"])))
        return out

    def _send(
        self, ep: Row, delivery_id: str, payload: dict[str, Any]
    ) -> tuple[HttpResult | None, str | None]:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode()
        ts = int(time.time())
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Axentra-Webhooks/1",
            "Axentra-Event": str(payload.get("type", "")),
            "Axentra-Event-Id": str(payload.get("id", "")),
            "Axentra-Delivery": delivery_id,
            SIGNATURE_HEADER: signature_header(self._secrets_of(ep), ts, body),
        }
        try:
            return (
                post_json(
                    ep["url"], body, headers, self.settings.events, production=self.settings.is_production
                ),
                None,
            )
        except TargetUnresolvable as exc:
            return None, f"unresolvable: {exc.detail}"
        except TargetRefused as exc:
            return None, f"refused: {exc.detail}"
        except (OSError, ValueError) as exc:
            return None, redact_text(f"{type(exc).__name__}: {exc}")[:500]

    def _record(
        self,
        scope: DbScope,
        delivery_id: str,
        result: HttpResult | None,
        error: str | None,
        *,
        final: bool,
        next_attempt_in: float | None = None,
    ) -> str:
        ok = result is not None and 200 <= result.status < 300
        if ok:
            status = "succeeded"
        elif final:
            status = "dead"
        else:
            status = "failed"
        if result is not None and not ok and error is None:
            error = f"HTTP {result.status}"
        with self.db.transaction(scope) as tx:
            tx.execute(
                "UPDATE axentra_webhook_deliveries SET status = %s, attempts = attempts + 1, response_code = %s,"
                " response_body = %s, duration_ms = %s, last_error = %s,"
                " next_attempt_at = CASE WHEN %s::float8 IS NULL THEN NULL"
                " ELSE now() + make_interval(secs => %s::float8) END,"
                " delivered_at = CASE WHEN %s THEN now() ELSE delivered_at END, updated_at = now() WHERE id = %s",
                (
                    status,
                    result.status if result else None,
                    result.body if result else None,
                    result.duration_ms if result else None,
                    None if ok else error,
                    None if ok or final else next_attempt_in,
                    None if ok or final else next_attempt_in,
                    ok,
                    delivery_id,
                ),
            )
        return status

    def _skipped(self, job: Job, reason: str) -> None:
        """The worker did not run a delivery job (product archived or tenant suspended): the
        delivery ends as ``dead`` with the reason and can be redelivered later."""
        delivery_id = str(job.payload.get("delivery_id", ""))
        with self.db.transaction(job_scope(job.product_id, job.tenant_id)) as tx:
            tx.execute(
                "UPDATE axentra_webhook_deliveries SET status = 'dead', last_error = %s, next_attempt_at = NULL,"
                " updated_at = now() WHERE id = %s AND status IN ('pending', 'failed')",
                (f"{SKIPPED_PREFIX}{reason}", delivery_id),
            )

    def _deliver_job(self, ctx: JobContext) -> dict[str, Any]:
        delivery_id = str(ctx.job.payload.get("delivery_id", ""))
        with ctx.transaction(read_only=True) as tx:
            d = tx.one("SELECT * FROM axentra_webhook_deliveries WHERE id = %s", (delivery_id,))
            ep = (
                tx.one("SELECT * FROM axentra_webhook_endpoints WHERE id = %s", (d["endpoint_id"],))
                if d
                else None
            )
        if d is None or ep is None:
            return {"skipped": "delivery or endpoint no longer exists"}
        if not ep["enabled"]:
            self._record(ctx.scope, delivery_id, None, "endpoint disabled", final=True)
            return {"skipped": "endpoint disabled"}
        if not self.creator_has_access(ep["product_id"], ep["created_by"]):
            # Queued before the creator lost access (or redelivered since): not sent.
            self._record(ctx.scope, delivery_id, None, CREATOR_LOST_ACCESS, final=True)
            return {"skipped": CREATOR_LOST_ACCESS}
        result, error = self._send(ep, delivery_id, d["payload"])
        ok = result is not None and 200 <= result.status < 300
        refused = error is not None and error.startswith("refused:")
        final = refused or ctx.job.attempts >= ctx.job.max_attempts
        delay = None
        if not ok and not final:
            delay = webhook_retry_delay(ctx.job.attempts, self.settings.events)
        status = self._record(ctx.scope, delivery_id, result, error, final=final, next_attempt_in=delay)
        if ok:
            return {"status": result.status if result else None, "delivery_id": delivery_id}
        message = error or f"HTTP {result.status if result else '?'}"
        if refused:
            raise PermanentJobError(message)
        if status == "dead":
            raise RuntimeError(message)
        raise RetryJob(message, delay_seconds=delay)


__all__ = [
    "DELIVER_KIND",
    "SIGNATURE_HEADER",
    "WebhookService",
    "sign",
    "signature_header",
    "verify_signature",
    "webhook_retry_delay",
]
