"""Plans, prices, entitlements and tenant subscriptions; provider checkout and signed webhooks.

Axentra performs no payment processing and stores no card data (see :mod:`axentra.billing.providers`).
Every state change goes through :mod:`axentra.billing.state`, is audited in the same transaction
and, when an events module is wired, published as an outbox event in that transaction.

Webhooks resolve the product and tenant ONLY through provider ids Axentra stored itself
(checkout session id, customer id, subscription id); ids in a payload's metadata are never trusted.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

from psycopg import errors as pg_errors
from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.billing.models import (
    CheckoutSession,
    Entitlements,
    Plan,
    Price,
    Subscription,
    WebhookResult,
)
from axentra.billing.providers import (
    CheckoutRequest,
    PaymentProvider,
    build_provider,
    verify_signature,
)
from axentra.billing.state import ENTITLED, PROVIDER_STATUS, STATUSES, can_transition, check_transition
from axentra.config.settings import Settings
from axentra.core.clock import utcnow
from axentra.core.context import Principal
from axentra.core.errors import (
    Conflict,
    ModeNotSupported,
    NotFound,
    PayloadTooLarge,
    PreconditionFailed,
    ValidationFailed,
)
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.usage.periods import add_months, anchored_period

logger = logging.getLogger(__name__)

_PLAN_KEY = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")
_ENT_KEY = re.compile(r"^(feature|limit)\.[a-z][a-z0-9_.]{0,62}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_EXT_ID = re.compile(r"^[A-Za-z0-9_]{1,255}$")
MAX_PRICES = 20
MAX_ENTITLEMENTS = 200
MAX_AMOUNT_MINOR = 10**10
MAX_WEBHOOK_BYTES = 256 * 1024
WEBHOOK_PROVIDERS = ("fake", "stripe")

_SUB_SQL = (
    "SELECT s.*, p.key AS plan_key FROM axentra_billing_subscriptions s"
    " JOIN axentra_billing_plans p ON p.id = s.plan_id AND p.product_id = s.product_id"
)


def _months(interval: str | None) -> int:
    return 12 if interval == "year" else 1


def _check_entitlements(ent: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(ent, Mapping):
        raise ValidationFailed("entitlements must be an object")
    if len(ent) > MAX_ENTITLEMENTS:
        raise ValidationFailed(f"at most {MAX_ENTITLEMENTS} entitlements")
    out: dict[str, Any] = {}
    for key, value in ent.items():
        if not isinstance(key, str) or not _ENT_KEY.match(key):
            raise ValidationFailed(
                f"invalid entitlement key {str(key)[:80]!r} (use feature.<name> or limit.<meter>)"
            )
        if key.startswith("feature."):
            if not isinstance(value, bool):
                raise ValidationFailed(f"{key} must be true or false")
        else:
            if value is not None and (isinstance(value, bool) or not isinstance(value, int | float)):
                raise ValidationFailed(f"{key} must be a number or null (unlimited)")
            if value is not None and (value < 0 or value > 10**15 or value != value):
                raise ValidationFailed(f"{key} must be between 0 and 1e15")
        out[key] = value
    return out


def _check_prices(
    prices: list[Mapping[str, Any]], existing: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    if len(prices) > MAX_PRICES:
        raise ValidationFailed(f"at most {MAX_PRICES} prices per plan")
    known = {p["id"] for p in existing or []}
    out = []
    for raw in prices:
        pid = raw.get("id")
        if pid is not None and pid not in known:
            raise ValidationFailed("unknown price id")
        amount = raw.get("amount_minor")
        if not isinstance(amount, int) or isinstance(amount, bool) or not 0 <= amount <= MAX_AMOUNT_MINOR:
            raise ValidationFailed("amount_minor must be an integer between 0 and 1e10")
        currency = str(raw.get("currency", "")).upper()
        if not _CURRENCY.match(currency):
            raise ValidationFailed("currency must be a three-letter ISO 4217 code")
        interval = raw.get("interval", "month")
        if interval not in ("month", "year"):
            raise ValidationFailed("interval must be month or year")
        ppid = raw.get("provider_price_id")
        if ppid is not None and (not isinstance(ppid, str) or not _EXT_ID.match(ppid)):
            raise ValidationFailed("provider_price_id must be 1-255 letters, digits or underscores")
        out.append(
            Price(
                id=pid or new_id("prc"),
                amount_minor=amount,
                currency=currency,
                interval=interval,
                provider_price_id=ppid,
            ).model_dump()
        )
    return out


def _plan(row: Row) -> Plan:
    prices = [Price.model_validate(p) for p in row["prices"]]
    return Plan.model_validate({**row, "prices": prices, "free": all(p.amount_minor == 0 for p in prices)})


def _subscription(row: Row) -> Subscription:
    return Subscription.model_validate(row)


def _ts(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(int(value), UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _ext_id(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("id")
    return value if isinstance(value, str) and _EXT_ID.match(value) else None


class BillingService:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        authz: Authorizer,
        audit: AuditLog,
        *,
        provider: PaymentProvider | None = None,
        clock: Callable[[], datetime] = utcnow,
        events: Callable[[], Any] | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.authz = authz
        self.audit = audit
        self.clock = clock
        self.provider: PaymentProvider = provider or build_provider(settings.billing, clock=clock)
        self._events = events

    # -- helpers -------------------------------------------------------------------------------

    def _publish(
        self, tx: Tx, product_id: str, tenant_id: str | None, event_type: str, data: dict[str, Any]
    ) -> None:
        """Outbox event in the same transaction, only if an events module is wired."""
        events = self._events() if self._events is not None else None
        publish_in_tx = getattr(events, "publish_in_tx", None)
        if publish_in_tx is None:
            return
        publish_in_tx(tx, product_id, tenant_id, event_type, data)

    def _changed(
        self,
        tx: Tx,
        principal: Principal | None,
        action: str,
        row: Row,
        details: dict[str, Any],
        *,
        actor_override: tuple[str, str, str] | None = None,
    ) -> None:
        self.audit.record(
            tx,
            principal,
            f"billing.subscription.{action}",
            target_type="subscription",
            target_id=row["id"],
            product_id=row["product_id"],
            tenant_id=row["tenant_id"],
            details=details,
            actor_override=actor_override,
        )
        self._publish(
            tx,
            row["product_id"],
            row["tenant_id"],
            f"billing.subscription.{action}",
            {
                "subscription_id": row["id"],
                **{k: v for k, v in details.items() if not isinstance(v, datetime)},
            },
        )

    def _plan_row(self, tx: Tx, product_id: str, plan: str, *, active_only: bool = False) -> Row:
        col = "id" if plan.startswith("pln_") else "key"
        row = tx.one(
            f"SELECT * FROM axentra_billing_plans WHERE product_id = %s AND {col} = %s", (product_id, plan)
        )
        if row is None:
            raise NotFound("plan not found")
        if active_only and not row["active"]:
            raise Conflict("the plan is not active")
        return row

    @staticmethod
    def _pick_price(plan: Row, price_id: str | None) -> dict[str, Any] | None:
        prices: list[dict[str, Any]] = plan["prices"]
        if price_id is not None:
            for p in prices:
                if p["id"] == price_id:
                    return p
            raise ValidationFailed("the price does not belong to the plan")
        if not prices:
            return None
        if len(prices) == 1:
            return prices[0]
        raise ValidationFailed("the plan has several prices; choose one with price_id")

    def _current_row(self, tx: Tx, product_id: str, tenant_id: str, *, lock: bool = False) -> Row | None:
        sql = (
            "SELECT * FROM axentra_billing_subscriptions WHERE product_id = %s AND tenant_id = %s"
            " AND status <> 'canceled'"
        )
        row = tx.one(sql + (" FOR UPDATE" if lock else ""), (product_id, tenant_id))
        if row is None:
            return None
        return tx.one_or_404(_SUB_SQL + " WHERE s.id = %s", (row["id"],))

    def _require_current(self, tx: Tx, product_id: str, tenant_id: str, *, lock: bool = False) -> Row:
        row = self._current_row(tx, product_id, tenant_id, lock=lock)
        if row is None:
            raise NotFound("the tenant has no subscription")
        return row

    def _reload(self, tx: Tx, sub_id: str) -> Row:
        return tx.one_or_404(_SUB_SQL + " WHERE s.id = %s", (sub_id,))

    def _check_redirect(self, url: str) -> str:
        if len(url) > 2000:
            raise ValidationFailed("redirect URL is too long")
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        allowed = {o.rstrip("/") for o in self.settings.security.allowed_origins}
        allowed.add(self.settings.security.public_url.rstrip("/"))
        if parts.scheme not in ("https", "http") or origin not in allowed:
            raise ValidationFailed("redirect URLs must start with an allowed origin")
        return url

    # -- plans ---------------------------------------------------------------------------------

    def list_plans(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str | None = None,
        *,
        include_inactive: bool = True,
    ) -> list[Plan]:
        """All plans (product readers) or the active plans a tenant can choose (``tenant_id``)."""
        self.authz.require(principal, "billing:read", product_id, tenant_id)
        sql = "SELECT * FROM axentra_billing_plans WHERE product_id = %s"
        if tenant_id is not None or not include_inactive:
            sql += " AND active"
        scope = DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)
        with self.db.transaction(scope, read_only=True) as tx:
            rows = tx.all(sql + " ORDER BY key", (product_id,))
        return [_plan(r) for r in rows]

    def get_plan(self, principal: Principal, product_id: str, plan_id: str) -> Plan:
        self.authz.require(principal, "billing:read", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            return _plan(self._plan_row(tx, product_id, plan_id))

    def create_plan(
        self,
        principal: Principal,
        product_id: str,
        *,
        key: str,
        name: str,
        description: str = "",
        active: bool = True,
        trial_days: int = 0,
        prices: list[Mapping[str, Any]] | None = None,
        entitlements: Mapping[str, Any] | None = None,
    ) -> Plan:
        self.authz.require(principal, "billing:manage", product_id)
        if not _PLAN_KEY.match(key):
            raise ValidationFailed("plan key must match ^[a-z][a-z0-9_-]{0,62}$")
        if not name.strip() or len(name) > 200 or len(description) > 2000:
            raise ValidationFailed("name must be 1-200 and description at most 2000 characters")
        if not 0 <= trial_days <= 365:
            raise ValidationFailed("trial_days must be between 0 and 365")
        price_list = _check_prices(list(prices or []))
        ent = _check_entitlements(entitlements or {})
        plan_id = new_id("pln")
        try:
            with self.db.transaction(DbScope.product(product_id)) as tx:
                tx.execute(
                    "INSERT INTO axentra_billing_plans (id, product_id, key, name, description, active, trial_days,"
                    " prices, entitlements) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        plan_id,
                        product_id,
                        key,
                        name.strip(),
                        description,
                        active,
                        trial_days,
                        Jsonb(price_list),
                        Jsonb(ent),
                    ),
                )
                self.audit.record(
                    tx,
                    principal,
                    "billing.plan.create",
                    target_type="plan",
                    target_id=plan_id,
                    product_id=product_id,
                    details={"key": key, "prices": len(price_list)},
                )
                row = tx.one_or_404("SELECT * FROM axentra_billing_plans WHERE id = %s", (plan_id,))
        except pg_errors.UniqueViolation:
            raise Conflict("a plan with this key exists") from None
        return _plan(row)

    def update_plan(
        self,
        principal: Principal,
        product_id: str,
        plan_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        active: bool | None = None,
        trial_days: int | None = None,
        prices: list[Mapping[str, Any]] | None = None,
        entitlements: Mapping[str, Any] | None = None,
        if_match: int | None = None,
    ) -> Plan:
        """``prices`` replaces the list (keep an entry's ``id`` to keep it); existing subscriptions keep
        their price snapshot."""
        self.authz.require(principal, "billing:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_billing_plans WHERE id = %s AND product_id = %s FOR UPDATE",
                (plan_id, product_id),
                what="plan",
            )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the plan was changed by someone else")
            changes: dict[str, Any] = {}
            if name is not None:
                if not name.strip() or len(name) > 200:
                    raise ValidationFailed("name must be 1-200 characters")
                changes["name"] = name.strip()
            if description is not None:
                if len(description) > 2000:
                    raise ValidationFailed("description is too long")
                changes["description"] = description
            if active is not None:
                changes["active"] = active
            if trial_days is not None:
                if not 0 <= trial_days <= 365:
                    raise ValidationFailed("trial_days must be between 0 and 365")
                changes["trial_days"] = trial_days
            if prices is not None:
                changes["prices"] = Jsonb(_check_prices(list(prices), row["prices"]))
            if entitlements is not None:
                changes["entitlements"] = Jsonb(_check_entitlements(entitlements))
            if changes:
                sets = ", ".join(f"{k} = %s" for k in changes)
                tx.execute(
                    f"UPDATE axentra_billing_plans SET {sets}, version = version + 1, updated_at = now() WHERE id = %s",
                    [*changes.values(), plan_id],
                )
                self.audit.record(
                    tx,
                    principal,
                    "billing.plan.update",
                    target_type="plan",
                    target_id=plan_id,
                    product_id=product_id,
                    details={"fields": sorted(changes)},
                )
            row = tx.one_or_404("SELECT * FROM axentra_billing_plans WHERE id = %s", (plan_id,))
        return _plan(row)

    def delete_plan(
        self, principal: Principal, product_id: str, plan_id: str, *, if_match: int | None = None
    ) -> None:
        """Plans that any subscription references cannot be deleted; deactivate them instead."""
        self.authz.require(principal, "billing:manage", product_id)
        try:
            with self.db.transaction(DbScope.product(product_id)) as tx:
                row = tx.one_or_404(
                    "SELECT * FROM axentra_billing_plans WHERE id = %s AND product_id = %s FOR UPDATE",
                    (plan_id, product_id),
                    what="plan",
                )
                if if_match is not None and row["version"] != if_match:
                    raise PreconditionFailed("the plan was changed by someone else")
                if tx.one(
                    "SELECT 1 FROM axentra_billing_subscriptions WHERE product_id = %s AND plan_id = %s LIMIT 1",
                    (product_id, plan_id),
                ):
                    raise Conflict("subscriptions use this plan; deactivate it instead")
                tx.execute("DELETE FROM axentra_billing_plans WHERE id = %s", (plan_id,))
                self.audit.record(
                    tx,
                    principal,
                    "billing.plan.delete",
                    target_type="plan",
                    target_id=plan_id,
                    product_id=product_id,
                    details={"key": row["key"]},
                )
        except pg_errors.ForeignKeyViolation:
            raise Conflict("subscriptions use this plan; deactivate it instead") from None

    # -- subscriptions -------------------------------------------------------------------------

    def get_subscription(self, principal: Principal, product_id: str, tenant_id: str) -> Subscription:
        """The tenant's current subscription, else its most recent canceled one."""
        self.authz.require(principal, "billing:read", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            row = self._current_row(tx, product_id, tenant_id) or tx.one(
                _SUB_SQL
                + " WHERE s.product_id = %s AND s.tenant_id = %s ORDER BY s.created_at DESC, s.id DESC LIMIT 1",
                (product_id, tenant_id),
            )
        if row is None:
            raise NotFound("the tenant has no subscription")
        return _subscription(row)

    def list_subscriptions(
        self,
        principal: Principal,
        product_id: str,
        *,
        status: str | None = None,
        plan: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Subscription]:
        self.authz.require(principal, "billing:read", product_id)
        limit = clamp_limit(limit)
        where = ["s.product_id = %s"]
        params: list[Any] = [product_id]
        if status:
            if status not in STATUSES:
                raise ValidationFailed("unknown status")
            where.append("s.status = %s")
            params.append(status)
        if plan:
            where.append("(p.key = %s OR p.id = %s)")
            params += [plan, plan]
        after = decode_cursor(cursor, ("timestamp", "str"))
        if after:
            where.append("(s.created_at, s.id) < (%s::timestamptz, %s)")
            params += after
        params.append(limit + 1)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(
                _SUB_SQL
                + " WHERE "
                + " AND ".join(where)
                + " ORDER BY s.created_at DESC, s.id DESC LIMIT %s",
                params,
            )
        items = [_subscription(r) for r in rows[:limit]]
        nxt = encode_cursor([items[-1].created_at.isoformat(), items[-1].id]) if len(rows) > limit else None
        return Page[Subscription](items=items, next_cursor=nxt)

    def _insert_subscription(
        self,
        tx: Tx,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        plan: Row,
        price: dict[str, Any] | None,
        *,
        provider: str,
        status: str,
    ) -> Row:
        now = self.clock()
        trial_end = now + timedelta(days=plan["trial_days"]) if status == "trialing" else None
        end = trial_end or add_months(now, _months(price["interval"] if price else None))
        sub_id = new_id("sub")
        tx.execute(
            "INSERT INTO axentra_billing_subscriptions (id, product_id, tenant_id, plan_id, price, status,"
            " period_anchor, current_period_start, current_period_end, trial_end, provider)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                sub_id,
                product_id,
                tenant_id,
                plan["id"],
                Jsonb(price) if price else None,
                status,
                now,
                now,
                end,
                trial_end,
                provider,
            ),
        )
        row = self._reload(tx, sub_id)
        self._changed(
            tx, principal, "create", row, {"plan": plan["key"], "status": status, "provider": provider}
        )
        return row

    def _discard_incomplete(self, tx: Tx, principal: Principal, current: Row | None) -> None:
        if current is None:
            return
        if current["status"] != "incomplete":
            raise Conflict("the tenant already has a subscription; change its plan instead")
        tx.execute(
            "UPDATE axentra_billing_subscriptions SET status = 'canceled', canceled_at = now(),"
            " version = version + 1, updated_at = now() WHERE id = %s",
            (current["id"],),
        )
        self._changed(tx, principal, "cancel", current, {"from": "incomplete", "reason": "replaced"})

    def create_subscription(
        self, principal: Principal, product_id: str, tenant_id: str, *, plan: str, price_id: str | None = None
    ) -> Subscription:
        """Subscribe a tenant directly: free plans, or any plan with the manual provider (the operator
        collects payment outside Axentra). Paid plans with a real provider go through checkout."""
        self.authz.require(principal, "billing:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            p = self._plan_row(tx, product_id, plan, active_only=True)
            price = self._pick_price(p, price_id)
            free = price is None or price["amount_minor"] == 0
            if not free and self.provider.name != "manual":
                raise Conflict(f"paid plans need a checkout with the {self.provider.name} provider")
            self._discard_incomplete(tx, principal, self._current_row(tx, product_id, tenant_id, lock=True))
            status = "trialing" if p["trial_days"] > 0 else "active"
            try:
                row = self._insert_subscription(
                    tx, principal, product_id, tenant_id, p, price, provider="manual", status=status
                )
            except pg_errors.UniqueViolation:
                raise Conflict("the tenant already has a subscription") from None
        return _subscription(row)

    def change_plan(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        plan: str,
        price_id: str | None = None,
        if_match: int | None = None,
    ) -> Subscription:
        self.authz.require(principal, "billing:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            cur = self._require_current(tx, product_id, tenant_id, lock=True)
            if if_match is not None and cur["version"] != if_match:
                raise PreconditionFailed("the subscription was changed by someone else")
            if cur["provider"] == "stripe":
                raise ModeNotSupported(
                    "change Stripe subscriptions in Stripe (e.g. the customer portal); the webhook updates Axentra"
                )
            p = self._plan_row(tx, product_id, plan, active_only=True)
            price = self._pick_price(p, price_id)
            paid = price is not None and price["amount_minor"] > 0
            if cur["provider"] == "manual" and paid and self.provider.name != "manual":
                raise Conflict(
                    f"upgrading to a paid plan needs a checkout with the {self.provider.name} provider"
                )
            if cur["status"] == "incomplete":
                raise Conflict("the subscription is incomplete; finish or restart the checkout")
            tx.execute(
                "UPDATE axentra_billing_subscriptions SET plan_id = %s, price = %s, version = version + 1,"
                " updated_at = now() WHERE id = %s",
                (p["id"], Jsonb(price) if price else None, cur["id"]),
            )
            row = self._reload(tx, cur["id"])
            self._changed(tx, principal, "change_plan", row, {"from": cur["plan_key"], "to": p["key"]})
        return _subscription(row)

    def cancel(
        self, principal: Principal, product_id: str, tenant_id: str, *, at_period_end: bool = True
    ) -> Subscription:
        self.authz.require(principal, "billing:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            cur = self._require_current(tx, product_id, tenant_id)
        immediate = not at_period_end or cur["status"] == "incomplete"
        if cur["provider"] == self.provider.name and cur["provider_subscription_id"]:
            # Provider first (outside the transaction); its webhook confirms later.
            self.provider.cancel_subscription(cur["provider_subscription_id"], at_period_end=not immediate)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            cur = self._require_current(tx, product_id, tenant_id, lock=True)
            if immediate:
                check_transition(cur["status"], "canceled")
                tx.execute(
                    "UPDATE axentra_billing_subscriptions SET status = 'canceled', canceled_at = %s,"
                    " cancel_at_period_end = false, version = version + 1, updated_at = now() WHERE id = %s",
                    (self.clock(), cur["id"]),
                )
            else:
                tx.execute(
                    "UPDATE axentra_billing_subscriptions SET cancel_at_period_end = true, version = version + 1,"
                    " updated_at = now() WHERE id = %s",
                    (cur["id"],),
                )
            row = self._reload(tx, cur["id"])
            self._changed(
                tx, principal, "cancel", row, {"at_period_end": not immediate, "from": cur["status"]}
            )
        return _subscription(row)

    def resume(self, principal: Principal, product_id: str, tenant_id: str) -> Subscription:
        """Undo a cancellation at period end (a canceled subscription cannot be resumed)."""
        self.authz.require(principal, "billing:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            cur = self._require_current(tx, product_id, tenant_id)
        if not cur["cancel_at_period_end"]:
            return _subscription(cur)
        if cur["provider"] == self.provider.name and cur["provider_subscription_id"]:
            self.provider.resume_subscription(cur["provider_subscription_id"])
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            cur = self._require_current(tx, product_id, tenant_id, lock=True)
            tx.execute(
                "UPDATE axentra_billing_subscriptions SET cancel_at_period_end = false, version = version + 1,"
                " updated_at = now() WHERE id = %s",
                (cur["id"],),
            )
            row = self._reload(tx, cur["id"])
            self._changed(tx, principal, "resume", row, {})
        return _subscription(row)

    def set_status(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        status: str,
        *,
        if_match: int | None = None,
    ) -> Subscription:
        """Manual provider only: the operator records what happened (e.g. an invoice was not paid)."""
        self.authz.require(principal, "billing:manage", product_id, tenant_id)
        if status not in STATUSES:
            raise ValidationFailed("unknown status")
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            cur = self._require_current(tx, product_id, tenant_id, lock=True)
            if if_match is not None and cur["version"] != if_match:
                raise PreconditionFailed("the subscription was changed by someone else")
            if cur["provider"] != "manual":
                raise Conflict("the payment provider manages this subscription's status")
            check_transition(cur["status"], status)
            if status != cur["status"]:
                now = self.clock()
                trial_end = cur["trial_end"]
                if cur["status"] == "trialing" and status == "active" and trial_end and trial_end > now:
                    trial_end = now
                tx.execute(
                    "UPDATE axentra_billing_subscriptions SET status = %s, trial_end = %s, canceled_at = %s,"
                    " version = version + 1, updated_at = now() WHERE id = %s",
                    (status, trial_end, now if status == "canceled" else None, cur["id"]),
                )
                row = self._reload(tx, cur["id"])
                self._changed(tx, principal, "status", row, {"from": cur["status"], "to": status})
            else:
                row = cur
        return _subscription(row)

    def advance_periods(self, now: datetime | None = None) -> int:
        """System task for manual subscriptions: end trials, roll periods forward, apply
        cancel-at-period-end. Provider-managed subscriptions follow their webhooks instead."""
        at = now or self.clock()
        system = Principal.system("billing.advance_periods")
        changed = 0
        with self.db.transaction(DbScope.platform()) as tx:
            rows = tx.all(
                "SELECT * FROM axentra_billing_subscriptions WHERE provider = 'manual'"
                " AND status IN ('trialing', 'active', 'past_due') AND current_period_end <= %s FOR UPDATE",
                (at,),
            )
            for r in rows:
                months = _months((r["price"] or {}).get("interval"))
                if r["cancel_at_period_end"]:
                    tx.execute(
                        "UPDATE axentra_billing_subscriptions SET status = 'canceled', canceled_at = %s,"
                        " version = version + 1, updated_at = now() WHERE id = %s",
                        (r["current_period_end"], r["id"]),
                    )
                    action, details = "cancel", {"from": r["status"], "reason": "period_end"}
                else:
                    status = "active" if r["status"] == "trialing" else r["status"]
                    anchor = r["current_period_end"] if r["status"] == "trialing" else r["period_anchor"]
                    start, end = anchored_period(anchor, at, months)
                    tx.execute(
                        "UPDATE axentra_billing_subscriptions SET status = %s, period_anchor = %s,"
                        " current_period_start = %s, current_period_end = %s, version = version + 1,"
                        " updated_at = now() WHERE id = %s",
                        (status, anchor, start, end, r["id"]),
                    )
                    action, details = "renew", {"from": r["status"], "to": status}
                self._changed(tx, system, action, self._reload(tx, r["id"]), details)
                changed += 1
        return changed

    # -- checkout ------------------------------------------------------------------------------

    def create_checkout(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        plan: str,
        success_url: str,
        cancel_url: str,
        price_id: str | None = None,
    ) -> CheckoutSession:
        """Start a subscription. Free plans and the manual provider complete locally; otherwise the
        subscription is ``incomplete`` until the provider's webhook confirms the checkout."""
        self.authz.require(principal, "billing:manage", product_id, tenant_id)
        self._check_redirect(success_url)
        self._check_redirect(cancel_url)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            p = self._plan_row(tx, product_id, plan, active_only=True)
            price = self._pick_price(p, price_id)
            free = price is None or price["amount_minor"] == 0
            current = self._current_row(tx, product_id, tenant_id, lock=True)
            if self.provider.name == "manual" or free:
                self._discard_incomplete(tx, principal, current)
                status = "trialing" if p["trial_days"] > 0 else "active"
                row = self._insert_subscription(
                    tx, principal, product_id, tenant_id, p, price, provider="manual", status=status
                )
                return CheckoutSession(
                    provider="manual",
                    checkout_id=None,
                    url=None,
                    completed=True,
                    subscription=_subscription(row),
                )
            customer = None
            if current is not None:
                if current["status"] != "incomplete" or current["provider"] != self.provider.name:
                    raise Conflict("the tenant already has a subscription; change its plan instead")
                customer = current["provider_customer_id"]
                tx.execute(
                    "UPDATE axentra_billing_subscriptions SET plan_id = %s, price = %s, provider_checkout_id = NULL,"
                    " version = version + 1, updated_at = now() WHERE id = %s",
                    (p["id"], Jsonb(price), current["id"]),
                )
                sub_id = current["id"]
            else:
                sub_id = self._insert_subscription(
                    tx,
                    principal,
                    product_id,
                    tenant_id,
                    p,
                    price,
                    provider=self.provider.name,
                    status="incomplete",
                )["id"]
        assert price is not None
        result = self.provider.create_checkout(
            CheckoutRequest(
                subscription_id=sub_id,
                product_id=product_id,
                tenant_id=tenant_id,
                plan_key=p["key"],
                provider_price_id=price.get("provider_price_id"),
                trial_days=p["trial_days"],
                success_url=success_url,
                cancel_url=cancel_url,
                customer_id=customer,
            )
        )
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            tx.execute(
                "UPDATE axentra_billing_subscriptions SET provider_checkout_id = %s,"
                " provider_customer_id = COALESCE(%s, provider_customer_id), updated_at = now() WHERE id = %s",
                (result.checkout_id, result.customer_id, sub_id),
            )
            row = self._reload(tx, sub_id)
            self.audit.record(
                tx,
                principal,
                "billing.checkout.create",
                target_type="subscription",
                target_id=sub_id,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"plan": p["key"], "provider": self.provider.name, "checkout_id": result.checkout_id},
            )
        return CheckoutSession(
            provider=self.provider.name,
            checkout_id=result.checkout_id,
            url=result.url,
            completed=result.completed,
            subscription=_subscription(row),
        )

    # -- webhooks ------------------------------------------------------------------------------

    def handle_webhook(self, provider: str, payload: bytes, signature: str | None) -> WebhookResult:
        """Verify, de-duplicate and apply one provider event. Safe to receive any number of times."""
        if provider not in WEBHOOK_PROVIDERS or provider != self.provider.name:
            raise NotFound("unknown webhook provider")
        if len(payload) > MAX_WEBHOOK_BYTES:
            raise PayloadTooLarge("webhook payload is too large")
        secret = self.provider.webhook_secret()
        if not secret:
            raise NotFound("unknown webhook provider")
        verify_signature(secret, payload, signature, now=int(self.clock().timestamp()))
        try:
            event = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            raise ValidationFailed("webhook payload is not JSON") from None
        if not isinstance(event, dict):
            raise ValidationFailed("webhook payload must be an object")
        event_id = event.get("id")
        event_type = event.get("type")
        obj = (event.get("data") or {}).get("object") if isinstance(event.get("data"), dict) else None
        if not isinstance(event_id, str) or not 0 < len(event_id) <= 255 or not isinstance(event_type, str):
            raise ValidationFailed("webhook event needs id and type")
        event_type = event_type[:100]
        created = _ts(event.get("created"))
        if not isinstance(obj, dict):
            obj = {}

        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            if tx.one(
                "SELECT 1 FROM axentra_billing_webhook_events WHERE provider = %s AND event_id = %s",
                (provider, event_id),
            ):
                return WebhookResult(event_id=event_id, outcome="duplicate")
            target = self._resolve_target(tx, provider, event_type, obj)

        if target is None:
            outcome = "unmatched" if event_type in _HANDLED else "ignored"
            with self.db.transaction(DbScope.platform()) as tx:
                ins = tx.one(
                    "INSERT INTO axentra_billing_webhook_events (provider, event_id, event_type, provider_created_at,"
                    " outcome) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING event_id",
                    (provider, event_id, event_type, created, outcome),
                )
            return WebhookResult(event_id=event_id, outcome=outcome if ins else "duplicate")

        product_id, tenant_id, sub_id = target
        actor = ("system", f"billing-webhook:{provider}", provider)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            ins = tx.one(
                "INSERT INTO axentra_billing_webhook_events (provider, event_id, event_type, provider_created_at,"
                " product_id, tenant_id, subscription_id, outcome) VALUES (%s,%s,%s,%s,%s,%s,%s,'processing')"
                " ON CONFLICT DO NOTHING RETURNING event_id",
                (provider, event_id, event_type, created, product_id, tenant_id, sub_id),
            )
            if ins is None:
                return WebhookResult(event_id=event_id, outcome="duplicate")
            sub = tx.one_or_404(_SUB_SQL + " WHERE s.id = %s FOR UPDATE OF s", (sub_id,))
            outcome = self._apply_event(tx, sub, event_type, obj, created, actor)
            tx.execute(
                "UPDATE axentra_billing_webhook_events SET outcome = %s WHERE provider = %s AND event_id = %s",
                (outcome, provider, event_id),
            )
        return WebhookResult(event_id=event_id, outcome=outcome)

    def _resolve_target(
        self, tx: Tx, provider: str, event_type: str, obj: dict[str, Any]
    ) -> tuple[str, str, str] | None:
        """Find the subscription through ids Axentra stored itself (never payload metadata)."""
        row: Row | None = None
        if event_type in _CHECKOUT_EVENTS:
            cid = _ext_id(obj.get("id"))
            if cid:
                row = tx.one(
                    "SELECT id, product_id, tenant_id FROM axentra_billing_subscriptions WHERE provider = %s"
                    " AND provider_checkout_id = %s",
                    (provider, cid),
                )
        elif event_type.startswith("customer.subscription."):
            sid = _ext_id(obj.get("id"))
            if sid:
                row = tx.one(
                    "SELECT id, product_id, tenant_id FROM axentra_billing_subscriptions WHERE provider = %s"
                    " AND provider_subscription_id = %s",
                    (provider, sid),
                )
            customer = _ext_id(obj.get("customer"))
            if row is None and customer:
                # Subscription events may arrive before checkout.session.completed: match the pending
                # subscription of the customer Axentra created at checkout.
                row = tx.one(
                    "SELECT id, product_id, tenant_id FROM axentra_billing_subscriptions WHERE provider = %s"
                    " AND provider_customer_id = %s AND status = 'incomplete' AND provider_subscription_id IS NULL"
                    " ORDER BY created_at DESC LIMIT 1",
                    (provider, customer),
                )
        elif event_type.startswith("invoice."):
            sid = _ext_id(obj.get("subscription"))
            if sid is None:
                parent = obj.get("parent") if isinstance(obj.get("parent"), dict) else {}
                details = parent.get("subscription_details") if isinstance(parent, dict) else None
                sid = _ext_id(details.get("subscription")) if isinstance(details, dict) else None
            if sid:
                row = tx.one(
                    "SELECT id, product_id, tenant_id FROM axentra_billing_subscriptions WHERE provider = %s"
                    " AND provider_subscription_id = %s",
                    (provider, sid),
                )
        if row is None:
            return None
        return row["product_id"], row["tenant_id"], row["id"]

    def _apply_event(
        self,
        tx: Tx,
        sub: Row,
        event_type: str,
        obj: dict[str, Any],
        created: datetime | None,
        actor: tuple[str, str, str],
    ) -> str:
        last = sub["last_provider_event_at"]
        if created is not None and last is not None and created < last:
            return "stale"
        changes: dict[str, Any] = {}
        target = sub["status"]
        if event_type in _CHECKOUT_EVENTS:
            sid = _ext_id(obj.get("subscription"))
            customer = _ext_id(obj.get("customer"))
            if sid:
                changes["provider_subscription_id"] = sid
            if customer:
                changes["provider_customer_id"] = customer
            # A completed checkout is not a payment: with a delayed payment method (SEPA debit, ...) the
            # session completes "unpaid" and the provider reports the outcome later with
            # checkout.session.async_payment_succeeded or _failed (LD-01). Only a paid session (or one
            # that needs no payment, such as a trial) starts the subscription; otherwise it stays
            # incomplete with the provider ids recorded.
            paid = (
                event_type != "checkout.session.async_payment_failed"
                and obj.get("payment_status") in _PAID_CHECKOUT
            )
            if paid and sub["status"] == "incomplete":
                plan = tx.one_or_404(
                    "SELECT trial_days FROM axentra_billing_plans WHERE id = %s", (sub["plan_id"],)
                )
                now = created or self.clock()
                months = _months((sub["price"] or {}).get("interval"))
                if plan["trial_days"] > 0:
                    target = "trialing"
                    changes["trial_end"] = now + timedelta(days=plan["trial_days"])
                    changes["current_period_end"] = changes["trial_end"]
                else:
                    target = "active"
                    changes["current_period_end"] = add_months(now, months)
                changes["current_period_start"] = now
                changes["period_anchor"] = now
        elif event_type.startswith("customer.subscription."):
            if event_type == "customer.subscription.deleted":
                target = "canceled"
            else:
                mapped = PROVIDER_STATUS.get(str(obj.get("status")))
                if mapped is None:
                    return "ignored"
                target = mapped
            sid = _ext_id(obj.get("id"))
            if sid and sub["provider_subscription_id"] is None:
                changes["provider_subscription_id"] = sid
            item = {}
            items = obj.get("items")
            if isinstance(items, dict) and isinstance(items.get("data"), list) and items["data"]:
                item = items["data"][0] if isinstance(items["data"][0], dict) else {}
            start = _ts(obj.get("current_period_start")) or _ts(item.get("current_period_start"))
            end = _ts(obj.get("current_period_end")) or _ts(item.get("current_period_end"))
            if start and end and start < end:
                changes["current_period_start"] = start
                changes["current_period_end"] = end
                if sub["provider_subscription_id"] is None or sub["status"] == "incomplete":
                    changes["period_anchor"] = start
            if "trial_end" in obj:
                changes["trial_end"] = _ts(obj.get("trial_end"))
            if isinstance(obj.get("cancel_at_period_end"), bool):
                changes["cancel_at_period_end"] = obj["cancel_at_period_end"]
            price_ref = item.get("price") if isinstance(item.get("price"), dict) else {}
            ppid = _ext_id(price_ref.get("id")) if price_ref else None
            if ppid:
                matched = tx.one(
                    "SELECT p.id, price FROM axentra_billing_plans p, jsonb_array_elements(p.prices) price"
                    " WHERE p.product_id = %s AND price->>'provider_price_id' = %s LIMIT 1",
                    (sub["product_id"], ppid),
                )
                if matched is not None:
                    changes["plan_id"] = matched["id"]
                    changes["price"] = Jsonb(matched["price"])
        elif event_type in ("invoice.paid", "invoice.payment_succeeded"):
            if sub["status"] in ("past_due", "incomplete"):
                target = "active"
        elif event_type == "invoice.payment_failed":
            if sub["status"] in ("active", "trialing"):
                target = "past_due"
        else:
            return "ignored"
        if not can_transition(sub["status"], target):
            return "rejected_transition"
        if target != sub["status"]:
            changes["status"] = target
            if target == "canceled":
                changes["canceled_at"] = _ts(obj.get("canceled_at")) or created or self.clock()
        if created is not None:
            changes["last_provider_event_at"] = created
        if changes:
            sets = ", ".join(f"{k} = %s" for k in changes)
            try:
                tx.execute(
                    f"UPDATE axentra_billing_subscriptions SET {sets}, version = version + 1, updated_at = now()"
                    " WHERE id = %s",
                    [*changes.values(), sub["id"]],
                )
            except pg_errors.UniqueViolation:
                raise Conflict("the provider subscription is linked to another subscription") from None
            row = self._reload(tx, sub["id"])
            self._changed(
                tx,
                None,
                "webhook",
                row,
                {"event_type": event_type, "from": sub["status"], "to": row["status"]},
                actor_override=actor,
            )
        return "applied"

    # -- entitlements --------------------------------------------------------------------------

    def _entitlements_tx(self, tx: Tx, product_id: str, tenant_id: str) -> Entitlements:
        sub = tx.one(
            _SUB_SQL.replace(
                "SELECT s.*, p.key AS plan_key", "SELECT s.id, s.status, p.key AS plan_key, p.entitlements"
            )
            + " WHERE s.product_id = %s AND s.tenant_id = %s AND s.status = ANY(%s)",
            (product_id, tenant_id, sorted(ENTITLED)),
        )
        ov = tx.one(
            "SELECT entitlements FROM axentra_billing_overrides WHERE product_id = %s AND tenant_id = %s",
            (product_id, tenant_id),
        )
        overrides: dict[str, Any] = ov["entitlements"] if ov else {}
        merged = {**(sub["entitlements"] if sub else {}), **overrides}
        return Entitlements(
            product_id=product_id,
            tenant_id=tenant_id,
            plan_key=sub["plan_key"] if sub else None,
            subscription_id=sub["id"] if sub else None,
            subscription_status=sub["status"] if sub else None,
            features={k.split(".", 1)[1]: bool(v) for k, v in merged.items() if k.startswith("feature.")},
            limits={k.split(".", 1)[1]: v for k, v in merged.items() if k.startswith("limit.")},
            overrides=overrides,
        )

    def entitlements(self, product_id: str, tenant_id: str) -> Entitlements:
        """Effective features and limits (plan of an entitled subscription + per-tenant overrides).

        Trusted library call for product backends (no authorization); the API uses
        :meth:`get_entitlements`."""
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            if (
                tx.one(
                    "SELECT 1 FROM axentra_tenants WHERE id = %s AND product_id = %s", (tenant_id, product_id)
                )
                is None
            ):
                raise NotFound("tenant not found")
            return self._entitlements_tx(tx, product_id, tenant_id)

    def get_entitlements(self, principal: Principal, product_id: str, tenant_id: str) -> Entitlements:
        self.authz.require(principal, "billing:read", product_id, tenant_id)
        return self.entitlements(product_id, tenant_id)

    def set_overrides(
        self, principal: Principal, product_id: str, tenant_id: str, entitlements: Mapping[str, Any]
    ) -> Entitlements:
        """Replace the tenant's overrides (an empty object removes them)."""
        self.authz.require(principal, "billing:manage", product_id, tenant_id)
        ent = _check_entitlements(entitlements)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            if ent:
                tx.execute(
                    "INSERT INTO axentra_billing_overrides (product_id, tenant_id, entitlements, updated_by)"
                    " VALUES (%s,%s,%s,%s) ON CONFLICT (product_id, tenant_id) DO UPDATE SET"
                    " entitlements = EXCLUDED.entitlements, updated_by = EXCLUDED.updated_by,"
                    " version = axentra_billing_overrides.version + 1, updated_at = now()",
                    (product_id, tenant_id, Jsonb(ent), principal.actor.id),
                )
            else:
                tx.execute(
                    "DELETE FROM axentra_billing_overrides WHERE product_id = %s AND tenant_id = %s",
                    (product_id, tenant_id),
                )
            self.audit.record(
                tx,
                principal,
                "billing.entitlements.override",
                target_type="tenant",
                target_id=tenant_id,
                product_id=product_id,
                tenant_id=tenant_id,
                details={"keys": sorted(ent)},
            )
            return self._entitlements_tx(tx, product_id, tenant_id)

    # -- usage integration ---------------------------------------------------------------------

    def usage_policy(self) -> BillingUsagePolicy:
        return BillingUsagePolicy(self)


#: Checkout session events, matched through the checkout id Axentra stored.
_CHECKOUT_EVENTS = frozenset(
    {
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
        "checkout.session.async_payment_failed",
    }
)
#: ``payment_status`` values of a checkout session that may start the subscription.
_PAID_CHECKOUT = frozenset({"paid", "no_payment_required"})

_HANDLED = frozenset(
    {
        *_CHECKOUT_EVENTS,
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
        "invoice.payment_succeeded",
        "invoice.payment_failed",
    }
)


class BillingUsagePolicy:
    """Implements :class:`axentra.usage.UsagePolicy`: plan limits and anchored billing periods."""

    def __init__(self, billing: BillingService) -> None:
        self.billing = billing

    def plan_limits(self, tx: Tx, product_id: str, tenant_id: str) -> Mapping[str, Decimal | None] | None:
        ent = self.billing._entitlements_tx(tx, product_id, tenant_id)
        if ent.plan_key is None and not ent.limits:
            return None
        return {k: None if v is None else Decimal(str(v)) for k, v in ent.limits.items()}

    def billing_period(
        self, tx: Tx, product_id: str, tenant_id: str, at: datetime
    ) -> tuple[datetime, datetime] | None:
        row = tx.one(
            "SELECT period_anchor, price FROM axentra_billing_subscriptions WHERE product_id = %s AND tenant_id = %s"
            " AND status IN ('trialing', 'active', 'past_due')",
            (product_id, tenant_id),
        )
        if row is None:
            return None
        return anchored_period(row["period_anchor"], at, _months((row["price"] or {}).get("interval")))
