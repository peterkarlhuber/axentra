"""Generic usage metering: meters, idempotent usage events, aggregated counters, quotas, reservations.

Every write runs in a tenant-scoped transaction. Recording an event, updating its aggregates and the
quota decision happen in ONE transaction that holds a row lock on the tenant's counter row for the
meter's current period, so concurrent ``check_and_record`` calls can never overshoot a hard limit.

Default limits come from (first match wins): a per-tenant quota override, the tenant's plan
entitlements (``limit.<meter key>``, provided by the billing module through :class:`UsagePolicy`)
and the meter's ``default_limit``. Usage never imports billing; billing registers a policy at wiring
time (:meth:`UsageService.set_policy`).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
from typing import Any, Protocol

from psycopg import errors as pg_errors
from psycopg.types.json import Jsonb

from axentra.access.authorizer import Authorizer
from axentra.audit.log import AuditLog
from axentra.core.clock import utcnow
from axentra.core.context import Principal
from axentra.core.errors import (
    BackdatingNotPermitted,
    Conflict,
    NotFound,
    PreconditionFailed,
    QuotaExceeded,
    ValidationFailed,
)
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.usage.models import (
    EffectiveLimit,
    Meter,
    MeterUsage,
    QuotaStatus,
    RecordResult,
    Reservation,
    TenantMeterTotal,
    TimePoint,
    TimeSeries,
    UsageEntry,
    UsageEvent,
)
from axentra.usage.periods import day_period, period_for

_METER_KEY = re.compile(r"^[a-z][a-z0-9_.]{0,62}$")
_IDEMPOTENCY_KEY = re.compile(r"^[\x21-\x7e]{1,200}$")
MAX_QUANTITY = Decimal(10) ** 15
#: Most entries in one :meth:`UsageService.record_batch` call.
MAX_BATCH = 100
MAX_PROPERTIES_BYTES = 4096
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_BACKDATE = timedelta(days=400)
MAX_RESERVATION_TTL = 86_400
MAX_SERIES_DAYS = 400
AGGREGATIONS = ("sum", "max", "last")
RESET_PERIODS = ("none", "day", "month", "billing_period")
ENFORCEMENTS = ("hard", "soft")


class _Unset:
    def __repr__(self) -> str:
        return "UNSET"


UNSET: Any = _Unset()


class UsagePolicy(Protocol):
    """Defaults supplied by another module (billing) without usage importing it.

    Both methods receive the caller's transaction (tenant scope) and must only read through it.
    """

    def plan_limits(self, tx: Tx, product_id: str, tenant_id: str) -> Mapping[str, Decimal | None] | None:
        """Limits per meter key from the tenant's plan (``None`` value = unlimited), or ``None``."""
        ...

    def billing_period(
        self, tx: Tx, product_id: str, tenant_id: str, at: datetime
    ) -> tuple[datetime, datetime] | None:
        """The tenant's billing cycle containing ``at``, or ``None`` for calendar months."""
        ...


def _quantity(value: Any, *, positive: bool = False) -> Decimal:
    try:
        q = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValidationFailed("quantity must be a number") from None
    if not q.is_finite():
        raise ValidationFailed("quantity must be finite")
    if q < 0 or (positive and q == 0):
        raise ValidationFailed("quantity must be positive" if positive else "quantity must not be negative")
    if q > MAX_QUANTITY:
        raise ValidationFailed("quantity is too large")
    exp = q.as_tuple().exponent
    if isinstance(exp, int) and exp < -6:
        raise ValidationFailed("quantity supports at most 6 decimal places")
    return q


def _limit(value: Any) -> Decimal | None:
    return None if value is None else _quantity(value)


def _canon(q: Decimal) -> str:
    text = format(q.normalize(), "f")
    return text


def _hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _check_key(key: str) -> str:
    if not _METER_KEY.match(key):
        raise ValidationFailed("meter key must match ^[a-z][a-z0-9_.]{0,62}$")
    return key


def _check_choice(value: str, allowed: tuple[str, ...], what: str) -> str:
    if value not in allowed:
        raise ValidationFailed(f"{what} must be one of {', '.join(allowed)}")
    return value


def _check_properties(props: dict[str, Any] | None) -> dict[str, Any]:
    props = props or {}
    if not isinstance(props, dict):
        raise ValidationFailed("properties must be an object")
    if len(json.dumps(props, default=str)) > MAX_PROPERTIES_BYTES:
        raise ValidationFailed(f"properties must be at most {MAX_PROPERTIES_BYTES} bytes")
    return props


@dataclass(frozen=True, slots=True)
class _LimitContext:
    quotas: dict[str, Row]
    plan: Mapping[str, Decimal | None] | None


def _meter(row: Row) -> Meter:
    return Meter.model_validate(row)


def _event(row: Row) -> UsageEvent:
    return UsageEvent.model_validate(row)


_EVENT_SQL = (
    "SELECT e.*, m.key AS meter FROM axentra_usage_events e"
    " JOIN axentra_usage_meters m ON m.id = e.meter_id AND m.product_id = e.product_id"
)
_RES_SQL = (
    "SELECT r.*, m.key AS meter FROM axentra_usage_reservations r"
    " JOIN axentra_usage_meters m ON m.id = r.meter_id AND m.product_id = r.product_id"
)


def _value_expr(aggregation: str) -> str:
    """SQL for the new aggregate value; ``c`` is the counter row, %(q)s/%(at)s the event."""
    if aggregation == "sum":
        return "c.value + %(q)s"
    if aggregation == "max":
        return "GREATEST(c.value, %(q)s)"
    return "CASE WHEN c.last_at IS NULL OR %(at)s >= c.last_at THEN %(q)s ELSE c.value END"


class UsageService:
    def __init__(
        self,
        db: Database,
        authz: Authorizer,
        audit: AuditLog,
        *,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.db = db
        self.authz = authz
        self.audit = audit
        self.clock = clock
        self._policy: UsagePolicy | None = None

    def set_policy(self, policy: UsagePolicy | None) -> None:
        """Register the provider of plan limits and billing periods (the billing module)."""
        self._policy = policy

    # -- meters --------------------------------------------------------------------------------

    def list_meters(
        self, principal: Principal, product_id: str, *, include_inactive: bool = True
    ) -> list[Meter]:
        self.authz.require(principal, "usage:read", product_id)
        sql = "SELECT * FROM axentra_usage_meters WHERE product_id = %s"
        if not include_inactive:
            sql += " AND active"
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(sql + " ORDER BY key", (product_id,))
        return [_meter(r) for r in rows]

    def get_meter(self, principal: Principal, product_id: str, meter_id: str) -> Meter:
        self.authz.require(principal, "usage:read", product_id)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_usage_meters WHERE id = %s AND product_id = %s",
                (meter_id, product_id),
                what="meter",
            )
        return _meter(row)

    def create_meter(
        self,
        principal: Principal,
        product_id: str,
        *,
        key: str,
        name: str = "",
        unit: str = "",
        aggregation: str = "sum",
        reset_period: str = "month",
        description: str = "",
        default_limit: Any = None,
        default_enforcement: str = "hard",
    ) -> Meter:
        self.authz.require(principal, "usage:manage", product_id)
        _check_key(key)
        _check_choice(aggregation, AGGREGATIONS, "aggregation")
        _check_choice(reset_period, RESET_PERIODS, "reset_period")
        _check_choice(default_enforcement, ENFORCEMENTS, "default_enforcement")
        if len(name) > 200 or len(unit) > 40 or len(description) > 2000:
            raise ValidationFailed("name, unit or description is too long")
        limit = _limit(default_limit)
        meter_id = new_id("mtr")
        try:
            with self.db.transaction(DbScope.product(product_id)) as tx:
                tx.execute(
                    "INSERT INTO axentra_usage_meters (id, product_id, key, name, unit, aggregation, reset_period,"
                    " description, default_limit, default_enforcement) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        meter_id,
                        product_id,
                        key,
                        name.strip() or key,
                        unit,
                        aggregation,
                        reset_period,
                        description,
                        limit,
                        default_enforcement,
                    ),
                )
                self.audit.record(
                    tx,
                    principal,
                    "usage.meter.create",
                    target_type="meter",
                    target_id=meter_id,
                    product_id=product_id,
                    details={"key": key, "aggregation": aggregation, "reset_period": reset_period},
                )
                row = tx.one_or_404("SELECT * FROM axentra_usage_meters WHERE id = %s", (meter_id,))
        except pg_errors.UniqueViolation:
            raise Conflict("a meter with this key exists") from None
        return _meter(row)

    def update_meter(
        self,
        principal: Principal,
        product_id: str,
        meter_id: str,
        *,
        name: str | None = None,
        unit: str | None = None,
        description: str | None = None,
        default_limit: Any = UNSET,
        default_enforcement: str | None = None,
        active: bool | None = None,
        if_match: int | None = None,
    ) -> Meter:
        """Key, aggregation and reset period are immutable (they define the stored aggregates)."""
        self.authz.require(principal, "usage:manage", product_id)
        with self.db.transaction(DbScope.product(product_id)) as tx:
            row = tx.one_or_404(
                "SELECT * FROM axentra_usage_meters WHERE id = %s AND product_id = %s FOR UPDATE",
                (meter_id, product_id),
                what="meter",
            )
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the meter was changed by someone else")
            changes: dict[str, Any] = {}
            if name is not None:
                if not name.strip() or len(name) > 200:
                    raise ValidationFailed("name must be 1-200 characters")
                changes["name"] = name.strip()
            if unit is not None:
                if len(unit) > 40:
                    raise ValidationFailed("unit is too long")
                changes["unit"] = unit
            if description is not None:
                if len(description) > 2000:
                    raise ValidationFailed("description is too long")
                changes["description"] = description
            if default_limit is not UNSET:
                changes["default_limit"] = _limit(default_limit)
            if default_enforcement is not None:
                changes["default_enforcement"] = _check_choice(
                    default_enforcement, ENFORCEMENTS, "default_enforcement"
                )
            if active is not None:
                changes["active"] = active
            if changes:
                sets = ", ".join(f"{k} = %s" for k in changes)
                tx.execute(
                    f"UPDATE axentra_usage_meters SET {sets}, version = version + 1, updated_at = now() WHERE id = %s",
                    [*changes.values(), meter_id],
                )
                self.audit.record(
                    tx,
                    principal,
                    "usage.meter.update",
                    target_type="meter",
                    target_id=meter_id,
                    product_id=product_id,
                    details={"fields": sorted(changes)},
                )
            row = tx.one_or_404("SELECT * FROM axentra_usage_meters WHERE id = %s", (meter_id,))
        return _meter(row)

    def delete_meter(
        self, principal: Principal, product_id: str, meter_id: str, *, if_match: int | None = None
    ) -> None:
        """Only meters without recorded events can be deleted; deactivate the others."""
        self.authz.require(principal, "usage:manage", product_id)
        try:
            with self.db.transaction(DbScope.product(product_id)) as tx:
                row = tx.one_or_404(
                    "SELECT * FROM axentra_usage_meters WHERE id = %s AND product_id = %s FOR UPDATE",
                    (meter_id, product_id),
                    what="meter",
                )
                if if_match is not None and row["version"] != if_match:
                    raise PreconditionFailed("the meter was changed by someone else")
                if tx.one(
                    "SELECT 1 FROM axentra_usage_events WHERE product_id = %s AND meter_id = %s LIMIT 1",
                    (product_id, meter_id),
                ):
                    raise Conflict("the meter has recorded usage; deactivate it instead")
                tx.execute("DELETE FROM axentra_usage_meters WHERE id = %s", (meter_id,))
                self.audit.record(
                    tx,
                    principal,
                    "usage.meter.delete",
                    target_type="meter",
                    target_id=meter_id,
                    product_id=product_id,
                    details={"key": row["key"]},
                )
        except pg_errors.ForeignKeyViolation:
            raise Conflict("the meter has recorded usage; deactivate it instead") from None

    # -- internals -----------------------------------------------------------------------------

    def _meter_by_key(self, tx: Tx, product_id: str, key: str, *, active_only: bool = True) -> Row:
        row = tx.one(
            "SELECT * FROM axentra_usage_meters WHERE product_id = %s AND key = %s", (product_id, key)
        )
        if row is None:
            raise NotFound("meter not found")
        if active_only and not row["active"]:
            raise Conflict("the meter is inactive")
        return row

    def _period(
        self, tx: Tx, product_id: str, tenant_id: str, reset: str, at: datetime
    ) -> tuple[datetime, datetime | None]:
        if reset == "billing_period" and self._policy is not None:
            p = self._policy.billing_period(tx, product_id, tenant_id, at)
            if p is not None:
                return p
        return period_for(reset, at)

    def _limit_context(self, tx: Tx, product_id: str, tenant_id: str) -> _LimitContext:
        quotas = {
            r["meter_id"]: r
            for r in tx.all(
                "SELECT * FROM axentra_usage_quotas WHERE product_id = %s AND tenant_id = %s",
                (product_id, tenant_id),
            )
        }
        plan = self._policy.plan_limits(tx, product_id, tenant_id) if self._policy is not None else None
        return _LimitContext(quotas, plan)

    @staticmethod
    def _resolve_limit(meter: Row, ctx: _LimitContext) -> EffectiveLimit:
        q = ctx.quotas.get(meter["id"])
        base = {"meter": meter["key"], "period": meter["reset_period"]}
        if q is not None:
            return EffectiveLimit(
                limit=q["limit_value"], enforcement=q["enforcement"], source="quota", **base
            )
        if ctx.plan is not None and meter["key"] in ctx.plan:
            return EffectiveLimit(
                limit=ctx.plan[meter["key"]], enforcement=meter["default_enforcement"], source="plan", **base
            )
        if meter["default_limit"] is not None:
            return EffectiveLimit(
                limit=meter["default_limit"], enforcement=meter["default_enforcement"], source="meter", **base
            )
        return EffectiveLimit(limit=None, enforcement=meter["default_enforcement"], source="none", **base)

    def _reserved(
        self, tx: Tx, product_id: str, tenant_id: str, meter_id: str, period_start: datetime
    ) -> Decimal:
        value = tx.scalar(
            "SELECT COALESCE(SUM(quantity), 0) FROM axentra_usage_reservations WHERE product_id = %s"
            " AND tenant_id = %s AND meter_id = %s AND period_start = %s AND status = 'active' AND expires_at > %s",
            (product_id, tenant_id, meter_id, period_start, self.clock()),
        )
        return Decimal(value)

    def _lock_counter(
        self, tx: Tx, product_id: str, tenant_id: str, meter_id: str, start: datetime, end: datetime | None
    ) -> Row:
        tx.execute(
            "INSERT INTO axentra_usage_counters (product_id, tenant_id, meter_id, granularity, period_start,"
            " period_end) VALUES (%s, %s, %s, 'period', %s, %s) ON CONFLICT DO NOTHING",
            (product_id, tenant_id, meter_id, start, end),
        )
        return tx.one_or_404(
            "SELECT * FROM axentra_usage_counters WHERE product_id = %s AND tenant_id = %s AND meter_id = %s"
            " AND granularity = 'period' AND period_start = %s FOR UPDATE",
            (product_id, tenant_id, meter_id, start),
        )

    @staticmethod
    def _status(
        meter: Row,
        limit: EffectiveLimit,
        start: datetime,
        end: datetime | None,
        used: Decimal,
        reserved: Decimal,
    ) -> QuotaStatus:
        committed = used + reserved if meter["aggregation"] == "sum" else used
        remaining = None if limit.limit is None else max(limit.limit - committed, Decimal(0))
        return QuotaStatus(
            meter=meter["key"],
            period_start=start,
            period_end=end,
            used=used,
            reserved=reserved,
            limit=limit.limit,
            remaining=remaining,
            enforcement=limit.enforcement,
            source=limit.source,
            over_limit=limit.limit is not None and committed > limit.limit,
        )

    def _current_status(
        self, tx: Tx, product_id: str, tenant_id: str, meter: Row, at: datetime
    ) -> QuotaStatus:
        start, end = self._period(tx, product_id, tenant_id, meter["reset_period"], at)
        row = tx.one(
            "SELECT value FROM axentra_usage_counters WHERE product_id = %s AND tenant_id = %s AND meter_id = %s"
            " AND granularity = 'period' AND period_start = %s",
            (product_id, tenant_id, meter["id"], start),
        )
        used = Decimal(row["value"]) if row else Decimal(0)
        limit = self._resolve_limit(meter, self._limit_context(tx, product_id, tenant_id))
        return self._status(
            meter, limit, start, end, used, self._reserved(tx, product_id, tenant_id, meter["id"], start)
        )

    def _occurred_at(self, occurred_at: datetime | None) -> datetime:
        now = self.clock()
        if occurred_at is None:
            return now
        if occurred_at.tzinfo is None:
            raise ValidationFailed("occurred_at must include a timezone")
        occurred_at = occurred_at.astimezone(UTC)
        if occurred_at > now + MAX_FUTURE_SKEW:
            raise ValidationFailed("occurred_at is in the future")
        if occurred_at < now - MAX_BACKDATE:
            raise ValidationFailed("occurred_at is too far in the past")
        return occurred_at

    def _check_backdate(
        self, tx: Tx, principal: Principal, product_id: str, tenant_id: str, occurred_at: datetime
    ) -> None:
        """Refuse usage dated before the tenant's current billing period (the subscription cycle,
        otherwise the calendar month) unless the caller holds ``usage:manage`` on the product
        (AX2-08): tenant members may record usage, but must not change closed periods."""
        start, _ = self._period(tx, product_id, tenant_id, "billing_period", self.clock())
        if occurred_at >= start or self.authz.has(principal, "usage:manage", product_id):
            return
        raise BackdatingNotPermitted(
            "usage before the current billing period needs usage:manage on the product",
            extra={"period_start": start.isoformat()},
        )

    def _replay(self, existing: Row, request_hash: str) -> UsageEvent:
        if existing["request_hash"] != request_hash:
            raise Conflict("the idempotency key was already used with a different request")
        return _event(existing)

    def _record_tx(
        self,
        tx: Tx,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        meter: Row,
        quantity: Decimal,
        idempotency_key: str,
        occurred_at: datetime,
        request_hash: str,
        properties: dict[str, Any],
        *,
        enforce: bool,
        reservation_id: str | None = None,
        check_backdate: bool = False,
        limit_ctx: _LimitContext | None = None,
    ) -> RecordResult:
        existing = tx.one(
            _EVENT_SQL + " WHERE e.product_id = %s AND e.tenant_id = %s AND e.idempotency_key = %s",
            (product_id, tenant_id, idempotency_key),
        )
        if existing is not None:
            event = self._replay(existing, request_hash)
            m = self._meter_by_key(tx, product_id, event.meter, active_only=False)
            return RecordResult(
                event=event,
                replayed=True,
                quota=self._current_status(tx, product_id, tenant_id, m, self.clock()),
            )
        if check_backdate:
            # After the replay lookup, so a retried request stays idempotent across a period change.
            self._check_backdate(tx, principal, product_id, tenant_id, occurred_at)
        start, end = self._period(tx, product_id, tenant_id, meter["reset_period"], occurred_at)
        counter = self._lock_counter(tx, product_id, tenant_id, meter["id"], start, end)
        limit = self._resolve_limit(meter, limit_ctx or self._limit_context(tx, product_id, tenant_id))
        reserved = self._reserved(tx, product_id, tenant_id, meter["id"], start)
        used = Decimal(counter["value"])
        agg = meter["aggregation"]
        if agg == "sum":
            projected = used + reserved + quantity
        elif agg == "max":
            projected = max(used, quantity)
        else:
            projected = quantity
        if enforce and limit.enforcement == "hard" and limit.limit is not None and projected > limit.limit:
            raise QuotaExceeded(
                f"the {meter['key']} limit of this period would be exceeded",
                extra={
                    "meter": meter["key"],
                    "limit": float(limit.limit),
                    "used": float(used),
                    "reserved": float(reserved),
                    "requested": float(quantity),
                    "period_end": end.isoformat() if end else None,
                },
            )
        event_id = new_id("uev")
        inserted = tx.one(
            "INSERT INTO axentra_usage_events (id, product_id, tenant_id, meter_id, quantity, idempotency_key,"
            " request_hash, occurred_at, recorded_at, period_start, properties, reservation_id, actor_id)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (product_id, tenant_id, idempotency_key) DO NOTHING RETURNING id",
            (
                event_id,
                product_id,
                tenant_id,
                meter["id"],
                quantity,
                idempotency_key,
                request_hash,
                occurred_at,
                self.clock(),
                start,
                Jsonb(properties),
                reservation_id,
                principal.actor.id,
            ),
        )
        if inserted is None:
            # A concurrent request with the same key won the race (and has committed by now).
            existing = tx.one_or_404(
                _EVENT_SQL + " WHERE e.product_id = %s AND e.tenant_id = %s AND e.idempotency_key = %s",
                (product_id, tenant_id, idempotency_key),
            )
            event = self._replay(existing, request_hash)
            return RecordResult(
                event=event,
                replayed=True,
                quota=self._status(meter, limit, start, end, used, reserved),
            )
        params = {"q": quantity, "at": occurred_at}
        expr = _value_expr(agg)
        new_value = tx.scalar(
            f"UPDATE axentra_usage_counters AS c SET value = {expr}, event_count = c.event_count + 1,"
            " last_at = GREATEST(c.last_at, %(at)s), updated_at = now() WHERE c.product_id = %(p)s"
            " AND c.tenant_id = %(t)s AND c.meter_id = %(m)s AND c.granularity = 'period'"
            " AND c.period_start = %(s)s RETURNING c.value",
            {**params, "p": product_id, "t": tenant_id, "m": meter["id"], "s": start},
        )
        d_start, d_end = day_period(occurred_at)
        tx.execute(
            "INSERT INTO axentra_usage_counters AS c (product_id, tenant_id, meter_id, granularity, period_start,"
            " period_end, value, event_count, last_at) VALUES (%(p)s, %(t)s, %(m)s, 'day', %(s)s, %(e)s, %(q)s, 1,"
            " %(at)s) ON CONFLICT (product_id, tenant_id, meter_id, granularity, period_start) DO UPDATE SET"
            f" value = {expr}, event_count = c.event_count + 1, last_at = GREATEST(c.last_at, %(at)s),"
            " updated_at = now()",
            {**params, "p": product_id, "t": tenant_id, "m": meter["id"], "s": d_start, "e": d_end},
        )
        row = tx.one_or_404(_EVENT_SQL + " WHERE e.id = %s", (event_id,))
        return RecordResult(
            event=_event(row),
            replayed=False,
            quota=self._status(meter, limit, start, end, Decimal(new_value), reserved),
        )

    # -- recording -----------------------------------------------------------------------------

    def record(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        meter: str,
        quantity: Any,
        idempotency_key: str,
        occurred_at: datetime | None = None,
        properties: dict[str, Any] | None = None,
    ) -> RecordResult:
        """Record usage that already happened (never refused by a limit; ``quota.over_limit`` tells)."""
        return self._record(
            principal,
            product_id,
            tenant_id,
            meter,
            quantity,
            idempotency_key,
            occurred_at,
            properties,
            enforce=False,
        )

    def check_and_record(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        meter: str,
        quantity: Any,
        idempotency_key: str,
        occurred_at: datetime | None = None,
        properties: dict[str, Any] | None = None,
    ) -> RecordResult:
        """Record usage unless a hard limit would be exceeded (:class:`QuotaExceeded`, 429)."""
        return self._record(
            principal,
            product_id,
            tenant_id,
            meter,
            quantity,
            idempotency_key,
            occurred_at,
            properties,
            enforce=True,
        )

    def record_in(
        self,
        tx: Tx,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        meter: str,
        quantity: Any,
        idempotency_key: str,
        occurred_at: datetime | None = None,
        properties: dict[str, Any] | None = None,
        *,
        enforce: bool = False,
    ) -> RecordResult:
        """Record usage inside the caller's transaction (e.g. one joined with
        :func:`axentra.data.database.join`), so it commits or rolls back with the caller's changes.

        Same checks and idempotency as :meth:`record` (``enforce=True``: as
        :meth:`check_and_record`): replaying an idempotency key returns the stored event and adds
        nothing. ``tx`` must be in platform scope, the product's scope or this tenant's scope.
        Authorization is read on a separate pooled connection (committed memberships and keys)."""
        tx.require_scope(product_id, tenant_id)
        return self._record(
            principal,
            product_id,
            tenant_id,
            meter,
            quantity,
            idempotency_key,
            occurred_at,
            properties,
            enforce=enforce,
            tx=tx,
        )

    def record_batch(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        entries: Sequence[UsageEntry],
        *,
        enforce: bool = False,
        tx: Tx | None = None,
    ) -> list[RecordResult]:
        """Record several usage entries of one tenant in one transaction, all or nothing.

        Each entry behaves like :meth:`record` (``enforce=True``: like :meth:`check_and_record`)
        with its own idempotency key: a replayed key returns the stored event. The permission
        check, the meters, the quota and plan limits and the billing-period check for backdated
        entries are read once per batch instead of once per entry. With ``enforce=True`` a hard
        limit that one entry would exceed refuses the whole batch (:class:`QuotaExceeded`); the
        entries are checked in the given order, so an earlier entry counts toward a later one's
        limit. Counter rows are locked in meter order, so concurrent batches cannot deadlock.
        With ``tx`` (like :meth:`record_in`) the batch joins the caller's transaction. At most
        :data:`MAX_BATCH` entries; idempotency keys must be unique within the batch."""
        self.authz.require(principal, "usage:record", product_id, tenant_id)
        if tx is not None:
            tx.require_scope(product_id, tenant_id)
        if not entries:
            raise ValidationFailed("the batch is empty")
        if len(entries) > MAX_BATCH:
            raise ValidationFailed(f"at most {MAX_BATCH} entries per batch")
        prepared: list[tuple[str, Decimal, str, datetime, str, dict[str, Any], bool]] = []
        keys: set[str] = set()
        for i, entry in enumerate(entries):
            try:
                _check_key(entry.meter)
                q = _quantity(entry.quantity)
                if not entry.idempotency_key or not _IDEMPOTENCY_KEY.match(entry.idempotency_key):
                    raise ValidationFailed("the idempotency key must be 1-200 printable ASCII characters")
                if entry.idempotency_key in keys:
                    raise ValidationFailed("the idempotency key is used twice in the batch")
                props = _check_properties(entry.properties)
                at = self._occurred_at(entry.occurred_at)
            except ValidationFailed as exc:
                raise ValidationFailed(f"entry {i}: {exc.detail}") from None
            keys.add(entry.idempotency_key)
            request_hash = _hash(
                {
                    "meter": entry.meter,
                    "quantity": _canon(q),
                    "occurred_at": entry.occurred_at.astimezone(UTC).isoformat()
                    if entry.occurred_at
                    else None,
                    "properties": props,
                }
            )
            prepared.append(
                (
                    entry.meter,
                    q,
                    entry.idempotency_key,
                    at,
                    request_hash,
                    props,
                    entry.occurred_at is not None,
                )
            )

        def run(t: Tx) -> list[RecordResult]:
            names = sorted({p[0] for p in prepared})
            rows = {
                r["key"]: r
                for r in t.all(
                    "SELECT * FROM axentra_usage_meters WHERE product_id = %s AND key = ANY(%s)",
                    (product_id, names),
                )
            }
            for name in names:
                if name not in rows:
                    raise NotFound(f"meter not found: {name}")
                if not rows[name]["active"]:
                    raise Conflict(f"the meter is inactive: {name}")
            # Lock every counter of the batch up front, in meter order (no deadlock between batches).
            for name in names:
                m = rows[name]
                for at in sorted({p[3] for p in prepared if p[0] == name}):
                    start, end = self._period(t, product_id, tenant_id, m["reset_period"], at)
                    self._lock_counter(t, product_id, tenant_id, m["id"], start, end)
            ctx = self._limit_context(t, product_id, tenant_id)
            results: list[RecordResult] = []
            for name, q, key, at, request_hash, props, dated in prepared:
                results.append(
                    self._record_tx(
                        t,
                        principal,
                        product_id,
                        tenant_id,
                        rows[name],
                        q,
                        key,
                        at,
                        request_hash,
                        props,
                        enforce=enforce,
                        check_backdate=dated,
                        limit_ctx=ctx,
                    )
                )
            return results

        if tx is not None:
            return run(tx)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as own:
            return run(own)

    def _record(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        meter: str,
        quantity: Any,
        idempotency_key: str,
        occurred_at: datetime | None,
        properties: dict[str, Any] | None,
        *,
        enforce: bool,
        tx: Tx | None = None,
    ) -> RecordResult:
        self.authz.require(principal, "usage:record", product_id, tenant_id)
        _check_key(meter)
        q = _quantity(quantity)
        if not idempotency_key or not _IDEMPOTENCY_KEY.match(idempotency_key):
            raise ValidationFailed("the idempotency key must be 1-200 printable ASCII characters")
        props = _check_properties(properties)
        request_hash = _hash(
            {
                "meter": meter,
                "quantity": _canon(q),
                "occurred_at": occurred_at.astimezone(UTC).isoformat() if occurred_at else None,
                "properties": props,
            }
        )
        at = self._occurred_at(occurred_at)

        def run(t: Tx) -> RecordResult:
            m = self._meter_by_key(t, product_id, meter)
            return self._record_tx(
                t,
                principal,
                product_id,
                tenant_id,
                m,
                q,
                idempotency_key,
                at,
                request_hash,
                props,
                enforce=enforce,
                check_backdate=occurred_at is not None,
            )

        if tx is not None:
            return run(tx)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as own:
            return run(own)

    def list_events(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        *,
        meter: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[UsageEvent]:
        self.authz.require(principal, "usage:read", product_id, tenant_id)
        limit = clamp_limit(limit)
        where = ["e.product_id = %s", "e.tenant_id = %s"]
        params: list[Any] = [product_id, tenant_id]
        if meter:
            where.append("m.key = %s")
            params.append(meter)
        if since:
            where.append("e.occurred_at >= %s")
            params.append(since)
        if until:
            where.append("e.occurred_at < %s")
            params.append(until)
        after = decode_cursor(cursor, ("timestamp", "str"))
        if after:
            where.append("(e.occurred_at, e.id) < (%s::timestamptz, %s)")
            params += after
        sql = (
            _EVENT_SQL + " WHERE " + " AND ".join(where) + " ORDER BY e.occurred_at DESC, e.id DESC LIMIT %s"
        )
        params.append(limit + 1)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [_event(r) for r in rows[:limit]]
        nxt = encode_cursor([items[-1].occurred_at.isoformat(), items[-1].id]) if len(rows) > limit else None
        return Page[UsageEvent](items=items, next_cursor=nxt)

    # -- quotas --------------------------------------------------------------------------------

    def limits(self, principal: Principal, product_id: str, tenant_id: str) -> list[EffectiveLimit]:
        """The effective limit of every active meter for the tenant, with its source."""
        self.authz.require(principal, "usage:read", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            meters = tx.all(
                "SELECT * FROM axentra_usage_meters WHERE product_id = %s AND active ORDER BY key",
                (product_id,),
            )
            ctx = self._limit_context(tx, product_id, tenant_id)
            return [self._resolve_limit(m, ctx) for m in meters]

    def set_quota(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        meter: str,
        *,
        limit: Any,
        enforcement: str = "hard",
    ) -> EffectiveLimit:
        """Set a per-tenant override (``limit=None`` = unlimited)."""
        self.authz.require(principal, "usage:manage", product_id, tenant_id)
        value = _limit(limit)
        _check_choice(enforcement, ENFORCEMENTS, "enforcement")
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            m = self._meter_by_key(tx, product_id, meter, active_only=False)
            tx.execute(
                "INSERT INTO axentra_usage_quotas (product_id, tenant_id, meter_id, limit_value, enforcement,"
                " updated_by) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (product_id, tenant_id, meter_id)"
                " DO UPDATE SET limit_value = EXCLUDED.limit_value, enforcement = EXCLUDED.enforcement,"
                " updated_by = EXCLUDED.updated_by, version = axentra_usage_quotas.version + 1, updated_at = now()",
                (product_id, tenant_id, m["id"], value, enforcement, principal.actor.id),
            )
            self.audit.record(
                tx,
                principal,
                "usage.quota.set",
                target_type="meter",
                target_id=m["id"],
                product_id=product_id,
                tenant_id=tenant_id,
                details={
                    "meter": meter,
                    "limit": None if value is None else str(value),
                    "enforcement": enforcement,
                },
            )
            return self._resolve_limit(m, self._limit_context(tx, product_id, tenant_id))

    def delete_quota(
        self, principal: Principal, product_id: str, tenant_id: str, meter: str
    ) -> EffectiveLimit:
        """Remove the override; the plan or meter default applies again."""
        self.authz.require(principal, "usage:manage", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            m = self._meter_by_key(tx, product_id, meter, active_only=False)
            n = tx.execute(
                "DELETE FROM axentra_usage_quotas WHERE product_id = %s AND tenant_id = %s AND meter_id = %s",
                (product_id, tenant_id, m["id"]),
            )
            if n:
                self.audit.record(
                    tx,
                    principal,
                    "usage.quota.delete",
                    target_type="meter",
                    target_id=m["id"],
                    product_id=product_id,
                    tenant_id=tenant_id,
                    details={"meter": meter},
                )
            return self._resolve_limit(m, self._limit_context(tx, product_id, tenant_id))

    # -- reservations --------------------------------------------------------------------------

    def _reservation(self, row: Row) -> Reservation:
        data = dict(row)
        if data["status"] == "active" and data["expires_at"] <= self.clock():
            data["status"] = "expired"
        return Reservation.model_validate(data)

    def reserve(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        meter: str,
        quantity: Any,
        *,
        ttl_seconds: int = 300,
        idempotency_key: str | None = None,
    ) -> Reservation:
        """Hold ``quantity`` against the limit until committed, released or expired (``sum`` meters)."""
        self.authz.require(principal, "usage:record", product_id, tenant_id)
        _check_key(meter)
        q = _quantity(quantity, positive=True)
        if not 1 <= ttl_seconds <= MAX_RESERVATION_TTL:
            raise ValidationFailed(f"ttl_seconds must be between 1 and {MAX_RESERVATION_TTL}")
        if idempotency_key is not None and not _IDEMPOTENCY_KEY.match(idempotency_key):
            raise ValidationFailed("the idempotency key must be 1-200 printable ASCII characters")
        request_hash = _hash({"meter": meter, "quantity": _canon(q), "ttl": ttl_seconds})
        now = self.clock()
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            m = self._meter_by_key(tx, product_id, meter)
            if m["aggregation"] != "sum":
                raise ValidationFailed("reservations are only supported for sum meters")
            if idempotency_key is not None:
                existing = tx.one(
                    _RES_SQL + " WHERE r.product_id = %s AND r.tenant_id = %s AND r.idempotency_key = %s",
                    (product_id, tenant_id, idempotency_key),
                )
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise Conflict("the idempotency key was already used with a different request")
                    return self._reservation(existing)
            start, end = self._period(tx, product_id, tenant_id, m["reset_period"], now)
            counter = self._lock_counter(tx, product_id, tenant_id, m["id"], start, end)
            limit = self._resolve_limit(m, self._limit_context(tx, product_id, tenant_id))
            reserved = self._reserved(tx, product_id, tenant_id, m["id"], start)
            used = Decimal(counter["value"])
            if limit.enforcement == "hard" and limit.limit is not None and used + reserved + q > limit.limit:
                raise QuotaExceeded(
                    f"the {meter} limit of this period would be exceeded",
                    extra={
                        "meter": meter,
                        "limit": float(limit.limit),
                        "used": float(used),
                        "reserved": float(reserved),
                        "requested": float(q),
                    },
                )
            rid = new_id("rsv")
            inserted = tx.one(
                "INSERT INTO axentra_usage_reservations (id, product_id, tenant_id, meter_id, quantity, period_start,"
                " expires_at, idempotency_key, request_hash, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (product_id, tenant_id, idempotency_key) DO NOTHING RETURNING id",
                (
                    rid,
                    product_id,
                    tenant_id,
                    m["id"],
                    q,
                    start,
                    now + timedelta(seconds=ttl_seconds),
                    idempotency_key,
                    request_hash,
                    principal.actor.id,
                ),
            )
            if inserted is None:
                existing = tx.one_or_404(
                    _RES_SQL + " WHERE r.product_id = %s AND r.tenant_id = %s AND r.idempotency_key = %s",
                    (product_id, tenant_id, idempotency_key),
                )
                if existing["request_hash"] != request_hash:
                    raise Conflict("the idempotency key was already used with a different request")
                return self._reservation(existing)
            row = tx.one_or_404(_RES_SQL + " WHERE r.id = %s", (rid,))
        return self._reservation(row)

    def get_reservation(
        self, principal: Principal, product_id: str, tenant_id: str, reservation_id: str
    ) -> Reservation:
        self.authz.require(principal, "usage:read", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            row = tx.one_or_404(
                _RES_SQL + " WHERE r.id = %s AND r.product_id = %s AND r.tenant_id = %s",
                (reservation_id, product_id, tenant_id),
                what="reservation",
            )
        return self._reservation(row)

    def commit_reservation(
        self,
        principal: Principal,
        product_id: str,
        tenant_id: str,
        reservation_id: str,
        *,
        quantity: Any = None,
        properties: dict[str, Any] | None = None,
    ) -> RecordResult:
        """Record the actual usage (default: the reserved quantity). Committing again is idempotent."""
        self.authz.require(principal, "usage:record", product_id, tenant_id)
        props = _check_properties(properties)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            res = tx.one_or_404(
                "SELECT * FROM axentra_usage_reservations WHERE id = %s AND product_id = %s AND tenant_id = %s"
                " FOR UPDATE",
                (reservation_id, product_id, tenant_id),
                what="reservation",
            )
            q = Decimal(res["quantity"]) if quantity is None else _quantity(quantity)
            meter = tx.one_or_404("SELECT * FROM axentra_usage_meters WHERE id = %s", (res["meter_id"],))
            key = f"reservation:{reservation_id}"
            if res["status"] == "committed":
                if quantity is not None and Decimal(res["committed_quantity"]) != q:
                    raise Conflict("the reservation was already committed with a different quantity")
                existing = tx.one_or_404(_EVENT_SQL + " WHERE e.id = %s", (res["event_id"],))
                return RecordResult(
                    event=_event(existing),
                    replayed=True,
                    quota=self._current_status(tx, product_id, tenant_id, meter, self.clock()),
                )
            now = self.clock()
            if res["status"] != "active" or res["expires_at"] <= now:
                raise Conflict(
                    f"the reservation is {'expired' if res['status'] == 'active' else res['status']}"
                )
            # Mark committed first so its quantity no longer counts as reserved.
            tx.execute(
                "UPDATE axentra_usage_reservations SET status = 'committed', committed_quantity = %s,"
                " updated_at = now() WHERE id = %s",
                (q, reservation_id),
            )
            result = self._record_tx(
                tx,
                principal,
                product_id,
                tenant_id,
                meter,
                q,
                key,
                now,
                _hash({"reservation": reservation_id}),
                props,
                enforce=False,
                reservation_id=reservation_id,
            )
            tx.execute(
                "UPDATE axentra_usage_reservations SET event_id = %s WHERE id = %s",
                (result.event.id, reservation_id),
            )
            return result

    def release_reservation(
        self, principal: Principal, product_id: str, tenant_id: str, reservation_id: str
    ) -> Reservation:
        """Give the reserved quantity back. Releasing a released or expired reservation is a no-op."""
        self.authz.require(principal, "usage:record", product_id, tenant_id)
        with self.db.transaction(DbScope.tenant(product_id, tenant_id)) as tx:
            res = tx.one_or_404(
                "SELECT * FROM axentra_usage_reservations WHERE id = %s AND product_id = %s AND tenant_id = %s"
                " FOR UPDATE",
                (reservation_id, product_id, tenant_id),
                what="reservation",
            )
            if res["status"] == "committed":
                raise Conflict("the reservation is already committed")
            if res["status"] == "active":
                tx.execute(
                    "UPDATE axentra_usage_reservations SET status = 'released', updated_at = now() WHERE id = %s",
                    (reservation_id,),
                )
            row = tx.one_or_404(_RES_SQL + " WHERE r.id = %s", (reservation_id,))
        return self._reservation(row)

    def sweep_expired_reservations(self, now: datetime | None = None) -> int:
        """Mark active reservations past their expiry as ``expired``; run periodically (system task)."""
        at = now or self.clock()
        with self.db.transaction(DbScope.platform()) as tx:
            return tx.execute(
                "UPDATE axentra_usage_reservations SET status = 'expired', updated_at = now()"
                " WHERE status = 'active' AND expires_at <= %s",
                (at,),
            )

    # -- statistics ----------------------------------------------------------------------------

    def summary(
        self, principal: Principal, product_id: str, tenant_id: str, *, at: datetime | None = None
    ) -> list[MeterUsage]:
        """Usage of every active meter in the period containing ``at`` (default now)."""
        self.authz.require(principal, "usage:read", product_id, tenant_id)
        when = at.astimezone(UTC) if at else self.clock()
        out: list[MeterUsage] = []
        with self.db.transaction(DbScope.tenant(product_id, tenant_id), read_only=True) as tx:
            meters = tx.all(
                "SELECT * FROM axentra_usage_meters WHERE product_id = %s AND active ORDER BY key",
                (product_id,),
            )
            ctx = self._limit_context(tx, product_id, tenant_id)
            for m in meters:
                start, end = self._period(tx, product_id, tenant_id, m["reset_period"], when)
                row = tx.one(
                    "SELECT value, event_count FROM axentra_usage_counters WHERE product_id = %s AND tenant_id = %s"
                    " AND meter_id = %s AND granularity = 'period' AND period_start = %s",
                    (product_id, tenant_id, m["id"], start),
                )
                used = Decimal(row["value"]) if row else Decimal(0)
                st = self._status(
                    m,
                    self._resolve_limit(m, ctx),
                    start,
                    end,
                    used,
                    self._reserved(tx, product_id, tenant_id, m["id"], start),
                )
                out.append(
                    MeterUsage(
                        meter=m["key"],
                        name=m["name"],
                        unit=m["unit"],
                        aggregation=m["aggregation"],
                        reset_period=m["reset_period"],
                        period_start=start,
                        period_end=end,
                        value=used,
                        event_count=row["event_count"] if row else 0,
                        reserved=st.reserved,
                        limit=st.limit,
                        remaining=st.remaining,
                        enforcement=st.enforcement,
                        source=st.source,
                        over_limit=st.over_limit,
                    )
                )
        return out

    @staticmethod
    def _date_range(since: date | None, until: date | None, today: date) -> tuple[date, date]:
        until = until or today
        since = since or (until - timedelta(days=29))
        if since > until:
            raise ValidationFailed("since must not be after until")
        if (until - since).days + 1 > MAX_SERIES_DAYS:
            raise ValidationFailed(f"the range may span at most {MAX_SERIES_DAYS} days")
        return since, until

    def product_totals(
        self,
        principal: Principal,
        product_id: str,
        *,
        since: date | None = None,
        until: date | None = None,
        meter: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[TenantMeterTotal]:
        """Per tenant and meter totals over whole UTC days ``since..until`` (inclusive, from daily buckets).

        ``sum`` meters add up, ``max`` meters take the maximum, ``last`` meters the latest day's value.
        """
        self.authz.require(principal, "usage:read", product_id)
        limit = clamp_limit(limit)
        since, until = self._date_range(since, until, self.clock().date())
        where = ["c.product_id = %s", "c.granularity = 'day'", "c.period_start >= %s", "c.period_start < %s"]
        params: list[Any] = [
            product_id,
            datetime.combine(since, time(), UTC),
            datetime.combine(until + timedelta(days=1), time(), UTC),
        ]
        if meter:
            where.append("m.key = %s")
            params.append(meter)
        after = decode_cursor(cursor, ("str", "str"))
        if after:
            where.append("(c.tenant_id, m.key) > (%s, %s)")
            params += after
        sql = (
            "SELECT c.tenant_id, m.key AS meter, m.aggregation, SUM(c.value) AS s, MAX(c.value) AS mx,"
            " (array_agg(c.value ORDER BY c.period_start DESC))[1] AS last, SUM(c.event_count) AS n"
            " FROM axentra_usage_counters c JOIN axentra_usage_meters m ON m.id = c.meter_id"
            " AND m.product_id = c.product_id WHERE "
            + " AND ".join(where)
            + " GROUP BY c.tenant_id, m.key, m.aggregation ORDER BY c.tenant_id, m.key LIMIT %s"
        )
        params.append(limit + 1)
        with self.db.transaction(DbScope.product(product_id), read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [
            TenantMeterTotal(
                tenant_id=r["tenant_id"],
                meter=r["meter"],
                value={"sum": r["s"], "max": r["mx"]}.get(r["aggregation"], r["last"]),
                event_count=int(r["n"]),
            )
            for r in rows[:limit]
        ]
        nxt = encode_cursor([items[-1].tenant_id, items[-1].meter]) if len(rows) > limit else None
        return Page[TenantMeterTotal](items=items, next_cursor=nxt)

    def timeseries(
        self,
        principal: Principal,
        product_id: str,
        meter: str,
        *,
        tenant_id: str | None = None,
        since: date | None = None,
        until: date | None = None,
    ) -> TimeSeries:
        """Daily buckets (UTC) for charts; days without usage are 0. Product-wide: tenants summed."""
        self.authz.require(principal, "usage:read", product_id, tenant_id)
        since, until = self._date_range(since, until, self.clock().date())
        scope = DbScope.tenant(product_id, tenant_id) if tenant_id else DbScope.product(product_id)
        with self.db.transaction(scope, read_only=True) as tx:
            m = self._meter_by_key(tx, product_id, _check_key(meter), active_only=False)
            sql = (
                "SELECT period_start, SUM(value) AS v, SUM(event_count) AS n FROM axentra_usage_counters"
                " WHERE product_id = %s AND meter_id = %s AND granularity = 'day' AND period_start >= %s"
                " AND period_start < %s"
            )
            params: list[Any] = [
                product_id,
                m["id"],
                datetime.combine(since, time(), UTC),
                datetime.combine(until + timedelta(days=1), time(), UTC),
            ]
            if tenant_id:
                sql += " AND tenant_id = %s"
                params.append(tenant_id)
            rows = tx.all(sql + " GROUP BY period_start", params)
        by_day = {r["period_start"].astimezone(UTC).date(): r for r in rows}
        points = []
        day = since
        while day <= until:
            r = by_day.get(day)
            points.append(
                TimePoint(
                    day=day, value=Decimal(r["v"]) if r else Decimal(0), event_count=int(r["n"]) if r else 0
                )
            )
            day += timedelta(days=1)
        return TimeSeries(
            meter=m["key"],
            unit=m["unit"],
            aggregation=m["aggregation"],
            tenant_id=tenant_id,
            since=since,
            until=until,
            points=points,
        )
