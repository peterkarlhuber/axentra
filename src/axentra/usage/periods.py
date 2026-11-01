"""Period arithmetic for usage counters and billing cycles (pure functions, all UTC).

- ``none``: one open-ended period starting at :data:`EPOCH` (counters never reset).
- ``day``: UTC calendar days.
- ``month``: UTC calendar months (the default billing period).
- ``billing_period``: the subscription's cycle, anchored at its period start (anchor day of month
  and time of day); months without the anchor day end on their last day. Without billing data it
  falls back to calendar months.
"""

from __future__ import annotations

import calendar
from datetime import UTC, datetime, timedelta

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

Period = tuple[datetime, datetime | None]


def as_utc(at: datetime) -> datetime:
    if at.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return at.astimezone(UTC)


def add_months(at: datetime, months: int, anchor_day: int | None = None) -> datetime:
    """``at`` shifted by ``months``; the day is ``anchor_day`` (default ``at.day``) clamped to the month."""
    day = anchor_day or at.day
    total = at.year * 12 + (at.month - 1) + months
    year, month = divmod(total, 12)
    month += 1
    last = calendar.monthrange(year, month)[1]
    return at.replace(year=year, month=month, day=min(day, last))


def day_period(at: datetime) -> tuple[datetime, datetime]:
    at = as_utc(at)
    start = at.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=1)


def month_period(at: datetime) -> tuple[datetime, datetime]:
    at = as_utc(at)
    start = at.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start, add_months(start, 1)


def anchored_period(anchor: datetime, at: datetime, months: int = 1) -> tuple[datetime, datetime]:
    """The cycle of ``months`` months, anchored at ``anchor``, that contains ``at``."""
    if months < 1:
        raise ValueError("months must be positive")
    anchor, at = as_utc(anchor), as_utc(at)
    day = anchor.day
    diff = (at.year - anchor.year) * 12 + (at.month - anchor.month)
    k = diff // months
    start = add_months(anchor, k * months, day)
    while start > at:
        k -= 1
        start = add_months(anchor, k * months, day)
    end = add_months(anchor, (k + 1) * months, day)
    while end <= at:
        k += 1
        start, end = end, add_months(anchor, (k + 1) * months, day)
    return start, end


def period_for(reset: str, at: datetime) -> Period:
    """Counter period for a meter reset kind; ``billing_period`` here means calendar month."""
    if reset == "none":
        return EPOCH, None
    if reset == "day":
        return day_period(at)
    if reset in ("month", "billing_period"):
        return month_period(at)
    raise ValueError(f"unknown reset period {reset!r}")
