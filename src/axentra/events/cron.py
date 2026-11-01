"""A small 5-field cron parser (UTC): ``minute hour day-of-month month day-of-week``.

Supported per field: ``*``, numbers, ranges ``a-b``, lists ``a,b``, steps ``*/n`` and ``a-b/n``.
Day of week is 0-7 (0 and 7 are Sunday). Month and weekday names, ``L``, ``W``, ``#``, ``?``,
``@daily`` style macros and seconds are not supported. As in Vixie cron, when both day-of-month
and day-of-week are restricted, a day matches if either matches. All times are UTC.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from axentra.core.errors import ValidationFailed

_FIELDS = (
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day of month", 1, 31),
    ("month", 1, 12),
    ("day of week", 0, 7),
)


def _parse_field(text: str, name: str, lo: int, hi: int) -> frozenset[int]:
    values: set[int] = set()
    for part in text.split(","):
        if not part:
            raise ValidationFailed(f"cron {name}: empty list item")
        rng, _, step_s = part.partition("/")
        step = 1
        if step_s:
            if not step_s.isdigit() or int(step_s) < 1:
                raise ValidationFailed(f"cron {name}: invalid step {step_s!r}")
            step = int(step_s)
        if rng == "*":
            start, end = lo, hi
        elif "-" in rng:
            a, _, b = rng.partition("-")
            if not (a.isdigit() and b.isdigit()):
                raise ValidationFailed(f"cron {name}: invalid range {rng!r}")
            start, end = int(a), int(b)
        elif rng.isdigit():
            start = int(rng)
            end = hi if step_s else start
        else:
            raise ValidationFailed(f"cron {name}: invalid value {rng!r}")
        if start < lo or end > hi or start > end:
            raise ValidationFailed(f"cron {name}: values must be within {lo}-{hi}")
        values.update(range(start, end + 1, step))
    return frozenset(values)


@dataclass(frozen=True)
class CronExpr:
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = Sunday
    dom_restricted: bool
    dow_restricted: bool

    @classmethod
    def parse(cls, expr: str) -> CronExpr:
        if not isinstance(expr, str) or len(expr) > 200:
            raise ValidationFailed("cron expression must be a string of at most 200 characters")
        parts = expr.split()
        if len(parts) != 5:
            raise ValidationFailed(
                "cron expression needs 5 fields: minute hour day-of-month month day-of-week"
            )
        sets = [_parse_field(p, n, lo, hi) for p, (n, lo, hi) in zip(parts, _FIELDS, strict=True)]
        weekdays = frozenset(d % 7 for d in sets[4])
        return cls(sets[0], sets[1], sets[2], sets[3], weekdays, parts[2] != "*", parts[4] != "*")

    def _day_matches(self, t: datetime) -> bool:
        dom = t.day in self.days
        dow = ((t.weekday() + 1) % 7) in self.weekdays
        if self.dom_restricted and self.dow_restricted:
            return dom or dow
        if self.dom_restricted:
            return dom
        if self.dow_restricted:
            return dow
        return True

    def next_after(self, after: datetime) -> datetime:
        """The first matching minute strictly after ``after`` (UTC)."""
        if after.tzinfo is None:
            raise ValueError("cron times need a time zone")
        t = after.astimezone(UTC).replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = t + timedelta(days=366 * 5)
        while t < limit:
            if t.month not in self.months:
                t = (t.replace(day=1, hour=0, minute=0) + timedelta(days=32)).replace(day=1)
                continue
            if not self._day_matches(t):
                t = t.replace(hour=0, minute=0) + timedelta(days=1)
                continue
            if t.hour not in self.hours:
                t = t.replace(minute=0) + timedelta(hours=1)
                continue
            if t.minute not in self.minutes:
                t += timedelta(minutes=1)
                continue
            return t
        raise ValidationFailed("the cron expression never matches")


def next_interval_slot(after: datetime, interval_seconds: int) -> datetime:
    """Interval schedules fire at multiples of the interval since the Unix epoch (UTC), so every
    process computes the same slots."""
    ts = after.timestamp()
    nxt = (int(ts // interval_seconds) + 1) * interval_seconds
    return datetime.fromtimestamp(nxt, UTC)
