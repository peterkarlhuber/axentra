"""A small, dependency-free Prometheus metrics registry (text exposition format 0.0.4).

Modules register metrics through ``ax.metrics``::

    sent = ax.metrics.counter("myproduct_invoices_sent_total", "Invoices sent", ("channel",))
    sent.inc(channel="email")
    latency = ax.metrics.histogram("myproduct_render_seconds", "Render time")
    latency.observe(0.12)

Registering the same name again returns the existing metric (same type and labels required).
Each metric keeps at most ``MAX_SERIES`` label combinations; further combinations are folded into
one series whose label values are ``other`` (protection against unbounded cardinality).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import logging
import math
import re
import threading
from typing import Any

logger = logging.getLogger(__name__)

_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
MAX_SERIES = 2000
DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

LabelKey = tuple[str, ...]


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _escape_help(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def _fmt(value: float) -> str:
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if math.isnan(value):
        return "NaN"
    if float(value).is_integer() and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


def _labels_text(names: Sequence[str], values: Sequence[str], extra: str = "") -> str:
    parts = [f'{n}="{_escape_label(v)}"' for n, v in zip(names, values, strict=True)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


class _Metric:
    kind = "untyped"

    def __init__(self, name: str, help: str, labelnames: Sequence[str]) -> None:
        if not _NAME.match(name):
            raise ValueError(f"invalid metric name {name!r}")
        for ln in labelnames:
            if not _LABEL.match(ln) or ln.startswith("__") or ln == "le":
                raise ValueError(f"invalid label name {ln!r}")
        self.name = name
        self.help = help
        self.labelnames = tuple(labelnames)
        self._lock = threading.Lock()

    def _key(self, labels: dict[str, Any], existing: dict[LabelKey, Any]) -> LabelKey:
        if set(labels) != set(self.labelnames):
            raise ValueError(f"metric {self.name} takes labels {self.labelnames}, got {tuple(labels)}")
        key = tuple(str(labels[n])[:200] for n in self.labelnames)
        if key not in existing and len(existing) >= MAX_SERIES:
            return tuple("other" for _ in self.labelnames)
        return key

    def render(self) -> list[str]:  # pragma: no cover - overridden
        raise NotImplementedError

    def _header(self) -> list[str]:
        return [f"# HELP {self.name} {_escape_help(self.help)}", f"# TYPE {self.name} {self.kind}"]


class Counter(_Metric):
    kind = "counter"

    def __init__(self, name: str, help: str, labelnames: Sequence[str] = ()) -> None:
        super().__init__(name, help, labelnames)
        self._values: dict[LabelKey, float] = {}

    def inc(self, amount: float = 1.0, **labels: Any) -> None:
        if amount < 0:
            raise ValueError("counters only increase")
        with self._lock:
            key = self._key(labels, self._values)
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels: Any) -> float:
        with self._lock:
            return self._values.get(tuple(str(labels[n]) for n in self.labelnames), 0.0)

    def render(self) -> list[str]:
        with self._lock:
            items = sorted(self._values.items())
        return self._header() + [f"{self.name}{_labels_text(self.labelnames, k)} {_fmt(v)}" for k, v in items]


class Gauge(_Metric):
    kind = "gauge"

    def __init__(
        self,
        name: str,
        help: str,
        labelnames: Sequence[str] = (),
        callback: Callable[[], Iterable[tuple[dict[str, Any], float]]] | None = None,
    ) -> None:
        super().__init__(name, help, labelnames)
        self._values: dict[LabelKey, float] = {}
        self._callback = callback

    def set(self, value: float, **labels: Any) -> None:
        with self._lock:
            self._values[self._key(labels, self._values)] = float(value)

    def inc(self, amount: float = 1.0, **labels: Any) -> None:
        with self._lock:
            key = self._key(labels, self._values)
            self._values[key] = self._values.get(key, 0.0) + amount

    def dec(self, amount: float = 1.0, **labels: Any) -> None:
        self.inc(-amount, **labels)

    def render(self) -> list[str]:
        if self._callback is not None:
            try:
                fresh = list(self._callback())
            except Exception:
                logger.warning("metrics callback for %s failed", self.name, exc_info=True)
                fresh = []
            with self._lock:
                self._values = {}
                for labels, value in fresh:
                    self._values[self._key(labels, self._values)] = float(value)
        with self._lock:
            items = sorted(self._values.items())
        return self._header() + [f"{self.name}{_labels_text(self.labelnames, k)} {_fmt(v)}" for k, v in items]


class CallbackCounter(Gauge):
    """A counter whose totals come from a callback at scrape time (totals the host keeps itself, e.g. per-process
    operation counts kept without importing Axentra). The callback must return monotonic totals."""

    kind = "counter"

    def __init__(
        self,
        name: str,
        help: str,
        labelnames: Sequence[str],
        callback: Callable[[], Iterable[tuple[dict[str, Any], float]]],
    ) -> None:
        super().__init__(name, help, labelnames, callback)


class Histogram(_Metric):
    kind = "histogram"

    def __init__(
        self, name: str, help: str, labelnames: Sequence[str] = (), buckets: Sequence[float] = DEFAULT_BUCKETS
    ) -> None:
        super().__init__(name, help, labelnames)
        bs = sorted(float(b) for b in buckets if not math.isinf(b))
        if not bs:
            raise ValueError("a histogram needs at least one finite bucket")
        self.buckets = tuple(bs)
        self._series: dict[LabelKey, list[float]] = {}
        """Per series: bucket counts (non-cumulative) + [+Inf count, sum]."""

    def observe(self, value: float, **labels: Any) -> None:
        with self._lock:
            key = self._key(labels, self._series)
            s = self._series.get(key)
            if s is None:
                s = self._series[key] = [0.0] * (len(self.buckets) + 2)
            for i, b in enumerate(self.buckets):
                if value <= b:
                    s[i] += 1
                    break
            else:
                s[len(self.buckets)] += 1
            s[-1] += value

    def count(self, **labels: Any) -> float:
        with self._lock:
            s = self._series.get(tuple(str(labels[n]) for n in self.labelnames))
            return sum(s[:-1]) if s else 0.0

    def render(self) -> list[str]:
        with self._lock:
            items = sorted((k, list(v)) for k, v in self._series.items())
        lines = self._header()
        for key, s in items:
            cumulative = 0.0
            for i, b in enumerate(self.buckets):
                cumulative += s[i]
                le = 'le="' + _fmt(b) + '"'
                lines.append(f"{self.name}_bucket{_labels_text(self.labelnames, key, le)} {_fmt(cumulative)}")
            cumulative += s[len(self.buckets)]
            inf = 'le="+Inf"'
            lines.append(f"{self.name}_bucket{_labels_text(self.labelnames, key, inf)} {_fmt(cumulative)}")
            lines.append(f"{self.name}_sum{_labels_text(self.labelnames, key)} {_fmt(s[-1])}")
            lines.append(f"{self.name}_count{_labels_text(self.labelnames, key)} {_fmt(cumulative)}")
        return lines


class MetricsRegistry:
    def __init__(self) -> None:
        self._metrics: dict[str, _Metric] = {}
        self._lock = threading.Lock()
        self.http_requests = self.counter(
            "axentra_http_requests_total",
            "HTTP requests by method, route template and status",
            ("method", "route", "status"),
        )
        self.http_duration = self.histogram(
            "axentra_http_request_duration_seconds",
            "HTTP request latency by method and route template",
            ("method", "route"),
        )
        self.auth_failures = self.counter(
            "axentra_auth_failures_total",
            "Requests refused with 401 (unauthenticated) or 403 (forbidden)",
            ("reason",),
        )

    def _register(self, metric: _Metric) -> Any:
        with self._lock:
            existing = self._metrics.get(metric.name)
            if existing is not None:
                if type(existing) is not type(metric) or existing.labelnames != metric.labelnames:
                    raise ValueError(
                        f"metric {metric.name} is already registered with another type or labels"
                    )
                return existing
            self._metrics[metric.name] = metric
            return metric

    def counter(self, name: str, help: str, labelnames: Sequence[str] = ()) -> Counter:
        result: Counter = self._register(Counter(name, help, labelnames))
        return result

    def gauge(
        self,
        name: str,
        help: str,
        labelnames: Sequence[str] = (),
        callback: Callable[[], Iterable[tuple[dict[str, Any], float]]] | None = None,
    ) -> Gauge:
        result: Gauge = self._register(Gauge(name, help, labelnames, callback))
        return result

    def counter_callback(
        self,
        name: str,
        help: str,
        labelnames: Sequence[str],
        callback: Callable[[], Iterable[tuple[dict[str, Any], float]]],
    ) -> CallbackCounter:
        """A counter read from ``callback`` at scrape time (see :class:`CallbackCounter`)."""
        result: CallbackCounter = self._register(CallbackCounter(name, help, labelnames, callback))
        return result

    def histogram(
        self, name: str, help: str, labelnames: Sequence[str] = (), buckets: Sequence[float] = DEFAULT_BUCKETS
    ) -> Histogram:
        result: Histogram = self._register(Histogram(name, help, labelnames, buckets))
        return result

    def get(self, name: str) -> _Metric | None:
        return self._metrics.get(name)

    def render(self) -> str:
        with self._lock:
            metrics = sorted(self._metrics.values(), key=lambda m: m.name)
        lines: list[str] = []
        for m in metrics:
            lines += m.render()
        return "\n".join(lines) + "\n"

    def observe_request(self, method: str, route: Any, status: int, duration_ms: float) -> None:
        """Called by the HTTP middleware once per request.

        ``route`` is the matched route object (its ``path`` template is used, never the raw path,
        so ids do not explode the label cardinality); unmatched requests count as ``unmatched``.
        """
        template = getattr(route, "path", None)
        route_label = template if isinstance(template, str) else "unmatched"
        m = method.upper() if method.upper() in _METHODS else "OTHER"
        self.http_requests.inc(method=m, route=route_label, status=str(int(status)))
        self.http_duration.observe(max(duration_ms, 0.0) / 1000.0, method=m, route=route_label)
        if status == 401:
            self.auth_failures.inc(reason="unauthenticated")
        elif status == 403:
            self.auth_failures.inc(reason="forbidden")


def register_db_pool_metrics(registry: MetricsRegistry, db: Any) -> None:
    """Gauges read from ``psycopg_pool`` statistics at scrape time."""

    def stats() -> dict[str, Any]:
        pool = getattr(db, "pool", None)
        if pool is None:
            return {}
        try:
            return dict(pool.get_stats())
        except Exception:
            return {}

    def gauge_of(key: str) -> Callable[[], list[tuple[dict[str, Any], float]]]:
        def read() -> list[tuple[dict[str, Any], float]]:
            s = stats()
            return [({}, float(s[key]))] if key in s else []

        return read

    for key, help_text in (
        ("pool_size", "Connections currently managed by the pool"),
        ("pool_available", "Idle connections in the pool"),
        ("pool_max", "Maximum pool size"),
        ("requests_waiting", "Clients waiting for a connection"),
        ("requests_num", "Connection requests since the pool was opened"),
        ("requests_errors", "Connection requests that failed (timeout, error)"),
        ("connections_errors", "Failed connection attempts"),
    ):
        name = f"axentra_db_{key}" if key.startswith("pool") else f"axentra_db_pool_{key}"
        registry.gauge(name, help_text, callback=gauge_of(key))


#: ``psycopg_pool`` statistics exported per pool by :func:`register_pool_metrics` (key, metric suffix, help).
_POOL_STATS = (
    ("pool_size", "pool_size", "Connections currently managed by the pool"),
    ("pool_available", "pool_idle", "Idle connections in the pool"),
    ("pool_max", "pool_max", "Maximum pool size"),
    ("requests_waiting", "pool_requests_waiting", "Clients waiting for a connection right now"),
    ("requests_num", "pool_requests", "Connection requests since the pool was opened"),
    ("requests_errors", "pool_requests_errors", "Connection requests that failed (timeout, error)"),
    ("connections_errors", "pool_connection_errors", "Failed connection attempts"),
)


def pool_stats(pool: Any) -> dict[str, float]:
    """The statistics of a ``psycopg_pool`` pool (or any object with ``get_stats()``), ``{}`` when unavailable.

    ``in_use`` (``pool_size - pool_available``) is added when both are known."""
    try:
        stats = {key: float(value) for key, value in dict(pool.get_stats()).items()}
    except Exception:
        return {}
    if "pool_size" in stats and "pool_available" in stats:
        stats["in_use"] = max(stats["pool_size"] - stats["pool_available"], 0.0)
    return stats


def register_pool_metrics(
    registry: MetricsRegistry, pools: Callable[[], Mapping[str, Any]], *, prefix: str
) -> None:
    """Gauges ``<prefix>_db_pool_*{pool="<name>"}`` for several named connection pools, read at scrape time.

    ``pools()`` returns the pools that exist right now by name (a host embedding Axentra may have its own pool next
    to Axentra's, or share one): a pool that is gone or closed simply disappears from the output. Names are labels,
    so they must be a small fixed set (``app``, ``axentra``, ...), never per tenant or per request."""

    def series(key: str) -> Callable[[], list[tuple[dict[str, Any], float]]]:
        def read() -> list[tuple[dict[str, Any], float]]:
            found = []
            for name, pool in dict(pools()).items():
                if pool is None:
                    continue
                stats = pool_stats(pool)
                if key in stats:
                    found.append(({"pool": name}, stats[key]))
            return found

        return read

    for key, suffix, help_text in (
        *_POOL_STATS,
        ("in_use", "pool_in_use", "Connections handed out right now"),
    ):
        registry.gauge(f"{prefix}_db_{suffix}", help_text, ("pool",), callback=series(key))


class CachedCallback:
    """Wraps an expensive metrics callback (e.g. a database count) so that it runs at most once per ``ttl`` seconds.

    Scrapes in between get the last result; a failing call keeps the previous result (and logs). Thread-safe: at most
    one call runs at a time, concurrent scrapes wait for it instead of running it again."""

    def __init__(
        self, fn: Callable[[], Any], ttl: float, *, clock: Callable[[], float] | None = None
    ) -> None:
        import time

        self.fn = fn
        self.ttl = ttl
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._value: Any = None
        self._at: float | None = None

    def __call__(self) -> Any:
        with self._lock:
            now = self._clock()
            if self._at is None or now - self._at >= self.ttl:
                try:
                    self._value = self.fn()
                except Exception:
                    logger.warning(
                        "cached metrics callback failed; keeping the previous value", exc_info=True
                    )
                self._at = now
            return self._value

    def invalidate(self) -> None:
        with self._lock:
            self._at = None
