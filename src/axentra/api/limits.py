"""Request body size limit and general request rate limiting (ASGI middlewares).

Body size (``security.max_body_bytes``, default 10 MiB): a declared ``Content-Length`` above the
limit is answered with 413 before the body is read; a chunked body is counted while the endpoint
reads it and aborted with 413 as soon as it exceeds the limit. Routes marked with
:func:`own_body_limit` (file uploads) are exempt; they enforce ``storage.max_file_bytes``
themselves while streaming.

Rate limiting (``security.rate_limit_per_minute`` / ``rate_limit_ip_per_minute``, both off by
default). A request is charged to its credential (a hash of the bearer token, API key or session
cookie; the client IP for anonymous requests) and, independently, to its client IP. An exhausted
budget answers 429 with ``Retry-After``. Health and metrics endpoints are never limited.

``security.rate_limit_store`` picks where the budgets live:

- ``"memory"`` (default): token buckets **per process** (:class:`TokenBuckets`). No database round
  trip per request, but every API process has its own budget (N replicas allow N times the rate)
  and a restart refills the buckets.
- ``"database"``: fixed one-minute windows in ``axentra_rate_limits``, **shared by all API
  processes** (:class:`DatabaseWindows`). Costs one upsert per limited budget and request, and a
  fixed window allows up to twice the budget across a window boundary (``rate_limit_burst`` does
  not apply). When the database cannot be reached the request is let through (the limiter must
  not turn a database problem into 429 or 500 answers for requests that need no database).
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
import hashlib
import logging
import math
import random
import re
import threading
import time
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from axentra.api.problems import problem

if TYPE_CHECKING:
    from axentra.data.database import Database

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])
_OWN_LIMIT_ATTR = "__axentra_own_body_limit__"
UNLIMITED_PATHS = ("/v1/health/", "/metrics")


def own_body_limit(fn: F) -> F:
    """Mark an endpoint that enforces its own (larger) body limit, e.g. a streaming upload."""
    setattr(fn, _OWN_LIMIT_ATTR, True)
    return fn


def has_own_body_limit(endpoint: Any) -> bool:
    return bool(getattr(endpoint, _OWN_LIMIT_ATTR, False))


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int, exempt: list[re.Pattern[str]]) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.exempt = exempt

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or any(p.match(scope["path"]) for p in self.exempt):
            await self.app(scope, receive, send)
            return
        limit = self.max_bytes
        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                if value.isdigit() and int(value) > limit:
                    response = problem(
                        Request(scope),
                        413,
                        "payload_too_large",
                        "Payload too large",
                        f"request bodies may be at most {limit} bytes",
                    )
                    await response(scope, receive, send)
                    return
                break
        seen = 0

        async def limited_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    # Raised inside the endpoint's body read: rendered by the HTTP exception handler.
                    raise HTTPException(413, f"request bodies may be at most {limit} bytes")
            return message

        await self.app(scope, limited_receive, send)


class Budgets(Protocol):
    #: True when :meth:`take` blocks on I/O (it then runs in the thread pool).
    blocking: bool

    def take(self, key: str) -> float:
        """Count one request; 0 when allowed, else the seconds until the next one is."""
        ...


class TokenBuckets:
    """Thread-safe token buckets with a bounded number of keys (least recently used evicted)."""

    blocking = False

    def __init__(self, per_minute: int, burst: int | None = None, max_keys: int = 100_000) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(burst or per_minute)
        self.max_keys = max_keys
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str, now: float | None = None) -> float:
        """Take one token; returns 0 when allowed, else the seconds until a token is available."""
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._buckets.pop(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            wait = 0.0
            if tokens >= 1.0:
                tokens -= 1.0
            else:
                wait = (1.0 - tokens) / self.rate
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            return wait


class DatabaseWindows:
    """Fixed one-minute windows in ``axentra_rate_limits``, shared by every process that uses
    the database. Keys are prefixed (``req:``) so they never collide with the login buckets."""

    blocking = True

    def __init__(self, db: Database, per_minute: int, *, prefix: str = "req:") -> None:
        self.db = db
        self.limit = per_minute
        self.prefix = prefix

    def take(self, key: str) -> float:
        from axentra.data.database import DbScope

        try:
            with self.db.transaction(DbScope.platform()) as tx:
                row = tx.one(
                    "INSERT INTO axentra_rate_limits (bucket, window_start, hits)"
                    " VALUES (%s, date_trunc('minute', now()), 1)"
                    " ON CONFLICT (bucket, window_start) DO UPDATE SET hits = axentra_rate_limits.hits + 1"
                    " RETURNING hits, 60 - extract(epoch FROM now() - window_start)::float8 AS left_s",
                    (self.prefix + key,),
                )
                if random.random() < 0.01:  # noqa: S311 - housekeeping, not security
                    tx.execute(
                        "DELETE FROM axentra_rate_limits WHERE window_start < now() - interval '10 minutes'"
                    )
        except Exception as exc:
            logger.warning("rate limit store unavailable, request let through (%s)", type(exc).__name__)
            return 0.0
        if row is None or int(row["hits"]) <= self.limit:
            return 0.0
        return max(1.0, float(row["left_s"]))


def credential_key(request: Request, session_cookie: str) -> str | None:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    token = (
        token or (request.headers.get("x-api-key") or "").strip() or request.cookies.get(session_cookie, "")
    )
    if not token:
        return None
    return "cred:" + hashlib.sha256(token.encode()).hexdigest()[:32]


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        per_credential: Budgets | None,
        per_ip: Budgets | None,
        client_ip: Callable[[Request], str | None],
        session_cookie: Callable[[], str],
    ) -> None:
        self.app = app
        self.per_credential = per_credential
        self.per_ip = per_ip
        self.client_ip = client_ip
        self.session_cookie = session_cookie

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["path"].startswith(UNLIMITED_PATHS)
            or scope["method"] == "OPTIONS"
        ):
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        ip = self.client_ip(request) or "unknown"
        wait = 0.0
        if self.per_ip is not None:
            wait = max(wait, await _take(self.per_ip, "ip:" + ip))
        if self.per_credential is not None and wait == 0.0:
            key = credential_key(request, self.session_cookie()) or "anon:" + ip
            wait = max(wait, await _take(self.per_credential, key))
        if wait > 0:
            retry = max(1, math.ceil(wait))
            response = problem(
                request, 429, "rate_limited", "Too many requests", "the request rate limit is exceeded"
            )
            response.headers["Retry-After"] = str(retry)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


async def _take(budgets: Budgets, key: str) -> float:
    if not budgets.blocking:
        return budgets.take(key)
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(budgets.take, key)
