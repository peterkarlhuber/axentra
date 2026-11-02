"""HTTP side of observability: metrics attachment, the tracing middleware, readiness checks."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import logging

from fastapi import FastAPI, Request, Response

from axentra.config.secrets import resolve_secret
from axentra.platform import Axentra

logger = logging.getLogger("axentra.http")


def install_observability(app: FastAPI, ax: Axentra) -> None:
    obs = ax.settings.observability
    if obs.metrics_enabled:
        app.state.metrics = ax.metrics
        app.state.metrics_token = resolve_secret(obs.metrics_token_ref) if obs.metrics_token_ref else None
        if app.state.metrics_token is None and ax.settings.is_production:
            logger.warning("GET /metrics is disabled: set observability.metrics_token_ref to enable it")

    checks = getattr(app.state, "readiness_checks", None)
    if checks is None:
        checks = app.state.readiness_checks = {}
    if ax.notify is not None:
        checks["notify_provider"] = ax.notify.check_config
    if ax.settings.database.require_current_schema:
        checks["schema"] = ax.schema_ready

    tracing = ax.tracing
    if tracing.enabled:

        @app.middleware("http")
        async def trace_requests(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            with tracing.span(f"HTTP {request.method}", {"http.request.method": request.method}) as span:
                response = await call_next(request)
                route = getattr(request.scope.get("route"), "path", None) or "unmatched"
                span.update_name(f"{request.method} {route}")
                span.set_attribute("http.route", route)
                span.set_attribute("http.response.status_code", response.status_code)
                rid = response.headers.get("x-request-id")
                if rid:
                    span.set_attribute("axentra.request_id", rid)
                if response.status_code >= 500:
                    from opentelemetry.trace import Status, StatusCode

                    span.set_status(Status(StatusCode.ERROR))
                return response
