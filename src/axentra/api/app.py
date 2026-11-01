"""The FastAPI application factory.

``create_app(settings)`` builds a complete Axentra API. Every ``/v1`` route either depends on
:func:`~axentra.api.context.resolve_principal` (directly or through a route dependency) or is
listed in :data:`PUBLIC_ROUTES`; :func:`check_routes` refuses to start otherwise, so a new route
cannot be accidentally public.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
import logging
import time

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException

from axentra import API_VERSION, __version__
from axentra.api.context import resolve_principal, valid_request_id
from axentra.api.problems import (
    axentra_error_handler,
    http_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from axentra.api.routes import ROUTERS
from axentra.audit.logging import request_id_var
from axentra.config.settings import Settings, load_settings
from axentra.core.errors import AxentraError, ConfigurationError
from axentra.core.ids import new_id
from axentra.platform import Axentra

logger = logging.getLogger("axentra.http")

#: Routes that work without authentication (method, path).
PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/v1/meta"),
        ("GET", "/v1/health/live"),
        ("GET", "/v1/health/ready"),
        ("POST", "/v1/auth/setup"),
        ("POST", "/v1/auth/login/password"),
        ("GET", "/v1/auth/oidc/{provider}/start"),
        ("GET", "/v1/auth/oidc/{provider}/callback"),
        ("POST", "/v1/billing/webhooks/{provider}"),
        ("GET", "/v1/files/download/{token}"),
        ("GET", "/metrics"),
    }
)

API_VERSION_STR = f"{API_VERSION[0]}.{API_VERSION[1]}"


def _depends_on_principal(route: APIRoute) -> bool:
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is resolve_principal:
            return True
        stack.extend(dep.dependencies)
    return False


def check_routes(app: FastAPI) -> None:
    unprotected = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods or ():
            if method == "HEAD":
                continue
            if (method, route.path) in PUBLIC_ROUTES:
                continue
            if not _depends_on_principal(route):
                unprotected.append(f"{method} {route.path}")
    if unprotected:
        raise ConfigurationError("routes without authentication: " + ", ".join(sorted(unprotected)))


def create_app(
    settings: Settings | None = None, *, axentra: Axentra | None = None, start: bool = True
) -> FastAPI:
    ax = axentra or Axentra.from_settings(settings or load_settings())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if start:
            ax.start()
        try:
            yield
        finally:
            if start:
                ax.close()

    app = FastAPI(
        title="Axentra API",
        version=API_VERSION_STR,
        summary="Modular SaaS backend foundation: identity, tenancy, access, data, storage, jobs, usage, billing, notifications, audit.",
        description=(
            "The public, versioned Axentra HTTP API. See docs/architecture/API_CONVENTIONS.md for authentication, "
            "scoping, pagination, errors and versioning rules."
        ),
        lifespan=lifespan,
        openapi_url="/v1/openapi.json",
        docs_url="/v1/docs",
        redoc_url=None,
        license_info={"name": "MIT", "identifier": "MIT"},
    )
    app.state.axentra = ax
    app.state.server_version = __version__

    app.add_exception_handler(AxentraError, axentra_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_error_handler)

    for router in ROUTERS:
        if router.module is None or ax.settings.module_enabled(router.module):
            app.include_router(router.router)

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-request-id")
        rid: str = incoming if incoming and valid_request_id(incoming) else new_id("req")
        request.state.request_id = rid
        token = request_id_var.set(rid)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        duration = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = str(rid)
        response.headers["Axentra-API-Version"] = API_VERSION_STR
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        if not request.url.path.startswith("/v1/docs"):
            response.headers.setdefault(
                "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
            )
        if ax.settings.secure_cookies:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path.startswith("/v1/auth") or request.url.path.startswith("/v1/me"):
            response.headers.setdefault("Cache-Control", "no-store")
        metrics = getattr(app.state, "metrics", None)
        if metrics is not None:
            metrics.observe_request(
                request.method, request.scope.get("route"), response.status_code, duration
            )
        logger.info(
            "%s %s %s",
            request.method,
            request.url.path,
            response.status_code,
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round(duration, 1),
            },
        )
        return response

    if ax.settings.security.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=ax.settings.security.allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "If-Match",
                "Idempotency-Key",
                "X-Axentra-CSRF",
                "X-Request-ID",
                "Axentra-Client",
                "X-API-Key",
            ],
            expose_headers=["X-Request-ID", "Axentra-API-Version", "ETag"],
            max_age=600,
        )

    check_routes(app)
    return app
