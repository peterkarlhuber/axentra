"""The FastAPI application factory.

``create_app(settings)`` builds a complete Axentra API. Every ``/v1`` route either depends on
:func:`~axentra.api.context.resolve_principal` (directly or through a route dependency) or is
listed in :data:`PUBLIC_ROUTES`; :func:`check_routes` refuses to start otherwise, so a new route
cannot be accidentally public.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager
import logging
import time
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException

from axentra import API_VERSION, __version__
from axentra.api.context import resolve_principal, valid_request_id
from axentra.api.openapi import install_openapi
from axentra.api.problems import (
    axentra_error_handler,
    http_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from axentra.api.routes import ROUTERS
from axentra.audit.logging import install_access_log_redaction, request_id_var
from axentra.config.settings import Settings, load_settings
from axentra.core.db_errors import install_db_error_redaction
from axentra.core.errors import AxentraError, ConfigurationError
from axentra.core.ids import new_id
from axentra.core.redaction import redact_text
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
        ("POST", "/v1/auth/password-reset"),
        ("POST", "/v1/auth/password-reset/confirm"),
        ("POST", "/v1/auth/email-verification/confirm"),
        ("GET", "/v1/auth/oidc/{provider}/start"),
        ("POST", "/v1/auth/oidc/{provider}/start"),
        ("GET", "/v1/auth/oidc/{provider}/callback"),
        ("POST", "/v1/billing/webhooks/{provider}"),
        ("GET", "/v1/files/download/{token}"),
        ("GET", "/metrics"),
        # Only registered when security.api_docs is "public" (see _install_api_docs).
        ("GET", "/v1/openapi.json"),
        ("GET", "/v1/docs"),
    }
)
DOCS_ROUTES = frozenset({("GET", "/v1/openapi.json"), ("GET", "/v1/docs")})

API_VERSION_STR = f"{API_VERSION[0]}.{API_VERSION[1]}"


def _depends_on_principal(route: APIRoute, extra: list[Any]) -> bool:
    stack = list(route.dependant.dependencies) + list(extra)
    while stack:
        dep = stack.pop()
        call = getattr(dep, "call", None) or getattr(dep, "dependency", None)
        if call is resolve_principal:
            return True
        stack.extend(getattr(dep, "dependencies", []) or [])
    return False


def iter_api_routes(
    routes: list[Any], prefix: str = "", deps: list[Any] | None = None
) -> Iterator[tuple[str, APIRoute, list[Any]]]:
    """All API routes with their full path, including routers mounted with ``include_router``.

    FastAPI >= 0.162 keeps included routers as wrapper objects in ``app.routes``; older versions
    copy the routes. Both shapes are walked so the protection check can never silently pass.
    """
    deps = deps or []
    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route, deps
            continue
        original = getattr(route, "original_router", None)
        if original is not None:
            ctx = getattr(route, "include_context", None)
            yield from iter_api_routes(
                list(original.routes),
                prefix + (getattr(ctx, "prefix", "") or ""),
                deps + list(getattr(ctx, "dependencies", []) or []),
            )


def _install_limits(app: FastAPI, ax: Axentra) -> None:
    """Body size limit and optional rate limits; added before request_context so they run inside it."""
    from starlette.routing import compile_path

    from axentra.api.context import client_ip, session_cookie_name
    from axentra.api.limits import (
        HEAVY_READ_PATHS,
        BodyLimitMiddleware,
        Budgets,
        DatabaseWindows,
        RateLimitMiddleware,
        TokenBuckets,
        has_own_body_limit,
    )
    from axentra.api.nul_guard import NulInputMiddleware

    sec = ax.settings.security
    exempt = [
        compile_path(path)[0]
        for path, route, _ in iter_api_routes(list(app.routes))
        if has_own_body_limit(route.endpoint)
    ]
    app.add_middleware(BodyLimitMiddleware, max_bytes=sec.max_body_bytes, exempt=exempt)

    def budgets(per_minute: int | None, prefix: str) -> Budgets | None:
        if not per_minute:
            return None
        if sec.rate_limit_store == "database":
            return DatabaseWindows(ax.db, per_minute, prefix=prefix)
        # The burst setting belongs to the general limit; the heavy-read bucket holds one minute's budget.
        return TokenBuckets(per_minute, sec.rate_limit_burst if prefix == "req:" else None)

    if sec.rate_limit_per_minute or sec.rate_limit_ip_per_minute:
        app.add_middleware(
            RateLimitMiddleware,
            per_credential=budgets(sec.rate_limit_per_minute, "req:"),
            per_ip=budgets(sec.rate_limit_ip_per_minute, "req:"),
            client_ip=client_ip,
            session_cookie=lambda: session_cookie_name(ax),
        )
    if sec.heavy_rate_limit_per_minute:
        app.add_middleware(
            RateLimitMiddleware,
            per_credential=budgets(sec.heavy_rate_limit_per_minute, "heavy:"),
            per_ip=None,
            client_ip=client_ip,
            session_cookie=lambda: session_cookie_name(ax),
            only=HEAVY_READ_PATHS,
        )
    # Outermost of these: a NUL in path, query or JSON body is a 422 before any limit is charged (B-04).
    app.add_middleware(NulInputMiddleware)


def check_routes(app: FastAPI) -> int:
    """Refuse to start if an API route is neither authenticated nor explicitly public. Returns the count checked."""
    unprotected = []
    checked = 0
    for path, route, deps in iter_api_routes(list(app.routes)):
        for method in route.methods or ():
            if method == "HEAD":
                continue
            checked += 1
            if (method, path) in PUBLIC_ROUTES:
                continue
            if not _depends_on_principal(route, deps):
                unprotected.append(f"{method} {path}")
    if unprotected:
        raise ConfigurationError("routes without authentication: " + ", ".join(sorted(unprotected)))
    if checked == 0:
        raise ConfigurationError("route protection check found no routes")
    return checked


#: Swagger UI for ``/v1/docs``, pinned to one release with Subresource Integrity, so a changed or compromised CDN
#: file is refused by the browser. The hashes are those of the files in the npm package (``dist.integrity``
#: ``sha512-VSr8fXfI93obYaQicLJbLUKGRxDojj/SfRJDDLCioGTUBj4BK/Nj4eE9jCeCAnJxVLi7iS+08PbiZLyrQKBkJQ==``); to update,
#: change the version and recompute both with ``openssl dgst -sha384 -binary <file> | base64``.
SWAGGER_UI_VERSION = "5.34.1"
SWAGGER_UI_JS = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui-bundle.js"
SWAGGER_UI_JS_SRI = "sha384-XFYN47VzPiDY6qPtxYKg0nqUeW/upo20xf1j2SUE7gT/i35FJB4cuS/71Iegzk8Z"
SWAGGER_UI_CSS = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui.css"
SWAGGER_UI_CSS_SRI = "sha384-4c3vsE5f+trhFyHrFrLM1fFGUn531NIaC7dcqEWIJdoRQJ5CkJbSuSCwXLpaS1KF"


def _swagger_ui_page(openapi_url: str, title: str) -> str:
    """FastAPI's Swagger UI page with the pinned files, ``integrity`` and ``crossorigin``, and no external favicon."""
    from fastapi.openapi.docs import get_swagger_ui_html

    html = bytes(
        get_swagger_ui_html(
            openapi_url=openapi_url,
            title=title,
            swagger_js_url=SWAGGER_UI_JS,
            swagger_css_url=SWAGGER_UI_CSS,
            swagger_favicon_url="data:,",
        ).body
    ).decode()
    replacements = {
        f'<script src="{SWAGGER_UI_JS}">': (
            f'<script src="{SWAGGER_UI_JS}" integrity="{SWAGGER_UI_JS_SRI}" crossorigin="anonymous"'
            ' referrerpolicy="no-referrer">'
        ),
        f'href="{SWAGGER_UI_CSS}">': (
            f'href="{SWAGGER_UI_CSS}" integrity="{SWAGGER_UI_CSS_SRI}" crossorigin="anonymous"'
            ' referrerpolicy="no-referrer">'
        ),
    }
    for old, new in replacements.items():
        if html.count(old) != 1:  # a FastAPI change of the template must not silently drop the pin
            raise RuntimeError(f"unexpected Swagger UI template: {old!r} not found exactly once")
        html = html.replace(old, new)
    return html


def _install_api_docs(app: FastAPI, mode: str) -> None:
    """``/v1/openapi.json`` and ``/v1/docs`` per ``security.api_docs`` (public/authenticated/disabled)."""
    if mode == "disabled":
        return
    from fastapi import Depends
    from fastapi.responses import HTMLResponse, JSONResponse

    deps = [Depends(resolve_principal)] if mode == "authenticated" else []

    @app.get("/v1/openapi.json", include_in_schema=False, dependencies=deps)
    def openapi_document() -> JSONResponse:
        return JSONResponse(app.openapi())

    @app.get("/v1/docs", include_in_schema=False, dependencies=deps)
    def swagger_ui() -> HTMLResponse:
        return HTMLResponse(_swagger_ui_page("/v1/openapi.json", "Axentra API"))


def create_app(
    settings: Settings | None = None, *, axentra: Axentra | None = None, start: bool = True
) -> FastAPI:
    ax = axentra or Axentra.from_settings(settings or load_settings())
    install_access_log_redaction()
    install_db_error_redaction()

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
        # Served by _install_api_docs according to security.api_docs (app.openapi() always works).
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
        license_info={"name": "Proprietary", "identifier": "LicenseRef-Proprietary"},
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
    install_openapi(app, PUBLIC_ROUTES)
    _install_api_docs(app, ax.settings.api_docs_mode)
    _install_limits(app, ax)

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
        # The path can carry a credential (``/v1/files/download/<signed token>``): log it redacted (B-01).
        path = redact_text(request.url.path)
        logger.info(
            "%s %s %s",
            request.method,
            path,
            response.status_code,
            extra={
                "method": request.method,
                "path": path,
                "status": response.status_code,
                "duration_ms": round(duration, 1),
            },
        )
        return response

    from axentra.api.observability import install_observability

    install_observability(app, ax)

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
