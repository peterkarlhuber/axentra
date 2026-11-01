"""The startup check refuses unauthenticated routes (regression: FastAPI 0.162 wraps included routers)."""

from __future__ import annotations

from fastapi import APIRouter
import pytest

from axentra.api.app import PUBLIC_ROUTES, check_routes, create_app, iter_api_routes
from axentra.config.settings import load_settings
from axentra.core.errors import ConfigurationError


def _app():
    return create_app(load_settings(None, environ={}, environment="test", mode="multi"), start=False)


def test_check_routes_sees_every_route():
    app = _app()
    paths = {(m, p) for p, r, _ in iter_api_routes(list(app.routes)) for m in r.methods}
    assert ("GET", "/v1/products") in paths
    assert check_routes(app) == len(
        [1 for p, r, _ in iter_api_routes(list(app.routes)) for m in r.methods if m != "HEAD"]
    )
    assert check_routes(app) > 30


def test_unprotected_route_is_refused():
    app = _app()
    router = APIRouter(prefix="/v1/oops")

    @router.get("/open")
    def open_route() -> dict[str, str]:
        return {"ok": "no auth"}

    app.include_router(router)
    with pytest.raises(ConfigurationError, match="GET /v1/oops/open"):
        check_routes(app)


def test_public_routes_exist():
    app = _app()
    paths = {(m, p) for p, r, _ in iter_api_routes(list(app.routes)) for m in r.methods}
    for entry in PUBLIC_ROUTES:
        if entry[1].startswith(("/v1/billing", "/v1/files", "/metrics")):
            continue  # registered by optional modules
        assert entry in paths, entry
