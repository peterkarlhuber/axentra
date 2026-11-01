"""``GET /metrics``: Prometheus text exposition, protected by an optional bearer token.

Policy (secure default):

- ``observability.metrics_enabled = false``: 404.
- ``observability.metrics_token_ref`` set: ``Authorization: Bearer <token>`` is required (401).
- no token and ``environment = production``: 404 (metrics stay disabled until a token is set).
- no token outside production: open (local development, CI).
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response

from axentra.api.context import Ax
from axentra.core.errors import NotFound, Unauthenticated

router = APIRouter(tags=["observability"])
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    summary="Prometheus metrics (bearer token from observability.metrics_token_ref)",
    responses={200: {"content": {"text/plain": {}}}},
)
def metrics(request: Request, ax: Ax) -> Response:
    registry = getattr(request.app.state, "metrics", None)
    if registry is None or not ax.settings.observability.metrics_enabled:
        raise NotFound("metrics are disabled")
    token: str | None = getattr(request.app.state, "metrics_token", None)
    if token is None:
        if ax.settings.is_production:
            raise NotFound("metrics are disabled")
    else:
        auth = request.headers.get("authorization", "")
        sent = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        if not sent or not hmac.compare_digest(sent.encode(), token.encode()):
            registry.auth_failures.inc(reason="metrics_token")
            raise Unauthenticated("a valid metrics bearer token is required")
    return Response(registry.render(), media_type=CONTENT_TYPE)
