"""RFC 9457 problem details for every error the API returns."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from axentra.core.errors import AxentraError
from axentra.core.redaction import redact_text

logger = logging.getLogger("axentra.http")
PROBLEM_BASE = "https://axentra.dev/problems/"
_STATUS_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    429: "rate_limited",
}


def problem(request: Request, status: int, code: str, title: str, detail: str, **extra: Any) -> JSONResponse:
    body = {
        "type": PROBLEM_BASE + code,
        "title": title,
        "status": status,
        "code": code,
        "detail": redact_text(detail),
        "request_id": getattr(request.state, "request_id", None),
        **extra,
    }
    headers = {"Retry-After": "60"} if status == 429 else None
    return JSONResponse(body, status_code=status, media_type="application/problem+json", headers=headers)


async def axentra_error_handler(request: Request, exc: AxentraError) -> JSONResponse:
    if exc.status >= 500:
        logger.error("internal error: %s", exc, exc_info=exc)
        return problem(request, 500, "internal", "Internal error", "An internal error occurred.")
    return problem(request, exc.status, exc.code, exc.title, exc.detail, **exc.extra)


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"loc": [str(p) for p in e.get("loc", ())], "msg": str(e.get("msg", ""))} for e in exc.errors()]
    return problem(
        request, 422, "validation_failed", "Validation failed", "The request is invalid.", errors=errors
    )


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = _STATUS_CODES.get(exc.status_code, "error")
    return problem(request, exc.status_code, code, code.replace("_", " ").capitalize(), str(exc.detail))


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled error", exc_info=exc)
    return problem(request, 500, "internal", "Internal error", "An internal error occurred.")
