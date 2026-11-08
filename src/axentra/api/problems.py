"""RFC 9457 problem details for every error the API returns."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from axentra.core.db_errors import DbErrorRedactionFilter
from axentra.core.errors import PROBLEM_BASE, AxentraError, ProblemInfo, problem_details
from axentra.core.errors import problem as make_problem

__all__ = [
    "PROBLEM_BASE",
    "axentra_error_handler",
    "http_error_handler",
    "problem",
    "problem_response",
    "unhandled_error_handler",
    "validation_error_handler",
]

logger = logging.getLogger("axentra.http")
# The handlers below log internal errors with their traceback; a database error in it must not carry the values
# of its DETAIL text (B-06-1). On the logger, so that every handler of the record sees the redacted text.
logger.addFilter(DbErrorRedactionFilter())
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


def problem_response(request: Request, info: ProblemInfo) -> JSONResponse:
    """Render a :class:`~axentra.core.errors.ProblemInfo` as ``application/problem+json``."""
    return JSONResponse(
        info.body(request_id=getattr(request.state, "request_id", None)),
        status_code=info.status,
        media_type="application/problem+json",
        headers=info.headers or None,
    )


def problem(request: Request, status: int, code: str, title: str, detail: str, **extra: Any) -> JSONResponse:
    return problem_response(request, make_problem(status, code, title, detail, extra=extra))


async def axentra_error_handler(request: Request, exc: AxentraError) -> JSONResponse:
    info = problem_details(exc)
    if info.internal:
        logger.error("internal error: %s", exc, exc_info=exc)
    return problem_response(request, info)


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
    return problem_response(request, problem_details(exc))
