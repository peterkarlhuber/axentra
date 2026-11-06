"""The OpenAPI document of the ``/v1`` API: FastAPI's generated schema plus what it cannot infer.

FastAPI documents only its own ``422 HTTPValidationError``, which is not what Axentra answers. Every
error is an RFC 9457 problem (``application/problem+json``, ADR 0009), so :func:`build_openapi`

- adds a ``Problem`` schema and documents it as the ``default`` response of every operation (and as
  the body of every documented 4xx/5xx response without one), replacing ``HTTPValidationError``;
- declares the three credentials (``securitySchemes``): the browser session cookie, a bearer token
  (an API key ``axk_...`` or a session token) and the ``X-API-Key`` header, required by every
  operation except the public ones (:data:`axentra.api.app.PUBLIC_ROUTES`, which declare
  ``security: []``).
"""

from __future__ import annotations

from collections.abc import Iterable
import copy
from typing import Any

from fastapi import FastAPI

from axentra.core.errors import PROBLEM_BASE

PROBLEM_MEDIA_TYPE = "application/problem+json"
PROBLEM_REF = {"$ref": "#/components/schemas/Problem"}

PROBLEM_SCHEMA: dict[str, Any] = {
    "title": "Problem",
    "type": "object",
    "description": "RFC 9457 problem details, the body of every error response. Clients switch on"
    " `code` (stable), never on `title`, `detail` or `type`. Some errors add members, documented with"
    " the operation (for example `errors` for validation failures, `reason` for refused invitations"
    " or password policy refusals, `permission` for `api_key_creator_lost_access`).",
    "required": ["type", "title", "status", "code", "detail"],
    "properties": {
        "type": {
            "type": "string",
            "description": f"`{PROBLEM_BASE}<code>`",
            "example": PROBLEM_BASE + "not_found",
        },
        "title": {"type": "string", "description": "Short English summary of the code"},
        "status": {"type": "integer", "description": "The HTTP status code"},
        "code": {
            "type": "string",
            "description": "Stable machine-readable error code",
            "example": "not_found",
        },
        "detail": {"type": "string", "description": "English explanation for this occurrence (no secrets)"},
        "request_id": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "description": "The request id (also in the `X-Request-ID` response header)",
        },
        "errors": {
            "type": "array",
            "description": 'Validation failures (`validation_failed`): where (`loc`, e.g. `["body", "email"]`) and what',
            "items": {"$ref": "#/components/schemas/ProblemFieldError"},
        },
    },
    "additionalProperties": True,
}
FIELD_ERROR_SCHEMA: dict[str, Any] = {
    "title": "ProblemFieldError",
    "type": "object",
    "required": ["loc", "msg"],
    "properties": {
        "loc": {"type": "array", "items": {"type": "string"}},
        "msg": {"type": "string"},
    },
}

SECURITY_SCHEMES: dict[str, Any] = {
    "sessionCookie": {
        "type": "apiKey",
        "in": "cookie",
        "name": "__Host-axentra-session",
        "description": "The browser session set by a login (`axentra-session` on plain-HTTP development"
        " servers). Writes (POST, PUT, PATCH, DELETE) also need the `X-Axentra-CSRF` header with the"
        " session's `csrf_token` and an allowed `Origin`.",
    },
    "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "description": "`Authorization: Bearer <token>`: an API key (`axk_...`) or a session token"
        " (SDKs, CLI). No CSRF header is needed.",
    },
    "apiKeyHeader": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": "An API key (`axk_...`) in its own header, as an alternative to the bearer token.",
    },
}
#: Any one of the three credentials.
SECURITY: list[dict[str, list[str]]] = [{"sessionCookie": []}, {"bearerAuth": []}, {"apiKeyHeader": []}]

_FASTAPI_VALIDATION_SCHEMAS = ("HTTPValidationError", "ValidationError")
_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "patch", "options", "head", "trace"})


def _problem_content() -> dict[str, Any]:
    return {PROBLEM_MEDIA_TYPE: {"schema": dict(PROBLEM_REF)}}


def _document_errors(operation: dict[str, Any]) -> None:
    responses: dict[str, Any] = operation.setdefault("responses", {})
    for status, response in responses.items():
        if not (status.startswith(("4", "5")) and len(status) == 3):
            continue
        content = response.get("content") or {}
        schema = (content.get("application/json") or {}).get("schema") or {}
        if schema.get("$ref", "").endswith("/HTTPValidationError"):
            response["description"] = "Validation failed (`validation_failed`, with `errors`)"
            response["content"] = _problem_content()
        elif not content:
            response["content"] = _problem_content()
    responses["default"] = {
        "description": "Error: problem details (RFC 9457)",
        "content": _problem_content(),
    }


def build_openapi(base: dict[str, Any], public_routes: Iterable[tuple[str, str]]) -> dict[str, Any]:
    """A copy of FastAPI's document ``base`` with problem responses and security schemes (see module doc)."""
    spec = copy.deepcopy(base)
    public = {(method.lower(), path) for method, path in public_routes}
    for path, item in spec.get("paths", {}).items():
        for method, operation in item.items():
            if method not in _HTTP_METHODS:
                continue
            _document_errors(operation)
            if (method, path) in public:
                operation["security"] = []
    components = spec.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    for name in _FASTAPI_VALIDATION_SCHEMAS:
        schemas.pop(name, None)
    schemas["Problem"] = PROBLEM_SCHEMA
    schemas["ProblemFieldError"] = FIELD_ERROR_SCHEMA
    components["securitySchemes"] = SECURITY_SCHEMES
    spec["security"] = SECURITY
    return spec


def install_openapi(app: FastAPI, public_routes: Iterable[tuple[str, str]]) -> None:
    """Make ``app.openapi()`` return :func:`build_openapi` of FastAPI's own document. FastAPI rebuilds
    its document when routes are added (for example by a host application after ``create_app``); the
    result here is rebuilt whenever that happens and cached otherwise."""
    routes = frozenset(public_routes)
    generate = app.openapi
    cache: dict[str, Any] = {}

    def openapi() -> dict[str, Any]:
        base = generate()
        if cache.get("base") is not base:
            cache["spec"] = build_openapi(base, routes)
            cache["base"] = base
        spec: dict[str, Any] = cache["spec"]
        return spec

    app.openapi = openapi  # type: ignore[method-assign]
