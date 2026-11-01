"""Code shared by the sync and the async client (no I/O here)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import json
from typing import Any
import uuid

import httpx

from axentra_client._version import API_VERSION, __version__
from axentra_client.errors import AxentraApiError, IncompatibleApiError

CSRF_HEADER = "X-Axentra-CSRF"
CLIENT_HEADER = f"axentra-client-python/{__version__}; api={API_VERSION[0]}.{API_VERSION[1]}"
#: Session cookie names (``__Host-`` when the server runs on https).
SESSION_COOKIES = ("__Host-axentra-session", "axentra-session")
IDEMPOTENCY_KEY_MAX_LENGTH = 200
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

_STATUS_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    412: "precondition_failed",
    413: "payload_too_large",
    422: "validation_failed",
    429: "rate_limited",
}


def new_idempotency_key() -> str:
    """A fresh random idempotency key. Store it with the operation if you may retry later."""
    return str(uuid.uuid4())


def check_idempotency_key(key: str) -> str:
    if not key or len(key) > IDEMPOTENCY_KEY_MAX_LENGTH:
        raise ValueError(f"idempotency key must be 1..{IDEMPOTENCY_KEY_MAX_LENGTH} characters")
    return key


def base_headers(token: str | None, extra: Mapping[str, str] | None) -> dict[str, str]:
    headers = {"Accept": "application/json", "Axentra-Client": CLIENT_HEADER}
    if extra:
        headers.update(extra)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def query(params: Mapping[str, Any]) -> dict[str, Any]:
    """Drop ``None`` values; serialize datetimes (RFC 3339) and dicts (JSON)."""
    out: dict[str, Any] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, datetime):
            out[key] = value.isoformat()
        elif isinstance(value, dict):
            out[key] = json.dumps(value, separators=(",", ":"))
        elif isinstance(value, bool):
            out[key] = "true" if value else "false"
        else:
            out[key] = value
    return out


def if_match(version: int | None) -> dict[str, str]:
    return {} if version is None else {"If-Match": str(version)}


def api_error(response: httpx.Response) -> AxentraApiError:
    """Build an ``AxentraApiError`` from a (read) failed response."""
    body: Any = None
    try:
        body = response.json()
    except (ValueError, httpx.ResponseNotRead):
        body = None
    problem: dict[str, Any] = body if isinstance(body, dict) else {}
    code = problem.get("code")
    if not isinstance(code, str) or not code:
        code = _STATUS_CODES.get(response.status_code, "internal" if response.status_code >= 500 else "error")
    detail = problem.get("detail")
    if not isinstance(detail, str):
        try:
            detail = response.text[:500]
        except httpx.ResponseNotRead:
            detail = ""
    retry = response.headers.get("retry-after")
    request_id = problem.get("request_id") or response.headers.get("x-request-id")
    errors = problem.get("errors")
    return AxentraApiError(
        response.status_code,
        code,
        title=str(problem.get("title") or response.reason_phrase),
        detail=detail,
        request_id=request_id if isinstance(request_id, str) else None,
        errors=errors if isinstance(errors, list) else [],
        problem=problem,
        retry_after=int(retry) if retry and retry.isdigit() else None,
    )


def session_token_from(response: httpx.Response) -> str | None:
    """The session token from a login/setup response's ``Set-Cookie`` header."""
    for line in response.headers.get_list("set-cookie"):
        pair = line.split(";", 1)[0]
        name, _, value = pair.partition("=")
        if name.strip() in SESSION_COOKIES and value.strip():
            return value.strip().strip('"')
    return None


def assert_compatible(api_version: Any, required: tuple[int, int] = API_VERSION) -> tuple[int, int]:
    """The version rule of API_CONVENTIONS: same major, server minor >= required minor."""
    major = (
        getattr(api_version, "major", None) if not isinstance(api_version, dict) else api_version.get("major")
    )
    minor = (
        getattr(api_version, "minor", None) if not isinstance(api_version, dict) else api_version.get("minor")
    )
    if not isinstance(major, int) or not isinstance(minor, int) or isinstance(major, bool):
        raise IncompatibleApiError("unparseable", None, required)
    server = (major, minor)
    if major != required[0]:
        raise IncompatibleApiError("major_mismatch", server, required)
    if minor < required[1]:
        raise IncompatibleApiError("minor_too_low", server, required)
    return server
