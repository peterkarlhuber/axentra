"""Request context: client IP (with explicit proxy trust), request ids, principal resolution, CSRF."""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated

from fastapi import Depends, Request

from axentra.core.context import Principal
from axentra.core.errors import Forbidden, Unauthenticated
from axentra.platform import Axentra

SESSION_COOKIE_SECURE = "__Host-axentra-session"
SESSION_COOKIE_DEV = "axentra-session"
LOGIN_COOKIE_SECURE = "__Host-axentra-login"
LOGIN_COOKIE_DEV = "axentra-login"
CSRF_HEADER = "x-axentra-csrf"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def get_ax(request: Request) -> Axentra:
    ax: Axentra = request.app.state.axentra
    return ax


def session_cookie_name(ax: Axentra) -> str:
    return SESSION_COOKIE_SECURE if ax.settings.secure_cookies else SESSION_COOKIE_DEV


def login_cookie_name(ax: Axentra) -> str:
    return LOGIN_COOKIE_SECURE if ax.settings.secure_cookies else LOGIN_COOKIE_DEV


def valid_request_id(value: str | None) -> bool:
    return bool(value and _REQUEST_ID.match(value))


def _trusted(peer: str | None, networks: list[str]) -> bool:
    if not peer:
        return False
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_ip(request: Request) -> str | None:
    """The client address; ``X-Forwarded-For`` counts only when the peer is a trusted proxy."""
    ax = get_ax(request)
    peer = request.client.host if request.client else None
    if _trusted(peer, ax.settings.security.trusted_proxies):
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            # Walk from the right, skipping trusted proxies; the first untrusted hop is the client.
            for hop in reversed([h.strip() for h in fwd.split(",") if h.strip()]):
                if not _trusted(hop, ax.settings.security.trusted_proxies):
                    return hop
    return peer


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip() or None
    key = request.headers.get("x-api-key")
    return key.strip() if key else None


def resolve_principal(request: Request) -> Principal:
    cached: Principal | None = getattr(request.state, "principal", None)
    if cached is not None:
        return cached
    ax = get_ax(request)
    rid = getattr(request.state, "request_id", None)
    ip = client_ip(request)
    token = _bearer(request)
    if token:
        if token.startswith("axk_"):
            principal = ax.api_keys.authenticate(token, request_id=rid, ip=ip)
        else:
            # Session tokens as bearer (SDKs, CLI): no CSRF needed, nothing is sent automatically.
            principal, info = ax.identity.resolve_session(token, request_id=rid, ip=ip)
            request.state.session_info = info
    else:
        cookie = request.cookies.get(session_cookie_name(ax))
        if not cookie:
            raise Unauthenticated()
        principal, info = ax.identity.resolve_session(cookie, request_id=rid, ip=ip)
        request.state.session_info = info
        if request.method in UNSAFE_METHODS:
            check_csrf(request, info.csrf_token)
    request.state.principal = principal
    return principal


def check_origin(request: Request) -> None:
    ax = get_ax(request)
    origin = request.headers.get("origin")
    allowed = set(ax.settings.security.allowed_origins) | {ax.settings.security.public_url.rstrip("/")}
    if origin is not None and origin.rstrip("/") not in allowed:
        raise Forbidden("cross-origin request refused")


def check_csrf(request: Request, expected: str) -> None:
    import hmac

    check_origin(request)
    sent = request.headers.get(CSRF_HEADER, "")
    if not sent or not hmac.compare_digest(sent, expected):
        raise Forbidden("missing or invalid CSRF token")


CurrentPrincipal = Annotated[Principal, Depends(resolve_principal)]
Ax = Annotated[Axentra, Depends(get_ax)]
