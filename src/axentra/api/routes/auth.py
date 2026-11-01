from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Path, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from axentra.api.context import (
    Ax,
    CurrentPrincipal,
    check_origin,
    client_ip,
    login_cookie_name,
    session_cookie_name,
)
from axentra.core.errors import NotFound, Unauthenticated
from axentra.identity.models import NewSession, Session, SessionInfo
from axentra.platform import Axentra

if TYPE_CHECKING:
    from axentra.identity.oidc import OidcService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/auth", tags=["auth"])


class PasswordLogin(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


class SetupRequest(BaseModel):
    setup_token: str = Field(max_length=200)
    email: str = Field(max_length=320)
    name: str = Field(default="", max_length=200)
    password: str = Field(max_length=1024)


def set_session_cookie(ax: Axentra, response: Response, new: NewSession) -> None:
    max_age = ax.settings.security.session_ttl_hours * 3600
    response.set_cookie(
        session_cookie_name(ax),
        new.token,
        max_age=max_age,
        httponly=True,
        secure=ax.settings.secure_cookies,
        samesite="lax",
        path="/",
    )


@router.post("/setup", response_model=SessionInfo, summary="First run: create the first platform admin")
def setup(body: SetupRequest, request: Request, response: Response, ax: Ax) -> SessionInfo:
    check_origin(request)
    new = ax.identity.complete_setup(
        body.setup_token,
        email=body.email,
        name=body.name,
        password=body.password,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    set_session_cookie(ax, response, new)
    return new.info


@router.post("/login/password", response_model=SessionInfo, summary="Log in with email and password")
def login_password(body: PasswordLogin, request: Request, response: Response, ax: Ax) -> SessionInfo:
    # Login CSRF: a cross-site page must not log the browser into an attacker's account.
    check_origin(request)
    new = ax.identity.login_password(
        body.email, body.password, ip=client_ip(request), user_agent=request.headers.get("user-agent", "")
    )
    set_session_cookie(ax, response, new)
    return new.info


@router.get("/session", response_model=SessionInfo, summary="The current session, including the CSRF token")
def get_session(principal: CurrentPrincipal, request: Request) -> SessionInfo:
    info: SessionInfo | None = getattr(request.state, "session_info", None)
    if info is None:
        raise Unauthenticated("this endpoint needs a user session")
    return info


@router.post("/logout", status_code=204, summary="End the current session")
def logout(principal: CurrentPrincipal, response: Response, ax: Ax) -> Response:
    ax.identity.logout(principal)
    out = Response(status_code=204)
    out.delete_cookie(
        session_cookie_name(ax), path="/", secure=ax.settings.secure_cookies, httponly=True, samesite="lax"
    )
    return out


@router.get("/sessions", response_model=list[Session], summary="My active sessions")
def my_sessions(principal: CurrentPrincipal, ax: Ax) -> list[Session]:
    if principal.user_id is None:
        raise Unauthenticated("this endpoint needs a user session")
    return ax.identity.list_sessions(principal.user_id, current_session=principal.session_id)


@router.delete("/sessions/{session_id}", status_code=204, summary="Revoke one of my sessions")
def revoke_my_session(session_id: str, principal: CurrentPrincipal, ax: Ax) -> Response:
    if principal.user_id is None:
        raise Unauthenticated("this endpoint needs a user session")
    ax.identity.revoke_session(principal, principal.user_id, session_id)
    return Response(status_code=204)


# -- OpenID Connect ----------------------------------------------------------------------------------

_REDIRECT: dict[int | str, dict[str, Any]] = {302: {"description": "Redirect (Location header)"}}
ProviderId = Annotated[str, Path(max_length=64, pattern=r"^[a-z0-9-]+$")]


def _login_cookie(ax: Axentra, response: Response, state: str | None) -> None:
    name = login_cookie_name(ax)
    secure = ax.settings.secure_cookies
    if state is None:
        response.delete_cookie(name, path="/", secure=secure, httponly=True, samesite="lax")
    else:
        response.set_cookie(name, state, max_age=600, path="/", secure=secure, httponly=True, samesite="lax")


def _oidc(ax: Axentra) -> OidcService:
    if ax.oidc is None:
        raise NotFound("unknown login provider")
    return ax.oidc


@router.get(
    "/oidc/{provider}/start",
    status_code=302,
    response_class=RedirectResponse,
    responses=_REDIRECT,
    summary="Start an OpenID Connect login (redirects to the identity provider)",
)
def oidc_start(
    provider: ProviderId,
    request: Request,
    ax: Ax,
    return_to: Annotated[str | None, Query(max_length=2000)] = None,
    invitation: Annotated[str | None, Query(max_length=200)] = None,
) -> Response:
    """``return_to``: a path on the API origin or an absolute URL on an allowed origin (else ``/``).
    ``invitation``: an invitation token; lets the invited email sign up and accepts the invitation."""
    from axentra.identity.oidc import OidcLoginError, login_error_url

    oidc = _oidc(ax)
    try:
        started = oidc.start(
            provider, return_to=return_to, invitation=invitation or None, ip=client_ip(request)
        )
    except OidcLoginError as exc:
        logger.warning("OIDC login for %s could not start: %s", provider, exc)
        target = login_error_url(ax.settings.security.login_page, exc.return_to, exc.code)
        return RedirectResponse(target, status_code=302)
    out = RedirectResponse(started.authorization_url, status_code=302)
    _login_cookie(ax, out, started.state)
    return out


@router.get(
    "/oidc/{provider}/callback",
    status_code=302,
    response_class=RedirectResponse,
    responses=_REDIRECT,
    summary="OpenID Connect redirect URI: completes the login and redirects to return_to",
)
def oidc_callback(
    provider: ProviderId,
    request: Request,
    ax: Ax,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    state: Annotated[str | None, Query(max_length=200)] = None,
    error: Annotated[str | None, Query(max_length=200)] = None,
) -> Response:
    """On failure the browser is sent to the login page with ``?login_error=<code>``."""
    from axentra.identity.oidc import OidcLoginError, login_error_url

    oidc = _oidc(ax)
    try:
        result = oidc.finish(
            provider,
            state=state,
            code=code,
            error=error,
            browser_state=request.cookies.get(login_cookie_name(ax)),
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
        )
    except OidcLoginError as exc:
        logger.warning("OIDC login with %s refused (%s): %s", provider, exc.code, exc)
        out = RedirectResponse(
            login_error_url(ax.settings.security.login_page, exc.return_to, exc.code), status_code=302
        )
        _login_cookie(ax, out, None)
        return out
    out = RedirectResponse(result.return_to, status_code=302)
    _login_cookie(ax, out, None)
    set_session_cookie(ax, out, result.session)
    return out
