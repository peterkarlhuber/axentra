from __future__ import annotations

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from axentra.api.context import Ax, CurrentPrincipal, check_origin, client_ip, session_cookie_name
from axentra.core.errors import Unauthenticated
from axentra.identity.models import NewSession, Session, SessionInfo
from axentra.platform import Axentra

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
