from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from axentra import API_VERSION, __version__
from axentra.api.context import Ax
from axentra.identity.passwords import MAX_PASSWORD_LENGTH
from axentra.tenancy.models import Product

router = APIRouter(prefix="/v1", tags=["meta"])


class ApiVersion(BaseModel):
    major: int
    minor: int


class OidcProviderInfo(BaseModel):
    id: str
    name: str


class PasswordPolicy(BaseModel):
    """What a new password must satisfy, so clients can check before sending (the server checks again)."""

    min_length: int
    max_length: int


class AuthInfo(BaseModel):
    password: bool
    oidc: list[OidcProviderInfo]
    password_policy: PasswordPolicy


class Meta(BaseModel):
    name: Literal["axentra"] = "axentra"
    version: str
    api_version: ApiVersion
    mode: Literal["single", "multi"]
    environment: str
    modules: list[str]
    product: Product | None
    auth: AuthInfo
    setup_required: bool


class Health(BaseModel):
    status: Literal["ok", "unavailable"]
    checks: dict[str, bool]


@router.get("/meta", response_model=Meta, summary="Server version, API version, mode and login options")
def get_meta(ax: Ax) -> Meta:
    return Meta(
        version=__version__,
        api_version=ApiVersion(major=API_VERSION[0], minor=API_VERSION[1]),
        mode=ax.settings.mode.value,
        environment=ax.settings.environment.value,
        modules=ax.settings.modules,
        product=ax.single_product(),
        auth=AuthInfo(
            password=ax.settings.security.password_login,
            oidc=[OidcProviderInfo(id=p.id, name=p.name) for p in ax.settings.oidc],
            password_policy=PasswordPolicy(
                min_length=ax.settings.security.password_min_length, max_length=MAX_PASSWORD_LENGTH
            ),
        ),
        setup_required=ax.identity.setup_required(),
    )


@router.get("/health/live", response_model=Health, summary="Liveness: the process answers")
def live() -> Health:
    return Health(status="ok", checks={"process": True})


@router.get(
    "/health/ready",
    response_model=Health,
    summary="Readiness: the database is reachable",
    responses={503: {"model": Health}},
)
def ready(ax: Ax, request: Request) -> Health | JSONResponse:
    checks = {"database": ax.db.ping()}
    extra = getattr(request.app.state, "readiness_checks", {})
    for name, fn in extra.items():
        checks[name] = bool(fn())
    if all(checks.values()):
        return Health(status="ok", checks=checks)
    return JSONResponse(Health(status="unavailable", checks=checks).model_dump(), status_code=503)
