"""Taskboard's HTTP layer: one FastAPI process with two parts.

- ``/axentra/v1/...``: the complete Axentra API, mounted as a sub-application (login, logout,
  sessions, ``/me``, members, invitations, roles, API keys, audit, usage, billing, files ...).
  The browser logs in with ``POST /axentra/v1/auth/login/password``; the session cookie has
  ``Path=/``, so it also authenticates Taskboard's own routes.
- ``/api/...``: Taskboard's own endpoints (projects, tasks, attachments, plan). They resolve the
  caller with Axentra's ``resolve_principal`` dependency, which accepts the session cookie (with
  the CSRF header on unsafe methods), a bearer session token or an Axentra API key.

Both parts share one :class:`~axentra.platform.Axentra` instance (one connection pool).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from axentra.api.app import create_app, iter_api_routes
from axentra.api.context import CurrentPrincipal, client_ip, resolve_principal
from axentra.api.multipart import parse_upload
from axentra.api.problems import axentra_error_handler, http_error_handler, validation_error_handler
from axentra.api.routes.common import IfMatch, parse_if_match
from axentra.config.settings import DeploymentMode, Settings, load_settings
from axentra.core.errors import AxentraError, ConfigurationError, NotFound
from axentra.core.pagination import Page
from axentra.data.migrations import Migration, load_directory
from axentra.platform import Axentra
from axentra.storage import safety
from axentra.storage.models import FileInfo
from axentra.tenancy.models import Tenant
from taskboard.service import (
    SYSTEM,
    Project,
    SignupResult,
    Task,
    TaskboardService,
    TaskStatus,
    WorkspaceUsage,
)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
#: Taskboard routes that work without authentication (everything else needs a principal).
PUBLIC_ROUTES = frozenset({("GET", "/api/health"), ("POST", "/api/signup")})


def taskboard_migrations() -> list[Migration]:
    """Taskboard's schema in its own migration namespace."""
    return load_directory("taskboard", MIGRATIONS_DIR)


def resolve_product_id(ax: Axentra) -> str:
    """The product Taskboard runs as: the single product, or ``product.slug`` in multi mode."""
    slug = ax.settings.product.slug
    if ax.settings.mode is DeploymentMode.SINGLE:
        product = ax.single_product()
        if product is None:
            raise ConfigurationError("the single product does not exist yet; call ax.start() first")
        return product.id
    for product in ax.tenancy.list_products(SYSTEM):
        if product.slug == slug:
            return product.id
    raise ConfigurationError(f"multi-product mode: create the product {slug!r} first (POST /v1/products)")


# -- request bodies --------------------------------------------------------------------------------


class SignupBody(BaseModel):
    email: str = Field(max_length=320)
    name: str = Field(default="", max_length=200)
    password: str = Field(max_length=1024)
    workspace_name: str = Field(min_length=1, max_length=200)
    workspace_slug: str = Field(min_length=2, max_length=63)


class WorkspaceBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=2, max_length=63)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    archived: bool | None = None


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=20000)
    status: TaskStatus = "todo"
    assignee_id: str | None = Field(default=None, max_length=64)
    due_date: date | None = None


class TaskUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    status: TaskStatus | None = None
    assignee_id: str | None = Field(default=None, max_length=64)
    due_date: date | None = None
    project_id: str | None = Field(default=None, max_length=64)


class PlanBody(BaseModel):
    plan: str = Field(max_length=64)


class Health(BaseModel):
    status: str


# -- routes ----------------------------------------------------------------------------------------


def get_service(request: Request) -> TaskboardService:
    svc: TaskboardService | None = getattr(request.app.state, "taskboard", None)
    if svc is None:
        raise ConfigurationError("Taskboard is not started")
    return svc


Svc = Annotated[TaskboardService, Depends(get_service)]
Limit = Annotated[int | None, Query(ge=1, le=200)]
Cursor = Annotated[str | None, Query(max_length=500)]
W = "/workspaces/{tenant_id}"

router = APIRouter(prefix="/api", tags=["taskboard"])


@router.get("/health", response_model=Health)
def health() -> Health:
    return Health(status="ok")


@router.post("/signup", response_model=SignupResult, status_code=201, summary="Sign up with a new workspace")
def signup(body: SignupBody, request: Request, svc: Svc) -> SignupResult:
    return svc.signup(
        email=body.email,
        name=body.name,
        password=body.password,
        workspace_name=body.workspace_name,
        workspace_slug=body.workspace_slug,
        ip=client_ip(request),
    )


@router.post("/workspaces", response_model=Tenant, status_code=201, summary="Create another workspace")
def create_workspace(body: WorkspaceBody, principal: CurrentPrincipal, svc: Svc) -> Tenant:
    return svc.create_workspace(principal, name=body.name, slug=body.slug)


@router.get(W + "/usage", response_model=WorkspaceUsage, summary="Plan and task quota of the workspace")
def workspace_usage(tenant_id: str, principal: CurrentPrincipal, svc: Svc) -> WorkspaceUsage:
    return svc.usage(principal, tenant_id)


@router.put(W + "/plan", response_model=WorkspaceUsage, summary="Switch the plan (workspace admins)")
def set_plan(tenant_id: str, body: PlanBody, principal: CurrentPrincipal, svc: Svc) -> WorkspaceUsage:
    return svc.change_plan(principal, tenant_id, body.plan)


@router.get(W + "/projects", response_model=Page[Project])
def list_projects(
    tenant_id: str, principal: CurrentPrincipal, svc: Svc, limit: Limit = None, cursor: Cursor = None
) -> Page[Project]:
    return svc.list_projects(principal, tenant_id, limit=limit, cursor=cursor)


@router.post(W + "/projects", response_model=Project, status_code=201)
def create_project(tenant_id: str, body: ProjectCreate, principal: CurrentPrincipal, svc: Svc) -> Project:
    return svc.create_project(principal, tenant_id, name=body.name, description=body.description)


@router.get(W + "/projects/{project_id}", response_model=Project)
def get_project(
    tenant_id: str, project_id: str, principal: CurrentPrincipal, svc: Svc, response: Response
) -> Project:
    project = svc.get_project(principal, tenant_id, project_id)
    response.headers["ETag"] = f'"{project.version}"'
    return project


@router.patch(W + "/projects/{project_id}", response_model=Project)
def update_project(
    tenant_id: str,
    project_id: str,
    body: ProjectUpdate,
    principal: CurrentPrincipal,
    svc: Svc,
    if_match: IfMatch = None,
) -> Project:
    return svc.update_project(
        principal,
        tenant_id,
        project_id,
        body.model_dump(exclude_unset=True),
        if_match=parse_if_match(if_match),
    )


@router.delete(W + "/projects/{project_id}", status_code=204)
def delete_project(
    tenant_id: str, project_id: str, principal: CurrentPrincipal, svc: Svc, if_match: IfMatch = None
) -> Response:
    svc.delete_project(principal, tenant_id, project_id, if_match=parse_if_match(if_match))
    return Response(status_code=204)


@router.get(W + "/projects/{project_id}/tasks", response_model=Page[Task])
def list_tasks(
    tenant_id: str,
    project_id: str,
    principal: CurrentPrincipal,
    svc: Svc,
    status: TaskStatus | None = None,
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[Task]:
    return svc.list_tasks(principal, tenant_id, project_id, status=status, limit=limit, cursor=cursor)


@router.post(
    W + "/projects/{project_id}/tasks",
    response_model=Task,
    status_code=201,
    summary="Create a task (counts against the plan's tasks_created limit; 429 when exhausted)",
    responses={200: {"description": "Replayed: a task with this Idempotency-Key exists"}},
)
def create_task(
    tenant_id: str,
    project_id: str,
    body: TaskCreate,
    principal: CurrentPrincipal,
    svc: Svc,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
) -> Task:
    created = svc.create_task(
        principal,
        tenant_id,
        project_id,
        title=body.title,
        description=body.description,
        status=body.status,
        assignee_id=body.assignee_id,
        due_date=body.due_date,
        idempotency_key=idempotency_key,
    )
    if created.replayed:
        response.status_code = 200
    return created.task


@router.get(W + "/tasks/{task_id}", response_model=Task)
def get_task(tenant_id: str, task_id: str, principal: CurrentPrincipal, svc: Svc, response: Response) -> Task:
    task = svc.get_task(principal, tenant_id, task_id)
    response.headers["ETag"] = f'"{task.version}"'
    return task


@router.patch(W + "/tasks/{task_id}", response_model=Task)
def update_task(
    tenant_id: str,
    task_id: str,
    body: TaskUpdate,
    principal: CurrentPrincipal,
    svc: Svc,
    if_match: IfMatch = None,
) -> Task:
    return svc.update_task(
        principal, tenant_id, task_id, body.model_dump(exclude_unset=True), if_match=parse_if_match(if_match)
    )


@router.delete(W + "/tasks/{task_id}", status_code=204, summary="Delete a task (audited)")
def delete_task(
    tenant_id: str, task_id: str, principal: CurrentPrincipal, svc: Svc, if_match: IfMatch = None
) -> Response:
    svc.delete_task(principal, tenant_id, task_id, if_match=parse_if_match(if_match))
    return Response(status_code=204)


@router.post(
    W + "/tasks/{task_id}/attachments",
    response_model=FileInfo,
    status_code=201,
    summary="Attach a file (multipart/form-data, field 'file')",
)
async def upload_attachment(
    tenant_id: str, task_id: str, request: Request, principal: CurrentPrincipal, svc: Svc
) -> FileInfo:
    storage = svc.ax.storage
    if storage is None:
        raise NotFound("attachments are not enabled (storage module is off)")
    # Authorize (and check the task exists) before reading the body.
    await run_in_threadpool(svc.get_task, principal, tenant_id, task_id)
    await run_in_threadpool(svc.ax.authz.require, principal, "files:write", svc.product_id, tenant_id)
    form = await parse_upload(request, max_file_bytes=storage.max_file_bytes)
    try:
        return await run_in_threadpool(
            svc.attach,
            principal,
            tenant_id,
            task_id,
            form.file,  # type: ignore[arg-type]
            name=form.fields.get("name") or form.filename,
            content_type=form.content_type,
        )
    finally:
        form.close()


@router.get(W + "/tasks/{task_id}/attachments", response_model=list[FileInfo])
def list_attachments(tenant_id: str, task_id: str, principal: CurrentPrincipal, svc: Svc) -> list[FileInfo]:
    return svc.list_attachments(principal, tenant_id, task_id)


@router.get(
    W + "/tasks/{task_id}/attachments/{file_id}",
    response_class=StreamingResponse,
    summary="Download an attachment",
)
def download_attachment(
    tenant_id: str, task_id: str, file_id: str, principal: CurrentPrincipal, svc: Svc
) -> StreamingResponse:
    info, stream = svc.open_attachment(principal, tenant_id, task_id, file_id)
    return StreamingResponse(
        stream,
        media_type=safety.served_content_type(info.content_type),
        headers={
            "Content-Disposition": safety.content_disposition(info.name),
            "Content-Length": str(info.size),
            "Cache-Control": "private, no-store",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


# -- application factory ---------------------------------------------------------------------------


def _depends_on_principal(route: APIRoute, extra: list[Any]) -> bool:
    stack: list[Any] = list(route.dependant.dependencies) + list(extra)
    while stack:
        dep = stack.pop()
        if (getattr(dep, "call", None) or getattr(dep, "dependency", None)) is resolve_principal:
            return True
        stack.extend(getattr(dep, "dependencies", None) or [])
    return False


def check_routes(app: FastAPI) -> int:
    """Refuse to start if a Taskboard route is neither authenticated nor listed as public.

    Walks included routers with Axentra's ``iter_api_routes`` (it handles both FastAPI router
    shapes); the mounted Axentra API checks its own routes when it is created.
    """
    checked, open_routes = 0, []
    for path, route, deps in iter_api_routes(list(app.routes)):
        for method in sorted(route.methods or ()):
            if method == "HEAD":
                continue
            checked += 1
            if (method, path) not in PUBLIC_ROUTES and not _depends_on_principal(route, deps):
                open_routes.append(f"{method} {path}")
    if open_routes:
        raise ConfigurationError("Taskboard routes without authentication: " + ", ".join(sorted(open_routes)))
    if checked == 0:
        raise ConfigurationError("route protection check found no routes")
    return checked


def create_taskboard_app(
    ax: Axentra | None = None, *, settings: Settings | None = None, start: bool = True
) -> FastAPI:
    """Build the Taskboard app.

    ``start=True`` (servers): the lifespan starts Axentra, provisions the meter and plans and
    closes Axentra on shutdown. ``start=False`` (tests): ``ax`` is already started by the caller.
    Migrations are not run here: the deployment step runs ``python -m taskboard migrate``, which
    registers :func:`taskboard_migrations` with ``ax.register_migrations`` and calls ``ax.migrate()``.
    """
    ax = ax or Axentra.from_settings(settings or load_settings())

    def init(app: FastAPI) -> None:
        svc = TaskboardService(ax, resolve_product_id(ax))
        svc.bootstrap()
        app.state.taskboard = svc

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if start:
            ax.start()
            init(app)
        try:
            yield
        finally:
            if start:
                ax.close()

    app = FastAPI(
        title="Taskboard API",
        version="1.0",
        summary="Demo SaaS built on Axentra: projects and tasks per workspace.",
        lifespan=lifespan,
        openapi_url="/api/openapi.json",
        docs_url="/api/docs",
        redoc_url=None,
    )
    # resolve_principal() and the problem handlers find the Axentra instance here.
    app.state.axentra = ax
    app.add_exception_handler(AxentraError, axentra_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_error_handler)  # type: ignore[arg-type]
    app.include_router(router)
    # The whole Axentra API (identity, tenancy, access, audit, usage, billing, storage, ...).
    app.mount("/axentra", create_app(axentra=ax, start=False))

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    check_routes(app)
    if not start:
        init(app)
    return app


def app_from_env() -> Any:
    """``uvicorn --factory taskboard.app:app_from_env`` (settings from AXENTRA_CONFIG / AXENTRA__*)."""
    return create_taskboard_app()
