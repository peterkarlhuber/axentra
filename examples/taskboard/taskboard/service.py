"""Taskboard's domain logic: projects, tasks, attachments, plans and signup.

This module is what a product team writes. Everything security-relevant is delegated to Axentra:

- **who is calling**: a :class:`~axentra.core.context.Principal` built by Axentra from a session
  cookie, a bearer session token or an API key (see ``taskboard.app``);
- **may they do it**: ``ax.authz.require(principal, permission, product_id, tenant_id)``, which
  also gives ``404`` for workspaces the caller has no relation to (no existence oracle);
- **which rows are visible**: every query runs in ``ax.db.transaction(DbScope.tenant(...))``, so
  PostgreSQL row-level security confines it to one workspace even if a ``WHERE`` is forgotten;
- **what happened**: ``ax.audit.record(tx, ...)`` in the same transaction as the change;
- **how much may they use**: the ``tasks_created`` usage meter with limits from the billing plan;
- **files**: ``ax.storage`` (size limits, content sniffing, quotas, local or S3 backends).

There are no FastAPI imports here; the HTTP layer is ``taskboard.app``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import date, datetime
import logging
import re
from typing import Any, Literal

from psycopg import errors as pg_errors
from pydantic import BaseModel

from axentra.core.context import Principal
from axentra.core.errors import (
    AxentraError,
    Conflict,
    Forbidden,
    NotFound,
    PreconditionFailed,
    ValidationFailed,
)
from axentra.core.ids import new_id
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import DbScope, Tx
from axentra.platform import Axentra
from axentra.storage.models import FileInfo
from axentra.storage.service import Source
from axentra.tenancy.models import Tenant

logger = logging.getLogger("taskboard")

#: The usage meter Taskboard records one unit on per created task.
METER = "tasks_created"
#: Plans Taskboard provisions: free (50 tasks per month) and pro (unlimited, 9 EUR/month).
PLANS: dict[str, dict[str, Any]] = {
    "free": {
        "name": "Free",
        "description": "50 new tasks per month",
        "prices": [],
        "entitlements": {f"limit.{METER}": 50, "feature.attachments": True},
    },
    "pro": {
        "name": "Pro",
        "description": "Unlimited tasks",
        "prices": [{"amount_minor": 900, "currency": "EUR", "interval": "month"}],
        "entitlements": {f"limit.{METER}": None, "feature.attachments": True},
    },
}
FREE_LIMIT = 50
TaskStatus = Literal["todo", "doing", "done"]
STATUSES: tuple[str, ...] = ("todo", "doing", "done")
_IDEMPOTENCY_KEY = re.compile(r"^[\x21-\x7e]{1,200}$")
#: Taskboard's own trusted principal for bookkeeping the user is not asked to hold permissions for
#: (recording usage, cleaning up attachments, subscribing new workspaces to the free plan).
SYSTEM = Principal.system("taskboard")


class Project(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: str
    archived: bool
    version: int
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class Task(BaseModel):
    id: str
    tenant_id: str
    project_id: str
    title: str
    description: str
    status: TaskStatus
    assignee_id: str | None
    due_date: date | None
    version: int
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class TaskQuota(BaseModel):
    """The ``tasks_created`` meter of the current month."""

    used: float
    limit: float | None
    remaining: float | None
    period_end: datetime | None


class WorkspaceUsage(BaseModel):
    plan: str | None
    subscription_status: str | None
    tasks_created: TaskQuota


class SignupResult(BaseModel):
    user_id: str
    workspace: Tenant
    plan: str


@dataclass(frozen=True, slots=True)
class CreatedTask:
    task: Task
    replayed: bool


def _project(row: Mapping[str, Any]) -> Project:
    return Project.model_validate(dict(row))


def _task(row: Mapping[str, Any]) -> Task:
    return Task.model_validate(dict(row))


def _text(value: str, what: str, *, min_len: int, max_len: int) -> str:
    value = value.strip()
    if not min_len <= len(value) <= max_len:
        raise ValidationFailed(f"{what} must be {min_len}-{max_len} characters")
    return value


class TaskboardService:
    """All Taskboard operations. Each public method takes the caller's principal first."""

    def __init__(self, ax: Axentra, product_id: str) -> None:
        self.ax = ax
        self.product_id = product_id

    # -- helpers -------------------------------------------------------------------------------

    def _require(self, principal: Principal, permission: str, tenant_id: str) -> None:
        # Raises NotFound (no relation to the workspace) or Forbidden (related, but not allowed).
        self.ax.authz.require(principal, permission, self.product_id, tenant_id)

    def _scope(self, tenant_id: str) -> DbScope:
        return DbScope.tenant(self.product_id, tenant_id)

    def _audit(
        self,
        tx: Tx,
        principal: Principal,
        action: str,
        tenant_id: str,
        target_type: str,
        target_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.ax.audit.record(
            tx,
            principal,
            action,
            target_type=target_type,
            target_id=target_id,
            product_id=self.product_id,
            tenant_id=tenant_id,
            details=details,
        )

    # -- provisioning (run once per deployment, idempotent) ------------------------------------

    def bootstrap(self) -> None:
        """Create the ``tasks_created`` meter and the free/pro plans if they do not exist."""
        pid = self.product_id
        if not any(m.key == METER for m in self.ax.usage.list_meters(SYSTEM, pid)):
            self.ax.usage.create_meter(
                SYSTEM,
                pid,
                key=METER,
                name="Tasks created",
                unit="tasks",
                aggregation="sum",
                reset_period="month",
                description="One unit per created task; limited by the plan entitlement limit.tasks_created",
                # Workspaces without a subscription get the free limit, too.
                default_limit=FREE_LIMIT,
                default_enforcement="hard",
            )
        existing = {p.key for p in self.ax.billing.list_plans(SYSTEM, pid)}
        for key, plan in PLANS.items():
            if key not in existing:
                self.ax.billing.create_plan(SYSTEM, pid, key=key, **plan)

    # -- workspaces ----------------------------------------------------------------------------

    def signup(
        self,
        *,
        email: str,
        name: str,
        password: str,
        workspace_name: str,
        workspace_slug: str,
        ip: str | None,
    ) -> SignupResult:
        """Public self-service signup: a new user owning a new workspace on the free plan."""
        bucket = f"taskboard:signup:{ip or 'unknown'}"
        self.ax.identity.hit(bucket, 10)  # 10 signups per minute and client address (atomic count)
        workspace_name = _text(workspace_name, "workspace name", min_len=1, max_len=200)

        def new_user() -> str:
            with self.ax.db.transaction(DbScope.platform()) as tx:
                uid = self.ax.identity.create_user(tx, email=email, name=name, password=password)
                self.ax.audit.record(tx, SYSTEM, "taskboard.signup", target_type="user", target_id=uid)
            return uid

        tenant, user_id = self._new_workspace(workspace_name, workspace_slug, new_user)
        return SignupResult(user_id=user_id, workspace=tenant, plan="free")

    def create_workspace(self, principal: Principal, *, name: str, slug: str) -> Tenant:
        """A signed-in user creates another workspace that they own."""
        user_id = principal.user_id
        if user_id is None:
            raise Forbidden("only users can create workspaces")
        name = _text(name, "workspace name", min_len=1, max_len=200)
        return self._new_workspace(name, slug, lambda: user_id)[0]

    def _new_workspace(self, name: str, slug: str, owner: Callable[[], str]) -> tuple[Tenant, str]:
        """Create the tenant first (slug conflicts fail before anything else exists), then the owner
        (``owner()`` may create the user), the membership and the free subscription. Any failure
        deletes the half-created tenant again (cascading to members and subscription)."""
        # tenancy.create_tenant authorizes "tenants:create" (a product permission). Taskboard, not
        # the end user, decides that anyone may open a workspace, so it acts as SYSTEM here.
        tenant = self.ax.tenancy.create_tenant(SYSTEM, self.product_id, slug=slug, name=name)
        try:
            user_id = owner()
            self.ax.tenancy.set_member(
                SYSTEM, self.product_id, tenant.id, role="tenant_owner", user_id=user_id
            )
            self.ax.billing.create_subscription(SYSTEM, self.product_id, tenant.id, plan="free")
        except BaseException:
            self.ax.tenancy.delete_tenant(SYSTEM, self.product_id, tenant.id)
            raise
        return self.ax.tenancy.get_tenant(SYSTEM, self.product_id, tenant.id), user_id

    def change_plan(self, principal: Principal, tenant_id: str, plan: str) -> WorkspaceUsage:
        """Workspace owners/admins switch between free and pro.

        ``billing:manage`` is a product permission that tenant owners do not have; Taskboard decides
        that a workspace admin (``members:manage``) may choose the plan and then acts as SYSTEM.
        With the ``manual`` billing provider no payment is collected (a demo); with Stripe this
        would be ``ax.billing.create_checkout`` instead.
        """
        if plan not in PLANS:
            raise ValidationFailed(f"plan must be one of: {', '.join(PLANS)}")
        self._require(principal, "members:manage", tenant_id)
        try:
            current = self.ax.billing.get_subscription(SYSTEM, self.product_id, tenant_id)
        except NotFound:
            current = None
        if current is None or current.status == "canceled":
            self.ax.billing.create_subscription(SYSTEM, self.product_id, tenant_id, plan=plan)
        elif current.plan_key != plan:
            self.ax.billing.change_plan(SYSTEM, self.product_id, tenant_id, plan=plan)
        return self.usage(principal, tenant_id)

    def usage(self, principal: Principal, tenant_id: str) -> WorkspaceUsage:
        summary = self.ax.usage.summary(principal, self.product_id, tenant_id)  # usage:read
        meter = next((m for m in summary if m.meter == METER), None)
        ent = self.ax.billing.entitlements(self.product_id, tenant_id)
        quota = TaskQuota(
            used=float(meter.value) if meter else 0.0,
            limit=float(meter.limit) if meter and meter.limit is not None else None,
            remaining=float(meter.remaining) if meter and meter.remaining is not None else None,
            period_end=meter.period_end if meter else None,
        )
        return WorkspaceUsage(
            plan=ent.plan_key, subscription_status=ent.subscription_status, tasks_created=quota
        )

    # -- projects ------------------------------------------------------------------------------

    def list_projects(
        self, principal: Principal, tenant_id: str, *, limit: int | None = None, cursor: str | None = None
    ) -> Page[Project]:
        self._require(principal, "records:read", tenant_id)
        n = clamp_limit(limit)
        after = decode_cursor(cursor, ("str",))
        sql = "SELECT * FROM taskboard_projects WHERE product_id = %s AND tenant_id = %s"
        params: list[Any] = [self.product_id, tenant_id]
        if after:
            sql += " AND id > %s"
            params.append(after[0])
        params.append(n + 1)
        with self.ax.db.transaction(self._scope(tenant_id), read_only=True) as tx:
            rows = tx.all(sql + " ORDER BY id LIMIT %s", params)
        items = [_project(r) for r in rows[:n]]
        return Page[Project](
            items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > n else None
        )

    def create_project(
        self, principal: Principal, tenant_id: str, *, name: str, description: str = ""
    ) -> Project:
        self._require(principal, "records:write", tenant_id)
        name = _text(name, "name", min_len=1, max_len=200)
        description = _text(description, "description", min_len=0, max_len=5000)
        project_id = new_id("prj")
        with self.ax.db.transaction(self._scope(tenant_id)) as tx:
            row = tx.one(
                "INSERT INTO taskboard_projects (id, product_id, tenant_id, name, description, created_by)"
                " VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (project_id, self.product_id, tenant_id, name, description, principal.actor.id),
            )
            self._audit(
                tx, principal, "taskboard.project.create", tenant_id, "project", project_id, {"name": name}
            )
        assert row is not None
        return _project(row)

    def _project_row(self, tx: Tx, tenant_id: str, project_id: str, *, lock: bool = False) -> dict[str, Any]:
        row = tx.one(
            "SELECT * FROM taskboard_projects WHERE id = %s AND product_id = %s AND tenant_id = %s"
            + (" FOR UPDATE" if lock else ""),
            (project_id, self.product_id, tenant_id),
        )
        if row is None:
            raise NotFound("project not found")
        return row

    def get_project(self, principal: Principal, tenant_id: str, project_id: str) -> Project:
        self._require(principal, "records:read", tenant_id)
        with self.ax.db.transaction(self._scope(tenant_id), read_only=True) as tx:
            return _project(self._project_row(tx, tenant_id, project_id))

    def update_project(
        self,
        principal: Principal,
        tenant_id: str,
        project_id: str,
        changes: Mapping[str, Any],
        *,
        if_match: int | None = None,
    ) -> Project:
        self._require(principal, "records:write", tenant_id)
        sets: dict[str, Any] = {}
        if "name" in changes:
            sets["name"] = _text(str(changes["name"]), "name", min_len=1, max_len=200)
        if "description" in changes:
            sets["description"] = _text(str(changes["description"]), "description", min_len=0, max_len=5000)
        if "archived" in changes:
            sets["archived"] = bool(changes["archived"])
        with self.ax.db.transaction(self._scope(tenant_id)) as tx:
            row = self._project_row(tx, tenant_id, project_id, lock=True)
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the project was changed by someone else")
            if sets:
                assignments = ", ".join(f"{k} = %s" for k in sets)
                row = (
                    tx.one(
                        f"UPDATE taskboard_projects SET {assignments}, version = version + 1, updated_at = now()"
                        " WHERE id = %s RETURNING *",
                        [*sets.values(), project_id],
                    )
                    or row
                )
                self._audit(
                    tx,
                    principal,
                    "taskboard.project.update",
                    tenant_id,
                    "project",
                    project_id,
                    {"fields": sorted(sets)},
                )
        return _project(row)

    def delete_project(
        self, principal: Principal, tenant_id: str, project_id: str, *, if_match: int | None = None
    ) -> None:
        """Delete a project, its tasks (foreign key cascade) and their attachments. Audited."""
        self._require(principal, "records:write", tenant_id)
        with self.ax.db.transaction(self._scope(tenant_id)) as tx:
            row = self._project_row(tx, tenant_id, project_id, lock=True)
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the project was changed by someone else")
            tasks = tx.scalar(
                "SELECT count(*) FROM taskboard_tasks WHERE product_id = %s AND tenant_id = %s AND project_id = %s",
                (self.product_id, tenant_id, project_id),
            )
            tx.execute("DELETE FROM taskboard_projects WHERE id = %s", (project_id,))
            self._audit(
                tx,
                principal,
                "taskboard.project.delete",
                tenant_id,
                "project",
                project_id,
                {"name": row["name"], "tasks": int(tasks or 0)},
            )
        self._delete_files(tenant_id, {"taskboard.project_id": project_id})

    # -- tasks ---------------------------------------------------------------------------------

    def list_tasks(
        self,
        principal: Principal,
        tenant_id: str,
        project_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Task]:
        self._require(principal, "records:read", tenant_id)
        if status is not None and status not in STATUSES:
            raise ValidationFailed(f"status must be one of: {', '.join(STATUSES)}")
        n = clamp_limit(limit)
        after = decode_cursor(cursor, ("str",))
        sql = "SELECT * FROM taskboard_tasks WHERE product_id = %s AND tenant_id = %s AND project_id = %s"
        params: list[Any] = [self.product_id, tenant_id, project_id]
        if status:
            sql += " AND status = %s"
            params.append(status)
        if after:
            sql += " AND id > %s"
            params.append(after[0])
        params.append(n + 1)
        with self.ax.db.transaction(self._scope(tenant_id), read_only=True) as tx:
            self._project_row(tx, tenant_id, project_id)
            rows = tx.all(sql + " ORDER BY id LIMIT %s", params)
        items = [_task(r) for r in rows[:n]]
        return Page[Task](items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > n else None)

    def _check_assignee(self, tenant_id: str, assignee_id: str | None) -> None:
        if assignee_id is None:
            return
        members = self.ax.tenancy.list_members(SYSTEM, self.product_id, tenant_id)
        if not any(m.user_id == assignee_id for m in members):
            raise ValidationFailed("the assignee must be a member of the workspace")

    def _task_by_key(self, tenant_id: str, key: str) -> Task | None:
        with self.ax.db.transaction(self._scope(tenant_id), read_only=True) as tx:
            row = tx.one(
                "SELECT * FROM taskboard_tasks WHERE product_id = %s AND tenant_id = %s AND idempotency_key = %s",
                (self.product_id, tenant_id, key),
            )
        return _task(row) if row else None

    def create_task(
        self,
        principal: Principal,
        tenant_id: str,
        project_id: str,
        *,
        title: str,
        description: str = "",
        status: str = "todo",
        assignee_id: str | None = None,
        due_date: date | None = None,
        idempotency_key: str | None = None,
    ) -> CreatedTask:
        """Create a task and count it against the ``tasks_created`` limit (429 when exhausted).

        Metering uses an Axentra usage *reservation*: reserve one unit (refused with
        ``QuotaExceeded`` when the plan limit is reached, race-free across concurrent requests),
        insert the task, then commit the reservation. If the insert fails the reservation is
        released. With an ``Idempotency-Key``, a retried request returns the original task.
        """
        self._require(principal, "records:write", tenant_id)
        title = _text(title, "title", min_len=1, max_len=300)
        description = _text(description, "description", min_len=0, max_len=20000)
        if status not in STATUSES:
            raise ValidationFailed(f"status must be one of: {', '.join(STATUSES)}")
        if idempotency_key is not None:
            if not _IDEMPOTENCY_KEY.match(idempotency_key):
                raise ValidationFailed("the idempotency key must be 1-200 printable ASCII characters")
            existing = self._task_by_key(tenant_id, idempotency_key)
            if existing is not None:
                return CreatedTask(existing, replayed=True)
        with self.ax.db.transaction(self._scope(tenant_id), read_only=True) as tx:
            self._project_row(tx, tenant_id, project_id)  # 404 before anything is reserved
        self._check_assignee(tenant_id, assignee_id)

        reservation = self.ax.usage.reserve(
            SYSTEM,
            self.product_id,
            tenant_id,
            METER,
            1,
            ttl_seconds=60,
            idempotency_key=f"taskboard:create:{idempotency_key}" if idempotency_key else None,
        )
        task_id = new_id("tsk")
        try:
            with self.ax.db.transaction(self._scope(tenant_id)) as tx:
                row = tx.one(
                    "INSERT INTO taskboard_tasks (id, product_id, tenant_id, project_id, title, description, status,"
                    " assignee_id, due_date, idempotency_key, created_by)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                    (
                        task_id,
                        self.product_id,
                        tenant_id,
                        project_id,
                        title,
                        description,
                        status,
                        assignee_id,
                        due_date,
                        idempotency_key,
                        principal.actor.id,
                    ),
                )
                self._audit(
                    tx,
                    principal,
                    "taskboard.task.create",
                    tenant_id,
                    "task",
                    task_id,
                    {"project_id": project_id, "title": title},
                )
        except pg_errors.UniqueViolation:
            # A concurrent request with the same Idempotency-Key won; return its task.
            self.ax.usage.release_reservation(SYSTEM, self.product_id, tenant_id, reservation.id)
            winner = self._task_by_key(tenant_id, idempotency_key or "")
            if winner is None:
                raise Conflict("the task could not be created; retry") from None
            return CreatedTask(winner, replayed=True)
        except pg_errors.ForeignKeyViolation:
            self.ax.usage.release_reservation(SYSTEM, self.product_id, tenant_id, reservation.id)
            raise NotFound("project not found") from None
        except BaseException:
            self.ax.usage.release_reservation(SYSTEM, self.product_id, tenant_id, reservation.id)
            raise
        try:
            self.ax.usage.commit_reservation(
                SYSTEM, self.product_id, tenant_id, reservation.id, properties={"task_id": task_id}
            )
        except AxentraError:
            # The task exists; the reservation expires after 60 s and the unit is not counted.
            logger.warning("could not commit the usage reservation of task %s", task_id, exc_info=True)
        assert row is not None
        return CreatedTask(_task(row), replayed=False)

    def _task_row(self, tx: Tx, tenant_id: str, task_id: str, *, lock: bool = False) -> dict[str, Any]:
        row = tx.one(
            "SELECT * FROM taskboard_tasks WHERE id = %s AND product_id = %s AND tenant_id = %s"
            + (" FOR UPDATE" if lock else ""),
            (task_id, self.product_id, tenant_id),
        )
        if row is None:
            raise NotFound("task not found")
        return row

    def get_task(self, principal: Principal, tenant_id: str, task_id: str) -> Task:
        self._require(principal, "records:read", tenant_id)
        with self.ax.db.transaction(self._scope(tenant_id), read_only=True) as tx:
            return _task(self._task_row(tx, tenant_id, task_id))

    def update_task(
        self,
        principal: Principal,
        tenant_id: str,
        task_id: str,
        changes: Mapping[str, Any],
        *,
        if_match: int | None = None,
    ) -> Task:
        """Partial update; only the keys present in ``changes`` are touched."""
        self._require(principal, "records:write", tenant_id)
        sets: dict[str, Any] = {}
        if "title" in changes:
            sets["title"] = _text(str(changes["title"]), "title", min_len=1, max_len=300)
        if "description" in changes:
            sets["description"] = _text(str(changes["description"]), "description", min_len=0, max_len=20000)
        if "status" in changes:
            if changes["status"] not in STATUSES:
                raise ValidationFailed(f"status must be one of: {', '.join(STATUSES)}")
            sets["status"] = changes["status"]
        if "assignee_id" in changes:
            self._check_assignee(tenant_id, changes["assignee_id"])
            sets["assignee_id"] = changes["assignee_id"]
        if "due_date" in changes:
            sets["due_date"] = changes["due_date"]
        if "project_id" in changes:
            sets["project_id"] = str(changes["project_id"])
        try:
            with self.ax.db.transaction(self._scope(tenant_id)) as tx:
                row = self._task_row(tx, tenant_id, task_id, lock=True)
                if if_match is not None and row["version"] != if_match:
                    raise PreconditionFailed("the task was changed by someone else")
                if sets:
                    assignments = ", ".join(f"{k} = %s" for k in sets)
                    row = (
                        tx.one(
                            f"UPDATE taskboard_tasks SET {assignments}, version = version + 1, updated_at = now()"
                            " WHERE id = %s RETURNING *",
                            [*sets.values(), task_id],
                        )
                        or row
                    )
                    self._audit(
                        tx,
                        principal,
                        "taskboard.task.update",
                        tenant_id,
                        "task",
                        task_id,
                        {"fields": sorted(sets)},
                    )
        except pg_errors.ForeignKeyViolation:
            # The composite foreign key refuses a project of another workspace like a missing one.
            raise NotFound("project not found") from None
        return _task(row)

    def delete_task(
        self, principal: Principal, tenant_id: str, task_id: str, *, if_match: int | None = None
    ) -> None:
        """Delete a task and its attachments. Writes the audit event ``taskboard.task.delete``."""
        self._require(principal, "records:write", tenant_id)
        with self.ax.db.transaction(self._scope(tenant_id)) as tx:
            row = self._task_row(tx, tenant_id, task_id, lock=True)
            if if_match is not None and row["version"] != if_match:
                raise PreconditionFailed("the task was changed by someone else")
            tx.execute("DELETE FROM taskboard_tasks WHERE id = %s", (task_id,))
            self._audit(
                tx,
                principal,
                "taskboard.task.delete",
                tenant_id,
                "task",
                task_id,
                {"project_id": row["project_id"], "title": row["title"], "status": row["status"]},
            )
        self._delete_files(tenant_id, {"taskboard.task_id": task_id})

    # -- attachments (ax.storage) --------------------------------------------------------------

    def _storage(self) -> Any:
        if self.ax.storage is None:
            raise NotFound("attachments are not enabled (storage module is off)")
        return self.ax.storage

    def attach(
        self,
        principal: Principal,
        tenant_id: str,
        task_id: str,
        data: Source,
        *,
        name: str,
        content_type: str | None = None,
    ) -> FileInfo:
        """Store a file for a task. Needs ``records:write`` here and ``files:write`` in ax.storage."""
        storage = self._storage()
        self._require(principal, "records:write", tenant_id)
        with self.ax.db.transaction(self._scope(tenant_id), read_only=True) as tx:
            task = self._task_row(tx, tenant_id, task_id)
        info: FileInfo = storage.upload(
            principal,
            self.product_id,
            tenant_id,
            data,
            name=name,
            content_type=content_type,
            metadata={"taskboard.task_id": task_id, "taskboard.project_id": task["project_id"]},
        )
        return info

    def list_attachments(self, principal: Principal, tenant_id: str, task_id: str) -> list[FileInfo]:
        storage = self._storage()
        self.get_task(principal, tenant_id, task_id)
        page: Page[FileInfo] = storage.list(
            principal, self.product_id, tenant_id, metadata={"taskboard.task_id": task_id}, limit=200
        )
        return page.items

    def open_attachment(
        self, principal: Principal, tenant_id: str, task_id: str, file_id: str
    ) -> tuple[FileInfo, Iterator[bytes]]:
        storage = self._storage()
        self.get_task(principal, tenant_id, task_id)
        info: FileInfo = storage.get(principal, self.product_id, tenant_id, file_id)  # files:read
        if info.metadata.get("taskboard.task_id") != task_id:
            raise NotFound("file not found")  # a file of the workspace, but not of this task
        opened: tuple[FileInfo, Iterator[bytes]] = storage.open(
            principal, self.product_id, tenant_id, file_id
        )
        return opened

    def _delete_files(self, tenant_id: str, metadata: dict[str, Any]) -> None:
        if self.ax.storage is None:
            return
        while True:
            page = self.ax.storage.list(SYSTEM, self.product_id, tenant_id, metadata=metadata, limit=200)
            if not page.items:
                return
            for f in page.items:
                try:
                    self.ax.storage.delete(SYSTEM, self.product_id, tenant_id, f.id)
                except NotFound:
                    continue
