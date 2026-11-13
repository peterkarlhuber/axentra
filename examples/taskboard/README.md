# Taskboard: a demo SaaS built on Axentra

Taskboard is a small multi-tenant project and task management backend. Each customer has one or
more **workspaces** (Axentra tenants) with projects, tasks and file attachments. It is a
realistic example of a product backend that **uses Axentra as a library** and adds only its own
domain code. It does not depend on Nodestro, orkexa or Axentra Studio, and it copies no Axentra
internals: it uses the public `Axentra` facade, its services and a few public helpers of
`axentra.api`.

## Architecture

```
                     browser / SDK / integration (API key)
                                   |
                                   v
 +----------------------------- one process (uvicorn) ------------------------------+
 |  Taskboard FastAPI app (taskboard.app)                                           |
 |                                                                                  |
 |   /api/...                               /axentra/v1/...                         |
 |   Taskboard routes                       Axentra API, mounted sub-application    |
 |   (signup, projects, tasks,              (login/logout, sessions, /me, members,  |
 |    attachments, usage, plan)              invitations, roles, API keys, audit,   |
 |        |  Depends(resolve_principal)      usage, billing, files ...)             |
 |        v                                           |                             |
 |   TaskboardService (taskboard.service)             |                             |
 |        |  ax.authz  ax.audit  ax.usage             |                             |
 |        |  ax.billing  ax.storage  ax.tenancy       |                             |
 |        v                                           v                             |
 |   +------------------- Axentra instance (axentra.platform.Axentra) ------------+ |
 |   |  identity · tenancy · access · audit · usage · billing · storage · db pool | |
 |   +----------------------------------------------------------------------------+ |
 +-----------------------------------|----------------------------------------------+
                                     v
              PostgreSQL: axentra_* tables + taskboard_projects, taskboard_tasks
              (row-level security forced on all of them; app role without BYPASSRLS)
```

**Login.** Taskboard does not implement login. The Axentra API is mounted under `/axentra` in the
same process, so the browser calls `POST /axentra/v1/auth/login/password`. The session cookie
has `Path=/`, so it authenticates Taskboard's routes, too. Taskboard's routes use Axentra's
`resolve_principal` dependency, which accepts the session cookie (with the `X-Axentra-CSRF`
header on unsafe methods), a session token as `Authorization: Bearer` and Axentra API keys
(`axk_...`). One process, one connection pool, one audit trail. This is the "library + HTTP"
combination. OIDC login works the same way (`/axentra/v1/auth/oidc/{provider}/start`) once
providers are configured. Set `security.public_url` to the URL including `/axentra`.

## What Taskboard writes and what it gets from Axentra

| Taskboard writes (about 1,300 lines incl. docstrings) | Axentra provides |
|---|---|
| `migrations/0001_projects_tasks.sql`: two tables with `product_id`/`tenant_id`, foreign keys to `axentra_tenants`, RLS policy | Migration runner (namespaces, checksums, advisory lock), `axentra_scope_allows()` policy function, tenant deletion cascades |
| `TaskboardService`: CRUD, validation, If-Match, idempotent create, attachment linking, plan switch policy | `ax.authz.require` (deny by default, 404 for foreign tenants), `ax.db.transaction(DbScope.tenant(...))`, `ax.audit.record` in the same transaction, pagination helpers, error classes |
| `POST /api/signup` (user + workspace + free plan) | `ax.identity.create_user` (Argon2id, password policy), throttling, `ax.tenancy` (tenants, memberships), `ax.billing` (plans, subscriptions, entitlements) |
| Metering policy: one `tasks_created` unit per task | `ax.usage` meters, race-free reservations, plan limits from billing entitlements, 429 problem details |
| Attachment endpoints | `ax.storage`: streaming upload with size limit, content sniffing, blocked types, quotas, local/S3 backends, audit |
| Nothing | Sessions, CSRF, API keys, roles, invitations, operator UI (Axentra Studio), audit queries, metrics |

## Endpoints

All paths under `/api/workspaces/{tenant_id}` need a principal with the listed permission in that
workspace. A caller without any relation to the workspace gets `404`.

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/api/health` | public | `{status}` |
| POST | `/api/signup` `{email, name, password, workspace_name, workspace_slug}` | public, 10/min per IP | `201 {user_id, workspace: Tenant, plan}` |
| POST | `/api/workspaces` `{name, slug}` | signed-in user | `201 Tenant` (caller is owner, free plan) |
| GET | `.../usage` | `usage:read` | `{plan, subscription_status, tasks_created: {used, limit, remaining, period_end}}` |
| PUT | `.../plan` `{plan: free\|pro}` | `members:manage` (workspace owner/admin) | same as usage |
| GET/POST | `.../projects` | `records:read` / `records:write` | `Page[Project]` / `201 Project` |
| GET/PATCH/DELETE | `.../projects/{project_id}` | `records:read` / `records:write` (`If-Match`) | `Project` (+`ETag`) / `204` (tasks cascade, audited) |
| GET | `.../projects/{project_id}/tasks?status&limit&cursor` | `records:read` | `Page[Task]` |
| POST | `.../projects/{project_id}/tasks` (optional `Idempotency-Key`) | `records:write` | `201 Task`, `200` on replay, `429 quota_exceeded` |
| GET/PATCH/DELETE | `.../tasks/{task_id}` | `records:read` / `records:write` (`If-Match`) | `Task` (+`ETag`) / `204` (audited `taskboard.task.delete`) |
| POST | `.../tasks/{task_id}/attachments` (multipart, field `file`) | `records:write` + `files:write` | `201 FileInfo` |
| GET | `.../tasks/{task_id}/attachments` | `records:read` + `files:read` | `FileInfo[]` |
| GET | `.../tasks/{task_id}/attachments/{file_id}` | `records:read` + `files:read` | file bytes (attachment) |

`Project`: `{id, tenant_id, name, description, archived, version, created_by, created_at, updated_at}`.
`Task`: `{id, tenant_id, project_id, title, description, status: todo|doing|done, assignee_id, due_date, version, created_by, created_at, updated_at}`.
Errors are RFC 9457 problem details from Axentra's handlers.

Authorization uses Axentra's built-in tenant roles: `tenant_owner`/`tenant_admin` (everything,
including the plan), `member` (projects, tasks, files) and `viewer` (read-only). Product-defined
permissions are not available yet (see `docs/TODO.md`), so the tables reuse `records:*`.

## Plans and metering

`TaskboardService.bootstrap()` (run at startup and by `python -m taskboard bootstrap`) creates:

- the meter `tasks_created` (`sum`, monthly reset, hard enforcement, default limit 50);
- the plan `free`: `limit.tasks_created = 50` (no price);
- the plan `pro`: `limit.tasks_created = null` (unlimited), 9 EUR/month.

Signup subscribes the new workspace to `free`. Creating a task reserves one unit with
`ax.usage.reserve(...)`. That call raises `QuotaExceeded` (HTTP 429) once 50 tasks were created
this month. Taskboard then inserts the task and commits the reservation. Deleting tasks does not
return quota, because the meter counts creations. `PUT .../plan {"plan": "pro"}` lifts the limit.
The billing provider is `manual` here, so no payment is collected. With Stripe the endpoint
would start `ax.billing.create_checkout` instead.

## Run it

```bash
# From the repository root: a virtualenv with Axentra and the example.
python3.12 -m venv .venv && .venv/bin/pip install --upgrade "pip>=25.0"
.venv/bin/pip install -r requirements/tabrion.txt -e ".[dev]" && .venv/bin/pip install -e examples/taskboard
createdb taskboard
export AXENTRA_CONFIG=examples/taskboard/taskboard.toml
export AXENTRA__DATABASE__URL=postgresql://$USER@127.0.0.1:5432/taskboard   # development only
.venv/bin/taskboard migrate          # Axentra's migrations, then the "taskboard" namespace
.venv/bin/taskboard serve            # http://127.0.0.1:8090/api/docs and /axentra/v1/docs
.venv/bin/python examples/taskboard/walkthrough.py --base-url http://127.0.0.1:8090
```

With Docker Compose (own PostgreSQL, owner/app roles, migration job):
`deploy/compose/docker-compose.taskboard.yml` (see the header of that file).

The walkthrough signs up two workspaces, logs in, creates a project and tasks (one idempotently),
edits with `If-Match`, attaches and downloads a file, shows `404` for the other workspace,
prints the quota, deletes a task and upgrades to pro. It exits non-zero on any unexpected answer.

## Tests

`examples/taskboard/tests` runs in the repository's normal `pytest` run (it is in `testpaths`)
on the same PostgreSQL fixtures, with a non-superuser role so RLS is really enforced:

- sign-in with cookie + CSRF, bearer session token, failures;
- two workspaces isolated over HTTP (every endpoint `404`), composite foreign key across tenants;
- RLS on `taskboard_*`: unfiltered queries see one tenant, `WITH CHECK` refuses foreign rows,
  an unscoped connection sees nothing, `FORCE` is set, tenant deletion cascades;
- permission denial: viewer, member, read-only and foreign-tenant API keys;
- quota: the 51st task gets `429`, pro lifts the limit, the limit holds under 12 concurrent requests;
- attachments: upload/list/download, cross-task/cross-tenant `404`, blocked HTML, cleanup on delete;
- audit of task and project deletions; route-protection check.

## Limitations

- Demo, not a product: no frontend (the API docs at `/api/docs` and the walkthrough show the flow),
  no e-mail verification, no password reset.
- Signup reveals whether an e-mail or workspace slug is taken (`409`), like most signups.
- Task creation and usage commit are two transactions. If the process dies between them, the task
  exists, the reservation expires after 60 s and that task is not counted.
- A failed signup after the user was created (very unlikely) leaves the user without a workspace.
  Workspace creation is compensated (the half-created tenant is deleted).
- Attachments are linked through file metadata (`taskboard.task_id`). Files are deleted after the
  task's transaction. If that fails, they remain in Axentra storage and are visible in its API.
