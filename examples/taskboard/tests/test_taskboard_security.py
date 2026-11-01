"""Taskboard: sign-in, tenant isolation (HTTP and RLS), permissions, quota, attachments, audit."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI
import psycopg
from psycopg.rows import dict_row
import pytest
from taskboard.app import check_routes
from taskboard.service import SYSTEM

from axentra.core.errors import ConfigurationError
from axentra.core.ids import new_id
from axentra.data.database import DbScope

pytestmark = pytest.mark.postgres


def _project(client, tid: str, name: str = "P") -> str:
    r = client.post(f"/api/workspaces/{tid}/projects", json={"name": name})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _task(client, tid: str, pid: str, title: str = "T", **headers: str):
    return client.post(f"/api/workspaces/{tid}/projects/{pid}/tasks", json={"title": title}, headers=headers)


# -- sign-in -----------------------------------------------------------------------------------


def test_sign_in_session_and_bearer_token(board):
    alice, tid = board.signup("alice", "acme")
    assert alice.get(f"/api/workspaces/{tid}/projects").json() == {"items": [], "next_cursor": None}

    # Unauthenticated and wrong password.
    anon = board.client()
    assert anon.get(f"/api/workspaces/{tid}/projects").status_code == 401
    r = anon.post("/axentra/v1/auth/login/password", json={"email": "alice@example.com", "password": "nope"})
    assert r.status_code == 401

    # A cookie session needs the CSRF header on unsafe methods.
    no_csrf = board.client().login("alice@example.com")
    no_csrf.csrf = None
    r = no_csrf.post(f"/api/workspaces/{tid}/projects", json={"name": "x"})
    assert r.status_code == 403 and r.json()["code"] == "forbidden"

    # A session token as bearer (SDKs/CLIs): no cookie, no CSRF.
    new = board.ax.identity.login_password(
        "alice@example.com", "taskboard password 123", ip=None, user_agent="t"
    )
    bearer = board.client(Authorization=f"Bearer {new.token}")
    assert bearer.post(f"/api/workspaces/{tid}/projects", json={"name": "via bearer"}).status_code == 201

    # Signup validation: a taken slug and a weak password fail without leaving anything behind.
    eve = {"email": "eve@example.com", "password": "taskboard password 123", "workspace_name": "X"}
    assert anon.post("/api/signup", json={**eve, "workspace_slug": "acme"}).status_code == 409
    weak = {**eve, "password": "short", "workspace_slug": "eve-ws"}
    assert anon.post("/api/signup", json=weak).status_code == 422
    slugs = {t.slug for t in board.ax.tenancy.list_tenants(SYSTEM, board.product_id).items}
    assert slugs == {"acme"}
    # ... so eve can sign up afterwards with a free slug (her e-mail was not consumed).
    assert anon.post("/api/signup", json={**eve, "workspace_slug": "eve-ws"}).status_code == 201
    assert anon.post("/api/signup", json={**eve, "workspace_slug": "eve-2"}).status_code == 409


def test_signed_in_user_creates_second_workspace(board):
    alice, t1 = board.signup("alice", "acme")
    r = alice.post("/api/workspaces", json={"name": "Side project", "slug": "side"})
    assert r.status_code == 201, r.text
    t2 = r.json()["id"]
    me = alice.get("/axentra/v1/me").json()
    assert {t["tenant"]["id"] for p in me["products"] for t in p["tenants"]} == {t1, t2}
    assert alice.get(f"/api/workspaces/{t2}/usage").json()["plan"] == "free"


# -- isolation ---------------------------------------------------------------------------------


def test_two_workspaces_are_isolated_over_http(board):
    alice, ta = board.signup("alice", "acme")
    bob, tb = board.signup("bob", "globex")
    pa = _project(alice, ta)
    task = _task(alice, ta, pa).json()

    for method, url in (
        ("GET", f"/api/workspaces/{ta}/projects"),
        ("POST", f"/api/workspaces/{ta}/projects"),
        ("GET", f"/api/workspaces/{ta}/projects/{pa}"),
        ("GET", f"/api/workspaces/{ta}/projects/{pa}/tasks"),
        ("GET", f"/api/workspaces/{ta}/tasks/{task['id']}"),
        ("PATCH", f"/api/workspaces/{ta}/tasks/{task['id']}"),
        ("DELETE", f"/api/workspaces/{ta}/tasks/{task['id']}"),
        ("GET", f"/api/workspaces/{ta}/usage"),
        ("PUT", f"/api/workspaces/{ta}/plan"),
    ):
        body = {"name": "x", "plan": "pro", "title": "x"} if method in ("POST", "PATCH", "PUT") else None
        r = bob.request(method, url, json=body)
        assert r.status_code == 404, (method, url, r.text)

    # Bob addressing alice's ids through his own workspace finds nothing either.
    assert bob.get(f"/api/workspaces/{tb}/projects/{pa}").status_code == 404
    assert bob.get(f"/api/workspaces/{tb}/tasks/{task['id']}").status_code == 404
    assert _task(bob, tb, pa).status_code == 404

    # Moving a task into another workspace's project is refused by the composite foreign key.
    pb = _project(bob, tb)
    tbt = _task(bob, tb, pb).json()
    r = bob.patch(f"/api/workspaces/{tb}/tasks/{tbt['id']}", json={"project_id": pa})
    assert r.status_code == 404

    # Assigning a task to a user outside the workspace is refused.
    alice_id = alice.get("/axentra/v1/me").json()["user"]["id"]
    r = bob.patch(f"/api/workspaces/{tb}/tasks/{tbt['id']}", json={"assignee_id": alice_id})
    assert r.status_code == 422


def test_rls_confines_taskboard_tables(board, pg_urls):
    """Even without WHERE clauses, PostgreSQL shows and accepts only rows of the scope's tenant."""
    alice, ta = board.signup("alice", "acme")
    bob, tb = board.signup("bob", "globex")
    _task(alice, ta, _project(alice, ta))
    _task(bob, tb, _project(bob, tb))
    ax, pid = board.ax, board.product_id

    with ax.db.transaction(DbScope.tenant(pid, ta), read_only=True) as tx:
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM taskboard_tasks")} == {ta}
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM taskboard_projects")} == {ta}
    with ax.db.transaction(DbScope.product(pid), read_only=True) as tx:
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM taskboard_tasks")} == {ta, tb}

    # WITH CHECK: a transaction scoped to tenant A cannot write rows of tenant B.
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        ax.db.transaction(DbScope.tenant(pid, ta)) as tx,
    ):
        tx.execute(
            "INSERT INTO taskboard_projects (id, product_id, tenant_id, name) VALUES (%s, %s, %s, 'smuggled')",
            (new_id("prj"), pid, tb),
        )
    # UPDATE/DELETE of another tenant's rows silently affect nothing.
    with ax.db.transaction(DbScope.tenant(pid, ta)) as tx:
        assert tx.execute("UPDATE taskboard_tasks SET title = 'x' WHERE tenant_id = %s", (tb,)) == 0
        assert tx.execute("DELETE FROM taskboard_projects WHERE tenant_id = %s", (tb,)) == 0

    # A raw connection of the application role without any scope sees nothing at all.
    with psycopg.connect(pg_urls["app"], row_factory=dict_row) as conn:
        assert conn.execute("SELECT count(*) AS n FROM taskboard_tasks").fetchone()["n"] == 0
        flags = conn.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname LIKE 'taskboard_%%'"
            " AND relkind = 'r'"
        ).fetchall()
    assert {f["relname"] for f in flags} == {"taskboard_projects", "taskboard_tasks"}
    assert all(f["relrowsecurity"] and f["relforcerowsecurity"] for f in flags)

    # Deleting a workspace through Axentra cascades to Taskboard's rows.
    ax.tenancy.delete_tenant(SYSTEM, pid, tb)
    with ax.db.transaction(DbScope.product(pid), read_only=True) as tx:
        assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM taskboard_tasks")} == {ta}


# -- permissions -------------------------------------------------------------------------------


def test_permission_denial(board):
    alice, tid = board.signup("alice", "acme")
    pid = _project(alice, tid)
    task = _task(alice, tid, pid).json()
    base = f"/api/workspaces/{tid}"

    # A viewer (built-in tenant role: records:read, no records:write) reads but cannot write.
    viewer = board.member(tid, "victor", "viewer")
    assert viewer.get(f"{base}/projects/{pid}/tasks").status_code == 200
    for r in (
        viewer.post(f"{base}/projects", json={"name": "x"}),
        _task(viewer, tid, pid),
        viewer.patch(f"{base}/tasks/{task['id']}", json={"status": "done"}),
        viewer.delete(f"{base}/tasks/{task['id']}"),
        viewer.delete(f"{base}/projects/{pid}"),
        viewer.put(f"{base}/plan", json={"plan": "pro"}),
    ):
        assert r.status_code == 403, r.text
        assert r.json()["code"] == "forbidden"

    # A plain member may work with tasks but not change the plan (members:manage).
    member = board.member(tid, "mia", "member")
    assert _task(member, tid, pid).status_code == 201
    assert member.put(f"{base}/plan", json={"plan": "pro"}).status_code == 403

    # API keys: a read-only key is refused writes; a key bound to another tenant gets 404.
    reader = board.api_key(["records:read"], tenant_id=tid)
    assert reader.get(f"{base}/projects").status_code == 200
    assert reader.post(f"{base}/projects", json={"name": "x"}).status_code == 403
    _, other = board.signup("bob", "globex")
    foreign = board.api_key(["records:read", "records:write"], tenant_id=other)
    assert foreign.get(f"{base}/projects").status_code == 404
    writer = board.api_key(["records:read", "records:write"], tenant_id=tid)
    assert _task(writer, tid, pid, "from integration").status_code == 201

    # Nothing changed by the refused calls.
    assert alice.get(f"{base}/tasks/{task['id']}").json()["version"] == 1


def test_every_route_is_protected(board):
    from fastapi import APIRouter

    # The real app: every route was checked (and the public ones are only health and signup).
    assert check_routes(board.app) >= 18

    app = FastAPI()
    r = APIRouter(prefix="/api")

    @r.get("/leak")
    def leak() -> dict[str, str]:
        return {}

    app.include_router(r)
    with pytest.raises(ConfigurationError, match="GET /api/leak"):
        check_routes(app)


# -- quota -------------------------------------------------------------------------------------


def test_free_plan_limits_task_creation(board):
    alice, tid = board.signup("alice", "acme")
    pid = _project(alice, tid)
    for i in range(50):
        r = _task(alice, tid, pid, f"task {i}")
        assert r.status_code == 201, (i, r.text)
    r = _task(alice, tid, pid, "one too many")
    assert r.status_code == 429
    problem = r.json()
    assert problem["code"] == "quota_exceeded"
    assert problem["meter"] == "tasks_created" and problem["limit"] == 50 and problem["used"] == 50
    assert r.headers["Retry-After"]
    usage = alice.get(f"/api/workspaces/{tid}/usage").json()
    assert usage["plan"] == "free"
    assert usage["tasks_created"] | {"period_end": None} == {
        "used": 50,
        "limit": 50,
        "remaining": 0,
        "period_end": None,
    }

    # Deleting tasks does not give quota back: the meter counts creations in the month.
    first = alice.get(f"/api/workspaces/{tid}/projects/{pid}/tasks?limit=1").json()["items"][0]
    assert alice.delete(f"/api/workspaces/{tid}/tasks/{first['id']}").status_code == 204
    assert _task(alice, tid, pid).status_code == 429

    # An idempotent replay of an existing task is not counted and not refused.
    # Upgrading to pro lifts the limit (plan entitlement limit.tasks_created = null).
    assert alice.put(f"/api/workspaces/{tid}/plan", json={"plan": "pro"}).status_code == 200
    r = _task(alice, tid, pid, "pro task", **{"Idempotency-Key": "k1"})
    assert r.status_code == 201
    assert _task(alice, tid, pid, "pro task", **{"Idempotency-Key": "k1"}).status_code == 200
    usage = alice.get(f"/api/workspaces/{tid}/usage").json()
    assert usage["plan"] == "pro" and usage["tasks_created"]["used"] == 51
    assert usage["tasks_created"]["limit"] is None

    # Back to free: over the limit again; other workspaces are unaffected.
    assert alice.put(f"/api/workspaces/{tid}/plan", json={"plan": "free"}).status_code == 200
    assert _task(alice, tid, pid).status_code == 429
    bob, tb = board.signup("bob", "globex")
    assert _task(bob, tb, _project(bob, tb)).status_code == 201


def test_quota_holds_under_concurrency(board):
    alice, tid = board.signup("alice", "acme")
    pid = _project(alice, tid)
    board.ax.usage.set_quota(SYSTEM, board.product_id, tid, "tasks_created", limit=5, enforcement="hard")

    def create(i: int) -> int:
        return int(_task(board.client().login("alice@example.com"), tid, pid, f"t{i}").status_code)

    with ThreadPoolExecutor(max_workers=6) as pool:
        codes = list(pool.map(create, range(12)))
    assert codes.count(201) == 5
    assert codes.count(429) == 7
    with board.ax.db.transaction(DbScope.tenant(board.product_id, tid), read_only=True) as tx:
        assert tx.scalar("SELECT count(*) FROM taskboard_tasks") == 5


# -- attachments and audit ---------------------------------------------------------------------


def test_file_attachments(board):
    alice, tid = board.signup("alice", "acme")
    pid = _project(alice, tid)
    task = _task(alice, tid, pid).json()
    other = _task(alice, tid, pid, "other").json()
    base = f"/api/workspaces/{tid}/tasks/{task['id']}/attachments"

    r = alice.post(base, files={"file": ("notes.txt", b"hello taskboard\n", "text/plain")})
    assert r.status_code == 201, r.text
    info = r.json()
    assert info["name"] == "notes.txt" and info["size"] == 16
    assert info["metadata"] == {"taskboard.task_id": task["id"], "taskboard.project_id": pid}
    assert [f["id"] for f in alice.get(base).json()] == [info["id"]]
    d = alice.get(f"{base}/{info['id']}")
    assert d.status_code == 200 and d.content == b"hello taskboard\n"
    assert "attachment" in d.headers["content-disposition"]

    # The file is stored by Axentra storage and visible in its API, too.
    assert alice.get(f"/axentra/v1/products/{board.product_id}/tenants/{tid}/files").status_code == 200

    # Not reachable through another task, another workspace, or by a viewer upload.
    assert alice.get(f"/api/workspaces/{tid}/tasks/{other['id']}/attachments/{info['id']}").status_code == 404
    bob, _ = board.signup("bob", "globex")
    assert bob.get(f"{base}/{info['id']}").status_code == 404
    assert bob.post(base, files={"file": ("x.txt", b"x", "text/plain")}).status_code == 404
    viewer = board.member(tid, "victor", "viewer")
    assert viewer.get(f"{base}/{info['id']}").status_code == 200
    assert viewer.post(base, files={"file": ("x.txt", b"x", "text/plain")}).status_code == 403

    # Dangerous content is refused by Axentra storage.
    r = alice.post(base, files={"file": ("x.html", b"<html><script>alert(1)</script>", "text/html")})
    assert r.status_code == 415

    # Deleting the task deletes its attachments.
    assert alice.delete(f"/api/workspaces/{tid}/tasks/{task['id']}").status_code == 204
    files = board.ax.storage.list(SYSTEM, board.product_id, tid)
    assert files.items == []


def test_task_deletion_is_audited(board):
    alice, tid = board.signup("alice", "acme")
    pid = _project(alice, tid)
    task = _task(alice, tid, pid, "secret plan").json()
    alice_id = alice.get("/axentra/v1/me").json()["user"]["id"]
    assert (
        alice.delete(f"/api/workspaces/{tid}/tasks/{task['id']}", headers={"If-Match": "7"}).status_code
        == 412
    )
    assert (
        alice.delete(f"/api/workspaces/{tid}/tasks/{task['id']}", headers={"If-Match": "1"}).status_code
        == 204
    )
    assert alice.delete(f"/api/workspaces/{tid}/tasks/{task['id']}").status_code == 404

    page = board.ax.audit.list(DbScope.product(board.product_id), action="taskboard.task.delete")
    assert len(page.items) == 1
    ev = page.items[0]
    assert (ev.actor_id, ev.tenant_id, ev.target_id) == (alice_id, tid, task["id"])
    assert ev.details["title"] == "secret plan" and ev.details["project_id"] == pid

    # Project deletion cascades to its tasks and is audited with the count.
    _task(alice, tid, pid)
    assert alice.delete(f"/api/workspaces/{tid}/projects/{pid}").status_code == 204
    page = board.ax.audit.list(DbScope.product(board.product_id), action="taskboard.project.delete")
    assert page.items[0].details["tasks"] == 1
    assert alice.get(f"/api/workspaces/{tid}/projects/{pid}/tasks").status_code == 404
