"""Scripted walkthrough of Taskboard over HTTP (httpx).

    python examples/taskboard/walkthrough.py --base-url http://127.0.0.1:8090

Signs up two workspaces, logs in through the mounted Axentra API, creates projects and tasks,
edits with If-Match, attaches and downloads a file, shows that the other workspace sees nothing
(404), shows the task quota, deletes a task and upgrades to the pro plan. Exits non-zero if any
step does not behave as expected. The tests run the same function in-process.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
import sys
from typing import Any
import uuid

import httpx

PASSWORD = "walkthrough password 123"  # noqa: S105 (demo accounts only)


class StepFailed(Exception):
    pass


def expect(response: httpx.Response, status: int, what: str) -> Any:
    if response.status_code != status:
        raise StepFailed(f"{what}: expected HTTP {status}, got {response.status_code}: {response.text[:300]}")
    return (
        response.json() if response.content and "json" in response.headers.get("content-type", "") else None
    )


class Session:
    """One browser-like user: session cookie from the Axentra login + the CSRF header."""

    def __init__(self, client: httpx.Client) -> None:
        self.client = client
        self.csrf = ""

    def login(self, email: str, password: str) -> dict[str, Any]:
        body = expect(
            self.client.post("/axentra/v1/auth/login/password", json={"email": email, "password": password}),
            200,
            f"login {email}",
        )
        self.csrf = body["csrf_token"]
        return dict(body)

    def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        headers = dict(kw.pop("headers", None) or {})
        if method != "GET" and self.csrf:
            headers["X-Axentra-CSRF"] = self.csrf
        return self.client.request(method, url, headers=headers, **kw)


def run(
    new_client: Callable[[], httpx.Client], *, suffix: str | None = None, log: Callable[[str], None] = print
) -> dict[str, Any]:
    sfx = suffix or uuid.uuid4().hex[:8]
    expect(new_client().get("/api/health"), 200, "health")

    # 1. Self-service signup (Taskboard endpoint; creates user, workspace, free subscription).
    anon = new_client()
    users = {}
    for who, ws in (("alice", "acme"), ("bob", "globex")):
        email = f"{who}-{sfx}@example.com"
        body = expect(
            anon.post(
                "/api/signup",
                json={
                    "email": email,
                    "name": who.title(),
                    "password": PASSWORD,
                    "workspace_name": ws.title(),
                    "workspace_slug": f"{ws}-{sfx}",
                },
            ),
            201,
            f"signup {who}",
        )
        users[who] = {"email": email, "workspace": body["workspace"]["id"]}
        log(f"signed up {email} with workspace {body['workspace']['slug']} on plan {body['plan']}")

    # 2. Login through the mounted Axentra API; /axentra/v1/me lists the user's workspaces.
    alice, bob = Session(new_client()), Session(new_client())
    alice.login(users["alice"]["email"], PASSWORD)
    bob.login(users["bob"]["email"], PASSWORD)
    me = expect(alice.request("GET", "/axentra/v1/me"), 200, "me")
    tenants = [t["tenant"]["id"] for p in me["products"] for t in p["tenants"]]
    if tenants != [users["alice"]["workspace"]]:
        raise StepFailed(f"alice should see exactly her workspace, got {tenants}")
    ws = users["alice"]["workspace"]
    base = f"/api/workspaces/{ws}"
    log(f"alice logged in; workspaces: {tenants}")

    # 3. Projects and tasks.
    project = expect(
        alice.request("POST", base + "/projects", json={"name": "Launch"}), 201, "create project"
    )
    pid = project["id"]
    tasks = []
    for title in ("Write landing page", "Set up billing", "Invite the team"):
        tasks.append(
            expect(
                alice.request("POST", f"{base}/projects/{pid}/tasks", json={"title": title}),
                201,
                "create task",
            )
        )
    again = alice.request(
        "POST",
        f"{base}/projects/{pid}/tasks",
        json={"title": "Once"},
        headers={"Idempotency-Key": f"once-{sfx}"},
    )
    first = expect(again, 201, "create task with Idempotency-Key")
    replay = alice.request(
        "POST",
        f"{base}/projects/{pid}/tasks",
        json={"title": "Once"},
        headers={"Idempotency-Key": f"once-{sfx}"},
    )
    if expect(replay, 200, "replayed create")["id"] != first["id"]:
        raise StepFailed("the replayed create returned another task")
    log(f"project {pid} with {len(tasks) + 1} tasks (one created idempotently)")

    t0 = tasks[0]
    updated = expect(
        alice.request(
            "PATCH",
            f"{base}/tasks/{t0['id']}",
            json={"status": "doing"},
            headers={"If-Match": str(t0["version"])},
        ),
        200,
        "update task",
    )
    stale = alice.request(
        "PATCH", f"{base}/tasks/{t0['id']}", json={"status": "done"}, headers={"If-Match": str(t0["version"])}
    )
    expect(stale, 412, "stale If-Match")
    doing = expect(alice.request("GET", f"{base}/projects/{pid}/tasks?status=doing"), 200, "filter tasks")
    if [t["id"] for t in doing["items"]] != [updated["id"]]:
        raise StepFailed("status filter returned unexpected tasks")
    log("task moved to 'doing' with If-Match; a stale If-Match was refused with 412")

    # 4. Attachments via ax.storage.
    content = b"%PDF-1.4\n% taskboard walkthrough\n"
    up = alice.request(
        "POST",
        f"{base}/tasks/{t0['id']}/attachments",
        files={"file": ("spec.pdf", content, "application/pdf")},
    )
    file_info = expect(up, 201, "attach file")
    listed = expect(alice.request("GET", f"{base}/tasks/{t0['id']}/attachments"), 200, "list attachments")
    if [f["id"] for f in listed] != [file_info["id"]]:
        raise StepFailed("attachment list is wrong")
    down = alice.request("GET", f"{base}/tasks/{t0['id']}/attachments/{file_info['id']}")
    if down.status_code != 200 or down.content != content:
        raise StepFailed("downloaded attachment differs")
    log(f"attached {file_info['name']} ({file_info['size']} bytes) and downloaded it again")

    # 5. Isolation: bob's session cannot see or change alice's workspace (404, no existence oracle).
    for method, url in (
        ("GET", f"{base}/projects"),
        ("GET", f"{base}/projects/{pid}"),
        ("GET", f"{base}/tasks/{t0['id']}"),
        ("DELETE", f"{base}/tasks/{t0['id']}"),
        ("GET", f"{base}/tasks/{t0['id']}/attachments/{file_info['id']}"),
    ):
        expect(bob.request(method, url), 404, f"bob {method} {url}")
    bob_ws = users["bob"]["workspace"]
    if expect(bob.request("GET", f"/api/workspaces/{bob_ws}/projects"), 200, "bob projects")["items"]:
        raise StepFailed("bob's workspace should be empty")
    log("bob gets 404 for everything in alice's workspace")

    # 6. Usage and plan.
    usage = expect(alice.request("GET", f"{base}/usage"), 200, "usage")
    if (
        usage["plan"] != "free"
        or usage["tasks_created"]["used"] != 4
        or usage["tasks_created"]["limit"] != 50
    ):
        raise StepFailed(f"unexpected usage: {usage}")
    log(
        f"plan {usage['plan']}: {usage['tasks_created']['used']:.0f} of {usage['tasks_created']['limit']:.0f} tasks this month"
    )

    # 7. Delete a task (audited as taskboard.task.delete) and upgrade to pro.
    expect(alice.request("DELETE", f"{base}/tasks/{tasks[2]['id']}"), 204, "delete task")
    expect(alice.request("GET", f"{base}/tasks/{tasks[2]['id']}"), 404, "deleted task is gone")
    pro = expect(alice.request("PUT", f"{base}/plan", json={"plan": "pro"}), 200, "upgrade")
    if pro["plan"] != "pro" or pro["tasks_created"]["limit"] is not None:
        raise StepFailed(f"unexpected usage after upgrade: {pro}")
    log("deleted a task; upgraded to pro (unlimited tasks)")

    expect(alice.request("POST", "/axentra/v1/auth/logout"), 204, "logout")
    expect(alice.request("GET", f"{base}/projects"), 401, "logged out")
    log("logged out; the session no longer works")
    return {"users": users, "project_id": pid, "file_id": file_info["id"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8090")
    args = parser.parse_args(argv)
    try:
        run(lambda: httpx.Client(base_url=args.base_url, timeout=30))
    except StepFailed as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"cannot reach Taskboard at {args.base_url}: {exc}", file=sys.stderr)
        return 2
    print("walkthrough completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
