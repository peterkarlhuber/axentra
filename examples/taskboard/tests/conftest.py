"""Fixtures for the Taskboard tests.

They reuse the repository's PostgreSQL fixtures (``tests/conftest.py``): a fresh database per test
session and a NON-superuser role, so row-level security is enforced on Taskboard's own tables.
Without ``AXENTRA_TEST_DATABASE_URL`` the tests are skipped (and reported as skipped).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
TASKBOARD_ROOT = HERE.parent  # examples/taskboard (the "taskboard" package and walkthrough.py)
REPO_ROOT = HERE.parents[2]
for p in (str(TASKBOARD_ROOT), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi.testclient import TestClient  # noqa: E402
from taskboard.app import create_taskboard_app, taskboard_migrations  # noqa: E402
from taskboard.service import SYSTEM, TaskboardService  # noqa: E402
from tests.conftest import make_settings, pg_urls, truncate_all  # noqa: E402, F401

from axentra.data.database import DbScope  # noqa: E402
from axentra.platform import Axentra  # noqa: E402

PASSWORD = "taskboard password 123"


class Client:
    """A browser-like client: session cookie after login plus the CSRF header on unsafe methods."""

    def __init__(self, app: Any, **headers: str) -> None:
        self.http = TestClient(app, base_url="http://testserver", headers=headers)
        self.csrf: str | None = None

    def request(self, method: str, url: str, **kw: Any) -> Any:
        headers = dict(kw.pop("headers", None) or {})
        if method != "GET" and self.csrf:
            headers.setdefault("X-Axentra-CSRF", self.csrf)
        return self.http.request(method, url, headers=headers, **kw)

    def get(self, url: str, **kw: Any) -> Any:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Any:
        return self.request("POST", url, **kw)

    def patch(self, url: str, **kw: Any) -> Any:
        return self.request("PATCH", url, **kw)

    def put(self, url: str, **kw: Any) -> Any:
        return self.request("PUT", url, **kw)

    def delete(self, url: str, **kw: Any) -> Any:
        return self.request("DELETE", url, **kw)

    def login(self, email: str, password: str = PASSWORD) -> Client:
        r = self.post("/axentra/v1/auth/login/password", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        return self


@dataclass
class Board:
    ax: Axentra
    app: Any
    svc: TaskboardService

    @property
    def product_id(self) -> str:
        return self.svc.product_id

    def client(self, **headers: str) -> Client:
        return Client(self.app, **headers)

    def signup(self, who: str, workspace: str) -> tuple[Client, str]:
        """Sign up ``who@example.com`` with a new workspace and return (logged-in client, tenant id)."""
        anon = self.client()
        r = anon.post(
            "/api/signup",
            json={
                "email": f"{who}@example.com",
                "name": who,
                "password": PASSWORD,
                "workspace_name": workspace.title(),
                "workspace_slug": workspace,
            },
        )
        assert r.status_code == 201, r.text
        return self.client().login(f"{who}@example.com"), r.json()["workspace"]["id"]

    def member(self, tenant_id: str, who: str, role: str) -> Client:
        """Add an existing-or-new user to a workspace with ``role`` and return a logged-in client."""
        with self.ax.db.transaction(DbScope.platform()) as tx:
            uid = self.ax.identity.create_user(tx, email=f"{who}@example.com", name=who, password=PASSWORD)
        self.ax.tenancy.set_member(SYSTEM, self.product_id, tenant_id, role=role, user_id=uid)
        return self.client().login(f"{who}@example.com")

    def api_key(self, permissions: list[str], tenant_id: str | None = None) -> Client:
        key = self.ax.api_keys.create_key(
            SYSTEM, self.product_id, name="test key", permissions=permissions, tenant_id=tenant_id
        )
        return self.client(Authorization=f"Bearer {key.secret}")


@pytest.fixture
def board(pg_urls: dict[str, str], tmp_path: Path) -> Iterator[Board]:  # noqa: F811
    truncate_all(pg_urls["admin"])  # cascades to taskboard_* through the tenant foreign keys
    settings = make_settings(
        pg_urls,
        mode="single",
        product={"slug": "taskboard", "name": "Taskboard"},
        _storage_path=str(tmp_path / "files"),
    )
    ax = Axentra.from_settings(settings)
    ax.register_migrations(taskboard_migrations())
    ax.migrate()  # idempotent: applies taskboard:0001 once per test database
    ax.start()
    try:
        app = create_taskboard_app(ax, start=False)
        yield Board(ax=ax, app=app, svc=app.state.taskboard)
    finally:
        ax.close()


@pytest.fixture
def new_client(board: Board) -> Callable[[], Any]:
    return lambda: TestClient(board.app, base_url="http://testserver")
