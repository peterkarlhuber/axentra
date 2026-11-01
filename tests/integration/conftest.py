from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient
import pytest

from axentra.api.app import create_app
from axentra.platform import Axentra
from tests.conftest import make_settings, truncate_all

pytestmark = pytest.mark.postgres

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "correct horse battery staple"
ORIGIN = "http://studio.test"


@pytest.fixture
def ax_factory(pg_urls: dict[str, str], tmp_path):  # type: ignore[no-untyped-def]
    created: list[Axentra] = []

    def make(**overrides: Any) -> Axentra:
        truncate_all(pg_urls["admin"])
        overrides.setdefault("_storage_path", str(tmp_path / "storage"))
        ax = Axentra.from_settings(make_settings(pg_urls, **overrides))
        ax.start()
        created.append(ax)
        return ax

    yield make
    for ax in created:
        ax.close()


@pytest.fixture
def ax(ax_factory) -> Axentra:  # type: ignore[no-untyped-def]
    return ax_factory()


class Browser:
    """A TestClient that behaves like a browser session from the Studio origin (cookie + CSRF)."""

    def __init__(self, app: Any) -> None:
        self.client = TestClient(app, base_url="http://testserver", headers={"Origin": ORIGIN})
        self.csrf: str | None = None

    def _headers(self, method: str, headers: dict[str, str] | None) -> dict[str, str]:
        h = dict(headers or {})
        if method != "GET" and self.csrf:
            h.setdefault("X-Axentra-CSRF", self.csrf)
        return h

    def request(self, method: str, url: str, **kw: Any) -> Any:
        kw["headers"] = self._headers(method, kw.get("headers"))
        return self.client.request(method, url, **kw)

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

    def login(self, email: str, password: str) -> dict[str, Any]:
        r = self.post("/v1/auth/login/password", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        return r.json()


@dataclass
class World:
    ax: Axentra
    app: Any
    admin: Browser

    def browser(self) -> Browser:
        return Browser(self.app)

    def user(self, email: str, password: str = "user password 12345", name: str = "") -> str:
        from axentra.data.database import DbScope

        with self.ax.db.transaction(DbScope.platform()) as tx:
            return self.ax.identity.create_user(
                tx, email=email, name=name or email.split("@")[0], password=password
            )

    def login_as(self, email: str, password: str = "user password 12345") -> Browser:
        b = self.browser()
        b.login(email, password)
        return b


def bootstrap_admin(ax: Axentra, app: Any) -> Browser:
    token = ax.identity.create_setup_token()
    admin = Browser(app)
    r = admin.post(
        "/v1/auth/setup",
        json={"setup_token": token, "email": ADMIN_EMAIL, "name": "Admin", "password": ADMIN_PASSWORD},
    )
    assert r.status_code == 200, r.text
    admin.csrf = r.json()["csrf_token"]
    return admin


@pytest.fixture
def world(ax: Axentra) -> Iterator[World]:
    app = create_app(axentra=ax, start=False)
    yield World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


@pytest.fixture
def single_world(ax_factory) -> Iterator[World]:  # type: ignore[no-untyped-def]
    ax = ax_factory(mode="single", product={"slug": "crm", "name": "CRM"})
    app = create_app(axentra=ax, start=False)
    yield World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
