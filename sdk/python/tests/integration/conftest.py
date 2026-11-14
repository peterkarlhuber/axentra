"""A real Axentra server for the SDK's contract tests.

The `axentra` server package is used ONLY here, in the tests: an `Axentra` instance on a fresh
PostgreSQL database (owned by a non-superuser role, so row-level security is enforced) is served
by uvicorn on a free loopback port in a background thread, and the SDK talks real HTTP to it.

Needs ``AXENTRA_TEST_DATABASE_URL`` (a superuser URL) and the server package installed
(``pip install -r ../../requirements/tabrion.txt -e "../..[server]"``); otherwise the tests are skipped and reported as skipped.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import os
import socket
import threading
import time
from typing import Any
import uuid

import pytest

from axentra_client import AxentraClient

ADMIN_URL = os.environ.get("AXENTRA_TEST_DATABASE_URL")
ADMIN_EMAIL = "sdk-admin@example.com"
ADMIN_PASSWORD = "sdk admin password 123"
USER_PASSWORD = "sdk user password 123"

pytestmark = pytest.mark.integration


def _with_db(url: str, dbname: str, user: str | None = None, password: str | None = None) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params: dict[str, Any] = conninfo_to_dict(url)
    params["dbname"] = dbname
    if user:
        params["user"] = user
        params["password"] = password
    return make_conninfo(**params)


@pytest.fixture(scope="session")
def pg_app_url() -> Iterator[str]:
    if not ADMIN_URL:
        pytest.skip("AXENTRA_TEST_DATABASE_URL is not set; SDK integration tests not executed")
    pytest.importorskip("axentra.api.app", reason="the axentra server package is not installed")
    import psycopg
    from psycopg import sql

    suffix = uuid.uuid4().hex[:8]
    dbname, role, password = f"axentra_sdk_{suffix}", f"axentra_sdk_{suffix}", uuid.uuid4().hex
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        conn.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(dbname), sql.Identifier(role))
        )
    from axentra.data.migrations import MigrationRunner

    url = _with_db(ADMIN_URL, dbname, role, password)
    MigrationRunner(url).migrate()
    try:
        yield url
    finally:
        with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(dbname)))
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


@dataclass
class Server:
    url: str
    ax: Any  # axentra.platform.Axentra (server side, for fixtures only)

    def client(self, **kw: Any) -> AxentraClient:
        return AxentraClient(self.url, **kw)

    def user(self, email: str, password: str = USER_PASSWORD) -> str:
        from axentra.data.database import DbScope

        with self.ax.db.transaction(DbScope.platform()) as tx:
            user_id: str = self.ax.identity.create_user(
                tx, email=email, name=email.split("@")[0], password=password
            )
            return user_id

    def login(self, email: str, password: str = USER_PASSWORD) -> AxentraClient:
        c = self.client()
        c.auth.login_password(email, password)
        return c


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@pytest.fixture(scope="session")
def server(pg_app_url: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Server]:
    from axentra.api.app import create_app
    from axentra.config.secrets import generate_key
    from axentra.config.settings import load_settings
    from axentra.platform import Axentra
    import uvicorn

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    settings = load_settings(
        None,
        environ={},
        environment="test",
        mode="multi",
        database={"url": pg_app_url, "pool_max": 8},
        security={
            "master_keys": f"t1:{generate_key()}",
            "public_url": base,
            "login_rate_per_minute": 100,
            "password_min_length": 12,
        },
        storage={"local_path": str(tmp_path_factory.mktemp("storage"))},
    )
    ax = Axentra.from_settings(settings)
    ax.start()
    app = create_app(axentra=ax, start=False)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not srv.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    try:
        yield Server(url=base, ax=ax)
    finally:
        srv.should_exit = True
        thread.join(timeout=10)
        ax.close()


@pytest.fixture(scope="session")
def admin(server: Server) -> Iterator[AxentraClient]:
    """The platform admin, registered through the SDK's setup call (session token as bearer)."""
    c = server.client()
    c.auth.setup(server.ax.identity.create_setup_token(), ADMIN_EMAIL, ADMIN_PASSWORD, name="SDK Admin")
    yield c
    c.close()


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def product(admin: AxentraClient) -> str:
    return admin.products.create(unique("p"), "SDK product").id


@pytest.fixture
def tenant(admin: AxentraClient, product: str) -> str:
    return admin.tenants.create(product, unique("t"), "Tenant A").id
