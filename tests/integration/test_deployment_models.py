"""The deployment-model demos (examples/single-product, examples/multi-product) against in-process servers.

Both scripts talk HTTP through httpx; here their client factory returns ``TestClient`` instances
(an ``httpx.Client`` subclass) bound to a real Axentra app on a real PostgreSQL database.
"""

from __future__ import annotations

import contextlib
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

from fastapi.testclient import TestClient
import pytest

from axentra.api.app import create_app
from axentra.core.errors import Conflict
from tests.integration.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, World, bootstrap_admin

pytestmark = pytest.mark.postgres

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
OPERATOR_PASSWORD = "operator password 12345"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look the module up while the file executes
    spec.loader.exec_module(module)
    return module


multi = _load("multi_product_provision", EXAMPLES / "multi-product" / "provision.py")
single = _load("single_product_provision", EXAMPLES / "single-product" / "provision.py")


@pytest.fixture(autouse=True)
def _passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AXENTRA_DEMO_ADMIN_PASSWORD", ADMIN_PASSWORD)
    monkeypatch.setenv("AXENTRA_DEMO_OPERATOR_PASSWORD", OPERATOR_PASSWORD)


def _creator(world: World):  # type: ignore[no-untyped-def]
    def create(email: str, name: str, password: str) -> None:
        with contextlib.suppress(Conflict):
            world.user(email, password, name)

    return create


def _clients(app: Any):  # type: ignore[no-untyped-def]
    return lambda: TestClient(app, base_url="http://testserver")


class _NotFoundBecomesOk:
    """A deliberately broken proxy: answers 200 where the API said 404 (to prove leaks are caught)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        async def patched(message: Any) -> None:
            if message["type"] == "http.response.start" and message["status"] == 404:
                message = {**message, "status": 200}
            await send(message)

        await self.app(scope, receive, patched)


# -- multi-product ---------------------------------------------------------------------------------


def test_multi_product_deployment_isolates_products(world: World):
    cfg = multi.load_config(EXAMPLES / "multi-product" / "products.toml")
    assert cfg["admin"]["email"] == ADMIN_EMAIL
    logs: list[str] = []
    products, checks = multi.run(_clients(world.app), cfg, create_user=_creator(world), log=logs.append)

    assert checks.leaks == [] and checks.failures == [], logs
    assert checks.exit_code == 0
    assert checks.passed >= 80
    assert [p.slug for p in products] == ["taskboard", "invoicing"]
    taskboard, invoicing = products
    assert taskboard.id != invoicing.id
    # Same tenant slug "acme" in both products: two different tenants.
    assert taskboard.tenants["acme"] != invoicing.tenants["acme"]
    assert set(taskboard.new_secrets) == {"taskboard/taskboard-backend", "taskboard/acme-integration"}

    # The provisioned backend key of one product works there and nowhere else.
    key = TestClient(
        world.app, headers={"Authorization": f"Bearer {taskboard.new_secrets['taskboard/taskboard-backend']}"}
    )
    assert key.get(f"/v1/products/{taskboard.id}/tenants").status_code == 200
    assert key.get(f"/v1/products/{invoicing.id}/tenants").status_code == 404
    # The probe keys were revoked afterwards; only the configured keys stay active.
    active = [
        k["name"]
        for k in world.admin.get(f"/v1/products/{taskboard.id}/api-keys").json()
        if k["status"] == "active"
    ]
    assert sorted(active) == ["acme-integration", "taskboard-backend"]

    # Running again is idempotent: nothing new is created and the checks still pass.
    products2, checks2 = multi.run(_clients(world.app), cfg, create_user=_creator(world), log=logs.append)
    assert [p.id for p in products2] == [p.id for p in products]
    assert all(not p.new_secrets for p in products2)
    assert checks2.exit_code == 0, logs
    tenants = world.admin.get(f"/v1/products/{invoicing.id}/tenants").json()["items"]
    assert sorted(t["slug"] for t in tenants) == ["acme", "initech"]


def test_multi_product_script_detects_a_leak(world: World):
    cfg = multi.load_config(EXAMPLES / "multi-product" / "products.toml")
    leaky = _NotFoundBecomesOk(world.app)
    logs: list[str] = []
    _, checks = multi.run(lambda: TestClient(leaky), cfg, create_user=_creator(world), log=logs.append)
    assert checks.leaks
    assert checks.exit_code == 1
    assert any("taskboard -> invoicing" in line for line in checks.leaks)


def test_multi_product_script_refuses_a_single_product_server(single_world: World):
    cfg = multi.load_config(EXAMPLES / "multi-product" / "products.toml")
    with pytest.raises(multi.DemoError, match="mode = 'multi'"):
        multi.run(_clients(single_world.app), cfg, create_user=_creator(single_world))


def test_multi_product_main_exit_codes(world: World, monkeypatch: pytest.MonkeyPatch):
    # main() builds real httpx clients; route them into the in-process app.
    monkeypatch.setattr(multi.httpx, "Client", lambda **kw: TestClient(world.app))
    for spec in multi.load_config(EXAMPLES / "multi-product" / "products.toml")["products"]:
        for op in spec["operators"]:
            _creator(world)(op["email"], op["name"], OPERATOR_PASSWORD)
    assert multi.main(["--base-url", "http://testserver"]) == 0
    monkeypatch.setenv("AXENTRA_DEMO_ADMIN_PASSWORD", "wrong password 123")
    assert multi.main(["--base-url", "http://testserver"]) == 2


# -- single-product --------------------------------------------------------------------------------


@pytest.fixture
def taskboard_world(ax_factory) -> World:  # type: ignore[no-untyped-def]
    ax = ax_factory(mode="single", product={"slug": "taskboard", "name": "Taskboard"})
    app = create_app(axentra=ax, start=False)
    return World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


def test_single_product_deployment(taskboard_world: World):
    cfg = single.load_config(EXAMPLES / "single-product" / "product.toml")
    logs: list[str] = []
    result, checks = single.run(
        _clients(taskboard_world.app), cfg, create_user=_creator(taskboard_world), log=logs.append
    )
    assert checks.leaks == [] and checks.failures == [], logs
    assert checks.exit_code == 0 and checks.passed >= 15
    assert set(result["tenants"]) == {"acme", "globex"}
    assert result["product_id"] == taskboard_world.ax.single_product().id

    # Idempotent.
    result2, checks2 = single.run(
        _clients(taskboard_world.app), cfg, create_user=_creator(taskboard_world), log=logs.append
    )
    assert result2["tenants"] == result["tenants"] and not result2["new_secrets"]
    assert checks2.exit_code == 0, logs


def test_single_product_script_rejects_a_multi_product_server(world: World):
    cfg = single.load_config(EXAMPLES / "single-product" / "product.toml")
    with pytest.raises(single.DemoError, match="mode = 'single'"):
        single.run(_clients(world.app), cfg)


def test_single_product_script_rejects_another_product(single_world: World):
    cfg = single.load_config(EXAMPLES / "single-product" / "product.toml")
    # single_world serves "crm", the config expects "taskboard".
    with pytest.raises(single.DemoError, match="expects 'taskboard'"):
        single.run(_clients(single_world.app), cfg)


def test_single_product_script_detects_a_leak(taskboard_world: World):
    cfg = single.load_config(EXAMPLES / "single-product" / "product.toml")
    leaky = _NotFoundBecomesOk(taskboard_world.app)
    _, checks = single.run(
        lambda: TestClient(leaky), cfg, create_user=_creator(taskboard_world), log=lambda _: None
    )
    assert checks.exit_code == 1
    assert any("tenant globex" in line for line in checks.leaks)
