"""Shared helpers of the deployment demos (examples/single-product, examples/multi-product).

Everything here talks to a running Axentra API over HTTP with httpx; nothing imports Axentra,
except :func:`library_user_creator`, which is the one step the HTTP API does not offer (see
below). The tests pass a ``new_client`` factory that returns in-process clients instead.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import sys
import tomllib
from typing import Any

import httpx

ClientFactory = Callable[[], httpx.Client]
#: ``(email, name, password) -> None``: make sure a user account exists.
UserCreator = Callable[[str, str, str], None]

DENIED = (403, 404)


class DemoError(Exception):
    """A provisioning step failed (not a leak; the setup itself did not work)."""


def load_config(path: str | Path) -> dict[str, Any]:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def secret_from_env(name: str, *, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise DemoError(f"set the environment variable {name}")
    return value


class Api:
    """One caller: a user session (cookie + CSRF header) or an API key (bearer)."""

    def __init__(self, client: httpx.Client, label: str) -> None:
        self.client = client
        self.label = label
        self.csrf: str | None = None

    @classmethod
    def with_key(cls, new_client: ClientFactory, secret: str, label: str) -> Api:
        api = cls(new_client(), label)
        api.client.headers["Authorization"] = f"Bearer {secret}"
        return api

    def request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        headers = dict(kw.pop("headers", None) or {})
        if method != "GET" and self.csrf:
            headers["X-Axentra-CSRF"] = self.csrf
        return self.client.request(method, path, headers=headers, **kw)

    def ok(self, method: str, path: str, *, status: int | tuple[int, ...] = (200, 201), **kw: Any) -> Any:
        r = self.request(method, path, **kw)
        expected = (status,) if isinstance(status, int) else status
        if r.status_code not in expected:
            raise DemoError(f"{self.label}: {method} {path} -> {r.status_code} {r.text[:300]}")
        return r.json() if r.content else None

    def login(self, email: str, password: str) -> Api:
        body = self.ok(
            "POST", "/v1/auth/login/password", json={"email": email, "password": password}, status=200
        )
        self.csrf = body["csrf_token"]
        return self

    def setup(self, token: str, email: str, password: str) -> Api:
        body = self.ok(
            "POST",
            "/v1/auth/setup",
            json={"setup_token": token, "email": email, "name": "Platform admin", "password": password},
            status=200,
        )
        self.csrf = body["csrf_token"]
        return self


def admin_session(new_client: ClientFactory, cfg: dict[str, Any], meta: dict[str, Any]) -> Api:
    """Log in as the platform admin; on a fresh installation complete the first-run setup."""
    admin = cfg["admin"]
    password = secret_from_env(admin.get("password_env", "AXENTRA_DEMO_ADMIN_PASSWORD"))
    api = Api(new_client(), "platform admin")
    if meta["setup_required"]:
        token = os.environ.get(admin.get("setup_token_env", "AXENTRA_SETUP_TOKEN"))
        if not token:
            raise DemoError(
                "the installation needs its first admin: set AXENTRA_SETUP_TOKEN (axentra admin setup-token)"
            )
        return api.setup(token, admin["email"], password)
    return api.login(admin["email"], password)


def library_user_creator() -> UserCreator:
    """Create missing accounts with the Axentra library (needs the server's database settings).

    Axentra's HTTP API has no "create user" endpoint by design: accounts come from the first-run
    setup, OpenID Connect sign-up, or the product backend's own signup (like Taskboard's
    ``POST /api/signup``, which calls ``ax.identity.create_user``). This demo therefore creates
    its operator accounts in-process, reading the same ``AXENTRA_CONFIG`` / ``AXENTRA__*``
    settings as the server.
    """
    from axentra.config.settings import load_settings
    from axentra.core.errors import Conflict
    from axentra.data.database import DbScope
    from axentra.platform import Axentra

    ax = Axentra.from_settings(load_settings())
    ax.db.open()

    def create(email: str, name: str, password: str) -> None:
        try:
            with ax.db.transaction(DbScope.platform()) as tx:
                ax.identity.create_user(tx, email=email, name=name, password=password)
        except Conflict:
            pass  # exists already

    return create


# -- idempotent provisioning steps ---------------------------------------------------------------


def ensure_tenant(api: Api, product_id: str, slug: str, name: str | None = None) -> str:
    page = api.ok("GET", f"/v1/products/{product_id}/tenants", params={"q": slug, "limit": 200}, status=200)
    for t in page["items"]:
        if t["slug"] == slug:
            return str(t["id"])
    body = api.ok(
        "POST", f"/v1/products/{product_id}/tenants", json={"slug": slug, "name": name or slug.title()}
    )
    return str(body["id"])


def ensure_operator(api: Api, product_id: str, email: str, role: str) -> str:
    """Add (or update) a product operator by email. Upsert: safe to repeat."""
    body = api.ok("POST", f"/v1/products/{product_id}/members", json={"email": email, "role": role})
    return str(body["user_id"])


def ensure_api_key(
    api: Api, product_id: str, name: str, permissions: list[str], tenant_id: str | None
) -> str | None:
    """Create the key unless an active key with this name exists. Returns the secret only when created."""
    for key in api.ok("GET", f"/v1/products/{product_id}/api-keys", status=200):
        if key["name"] == name and key["status"] == "active":
            return None
    body = api.ok(
        "POST",
        f"/v1/products/{product_id}/api-keys",
        json={"name": name, "permissions": permissions, "tenant_id": tenant_id},
    )
    return str(body["secret"])


def probe_key(
    api: Api, product_id: str, permissions: list[str], tenant_id: str | None, label: str
) -> tuple[str, str]:
    """A short-lived key for the isolation checks (revoked afterwards). Returns (id, secret)."""
    expires = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
    body = api.ok(
        "POST",
        f"/v1/products/{product_id}/api-keys",
        json={
            "name": f"isolation probe {label}",
            "permissions": permissions,
            "tenant_id": tenant_id,
            "expires_at": expires,
        },
    )
    return str(body["key"]["id"]), str(body["secret"])


# -- isolation checks ----------------------------------------------------------------------------


@dataclass
class Checks:
    """Expected outcomes; ``leaks`` are requests that should have been refused but were not."""

    passed: int = 0
    leaks: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    log: Callable[[str], None] = print

    def denied(self, api: Api, method: str, path: str, what: str, **kw: Any) -> None:
        r = api.request(method, path, **kw)
        if r.status_code in DENIED:
            self.passed += 1
        elif r.status_code < 400:
            self.leaks.append(f"LEAK [{api.label}] {what}: {method} {path} -> {r.status_code}")
            self.log(self.leaks[-1])
        else:
            self.failures.append(
                f"[{api.label}] {what}: {method} {path} -> {r.status_code} (expected 403/404)"
            )
            self.log(self.failures[-1])

    def allowed(self, api: Api, method: str, path: str, what: str, **kw: Any) -> httpx.Response:
        r = api.request(method, path, **kw)
        if r.status_code < 300:
            self.passed += 1
        else:
            self.failures.append(
                f"[{api.label}] {what}: {method} {path} -> {r.status_code} (expected success)"
            )
            self.log(self.failures[-1])
        return r

    def expect(self, condition: bool, what: str, *, leak: bool = False) -> None:
        if condition:
            self.passed += 1
        elif leak:
            self.leaks.append(f"LEAK {what}")
            self.log(self.leaks[-1])
        else:
            self.failures.append(what)
            self.log(what)

    @property
    def exit_code(self) -> int:
        return 1 if self.leaks or self.failures else 0

    def summary(self) -> str:
        return f"{self.passed} checks passed, {len(self.leaks)} leaks, {len(self.failures)} other failures"


def write_secrets(path: str | None, secrets: dict[str, str]) -> None:
    """New API key secrets are shown once; store them in a 0600 file (or print them)."""
    if not secrets:
        return
    if path is None:
        for name, value in secrets.items():
            print(f"new API key {name}: {value}  (shown once)", file=sys.stderr)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        for name, value in secrets.items():
            fh.write(f"{name}={value}\n")
