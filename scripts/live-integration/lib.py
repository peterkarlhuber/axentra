# ruff: noqa: S105, S603
"""Shared helpers for the opt-in live integration checks (see README.md).

Every check starts a real ``axentra serve`` process (``python -m axentra.cli serve --migrate``) against
its own PostgreSQL database and talks to it over HTTP, like a browser or product backend would.
Nothing here is imported by the regular test suite.
"""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from typing import Any

import httpx

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
# The Axentra source tree the server processes run (LC_AXENTRA_SRC: e.g. another worktree under test).
SRC = Path(os.environ.get("LC_AXENTRA_SRC", str(REPO / "src")))
PYTHON = os.environ.get("LC_PYTHON", sys.executable)
EVIDENCE = Path(os.environ.get("LC_EVIDENCE", str(HERE / "evidence")))
PG_ADMIN_URL = os.environ.get("LC_PG_ADMIN_URL", "postgresql://postgres:pg@127.0.0.1:5432/postgres")
PG_ROLE = os.environ.get("LC_PG_ROLE", "lc_ax")
PG_ROLE_PASSWORD = os.environ.get("LC_PG_ROLE_PASSWORD", "lc_ax_pw")

ADMIN_EMAIL = "admin@lc.example.com"
ADMIN_PASSWORD = "lc synthetic admin password 1"


class CheckFailed(AssertionError):
    pass


class Report:
    """Collects PASS/FAIL lines for one integration and writes them to the evidence directory."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.lines: list[str] = []
        self.failed = 0
        EVIDENCE.mkdir(parents=True, exist_ok=True)

    def check(self, label: str, ok: bool, detail: Any = "") -> bool:
        status = "PASS" if ok else "FAIL"
        if not ok:
            self.failed += 1
        line = f"[{status}] {label}" + (f" :: {detail}" if detail != "" else "")
        print(line, flush=True)
        self.lines.append(line)
        return ok

    def note(self, text: str) -> None:
        line = f"[NOTE] {text}"
        print(line, flush=True)
        self.lines.append(line)

    def save_json(self, name: str, data: Any) -> Path:
        p = EVIDENCE / f"{self.name}-{name}.json"
        p.write_text(json.dumps(data, indent=2, default=str))
        return p

    def finish(self) -> int:
        summary = f"{self.name}: {'PASSED' if not self.failed else f'FAILED ({self.failed} failed checks)'}"
        self.lines.append(summary)
        (EVIDENCE / f"{self.name}-results.txt").write_text("\n".join(self.lines) + "\n")
        print(summary, flush=True)
        return 0 if not self.failed else 1


def reset_database(name: str) -> str:
    """Drop and recreate database ``name`` owned by the lane role; return its URL."""
    import psycopg

    with psycopg.connect(PG_ADMIN_URL, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{name}" OWNER "{PG_ROLE}"')
    return f"postgresql://{PG_ROLE}:{PG_ROLE_PASSWORD}@127.0.0.1:5432/{name}"


def base_env(db_url: str, port: int, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXENTRA")}
    env.update(
        {
            "PYTHONPATH": str(SRC),
            "AXENTRA__ENVIRONMENT": "development",
            "AXENTRA__MODE": "multi",
            "AXENTRA__DATABASE__URL": db_url,
            "AXENTRA__SECURITY__PUBLIC_URL": f"http://127.0.0.1:{port}",
            "AXENTRA__SECURITY__MASTER_KEYS": "lc1:" + _key(),
            "AXENTRA__SECURITY__LOGIN_RATE_PER_MINUTE": "100",
            "AXENTRA__OBSERVABILITY__LOG_FORMAT": "json",
            "AXENTRA__OBSERVABILITY__LOG_LEVEL": "DEBUG",
        }
    )
    env.update(extra)
    return env


_KEY: str | None = None


def _key() -> str:
    global _KEY
    if _KEY is None:
        import base64

        _KEY = base64.b64encode(secrets.token_bytes(32)).decode()
    return _KEY


def run_cli(env: dict[str, str], *args: str, log: Path | None = None, timeout: float = 120) -> str:
    proc = subprocess.run(
        [PYTHON, "-m", "axentra.cli", *args], env=env, capture_output=True, text=True, timeout=timeout
    )
    if log is not None:
        with log.open("a") as fh:
            fh.write(f"$ axentra {' '.join(args)}\n{proc.stdout}{proc.stderr}\n")
    if proc.returncode != 0:
        raise CheckFailed(f"axentra {' '.join(args)} failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return proc.stdout


@contextlib.contextmanager
def serve(env: dict[str, str], port: int, log: Path) -> Iterator[subprocess.Popen[bytes]]:
    """Run ``axentra serve --migrate`` until the block ends; stdout/stderr go to ``log``."""
    fh = log.open("ab")
    proc = subprocess.Popen(
        [PYTHON, "-m", "axentra.cli", "serve", "--migrate", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        stdout=fh,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 90
        while True:
            if proc.poll() is not None:
                raise CheckFailed(f"axentra serve exited with {proc.returncode}; see {log}")
            try:
                if httpx.get(f"http://127.0.0.1:{port}/v1/health/live", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                raise CheckFailed("axentra serve did not become live")
            time.sleep(0.5)
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
        fh.close()


class Api:
    """A browser-like client: session cookie + CSRF header, Origin = public URL."""

    def __init__(self, port: int) -> None:
        self.base = f"http://127.0.0.1:{port}"
        self.client = httpx.Client(base_url=self.base, headers={"Origin": self.base}, timeout=30)
        self.csrf: str | None = None

    def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        headers = dict(kw.pop("headers", None) or {})
        if method != "GET" and self.csrf:
            headers.setdefault("X-Axentra-CSRF", self.csrf)
        return self.client.request(method, url, headers=headers, **kw)

    def get(self, url: str, **kw: Any) -> httpx.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> httpx.Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Any) -> httpx.Response:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Any) -> httpx.Response:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> httpx.Response:
        return self.request("DELETE", url, **kw)

    def ok(
        self, method: str, url: str, expect: int | tuple[int, ...] = (200, 201, 202, 204), **kw: Any
    ) -> Any:
        r = self.request(method, url, **kw)
        exp = (expect,) if isinstance(expect, int) else expect
        if r.status_code not in exp:
            raise CheckFailed(f"{method} {url} -> {r.status_code}: {r.text[:800]}")
        return (
            r.json()
            if r.content
            and r.headers.get("content-type", "").startswith(("application/json", "application/problem"))
            else r
        )

    def login(self, email: str, password: str) -> None:
        body = self.ok("POST", "/v1/auth/login/password", json={"email": email, "password": password})
        self.csrf = body["csrf_token"]


def bootstrap_admin(env: dict[str, str], port: int, log: Path) -> Api:
    token = run_cli(env, "admin", "setup-token", log=None).strip().splitlines()[-1]
    api = Api(port)
    body = api.ok(
        "POST",
        "/v1/auth/setup",
        json={"setup_token": token, "email": ADMIN_EMAIL, "name": "LC Admin", "password": ADMIN_PASSWORD},
    )
    api.csrf = body["csrf_token"]
    with log.open("a") as fh:
        fh.write("bootstrap: setup token created via `axentra admin setup-token`, first admin registered\n")
    return api


def product_and_tenant(api: Api, slug: str = "lcprod", tenant: str = "acme") -> tuple[str, str]:
    pid = api.ok("POST", "/v1/products", json={"slug": slug, "name": slug.upper()})["id"]
    tid = api.ok("POST", f"/v1/products/{pid}/tenants", json={"slug": tenant, "name": tenant.title()})["id"]
    return pid, tid


def scan_for_secrets(path: Path, needles: dict[str, str]) -> dict[str, int]:
    """Count occurrences of each secret value in a log file (0 is what we want)."""
    text = path.read_text(errors="replace") if path.exists() else ""
    return {label: text.count(value) for label, value in needles.items() if value}
