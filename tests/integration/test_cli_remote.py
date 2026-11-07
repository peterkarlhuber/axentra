"""``axentra remote``: the CLI over HTTP against a real server (uvicorn on a loopback port)."""

from __future__ import annotations

from collections.abc import Iterator
import json
import socket
import threading
import time
from typing import Any

import pytest

from axentra.api.app import create_app
from axentra.cli import main
from tests.integration.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, bootstrap_admin


def _free_port() -> int:
    # Prefer the stream's port range (shared machine); fall back to any free port.
    for port in [*range(9600, 9700), 0]:
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return int(s.getsockname()[1])
    raise RuntimeError("no free port")  # pragma: no cover


@pytest.fixture
def served(ax) -> Iterator[str]:  # type: ignore[no-untyped-def]
    import uvicorn

    app = create_app(axentra=ax, start=False)
    bootstrap_admin(ax, app)
    port = _free_port()
    srv = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    )
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not srv.started:
        assert time.monotonic() < deadline and thread.is_alive(), "uvicorn did not start"
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        thread.join(timeout=10)


def _run(capsys: Any, *argv: str) -> tuple[int, Any, str]:
    capsys.readouterr()
    code = main(["remote", *argv])
    out = capsys.readouterr()
    try:
        parsed = json.loads(out.out) if out.out.strip().startswith(("{", "[")) else out.out.strip()
    except ValueError:  # pragma: no cover - printed for the assertion message
        parsed = out.out
    return code, parsed, out.err


def test_remote_admin_flow(served, capsys, monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AXENTRA_URL", served)
    monkeypatch.delenv("AXENTRA_API_KEY", raising=False)
    monkeypatch.delenv("AXENTRA_SESSION_TOKEN", raising=False)
    code, meta, _ = _run(capsys, "meta")
    assert code == 0 and meta["api_version"]["major"] == 1
    # No credential: a clear operator error, nothing sent.
    code, _, err = _run(capsys, "products", "list")
    assert code == 2 and "missing_credential" in err
    # Sign in (password from the environment instead of the prompt); only the token goes to stdout.
    monkeypatch.setenv("AXENTRA_PASSWORD", ADMIN_PASSWORD)
    code, token, err = _run(capsys, "login", ADMIN_EMAIL)
    assert code == 0 and token and "signed in as admin@example.com" in err, err
    monkeypatch.setenv("AXENTRA_SESSION_TOKEN", token)
    code, me, _ = _run(capsys, "whoami")
    assert code == 0 and me["user"]["email"] == ADMIN_EMAIL and me["platform_role"] == "platform_admin"
    code, product, _ = _run(capsys, "products", "create", "crm", "CRM", "--description", "via CLI")
    assert code == 0 and product["slug"] == "crm" and product["description"] == "via CLI"
    pid = product["id"]
    code, products, _ = _run(capsys, "products", "list")
    assert [p["id"] for p in products] == [pid]
    code, tenant, _ = _run(capsys, "tenants", "create", pid, "acme", "Acme")
    tid = tenant["id"]
    assert _run(capsys, "tenants", "suspend", pid, tid)[1]["status"] == "suspended"
    assert _run(capsys, "tenants", "activate", pid, tid)[1]["status"] == "active"
    code, page, _ = _run(capsys, "tenants", "list", pid, "--sort", "name", "--limit", "5")
    assert [t["id"] for t in page["items"]] == [tid]
    assert _run(capsys, "tenants", "get", pid, tid)[1]["slug"] == "acme"
    # API keys: the secret is printed once; the key then works as the CLI's credential.
    code, new, _ = _run(
        capsys, "keys", "create", pid, "ci", "--permission", "tenant:read", "--tenant-id", tid
    )
    assert code == 0 and new["secret"].startswith("axk_")
    key_file = tmp_path / "key"
    key_file.write_text(new["secret"] + "\n", encoding="utf-8")
    code, got, _ = _run(capsys, "--api-key-file", str(key_file), "tenants", "get", pid, tid)
    assert code == 0 and got["id"] == tid
    code, _, err = _run(capsys, "--api-key-file", str(key_file), "products", "create", "x2", "X")
    assert code == 2 and "axentra: forbidden:" in err
    code, rotated, _ = _run(capsys, "keys", "rotate", pid, new["key"]["id"], "--grace-seconds", "60")
    assert code == 0 and rotated["secret"] != new["secret"]
    code, revoked, _ = _run(capsys, "keys", "revoke", pid, rotated["key"]["id"])
    assert revoked["revoked_at"] is not None
    assert len(_run(capsys, "keys", "list", pid)[1]) == 2
    # Users.
    code, users, _ = _run(capsys, "users", "list", "--q", "admin")
    admin_id = users["items"][0]["id"]
    code, _, err = _run(capsys, "users", "disable", admin_id)
    assert code == 2 and "axentra: " in err  # an admin cannot disable themselves
    assert _run(capsys, "users", "revoke-sessions", admin_id)[1]["revoked"] >= 1
    # The session ended, so the token no longer works.
    code, _, err = _run(capsys, "whoami")
    assert code == 2 and "unauthenticated" in err


def test_remote_errors(served, capsys, monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AXENTRA_SESSION_TOKEN", "not-a-session")
    code, _, err = _run(capsys, "--url", served, "whoami")
    assert code == 2 and "axentra: unauthenticated:" in err
    code, _, err = _run(capsys, "--url", "ftp://example.com", "whoami")
    assert code == 2 and "invalid_url" in err
    monkeypatch.delenv("AXENTRA_URL", raising=False)
    code, _, err = _run(capsys, "whoami")
    assert code == 2 and "AXENTRA_URL" in err
    # Nothing listens on this port: the API is unreachable.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    code, _, err = _run(capsys, "--url", f"http://127.0.0.1:{dead}", "--timeout", "2", "meta")
    assert code == 2 and "api_unreachable" in err
    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")
    code, _, err = _run(capsys, "--url", served, "--api-key-file", str(empty), "whoami")
    assert code == 2 and "missing_credential" in err
    monkeypatch.setenv("AXENTRA_PASSWORD", "wrong password 123")
    code, out, err = _run(capsys, "--url", served, "login", ADMIN_EMAIL)
    assert code == 2 and out == "" and "axentra: unauthenticated:" in err
