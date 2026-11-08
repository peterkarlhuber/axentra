"""Database errors in logs and HTTP answers (finding B-06-1, TABRION MIG-AXE-0).

A psycopg error carries the server's ``DETAIL`` text, and for a unique, foreign key or check violation that text
holds the offending values (``Key (email)=(someone@example.com) already exists.``). These tests make a real
PostgreSQL statement fail with a unique canary value and check what leaves Axentra:

- the problem details answer of the HTTP API (a snapshot: it must not change),
- every log record that pytest captures, at every level, and the output of the handler that
  :func:`axentra.audit.logging.configure_logging` installs (JSON and text), and uvicorn's error log.

The tests only look at observable output (answers, captured and emitted log text), never at how the redaction is
implemented, so they keep holding when TABRION MIG-AXE-3 replaces the local filter with Tabrion's.
"""

from __future__ import annotations

from collections.abc import Iterator
import json
import logging
from typing import Any
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
import psycopg
import pytest

from axentra.api.app import create_app
from axentra.core.errors import AxentraError, Conflict
from axentra.platform import Axentra

pytestmark = pytest.mark.postgres

#: The problem details every internal error answers with (``request_id`` is checked separately).
INTERNAL_PROBLEM = {
    "type": "urn:axentra:problem:internal",
    "title": "Internal error",
    "status": 500,
    "code": "internal",
    "detail": "An internal error occurred.",
}

#: A typed conflict raised from a database error (``raise Conflict(...) from exc``), as Axentra's modules do.
CONFLICT_PROBLEM = {
    "type": "urn:axentra:problem:conflict",
    "title": "Conflict",
    "status": 409,
    "code": "conflict",
    "detail": "The address is already in use.",
}

#: What each failing statement must still say in the logs: the SQLSTATE and the constraint name.
EXPECTED_DIAGNOSTICS = {
    "unique": ("23505", "canary_people_email_key"),
    "foreign-key": ("23503", "canary_people_team_fkey"),
    "check": ("23514", "canary_people_age_check"),
}


def _canary() -> str:
    return f"canary-{uuid.uuid4().hex}@example.com"


def _fail(admin_url: str, kind: str, canary: str) -> None:
    """Run a statement that fails with ``canary`` in the server's DETAIL text (raises the psycopg error)."""
    with psycopg.connect(admin_url) as conn:
        conn.execute(
            "CREATE TEMP TABLE canary_teams (id text PRIMARY KEY);"
            "CREATE TEMP TABLE canary_people ("
            " email text CONSTRAINT canary_people_email_key UNIQUE,"
            " team text CONSTRAINT canary_people_team_fkey REFERENCES canary_teams (id),"
            " age text CONSTRAINT canary_people_age_check CHECK (length(age) < 5))"
        )
        if kind == "unique":
            conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (canary,))
            conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (canary,))
        elif kind == "foreign-key":
            conn.execute("INSERT INTO canary_people (team) VALUES (%s)", (canary,))
        elif kind == "check":
            # The canary is too long for the check, and DETAIL lists the row: ``Failing row contains (...)``.
            conn.execute("INSERT INTO canary_people (email, age) VALUES (%s, %s)", (canary, canary))
        else:  # pragma: no cover - test bug
            raise AssertionError(kind)


@pytest.fixture
def failing_app(ax: Axentra, pg_urls: dict[str, str]) -> Iterator[tuple[FastAPI, dict[str, str]]]:
    """Axentra's app with test routes whose handlers run a failing statement with a fresh canary each time.

    ``/_test/db/{kind}`` lets the psycopg error escape (the generic handler for unhandled errors);
    ``/_test/db-wrapped/{kind}`` raises an internal :class:`AxentraError` from it (the handler for Axentra's
    own errors, ``api/problems.py``); ``/_test/db-conflict`` raises a typed 409 from it.
    """
    app = create_app(axentra=ax)
    canaries: dict[str, str] = {}

    def run(kind: str) -> None:
        canaries["last"] = canary = _canary()
        _fail(pg_urls["admin"], kind, canary)

    def unhandled(kind: str) -> None:
        run(kind)

    def wrapped(kind: str) -> None:
        try:
            run(kind)
        except psycopg.Error as exc:
            raise AxentraError("the database refused the write") from exc

    def conflict() -> None:
        try:
            run("unique")
        except psycopg.errors.UniqueViolation as exc:
            raise Conflict("The address is already in use.") from exc

    app.add_api_route("/_test/db/{kind}", unhandled, methods=["POST"])
    app.add_api_route("/_test/db-wrapped/{kind}", wrapped, methods=["POST"])
    app.add_api_route("/_test/db-conflict", conflict, methods=["POST"])
    yield app, canaries


def _client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


#: Response header names of an answer that passed Axentra's request middleware.
MIDDLEWARE_HEADERS = sorted(
    [
        "axentra-api-version",
        "content-length",
        "content-security-policy",
        "content-type",
        "cross-origin-resource-policy",
        "referrer-policy",
        "vary",
        "x-content-type-options",
        "x-frame-options",
        "x-request-id",
    ]
)
#: An unhandled exception is answered by Starlette's outermost error middleware, before Axentra's request
#: middleware adds its headers (the body still names the request id).
UNHANDLED_HEADERS = ["content-length", "content-type"]


def _problem(response: Any) -> dict[str, Any]:
    """The problem details body with its request id checked and replaced by ``"<request id>"``."""
    assert response.headers["content-type"] == "application/problem+json"
    body = dict(response.json())
    rid = body.pop("request_id")
    assert isinstance(rid, str) and rid.startswith("req_")
    if "x-request-id" in response.headers:
        assert rid == response.headers["x-request-id"]
    return body


# --- Problem details snapshot (written before the fix; must stay unchanged) --------------------------------------


@pytest.mark.parametrize("kind", sorted(EXPECTED_DIAGNOSTICS))
@pytest.mark.parametrize(
    ("route", "headers"), [("/_test/db/", UNHANDLED_HEADERS), ("/_test/db-wrapped/", MIDDLEWARE_HEADERS)]
)
def test_internal_db_error_problem_snapshot(
    failing_app: Any, route: str, headers: list[str], kind: str
) -> None:
    app, canaries = failing_app
    r = _client(app).post(route + kind)
    assert r.status_code == 500
    assert _problem(r) == INTERNAL_PROBLEM
    assert sorted(r.headers.keys()) == headers
    assert canaries["last"] not in r.text
    assert canaries["last"] not in str(r.headers)


def test_typed_conflict_from_db_error_problem_snapshot(failing_app: Any) -> None:
    app, canaries = failing_app
    r = _client(app).post("/_test/db-conflict")
    assert r.status_code == 409
    assert _problem(r) == CONFLICT_PROBLEM
    assert sorted(r.headers.keys()) == MIDDLEWARE_HEADERS
    assert canaries["last"] not in r.text


# --- Logs (B-06-1): the canary never appears, SQLSTATE and constraint name do --------------------------------------

ROUTES = ["/_test/db/", "/_test/db-wrapped/"]


@pytest.fixture
def _restore_logger_state() -> Iterator[None]:
    """Undo what ``configure_logging`` and uvicorn's logging configuration change on the named loggers."""
    names = ["uvicorn", "uvicorn.error", "uvicorn.access", "axentra.http"]
    saved = {
        n: (lg.handlers[:], lg.filters[:], lg.level, lg.propagate, lg.disabled)
        for n in names
        for lg in [logging.getLogger(n)]
    }
    yield
    for name, (handlers, filters, level, propagate, disabled) in saved.items():
        lg = logging.getLogger(name)
        lg.handlers[:], lg.filters[:] = handlers, filters
        lg.setLevel(level)
        lg.propagate, lg.disabled = propagate, disabled


def _captured_text(caplog: pytest.LogCaptureFixture) -> str:
    """Everything pytest captured: the formatted log, and each record's message, cached traceback and extras."""
    parts = [caplog.text]
    for record in caplog.records:
        parts.append(record.getMessage())
        parts.append(logging.Formatter().format(record))
        parts.append(record.exc_text or "")
        parts.append(repr(record.args))
    return "\n".join(parts)


@pytest.mark.parametrize("kind", sorted(EXPECTED_DIAGNOSTICS))
@pytest.mark.parametrize("route", ROUTES)
def test_canary_never_in_captured_logs(
    failing_app: Any, caplog: pytest.LogCaptureFixture, route: str, kind: str
) -> None:
    app, canaries = failing_app
    caplog.set_level(logging.DEBUG)
    r = _client(app).post(route + kind)
    assert r.status_code == 500
    records = [rec for rec in caplog.records if rec.levelno >= logging.ERROR]
    assert records, "the internal error was not logged"
    captured = _captured_text(caplog)
    assert canaries["last"] not in captured
    assert "DETAIL" not in captured
    sqlstate, constraint = EXPECTED_DIAGNOSTICS[kind]
    assert sqlstate in caplog.text
    assert constraint in caplog.text


@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.usefixtures("_restore_logger_state")
def test_canary_never_in_configured_log_output(
    failing_app: Any, capsys: pytest.CaptureFixture[str], route: str, fmt: str
) -> None:
    from axentra.audit.logging import configure_logging

    app, canaries = failing_app
    configure_logging("DEBUG", fmt)
    r = _client(app).post(route + "unique")
    assert r.status_code == 500
    out = capsys.readouterr().err
    assert "internal" in out or "unhandled" in out, out
    assert canaries["last"] not in out
    assert "23505" in out and "canary_people_email_key" in out
    if fmt == "json":
        errors = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        logged = [e for e in errors if e["level"] == "ERROR"]
        assert logged and all("23505" in e["exc"] for e in logged)


@pytest.mark.usefixtures("_restore_logger_state")
def test_canary_never_in_logs_of_other_modules(
    pg_urls: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """A database error that any Axentra module logs (here as the job worker does) goes through the handler of
    ``configure_logging`` without its values, also as an argument of the message."""
    from axentra.audit.logging import configure_logging

    configure_logging("DEBUG", "text")
    canary = _canary()
    try:
        _fail(pg_urls["admin"], "unique", canary)
    except psycopg.Error as exc:
        logging.getLogger("axentra.events.worker").warning("job failed: %s", exc, exc_info=True)
        logging.getLogger("axentra.events.worker").debug("job failed: %r", exc)
    out = capsys.readouterr().err
    assert "job failed" in out
    assert canary not in out
    assert "23505" in out and "canary_people_email_key" in out


@pytest.mark.usefixtures("_restore_logger_state")
def test_canary_never_in_uvicorn_error_log(failing_app: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Served by uvicorn as ``axentra serve`` does: uvicorn logs the unhandled error with its own handler."""
    import socket
    import threading
    import time

    import httpx
    import uvicorn

    from axentra.audit.logging import configure_logging

    app, canaries = failing_app
    configure_logging("INFO", "text")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False, lifespan="off")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.05)
        r = httpx.post(f"http://127.0.0.1:{port}/_test/db/unique", timeout=10)
        assert r.status_code == 500
        assert _problem(r) == INTERNAL_PROBLEM
    finally:
        server.should_exit = True
        thread.join(10)
    out = capsys.readouterr().err
    assert "Exception in ASGI application" in out
    assert canaries["last"] not in out
    assert "23505" in out and "canary_people_email_key" in out


@pytest.mark.usefixtures("_restore_logger_state")
def test_other_exceptions_are_logged_unchanged(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from axentra.audit.logging import configure_logging

    configure_logging("DEBUG", "text")
    try:
        raise ValueError("visible-diagnostic-text 4711")
    except ValueError:
        logging.getLogger("axentra.http").error("internal error: %s", "plain", exc_info=True)
    out = capsys.readouterr().err
    assert "internal error: plain" in out
    assert "ValueError: visible-diagnostic-text 4711" in out
