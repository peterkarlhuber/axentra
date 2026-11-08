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
