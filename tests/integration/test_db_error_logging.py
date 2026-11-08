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

from collections.abc import Callable, Iterator
import io
import json
import logging
from typing import Any
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
import psycopg
from psycopg import sql
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
            " age text CONSTRAINT canary_people_age_check CHECK (length(age) < 5),"
            # A value the statement never passes: it only shows up in ``Failing row contains (...)``.
            " note text DEFAULT {})".format(sql.Literal("server-side-" + canary).as_string(conn))
        )
        if kind == "unique":
            conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (canary,))
            conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (canary,))
        elif kind == "foreign-key":
            conn.execute("INSERT INTO canary_people (team) VALUES (%s)", (canary,))
        elif kind == "check":
            # The value is too long for the check, and DETAIL lists the row: ``Failing row contains (...)``,
            # with the canary only in the column default (``note``), not in any parameter.
            conn.execute("INSERT INTO canary_people (age) VALUES (%s)", ("too long",))
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
    assert "DETAIL" not in out
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
    assert "DETAIL" not in out
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
    assert "DETAIL" not in out
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


# --- Review MIG-AXE-0 (M-1 .. M-3, L-1 .. L-7): every path out of the process -----------------------------------


def _db_error(admin_url: str, kind: str = "unique") -> tuple[str, psycopg.Error]:
    canary = _canary()
    try:
        _fail(admin_url, kind, canary)
    except psycopg.Error as exc:
        return canary, exc
    raise AssertionError("the statement did not fail")


def _plain_handler_output(log: Callable[[logging.Logger], None]) -> str:
    """Output of a product's own handler: a plain ``StreamHandler`` without any Axentra filter or formatter, on a
    logger that does not propagate. Only a process-wide redaction reaches it."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    lg = logging.getLogger(f"axentra.test.{uuid.uuid4().hex}")
    lg.propagate = False
    lg.setLevel(logging.DEBUG)
    lg.addHandler(handler)
    try:
        log(lg)
    finally:
        lg.removeHandler(handler)
    return stream.getvalue()


def _assert_clean(out: str, canary: str) -> None:
    assert canary not in out, out
    assert "DETAIL" not in out, out
    assert "23505" in out and "canary_people_email_key" in out, out


@pytest.mark.usefixtures("ax")
def test_m1_redaction_without_configure_logging(
    pg_urls: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """M-1: an embedding application or a CLI command that never calls ``configure_logging``: a module logger's
    record reaches ``logging.lastResort`` or the application's own root handler without the values."""
    canary, exc = _db_error(pg_urls["admin"])
    root = logging.getLogger()
    saved = root.handlers[:]
    own = io.StringIO()
    try:
        root.handlers[:] = []  # logging.lastResort (stderr)
        try:
            raise exc
        except psycopg.Error:
            logging.getLogger("axentra.observability.maintenance").exception(
                "maintenance task %s failed", "x"
            )
        root.handlers[:] = [logging.StreamHandler(own)]  # the application's own handler
        try:
            raise exc
        except psycopg.Error:
            logging.getLogger("axentra.events.worker").warning("job failed", exc_info=True)
    finally:
        root.handlers[:] = saved
    _assert_clean(capsys.readouterr().err, canary)
    _assert_clean(own.getvalue(), canary)


def test_m1_m3_job_worker_logs_and_last_error(world: Any, pg_urls: dict[str, str]) -> None:
    """M-1 and M-3: a job whose handler fails on a unique violation. The worker's log (through the application's
    own handler) and the job's ``last_error`` (``GET /v1/products/{id}/jobs/{job_id}``) carry no values."""
    from axentra.core.context import Principal
    from axentra.events import JobWorker

    ax = world.ax
    sys_principal = Principal.system("test")
    product = ax.tenancy.create_product(sys_principal, slug="crm", name="CRM")
    tenant = ax.tenancy.create_tenant(sys_principal, product.id, slug="acme", name="Acme")
    canaries: list[str] = []

    def handler(ctx: Any) -> None:
        canary, exc = _db_error(pg_urls["admin"])
        canaries.append(canary)
        raise exc

    ax.jobs.register("canary.fail", handler)
    job = ax.jobs.enqueue(sys_principal, product.id, "canary.fail", {}, tenant_id=tenant.id)
    root = logging.getLogger()
    saved, level = root.handlers[:], root.level
    own = io.StringIO()
    root.handlers[:] = [logging.StreamHandler(own)]
    root.setLevel(logging.DEBUG)
    try:
        assert JobWorker(ax, scheduler=False, housekeeping=False).run_once(maintenance=False) == 1
    finally:
        root.handlers[:] = saved
        root.setLevel(level)
    (canary,) = canaries
    _assert_clean(own.getvalue(), canary)
    r = world.admin.get(f"/v1/products/{product.id}/jobs/{job.id}")
    assert r.status_code == 200, r.text
    last_error = r.json()["last_error"]
    assert canary not in r.text and "DETAIL" not in r.text
    assert (
        "UniqueViolation" in last_error and "23505" in last_error and "canary_people_email_key" in last_error
    )
    listing = world.admin.get(f"/v1/products/{product.id}/jobs")
    assert listing.status_code == 200 and canary not in listing.text


def test_m3_notification_last_error(world: Any, pg_urls: dict[str, str]) -> None:
    """M-3: a notification whose delivery fails on a database error stores and returns ``last_error`` without
    the values."""
    from tests.integration.test_notify import _product, _send, _template, _tenant

    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    mid = _send(world.admin, pid, tid, {"email": "bob@example.com"}).json()["id"]
    canaries: list[str] = []

    class FailingProvider:
        name = "failing"

        def send(self, message: Any) -> str:
            canary, exc = _db_error(pg_urls["admin"])
            canaries.append(canary)
            raise exc

        def check(self) -> bool:
            return True

    world.ax.notify.set_provider(FailingProvider())
    assert world.ax.notify.dispatcher(jitter=0).run_once().claimed == 1
    r = world.admin.get(f"/v1/products/{pid}/notify/messages/{mid}")
    assert r.status_code == 200, r.text
    (canary,) = canaries
    assert canary not in r.text and "DETAIL" not in r.text
    assert "23505" in r.json()["last_error"]


def test_m2_trace_spans_carry_no_values(ax_factory: Any, pg_urls: dict[str, str]) -> None:
    """M-2: with tracing on, the span of a request that fails on a database error records the exception (event
    and status) without the values."""
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.trace import StatusCode

    from axentra.observability.tracing import setup_tracing

    ax = ax_factory(observability={"otel_enabled": True})
    exporter = InMemorySpanExporter()
    ax.tracing = setup_tracing(ax.settings.observability, span_processor=SimpleSpanProcessor(exporter))
    app = create_app(axentra=ax, start=False)
    canaries: list[str] = []

    def boom() -> None:
        canary, exc = _db_error(pg_urls["admin"])
        canaries.append(canary)
        raise exc

    app.add_api_route("/_test/traced", boom, methods=["POST"])
    r = _client(app).post("/_test/traced")
    assert r.status_code == 500
    spans = exporter.get_finished_spans()
    dump = repr([(s.name, s.status, [(e.name, dict(e.attributes or {})) for e in s.events]) for s in spans])
    (canary,) = canaries
    assert canary not in dump and "DETAIL" not in dump
    events = [e for s in spans for e in s.events if e.name == "exception"]
    assert events and all("23505" in str((e.attributes or {})["exception.message"]) for e in events)
    assert any(s.status.status_code is StatusCode.ERROR for s in spans)


@pytest.mark.usefixtures("ax")
def test_l1_wrapper_text_in_traceback(pg_urls: dict[str, str]) -> None:
    """L-1: an exception whose own text quotes the database error (``raise RuntimeError(f"...: {e}") from e``)."""
    canary, exc = _db_error(pg_urls["admin"])

    def log(lg: logging.Logger) -> None:
        try:
            try:
                raise exc
            except psycopg.Error as e:
                raise RuntimeError(f"saving the user failed: {e}") from e
        except RuntimeError:
            lg.exception("job failed")

    out = _plain_handler_output(log)
    _assert_clean(out, canary)
    assert "RuntimeError: saving the user failed: unique violation" in out


@pytest.mark.usefixtures("ax")
def test_l2_messages_formatted_before_logging(pg_urls: dict[str, str]) -> None:
    """L-2: the error's text is put into the message before logging (f-string, ``str(exc)``, one line)."""
    canary, exc = _db_error(pg_urls["admin"])
    out = _plain_handler_output(
        lambda lg: (
            lg.error(f"insert failed: {exc}"),
            lg.error("insert failed: %s", str(exc)),
            lg.error("insert failed: %s", str(exc).replace("\n", " ")),
        )
    )
    assert out.count("insert failed") == 3
    assert canary not in out and "DETAIL" not in out


@pytest.mark.usefixtures("ax")
def test_l3_mapping_arguments(pg_urls: dict[str, str]) -> None:
    """L-3: the error as a value of a mapping argument (``%(e)s``)."""
    canary, exc = _db_error(pg_urls["admin"])
    _assert_clean(_plain_handler_output(lambda lg: lg.error("insert failed: %(e)s", {"e": exc})), canary)


@pytest.mark.usefixtures("ax")
def test_l4_deep_chains_and_exception_groups(pg_urls: dict[str, str]) -> None:
    """L-4: the database error deep in a chain of wrappers, and inside nested exception groups."""
    canary, exc = _db_error(pg_urls["admin"])

    def deep(lg: logging.Logger) -> None:
        current: BaseException = exc
        for layer in range(20):
            try:
                try:
                    raise current
                except BaseException as inner:
                    raise ValueError(f"layer {layer}") from inner
            except ValueError as outer:
                current = outer
        try:
            raise current
        except ValueError:
            lg.exception("deep")

    def groups(lg: logging.Logger) -> None:
        try:
            raise ExceptionGroup("outer", [ExceptionGroup("inner", [exc])])
        except ExceptionGroup:
            lg.exception("group")

    _assert_clean(_plain_handler_output(deep), canary)
    _assert_clean(_plain_handler_output(groups), canary)


@pytest.mark.usefixtures("ax")
def test_l5_broken_log_call_keeps_the_redacted_record(pg_urls: dict[str, str]) -> None:
    """L-5: a log call that cannot be formatted (too few arguments) still logs, with its traceback, no values."""
    canary, exc = _db_error(pg_urls["admin"])

    def log(lg: logging.Logger) -> None:
        try:
            raise exc
        except psycopg.Error as e:
            lg.error("insert %s failed: %s", e, exc_info=True)

    out = _plain_handler_output(log)
    _assert_clean(out, canary)
    assert "Traceback (most recent call last)" in out
    assert "insert %s failed: %s" in out


def test_l6_cli_operator_error_without_values(
    pg_urls: dict[str, str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """L-6: a CLI command that fails on a database error prints ``axentra: database_error: ...`` without the
    values on stderr."""
    from axentra import cli

    canaries: list[str] = []

    def failing(args: Any) -> int:
        canary, exc = _db_error(pg_urls["admin"])
        canaries.append(canary)
        raise exc

    monkeypatch.setattr(cli, "cmd_setup_token", failing)
    monkeypatch.delenv("AXENTRA_DEBUG", raising=False)
    assert cli.main(["admin", "setup-token"]) == cli.EXIT_OPERATOR_ERROR
    err = capsys.readouterr().err
    (canary,) = canaries
    assert "axentra: database_error: unique violation" in err
    _assert_clean(err, canary)
