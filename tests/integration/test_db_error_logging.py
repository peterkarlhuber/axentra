"""Database errors in logs and HTTP answers (finding B-06-1, TABRION MIG-AXE-0, kept by TABRION MIG-AXE-3).

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


# --- TABRION TB-031: the Tabrion review's leaks (H-2, M-2, N-1) and the H-1 chain rule ------------------------------


def _sa_style_wrapper(err: psycopg.Error) -> Exception:
    """An error shaped like SQLAlchemy's ``IntegrityError`` (Axentra does not depend on SQLAlchemy): it keeps the
    driver error in ``orig`` and quotes its text, the statement and the parameters."""
    cls = type("IntegrityError", (Exception,), {"__module__": "sqlalchemy.exc"})
    wrapper = cls(
        f"({type(err).__module__}.{type(err).__qualname__}) {err}\n"
        "[SQL: INSERT INTO canary_people (email) VALUES (%(email)s)]\n"
        "(Background on this error at: https://sqlalche.me/e/20/gkpj)"
    )
    wrapper.orig = err  # type: ignore[attr-defined]
    return wrapper


#: Every log call of the Tabrion review's H-2 table that leaked the DETAIL value through Axentra's filter at
#: 9c4666f. ``e`` is a real psycopg error, ``sa`` a wrapper of it.
H2_CALLS: dict[str, Callable[[logging.Logger, psycopg.Error, Exception], None]] = {
    "f-string repr": lambda lg, e, sa: lg.error(f"x {e!r}"),
    "%s of repr(e)": lambda lg, e, sa: lg.error("x %s", repr(e)),
    "%r of str(e)": lambda lg, e, sa: lg.error("x %r", str(e)),
    "list argument": lambda lg, e, sa: lg.error("x %s", [e]),
    "tuple argument": lambda lg, e, sa: lg.error("x %s", (e,)),
    "e.args argument": lambda lg, e, sa: lg.error("x %s", e.args),
    "dict as msg": lambda lg, e, sa: lg.error({"err": e}),
    "nested containers": lambda lg, e, sa: lg.error("x %s", {"k": [(e,)]}),
    "exception args": lambda lg, e, sa: lg.error("x %s", RuntimeError(e)),
    "wrapper in a list": lambda lg, e, sa: lg.error("x %s", [sa]),
    "wrapper repr": lambda lg, e, sa: lg.error(f"x {sa!r}"),
    "set argument": lambda lg, e, sa: lg.error("x %s", {e}),
    "ascii()": lambda lg, e, sa: lg.error("x %s", ascii(e)),
}


@pytest.mark.parametrize("call", sorted(H2_CALLS))
@pytest.mark.usefixtures("ax")
def test_tb031_h2_repr_and_container_arguments(pg_urls: dict[str, str], call: str) -> None:
    """H-2: the DETAIL value never survives in ``repr`` (escaped ``\\nDETAIL:``) form or inside container, exception
    ``args`` and non-``str`` message arguments, through a product's own plain handler."""
    canary, exc = _db_error(pg_urls["admin"])
    assert canary in repr(exc)  # the leak the filter has to close
    out = _plain_handler_output(lambda lg: H2_CALLS[call](lg, exc, _sa_style_wrapper(exc)))
    assert out.count("\n") == 1, out  # the record is kept, on one line
    assert canary not in out, out
    assert "DETAIL" not in out, out
    assert "duplicate key" in out or "23505" in out, out


@pytest.mark.usefixtures("ax")
def test_tb031_h2_container_errors_name_the_sqlstate(pg_urls: dict[str, str]) -> None:
    """A database error found inside a container argument is replaced by its safe message and named in
    ``db_sqlstate`` / ``db_constraint`` (JSON logs)."""
    canary, exc = _db_error(pg_urls["admin"])
    # The process-wide redaction runs when the record is created.
    record = logging.getLogRecordFactory()("x", logging.ERROR, __file__, 1, "x %s", ([exc],), None)
    assert canary not in record.getMessage()
    # Tabrion's safe message (TABRION MIG-AXE-3) also names the table: ``..., table canary_people)``.
    assert "unique violation (SQLSTATE 23505, constraint canary_people_email_key" in record.getMessage()
    assert (record.db_sqlstate, record.db_constraint) == ("23505", "canary_people_email_key")  # type: ignore[attr-defined]


def _db_error_with_value(admin_url: str, value: str) -> psycopg.Error:
    try:
        with psycopg.connect(admin_url) as conn:
            conn.execute(
                "CREATE TEMP TABLE canary_people (email text CONSTRAINT canary_people_email_key UNIQUE)"
            )
            conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (value,))
            conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (value,))
    except psycopg.Error as exc:
        return exc
    raise AssertionError("the statement did not fail")


@pytest.mark.parametrize(
    "shape",
    [
        "{c}-1\n{c}-2\n{c}-3",  # M-2: continuation lines
        "a\n+-{c}",  # N-1: a value line that starts like an exception group frame
        'a\nFile "{c}',  # N-1: ... like a traceback frame
        "a\n[SQL: {c}",  # N-1: ... like SQLAlchemy's statement line
        "a\nTraceback (most recent call last): {c}",
    ],
)
@pytest.mark.usefixtures("ax")
def test_tb031_m2_n1_multi_line_detail_in_preformatted_text(pg_urls: dict[str, str], shape: str) -> None:
    """M-2 and N-1: a multi-line key value in a message formatted before logging (the error object is not in the
    record, so only the text can be cleaned)."""
    canary = _canary()
    exc = _db_error_with_value(pg_urls["admin"], shape.format(c=canary))
    assert canary in str(exc)

    def log(lg: logging.Logger) -> None:
        lg.error("x %s" % exc)  # noqa: UP031 - preformatted on purpose
        lg.error("wrapped: %s", str(exc))
        try:
            try:
                raise exc
            except psycopg.Error as e:
                raise RuntimeError(f"quoting {e}") from None
        except RuntimeError:
            lg.exception("again")

    out = _plain_handler_output(log)
    assert canary not in out, out
    assert "DETAIL" not in out, out
    assert "Traceback (most recent call last)" in out


def _cut(conn: psycopg.Connection[Any]) -> None:
    """Shut the connection's socket down under the driver, as a lost network would."""
    import os
    import socket

    sock = socket.socket(fileno=os.dup(conn.fileno()))
    try:
        sock.shutdown(socket.SHUT_RDWR)
    finally:
        sock.close()


@pytest.mark.usefixtures("ax")
def test_tb031_h1_commit_lost_while_handling_a_unique_violation(
    pg_urls: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """H-1 analog: an upsert fallback runs inside ``except UniqueViolation`` and its COMMIT loses the connection.
    The lost connection (``OperationalError`` without SQLSTATE, the 23505 only as ``__context__``) is what the job's
    ``last_error`` and the log record name, never the older unique violation."""
    from axentra.events.jobs import format_error

    canary = _canary()
    lost: BaseException | None = None
    conn = psycopg.connect(pg_urls["admin"])
    try:
        conn.execute("CREATE TEMP TABLE canary_people (email text CONSTRAINT canary_people_email_key UNIQUE)")
        conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (canary,))
        conn.commit()
        try:
            conn.execute("INSERT INTO canary_people (email) VALUES (%s)", (canary,))
        except psycopg.errors.UniqueViolation:
            conn.rollback()
            conn.execute("UPDATE canary_people SET email = %s WHERE email = %s", (canary, canary))
            _cut(conn)
            try:
                conn.commit()
            except psycopg.OperationalError as exc:
                lost = exc
    finally:
        conn.close()
    assert isinstance(lost, psycopg.OperationalError)
    assert isinstance(lost.__context__, psycopg.errors.UniqueViolation)
    assert getattr(lost, "sqlstate", None) is None
    text = format_error(lost)
    # Tabrion's safe message of the lost connection (TABRION MIG-AXE-3; the local fix said "database client error").
    assert text.startswith("OperationalError: connection error")
    assert "23505" not in text and canary not in text
    # The service wraps the lost connection (raised in its handler, so the 23505 is two contexts down).
    wrapper: BaseException | None = None
    try:
        try:
            raise lost
        except psycopg.OperationalError:
            raise AxentraError("saving failed")  # noqa: B904 - the implicit context is the point
    except AxentraError as exc:
        wrapper = exc
    assert wrapper is not None
    assert "23505" not in format_error(wrapper) and canary not in format_error(wrapper)
    records: list[logging.LogRecord] = []

    def log(lg: logging.Logger) -> None:
        class Keep(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        keep = Keep()
        lg.addHandler(keep)
        try:
            lg.error("commit failed", exc_info=lost)
            lg.error("saving failed", exc_info=wrapper)
        finally:
            lg.removeHandler(keep)

    out = _plain_handler_output(log)
    assert canary not in out and "DETAIL" not in out
    # Both name the lost connection (no SQLSTATE), not the 23505 the handler was handling.
    assert [r.db_sqlstate for r in records] == [None, None]  # type: ignore[attr-defined]


# --- Review axe-tb031-review.md: tracebacks without a database error object (F-1), handleError (F-2), F-8 -----


def test_f1_job_handler_with_a_retry_loop(world: Any, pg_urls: dict[str, str]) -> None:
    """F-1: a job handler retries, keeps the last error and raises after the loop (no ``__context__``). The worker
    logs the failure with its traceback; neither the log nor ``last_error`` carries the value."""
    from axentra.core.context import Principal
    from axentra.events import JobWorker

    ax = world.ax
    sys_principal = Principal.system("test")
    product = ax.tenancy.create_product(sys_principal, slug="crm", name="CRM")
    tenant = ax.tenancy.create_tenant(sys_principal, product.id, slug="acme", name="Acme")
    canaries: list[str] = []

    def handler(ctx: Any) -> None:
        last: psycopg.Error | None = None
        for _ in range(2):
            canary, exc = _db_error(pg_urls["admin"])
            canaries.append(canary)
            last = exc
        raise RuntimeError(f"gave up after 2 attempts: {last}")

    ax.jobs.register("canary.retry", handler)
    job = ax.jobs.enqueue(sys_principal, product.id, "canary.retry", {}, tenant_id=tenant.id)
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
    out = own.getvalue()
    assert "Traceback (most recent call last)" in out and "RuntimeError: gave up after 2 attempts" in out
    assert all(c not in out for c in canaries) and "DETAIL" not in out, out
    r = world.admin.get(f"/v1/products/{product.id}/jobs/{job.id}")
    assert r.status_code == 200, r.text
    assert all(c not in r.text for c in canaries) and "DETAIL" not in r.text


@pytest.mark.usefixtures("ax")
def test_f1_exc_info_without_a_chain(pg_urls: dict[str, str]) -> None:
    """F-1: the database error, or only its text, in the exception's args or notes; no ``__context__``."""
    canary, exc = _db_error(pg_urls["admin"])
    noted = RuntimeError("wrap")
    noted.add_note(str(exc))

    def log(lg: logging.Logger) -> None:
        lg.error("a", exc_info=RuntimeError(exc))
        lg.error("b", exc_info=RuntimeError("batch failed", [exc]))
        lg.error("c", exc_info=RuntimeError(f"gave up: {exc}"))
        lg.error("d", exc_info=noted)

    out = _plain_handler_output(log)
    assert canary not in out and "DETAIL" not in out, out
    assert out.count("RuntimeError: ") == 4  # never raised, so no frames: one exception line each


@pytest.mark.usefixtures("ax")
def test_f2_failed_emit_while_handling_a_database_error(
    pg_urls: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """F-2: a log call that fails while the database error is handled. Logging would report it through
    ``handleError`` with the database error as the ``__context__`` of the formatting error. Tabrion's filter
    (TABRION MIG-AXE-3) already keeps such a record with a fixed message that names the error, so the call no longer
    fails in ``emit``; either way, neither the handler's output nor stderr carries the value, and the failure is
    visible."""
    canary, exc = _db_error(pg_urls["admin"])
    saved = logging.raiseExceptions
    logging.raiseExceptions = True
    try:

        def log(lg: logging.Logger) -> None:
            try:
                raise exc
            except psycopg.Error:
                lg.error("user %s failed with %s", "bob")  # too few arguments

        out = _plain_handler_output(log)
    finally:
        logging.raiseExceptions = saved
    err = capsys.readouterr().err
    assert "--- Logging error ---" in err or "could not be formatted: 'user %s failed with %s'" in out
    assert canary not in err + out and "DETAIL" not in err + out, err + out
    assert "23505" in err + out


@pytest.mark.usefixtures("ax")
def test_f8_rewritten_label_with_the_error_object(pg_urls: dict[str, str]) -> None:
    """F-8: the label was rewritten (single spaces), so only the replacement of the known DETAIL value helps."""
    canary, exc = _db_error(pg_urls["admin"])
    out = _plain_handler_output(lambda lg: lg.error("x %s / %s", exc, " ".join(str(exc).split())))
    assert canary not in out, out
    # Tabrion 0.1 replaced the known DETAIL value; since 0.2.1 a label in the middle of a line starts a removed part
    # (TB-145), so the whole server text goes.
    assert "[redacted]" in out or "[redacted: database server text]" in out


# --- Delta review of the fix round (axe-tb031-review.md D-1, D-2) ---------------------------------------------------


@pytest.mark.usefixtures("ax")
def test_d1_mapping_message_with_exc_info(pg_urls: dict[str, str]) -> None:
    """D-1: a mapping message logged with ``exc_info`` inside ``except UniqueViolation`` (and chained)."""
    canary, exc = _db_error(pg_urls["admin"])

    def log(lg: logging.Logger) -> None:
        try:
            raise exc
        except psycopg.errors.UniqueViolation:
            lg.error({"event": "failed"}, exc_info=True)
        try:
            try:
                raise exc
            except psycopg.Error as e:
                raise RuntimeError("wrap") from e
        except RuntimeError:
            lg.exception({"event": "boom", "n": 1})

    out = _plain_handler_output(log)
    assert canary not in out and "DETAIL" not in out, out
    assert "{'event': 'failed'}" in out and "unique violation (SQLSTATE 23505" in out


def _structlog_stdlib(formatter_processors: list[Any]) -> tuple[Any, io.StringIO, logging.Logger]:
    """structlog's documented stdlib integration: ``wrap_for_formatter`` and a ``ProcessorFormatter``."""
    structlog = pytest.importorskip("structlog")
    structlog.reset_defaults()
    structlog.configure(
        processors=[structlog.stdlib.add_log_level, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, *formatter_processors]
        )
    )
    name = f"axentra.test.structlog.{uuid.uuid4().hex}"
    lg = logging.getLogger(name)
    lg.handlers[:] = [handler]
    lg.propagate = False
    lg.setLevel(logging.DEBUG)
    return structlog.get_logger(name), stream, lg


@pytest.mark.parametrize("config", ["format_exc_info", "dict_tracebacks", "console"])
@pytest.mark.usefixtures("ax")
def test_d2_structlog_stdlib_exceptions(pg_urls: dict[str, str], config: str) -> None:
    """D-2: structlog renders ``exc_info=True`` from its event dict itself (``format_exc_info``,
    ``dict_tracebacks``, ``ConsoleRenderer``); the value must not reach its output."""
    structlog = pytest.importorskip("structlog")
    processors = {
        "format_exc_info": [structlog.processors.format_exc_info, structlog.processors.JSONRenderer()],
        "dict_tracebacks": [structlog.processors.dict_tracebacks, structlog.processors.JSONRenderer()],
        "console": [structlog.dev.ConsoleRenderer(colors=False)],
    }[config]
    canary, exc = _db_error(pg_urls["admin"])
    slog, stream, lg = _structlog_stdlib(processors)
    try:
        try:
            try:
                raise exc
            except psycopg.Error as e:
                raise RuntimeError("wrap") from e
        except RuntimeError:
            slog.exception("boom")
        try:
            raise exc
        except psycopg.Error:
            slog.error("failed", exc_info=True)
        slog.error("kw", err=exc, text=str(exc))
    finally:
        lg.handlers[:] = []
        structlog.reset_defaults()
    out = stream.getvalue()
    assert out.count("boom") == 1 and "failed" in out and "kw" in out, out
    assert canary not in out and "DETAIL" not in out, out
    assert "unique violation (SQLSTATE 23505" in out
