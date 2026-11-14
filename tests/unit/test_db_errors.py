"""Axentra's use of Tabrion's database error redaction (``axentra.core.db_errors``, TABRION MIG-AXE-3).

``tabrion.errors`` does the redaction (its own tests pin how). These tests pin what Axentra adds around it: the
process-wide installation (record factory, ``handleError``, ``makeRecord``), the helpers for stored and exported
texts, the structlog processor and the CLI's exception hook, and they check the review cases of the local fix
(TABRION MIG-AXE-0, TB-031, ``axe-tb031-review.md``) through the filter as Axentra installs it. The PostgreSQL
regression tests are in ``tests/integration/test_db_error_logging.py``.
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg
import pytest

from axentra.core import db_errors
from axentra.core.db_errors import DbErrorRedactionFilter, install_db_error_redaction, safe_message


def test_install_is_idempotent() -> None:
    install_db_error_redaction()
    factory = logging.getLogRecordFactory()
    install_db_error_redaction()
    assert logging.getLogRecordFactory() is factory
    assert sum(isinstance(f, DbErrorRedactionFilter) for f in logging.getLogger("axentra.http").filters) == 1


def test_unusual_records_do_not_fail() -> None:
    f = DbErrorRedactionFilter()
    bare = psycopg.errors.UniqueViolation("no diag")
    for record in [
        logging.LogRecord("x", 40, __file__, 1, {"a": 1}, None, None),
        logging.LogRecord("x", 40, __file__, 1, "%s", (bare,), None),
        logging.LogRecord("x", 40, __file__, 1, bare, None, (type(bare), bare, None)),
        logging.LogRecord("x", 40, __file__, 1, "m", None, (None, None, None)),
        logging.LogRecord("x", 40, __file__, 1, "m %(a)s", ({"a": bare},), None),
    ]:
        assert f.filter(record) is True
        logging.Formatter().format(record)
    assert safe_message(bare) == "unique violation (SQLSTATE 23505)"


# --- TABRION TB-031 (Tabrion review H-1, H-2, M-2, N-1, N-2, N-3) ---------------------------------------------------

SECRET = "SECRET-4711"


def _unique(detail: str = f"Key (email)=({SECRET}) already exists.") -> psycopg.Error:
    return psycopg.errors.UniqueViolation(
        f'duplicate key value violates unique constraint "u_key"\nDETAIL:  {detail}'
    )


def _filtered(msg: object, args: object = None, exc: BaseException | None = None) -> logging.LogRecord:
    exc_info = (type(exc), exc, exc.__traceback__) if exc is not None else None
    record = logging.LogRecord("x", logging.ERROR, __file__, 1, msg, args, exc_info)  # type: ignore[arg-type]
    assert DbErrorRedactionFilter().filter(record) is True
    return record


def _raised_in_handler(handled: BaseException, raised: BaseException) -> BaseException:
    """``raised``, raised inside ``except`` for ``handled``: Python sets ``raised.__context__ = handled``."""
    try:
        try:
            raise handled
        except BaseException:
            raise raised  # noqa: B904 - the implicit context is the point
    except BaseException as exc:
        return exc


#: What Tabrion puts in place of a removed server text part.
MARK = "[redacted: database server text]"


def test_f3_inline_label_after_long_blank_runs_is_linear() -> None:
    """F-3: a logged value with a long run of blanks and a label used to take quadratic time (7.7 s at 40 KB)."""
    import time

    for blanks in (" ", "\t", " \t"):
        value = "a" + blanks * 50_000 + " DETAIL:"
        started = time.perf_counter()
        _filtered("rejected value %s", (value,))
        db_errors.strip_server_text(value + "  x")
        assert time.perf_counter() - started < 0.5, repr(blanks)


@pytest.mark.parametrize(
    ("msg", "args"),
    [
        ("x %s", ([_unique()],)),
        ("x %s", ((_unique(),),)),
        ("x %s", ({_unique()},)),
        ("x %s", ({"k": [_unique()]},)),
        ("x %s", (RuntimeError(_unique()),)),
        ({"err": _unique()}, None),
        ([_unique()], None),
    ],
)
def test_errors_inside_containers_are_found(msg: object, args: object) -> None:
    record = _filtered(msg, args)
    text = record.getMessage()
    assert SECRET not in text and "DETAIL" not in text
    assert "unique violation (SQLSTATE 23505)" in text
    assert record.db_sqlstate == "23505"  # type: ignore[attr-defined]


def test_n2_container_whose_iteration_fails_keeps_the_record() -> None:
    class BadList(list[int]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("lazy collection")

    record = _filtered("hello %s", (BadList([1]),))
    assert record.msg == "hello %s"  # not replaced by the fallback message
    assert "DbErrorRedactionFilter" not in logging.Formatter().format(record)


def test_notes_on_a_driver_error_are_dropped() -> None:
    e = _unique()
    e.add_note(f"params={SECRET}")
    record = _filtered("failed", None, e)
    assert SECRET not in logging.Formatter().format(record)


def test_group_whose_only_database_error_is_a_member() -> None:
    group = ExceptionGroup("batch", [ValueError("other"), _unique()])
    assert group.__context__ is None
    text = logging.Formatter().format(_filtered("batch failed", None, group))
    assert SECRET not in text and "SQLSTATE 23505" in text


def _lost() -> psycopg.Error:
    return psycopg.OperationalError("consuming input failed: server closed the connection unexpectedly")


@pytest.mark.parametrize("handled", ["40001", "40P01", "55P03", "23505"])
def test_h1_lost_commit_inside_a_handler_is_named_by_itself(handled: str) -> None:
    older = psycopg.errors.lookup(handled)("older error")
    lost = _raised_in_handler(older, _lost())
    assert lost.__context__ is older
    record = _filtered("commit failed", None, lost)
    assert record.db_sqlstate is None  # type: ignore[attr-defined]
    assert db_errors.safe_error_text(lost).startswith("connection error")
    assert handled not in db_errors.safe_error_text(lost)


def test_h1_cause_wins_over_an_older_context() -> None:
    caused = RuntimeError("outer")
    caused.__context__ = psycopg.errors.lookup("40001")("handled")
    caused.__cause__ = _unique()
    caused.__suppress_context__ = False  # a context that is printed too still yields to the cause
    record = _filtered("failed", None, caused)
    assert record.db_sqlstate == "23505"  # type: ignore[attr-defined]
    # A plain wrapper raised in a handler: the context is the only database error, so it is named.
    wrapped = _raised_in_handler(_unique(), RuntimeError("save failed"))
    assert _filtered("failed", None, wrapped).db_sqlstate == "23505"  # type: ignore[attr-defined]


def test_h1_outermost_connection_loss_wins_over_a_cause() -> None:
    outer = _lost()
    outer.__cause__ = psycopg.errors.lookup("40001")("inner")
    assert safe_message(outer).startswith("connection error")
    terminated = psycopg.errors.lookup("57P01")("terminated")
    terminated.__cause__ = _unique()
    assert "SQLSTATE 57P01" in safe_message(terminated)


# --- Review axe-tb031-review.md (F-1, F-2, F-5, F-6, F-8) -----------------------------------------------------------


def _traceback_text(record: logging.LogRecord) -> str:
    return logging.Formatter().format(record)


def test_f1_traceback_of_a_wrapper_without_a_chain() -> None:
    """F-1: a retry loop keeps the last error and raises after the loop: no ``__context__``, the text in the
    message."""
    last: BaseException | None = None
    for _ in range(2):
        try:
            raise _unique()
        except psycopg.Error as exc:
            last = exc
    try:
        raise RuntimeError(f"gave up: {last}")
    except RuntimeError as exc:
        raised = exc
    assert raised.__context__ is None
    record = _filtered("job failed", None, raised)
    text = _traceback_text(record)
    assert SECRET not in text and "DETAIL" not in text
    assert "RuntimeError: gave up: duplicate key value" in text and MARK in text
    assert record.exc_info is None


@pytest.mark.parametrize(
    ("make", "as_object"),
    [
        (lambda e: RuntimeError(e), True),  # the error object in args, raised outside an except block
        (lambda e: RuntimeError("batch failed", [e]), True),
        (lambda e: RuntimeError(str(e)), False),  # only its text
    ],
)
def test_f1_exception_args_carry_the_error(make: Any, as_object: bool) -> None:
    record = _filtered("x", None, make(_unique()))
    text = _traceback_text(record)
    assert SECRET not in text and "DETAIL" not in text
    # An error object in the args is found as such: replaced by its safe message and named in the fields.
    assert ("unique violation (SQLSTATE 23505)" in text) is as_object
    assert getattr(record, "db_sqlstate", None) == ("23505" if as_object else None)


@pytest.mark.parametrize("with_args", [False, True])
def test_f1_note_with_the_error_text(with_args: bool) -> None:
    wrapper = RuntimeError("wrap")
    wrapper.add_note(str(_unique()))
    text = _traceback_text(_filtered("x %s" if with_args else "x", (1,) if with_args else None, wrapper))
    assert SECRET not in text and "DETAIL" not in text and "RuntimeError: wrap" in text


def test_f1_wrapper_quoting_an_original_attribute() -> None:
    class Wrapped(Exception):
        def __init__(self, original: BaseException) -> None:
            super().__init__("wrapped")
            self.original = original

        def __str__(self) -> str:
            return f"wrap: {self.original}"

    text = _traceback_text(_filtered("x", None, Wrapped(_unique())))
    assert SECRET not in text and "DETAIL" not in text


def test_f1_json_formatter_exc_field() -> None:
    import json

    from axentra.audit.logging import JsonFormatter

    record = _filtered("job failed", None, RuntimeError(f"gave up: {_unique()}"))
    line = json.loads(JsonFormatter().format(record))
    assert SECRET not in json.dumps(line) and "RuntimeError: gave up" in line["exc"]


def test_f1_other_exceptions_keep_their_traceback() -> None:
    record = _filtered("x", None, ValueError("visible 4711"))
    assert record.exc_info is not None
    assert "ValueError: visible 4711" in _traceback_text(record)


def test_f2_handle_error_prints_no_values(capsys: pytest.CaptureFixture[str]) -> None:
    """F-2: a log call that fails in ``emit`` while a database error is being handled: the standard
    ``handleError`` prints the exception's ``__context__`` (the database error) raw to stderr."""
    import io

    install_db_error_redaction()
    handlers = [logging.StreamHandler(io.StringIO()), logging.StreamHandler(io.StringIO())]
    handlers[1].setFormatter(logging.Formatter("%(message)s %(request_id)s"))  # a formatter that raises
    lg = logging.getLogger("axentra.test.handle_error")
    lg.propagate = False
    saved = logging.raiseExceptions
    logging.raiseExceptions = True
    try:
        for handler in handlers:
            lg.handlers[:] = [handler]
            try:
                raise _unique()
            except psycopg.Error:
                lg.error("user %s failed with %s", "bob")  # too few arguments
                lg.error("insert failed, retrying")
    finally:
        lg.handlers[:] = []
        logging.raiseExceptions = saved
    err = capsys.readouterr().err
    # Only the formatter that raises fails in emit: Tabrion's filter keeps the broken call (too few arguments) as a
    # record with a fixed message that names the error, so it no longer fails on the plain handler.
    assert err.count("--- Logging error ---") == 2
    assert SECRET not in err and "DETAIL" not in err
    assert "unique violation (SQLSTATE 23505)" in err
    assert "could not be formatted: 'user %s failed with %s'" in err


def test_f2_install_patches_once() -> None:
    install_db_error_redaction()
    patched = logging.Handler.handleError
    make_record = logging.Logger.makeRecord
    install_db_error_redaction()
    assert logging.Handler.handleError is patched is db_errors._redacted_handle_error
    assert logging.Logger.makeRecord is make_record


def test_f5_mapping_message_stays_a_mapping() -> None:
    """F-5: structlog's ProcessorFormatter passes its event dict as ``msg`` and copies it."""
    e = _unique()
    record = _filtered({"event": "failed", "error": e, "text": str(e), "n": 1, "items": [e]})
    assert isinstance(record.msg, dict)
    assert record.msg["event"] == "failed" and record.msg["n"] == 1
    assert record.msg["error"] == "unique violation (SQLSTATE 23505)"
    assert SECRET not in repr(record.msg) and "DETAIL" not in repr(record.msg)
    assert record.db_sqlstate == "23505"  # type: ignore[attr-defined]
    clean = {"event": "ok", "n": 2}
    assert _filtered(clean).msg is clean


def test_f6_extra_may_carry_the_db_fields() -> None:
    """F-6: ``extra={"db_sqlstate": ...}`` must not raise ``KeyError`` from the logging call."""
    install_db_error_redaction()
    records: list[logging.LogRecord] = []

    class Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    lg = logging.getLogger("axentra.test.extra_fields")
    lg.propagate = False
    lg.handlers[:] = [Keep()]
    try:
        e = _unique()
        lg.error("x %s", e, extra={"db_sqlstate": "given", "db_constraint": "c", "other": 1})
        lg.error("x %s", e, extra={"other": 2})
    finally:
        lg.handlers[:] = []
    assert [(r.db_sqlstate, r.other) for r in records] == [("given", 1), ("23505", 2)]  # type: ignore[attr-defined]
    assert SECRET not in records[0].getMessage()


def test_f8_string_args_of_an_error_are_replaced() -> None:
    """F-8: an error whose ``str`` differs from its ``args``: the args text is replaced as well."""
    cls = type("Odd", (Exception,), {"__module__": "psycopg.errors", "__str__": lambda self: "odd error"})
    e = cls(f"value {SECRET} rejected")
    text = _filtered("failed: %s / %s", (e, e.args[0])).getMessage()
    assert SECRET not in text


# --- Delta review (D-2 processor, D-3) ------------------------------------------------------------------------------


def test_d2_structlog_processor_without_stdlib() -> None:
    """D-2: the optional processor protects a structlog chain that does not go through ``logging``."""
    import io

    structlog = pytest.importorskip("structlog")
    stream = io.StringIO()
    structlog.reset_defaults()
    structlog.configure(
        processors=[
            db_errors.redact_db_errors_processor,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=stream),
        cache_logger_on_first_use=False,
    )
    try:
        slog = structlog.get_logger()
        try:
            raise _unique()
        except psycopg.Error:
            slog.exception("boom")
        slog.error("kw", err=_unique(), items=[_unique()], text=str(_unique()))
        slog.info("plain", n=1)
    finally:
        structlog.reset_defaults()
    out = stream.getvalue()
    assert SECRET not in out and "DETAIL" not in out, out
    assert out.count("unique violation (SQLSTATE 23505)") >= 3
    assert '"n": 1' in out


@pytest.mark.parametrize(
    "exc_info",
    [True, "instance", "tuple", False, None],
)
def test_d2_processor_exc_info_forms(exc_info: object) -> None:
    e = _unique()
    try:
        raise e
    except psycopg.Error:
        value = {"instance": e, "tuple": (type(e), e, e.__traceback__)}.get(exc_info, exc_info)  # type: ignore[call-overload]
        out = db_errors.redact_db_errors_processor(None, "error", {"event": "x", "exc_info": value})
    assert SECRET not in repr(out)
    if exc_info in (False, None):
        assert out == {"event": "x", "exc_info": exc_info}
    else:
        assert "exc_info" not in out and "unique violation (SQLSTATE 23505)" in out["exception"]


def test_d2_processor_never_raises() -> None:
    class Bad:
        def __repr__(self) -> str:
            raise RuntimeError("bad repr")

    assert db_errors.redact_db_errors_processor(None, "error", {"event": "x", "b": Bad()})["event"] == "x"
    assert db_errors.redact_db_errors_processor(None, "error", "not a dict") == "not a dict"


def test_d3_exception_whose_args_property_raises() -> None:
    class Odd(Exception):
        @property
        def args(self):  # type: ignore[override]
            raise RuntimeError("no args")

    record = _filtered("payment %s failed", ("ord-1",), Odd())
    assert record.getMessage() == "payment ord-1 failed"
    assert "DbErrorRedactionFilter" not in _traceback_text(record)


# --- TABRION MIG-AXE-3: Axentra's helpers around Tabrion's filter ---------------------------------------------------


def _raised(exc: BaseException) -> BaseException:
    try:
        raise exc
    except BaseException as caught:
        return caught


def test_the_filter_and_safe_message_are_tabrions() -> None:
    import tabrion.errors

    assert db_errors.DbErrorRedactionFilter is tabrion.errors.DbErrorRedactionFilter
    assert db_errors.safe_message is tabrion.errors.safe_message
    install_db_error_redaction()
    assert any(
        isinstance(f, tabrion.errors.DbErrorRedactionFilter)
        for f in logging.getLogger("axentra.http").filters
    )


def test_safe_error_text() -> None:
    assert db_errors.safe_error_text(_unique()) == "unique violation (SQLSTATE 23505)"
    quoting = RuntimeError(f"saving failed: {_unique()}")
    quoting.__cause__ = _unique()
    text = db_errors.safe_error_text(quoting)
    assert SECRET not in text and "DETAIL" not in text and text.startswith("saving failed: ")
    # The error only as text (no object): everything from the label on is removed.
    text = db_errors.safe_error_text(RuntimeError(f"gave up: {_unique()}"))
    assert SECRET not in text and text.endswith(MARK)
    assert db_errors.safe_error_text(ValueError("visible 4711")) == "visible 4711"

    class Unprintable(Exception):
        def __str__(self) -> str:
            raise RuntimeError("no text")

    assert db_errors.safe_error_text(Unprintable()) == "database error"


def test_redacted_traceback() -> None:
    wrapper = RuntimeError("wrap")
    wrapper.__cause__ = _raised(_unique())
    text = db_errors.redacted_traceback(_raised(wrapper))
    assert SECRET not in text and "DETAIL" not in text
    assert (
        "unique violation (SQLSTATE 23505)" in text
        and 'File "' in text
        and text.endswith("RuntimeError: wrap")
    )
    plain = db_errors.redacted_traceback(_raised(ValueError("visible 4711")))
    assert plain.startswith("Traceback (most recent call last):") and plain.endswith(
        "ValueError: visible 4711"
    )


def test_strip_server_text() -> None:
    assert (
        db_errors.strip_server_text(str(_unique()))
        == f'duplicate key value violates unique constraint "u_key"\n{MARK}'
    )
    assert db_errors.strip_server_text("plain text") == "plain text"


def test_redacted_excepthook(capsys: pytest.CaptureFixture[str]) -> None:
    wrapper = RuntimeError(f"saving failed: {_unique()}")
    wrapper.__cause__ = _unique()
    exc = _raised(wrapper)
    db_errors.redacted_excepthook(type(exc), exc, exc.__traceback__)
    err = capsys.readouterr().err
    assert SECRET not in err and "DETAIL" not in err
    assert "Traceback (most recent call last):" in err and "unique violation (SQLSTATE 23505)" in err


def test_cli_installs_the_excepthook_and_keeps_an_own_one(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from axentra import cli

    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert sys.excepthook is db_errors.redacted_excepthook

    def own(*args: object) -> None:
        pass

    monkeypatch.setattr(sys, "excepthook", own)
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert sys.excepthook is own


def test_cli_unreachable_text_keeps_the_client_reason_without_server_text() -> None:
    from axentra.cli import _unreachable_text

    refused = psycopg.OperationalError("connection failed: connection refused")
    assert _unreachable_text(refused) == "connection error: connection failed: connection refused"
    odd = psycopg.OperationalError(f"connection failed\nDETAIL:  {SECRET}")
    assert SECRET not in _unreachable_text(odd) and "DETAIL" not in _unreachable_text(odd)
    terminated = psycopg.errors.lookup("57P01")(f"terminating connection\nDETAIL:  {SECRET}")
    assert _unreachable_text(terminated) == "connection error (SQLSTATE 57P01)"


# --- N-3: threading.excepthook and sys.unraisablehook ---------------------------------------------------------------


def _install_cli_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    """The interpreter's default hooks (pytest replaces some during a test), then the CLI's."""
    import sys
    import threading

    from axentra import cli

    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    monkeypatch.setattr(threading, "excepthook", threading.__excepthook__)
    monkeypatch.setattr(sys, "unraisablehook", sys.__unraisablehook__)
    with pytest.raises(SystemExit):
        cli.main(["--version"])


def test_cli_redacts_an_exception_that_ends_a_thread(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import threading

    _install_cli_hooks(monkeypatch)

    def run() -> None:
        try:
            raise _unique()
        except psycopg.Error as exc:
            raise RuntimeError("worker failed") from exc

    thread = threading.Thread(target=run, name="n3-probe")
    thread.start()
    thread.join()
    err = capsys.readouterr().err
    assert SECRET not in err and "DETAIL" not in err
    assert "Exception in thread n3-probe:" in err and "RuntimeError: worker failed" in err
    assert "unique violation (SQLSTATE 23505)" in err


def test_cli_redacts_an_unraisable_exception(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import gc

    _install_cli_hooks(monkeypatch)

    class Holder:
        def __repr__(self) -> str:
            return f"<Holder {SECRET}>"

        def __del__(self) -> None:
            raise _unique()

    Holder()
    gc.collect()
    err = capsys.readouterr().err
    assert SECRET not in err and "DETAIL" not in err
    assert "Exception ignored in: <function " in err and "Holder.__del__>" in err
    assert "unique violation (SQLSTATE 23505)" in err


def test_unraisable_hook_names_an_object_by_its_type(capsys: pytest.CaptureFixture[str]) -> None:
    from types import SimpleNamespace

    class Box:
        def __repr__(self) -> str:
            return f"<Box {SECRET}>"

    exc = _unique()
    args = SimpleNamespace(exc_type=type(exc), exc_value=exc, exc_traceback=None, err_msg=None, object=Box())
    db_errors.redacted_unraisablehook(args)
    err = capsys.readouterr().err
    assert SECRET not in err and "DETAIL" not in err
    assert err.startswith("Exception ignored in: <") and "Box object>" in err
    assert "unique violation (SQLSTATE 23505)" in err


def test_cli_keeps_own_thread_and_unraisable_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import threading

    from axentra import cli

    def own(*args: object) -> None:
        pass

    monkeypatch.setattr(threading, "excepthook", own)
    monkeypatch.setattr(sys, "unraisablehook", own)
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert threading.excepthook is own and sys.unraisablehook is own


def test_thread_hook_stays_silent_for_system_exit(capsys: pytest.CaptureFixture[str]) -> None:
    import threading

    exc = SystemExit(1)
    db_errors.redacted_threading_excepthook(
        threading.ExceptHookArgs((SystemExit, exc, None, threading.current_thread()))  # type: ignore[call-arg]
    )
    assert capsys.readouterr().err == ""


def test_asyncio_default_exception_handler_logs_through_the_filter(caplog: pytest.LogCaptureFixture) -> None:
    """The event loop's default handler (an unretrieved task exception under uvicorn/anyio) reports through the
    ``asyncio`` logger, so the record factory redacts it: no hook of its own is needed (N-3)."""
    import asyncio

    install_db_error_redaction()

    async def failing() -> None:
        raise _unique()

    loop = asyncio.new_event_loop()
    try:
        task = loop.create_task(failing())
        loop.run_until_complete(asyncio.sleep(0))
        loop.call_exception_handler(
            {"message": "Task exception was never retrieved", "exception": task.exception()}
        )
    finally:
        loop.close()
    text = "\n".join(caplog.text.splitlines())
    assert "Task exception was never retrieved" in text and "unique violation (SQLSTATE 23505)" in text
    assert SECRET not in text and "DETAIL" not in text


@pytest.mark.parametrize(
    "text",
    [
        # psycopg's text of a 22P02 error, formatted before it was logged (no DETAIL/HINT/CONTEXT label).
        "invalid input syntax for type integer: \"x\"\nLINE 1: select 'CANARY-line'::int\n               ^",
        # The same inside a repr: the line break is the two characters backslash and n.
        repr(RuntimeError("invalid input syntax for type integer: \"x\"\nLINE 1: select 'CANARY-line'::int")),
    ],
)
def test_h2_statement_echo_without_another_label_is_removed(text: str) -> None:
    """Delta review N-2 / H-2: Tabrion 0.2.1 (22fa7ad) removes a lone ``LINE n:`` statement echo. A value in the
    primary text (``"x"`` here) stays: label-based removal cannot see it (residual R-1, OBSERVABILITY.md)."""
    out = db_errors.strip_server_text(text)
    assert "CANARY-line" not in out
    assert out.startswith(text[:30])
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "job failed: %s", (text,), None)
    assert DbErrorRedactionFilter().filter(record)
    assert "CANARY-line" not in record.getMessage()
    assert "CANARY-line" not in db_errors.safe_error_text(RuntimeError(text))
