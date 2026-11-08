"""Internals of Axentra's local database error redaction (``axentra.core.db_errors``, TABRION MIG-AXE-0).

Unlike ``tests/integration/test_db_error_logging.py`` (observable behavior, kept after TABRION MIG-AXE-3), these
tests pin details of the local module; MIG-AXE-3 removes this file together with the module.
"""

from __future__ import annotations

import logging
import traceback
from typing import Any

import psycopg
import pytest

from axentra.core import db_errors
from axentra.core.db_errors import DbErrorRedactionFilter, install_db_error_redaction, safe_message


def test_traceback_exception_still_has_str() -> None:
    """``redacted_traceback`` replaces ``TracebackException._str``; without it, it would fall back to a summary
    without file names and line numbers. Fail loudly on a Python version that drops the attribute."""
    try:
        raise ValueError("x")
    except ValueError as exc:
        te = traceback.TracebackException.from_exception(exc)
    assert te._str == "x"  # type: ignore[attr-defined]
    assert hasattr(te, "exceptions")


def test_install_is_idempotent() -> None:
    install_db_error_redaction()
    factory = logging.getLogRecordFactory()
    install_db_error_redaction()
    assert logging.getLogRecordFactory() is factory
    assert sum(isinstance(f, DbErrorRedactionFilter) for f in logging.getLogger("axentra.http").filters) == 1


def test_internal_failure_keeps_the_record_without_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """L-5: if the redaction itself fails, the record is kept with a fixed message and a summary that has no
    database values (never the original text)."""
    bare = psycopg.errors.UniqueViolation("duplicate key\nDETAIL:  Key (email)=(SECRET-4711) already exists.")

    def broken(*args: object, **kwargs: object) -> str:
        raise RuntimeError("broken")

    monkeypatch.setattr(db_errors, "redacted_traceback", broken)
    record = logging.LogRecord(
        "x", logging.ERROR, __file__, 1, "failed: %s", (bare,), (type(bare), bare, None)
    )
    assert DbErrorRedactionFilter().filter(record) is True
    text = logging.Formatter().format(record)
    assert "SECRET-4711" not in text and "DETAIL" not in text
    assert "replaced by DbErrorRedactionFilter" in text
    assert safe_message(bare) in text


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


MARK = db_errors.SERVER_TEXT_MARK


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"dup key DETAIL:  Key (e)=({SECRET})", f"dup key {MARK}"),
        (f"a\nDETAIL:  {SECRET}\nHINT:  {SECRET}", f"a\n{MARK}"),
        (f"x ('dup\\nDETAIL:  {SECRET}')", f"x ('dup {MARK}"),  # escaped (repr) form
        (f"x ('dup\\r\\nHINT:  {SECRET}') tail", f"x ('dup {MARK}"),
        (f"a\nDETAIL:  Key (e)=(l1\n{SECRET}-2\n{SECRET}-3) already exists.", f"a\n{MARK}"),  # M-2
        (f"a\nDETAIL:  Key (e)=(l1\n+-{SECRET}) already exists.", f"a\n{MARK}"),  # N-1
        (f'a\nDETAIL:  Key (e)=(l1\nFile "{SECRET}) already exists.', f"a\n{MARK}"),  # N-1
        (f"a\nDETAIL:  Key (e)=(l1\n[SQL: {SECRET}) already exists.", f"a\n{MARK}"),  # N-1
        # F-4: outside a traceback, no line ends the removal (a table rule, a lone "+", a frame-like line).
        (f"a\nDETAIL:  Key (e)=(l1\n+------+\n{SECRET}) already exists.", f"a\n{MARK}"),
        (f"a\nDETAIL:  Key (e)=(l1\n+\n{SECRET}) already exists.", f"a\n{MARK}"),
        (f"a\nDETAIL:  Key (e)=(l1\n| +---\n{SECRET}) already exists.", f"a\n{MARK}"),
        (f'a\nDETAIL:  Key (e)=(l1\n  File "x", line 1\n{SECRET}) already exists.', f"a\n{MARK}"),
        ("plain text", "plain text"),
    ],
)
def test_strip_server_text_forms(text: str, expected: str) -> None:
    assert db_errors.strip_server_text(text) == expected


def test_strip_server_text_ends_at_traceback_structure() -> None:
    text = (
        "Traceback (most recent call last):\n"
        '  File "/srv/db.py", line 3, in insert\n'
        "    cur.execute(sql)\n"
        f"RuntimeError: quoting dup\nDETAIL:  Key (e)=(l1\n{SECRET}) already exists.\n\n"
        "The above exception was the direct cause of the following exception:\n\n"
        "Traceback (most recent call last):\n"
        '  File "/srv/app.py", line 12, in save\n'
        "    run()\n"
        "ValueError: next"
    )
    out = db_errors.strip_server_text(text)
    assert SECRET not in out
    assert f"RuntimeError: quoting dup\n{MARK}\nThe above exception was the direct cause" in out
    assert 'File "/srv/app.py", line 12, in save' in out and "ValueError: next" in out
    # The same text without the header (a message, a stored last_error): removed to the end.
    headless = text.split("\n", 3)[3]
    assert db_errors.strip_server_text(headless) == f"RuntimeError: quoting dup\n{MARK}"


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


def test_collect_is_bounded_and_survives_cycles() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    cyclic.append(_unique())
    mapping: dict[str, object] = {}
    mapping["self"] = mapping
    mapping["e"] = _unique()
    for value in (cyclic, mapping):
        found: list[BaseException] = []
        db_errors._collect(value, found)
        assert len(found) == 1
    # Beyond the bounds, the error object is not found; the escaped DETAIL of its repr is still removed.
    deep: object = _unique()
    for _ in range(6):
        deep = [deep]
    late = [*range(2_000), _unique()]
    for value in (deep, late):
        found = []
        db_errors._collect(value, found)
        assert found == []
        text = _filtered("x %s", (value,)).getMessage()
        assert SECRET not in text and "DETAIL" not in text


def test_n2_container_whose_iteration_fails_keeps_the_record() -> None:
    class BadList(list[int]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("lazy collection")

    record = _filtered("hello %s", (BadList([1]),))
    assert record.msg == "hello %s"  # not replaced by the fallback message
    assert "DbErrorRedactionFilter" not in logging.Formatter().format(record)


def test_fast_path_does_not_format_plain_records(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = logging.LogRecord.getMessage

    def counting(self: logging.LogRecord) -> str:
        calls.append("x")
        return real(self)

    monkeypatch.setattr(logging.LogRecord, "getMessage", counting)
    _filtered("job %s took %d ms (%s)", ("a", 3, None))
    assert calls == []
    # A str argument with a label, a non-plain argument or a str subclass is formatted and checked.
    for args in [(f"x\nDETAIL:  {SECRET}",), ([1],), (type("S", (str,), {})("s"),)]:
        record = _filtered("x %s", args)
        assert SECRET not in record.getMessage()
    assert len(calls) >= 3


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
    assert db_errors.primary_db_error(lost) is lost
    record = _filtered("commit failed", None, lost)
    assert record.db_sqlstate is None  # type: ignore[attr-defined]
    assert db_errors.safe_error_text(lost).startswith("database client error")


def test_h1_context_is_a_fallback_only() -> None:
    # A plain wrapper raised in a handler: the context is the only database error, so it is used.
    wrapped = _raised_in_handler(_unique(), RuntimeError("save failed"))
    assert db_errors.primary_db_error(wrapped) is wrapped.__context__
    # ``raise ... from None`` suppresses the context: nothing is followed.
    suppressed = RuntimeError("save failed")
    suppressed.__context__ = _unique()
    suppressed.__suppress_context__ = True
    assert db_errors.primary_db_error(suppressed) is None
    # The cause chain wins over an older context, at any depth.
    outer = RuntimeError("outer")
    outer.__cause__ = RuntimeError("retry layer")
    outer.__cause__.__context__ = psycopg.errors.lookup("40001")("older")
    outer.__suppress_context__ = False
    outer.__context__ = _lost()
    # Both are reached through a context only: the loss is reached first.
    assert db_errors.primary_db_error(outer) is outer.__context__
    caused = RuntimeError("outer")
    caused.__context__ = psycopg.errors.lookup("40001")("handled")
    caused.__cause__ = _unique()
    caused.__suppress_context__ = False  # a context that is printed too still yields to the cause
    assert db_errors.primary_db_error(caused) is caused.__cause__
    record = _filtered("failed", None, caused)
    assert record.db_sqlstate == "23505"  # type: ignore[attr-defined]


def test_h1_outermost_connection_loss_wins_over_a_cause() -> None:
    outer = _lost()
    outer.__cause__ = psycopg.errors.lookup("40001")("inner")
    assert db_errors.primary_db_error(outer) is outer
    terminated = psycopg.errors.lookup("57P01")("terminated")
    terminated.__cause__ = _unique()
    assert db_errors.primary_db_error(terminated) is terminated
    # A driver error without SQLSTATE that is no connection loss yields to the first one with a SQLSTATE.
    programming = psycopg.ProgrammingError("2 placeholders")
    programming.__cause__ = _unique()
    assert db_errors.primary_db_error(programming) is programming.__cause__


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
    assert err.count("--- Logging error ---") == 3  # the plain call on the plain handler succeeds
    assert SECRET not in err and "DETAIL" not in err
    assert "unique violation (SQLSTATE 23505)" in err
    assert "Message: 'user %s failed with %s'" in err


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
